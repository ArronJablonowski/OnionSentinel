#!/usr/bin/env python3
"""Parse fulfilled PCAP broker artifacts into LLM-safe evidence summaries.

Raw PCAPs are intentionally runtime-only. This worker runs on the Mac Studio,
where Zeek, TShark, Ollama, and the local SOC corpus live. It converts copied
PCAP artifacts into bounded JSON/Markdown summaries that can be included in SOC
Analyst prompt packages without handing binary packets or raw payloads to a
model.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import ipaddress
import json
import os
import re
import shutil
import sqlite3
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

BIN_DIR = Path(__file__).resolve().parent
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))
from pcap_lifecycle import analysis_completed, delete_request_artifacts
from disk_capacity import require_runtime_capacity
from bounded_http import BoundedHttpError, read_bounded_json
from bounded_process import BoundedProcessError, run_bounded_command, run_bounded_command_to_file
from pcap_analysis_core import BoundedTopCounter, CoverageTracker, DeterministicReservoir, sanitize_evidence_text
from pcap_tool_runtime import run_isolated_command, stream_isolated_lines
from detection_validation import (
    extract_rule_context,
    load_detection_playbooks,
    marker_specs as detection_marker_specs,
    resolve_detection_playbook,
)


HOME = Path.home()
DEFAULT_DB = HOME / "n8n-local" / "alert_store_data" / "alerts.sqlite3"
DEFAULT_AI_SETTINGS = HOME / "n8n-local" / "config" / "ai_model_settings.json"
DEFAULT_DETECTION_PLAYBOOKS = HOME / "n8n-local" / "config" / "detection_playbooks.json"
DEFAULT_MAXMIND_DBS = {
    "asn": HOME / "n8n-local" / "config" / "maxmind" / "GeoLite2-ASN.mmdb",
    "city": HOME / "n8n-local" / "config" / "maxmind" / "GeoLite2-City.mmdb",
    "country": HOME / "n8n-local" / "config" / "maxmind" / "GeoLite2-Country.mmdb",
}
# Kept as a compatibility alias for direct callers and older tests. Existing
# City-only deployments are migrated by configured_maxmind_db_paths().
DEFAULT_MAXMIND_DB = DEFAULT_MAXMIND_DBS["city"]
RUNTIME_PYTHON_DIR = HOME / "n8n-local" / "python"
if RUNTIME_PYTHON_DIR.is_dir() and str(RUNTIME_PYTHON_DIR) not in sys.path:
    sys.path.insert(0, str(RUNTIME_PYTHON_DIR))
DEFAULT_ARTIFACT_DIR = HOME / "n8n-local" / "pcap-evidence" / "artifacts"
DEFAULT_OUT_DIR = HOME / "n8n-local" / "soc-alerts" / "pcap-analysis"
DEFAULT_WAKE = Path(os.environ.get(
    "PCAP_ANALYSIS_WAKE_PATH",
    HOME / "n8n-local" / "run" / "pcap-analysis.wake",
))
PCAP_SUFFIXES = {".pcap", ".pcapng", ".cap"}
LOG_LIMIT = 2000
SUMMARY_LIMIT = 20
MAX_TOOL_STDOUT_BYTES = max(64 * 1024, int(os.environ.get("PCAP_TOOL_MAX_STDOUT_BYTES", str(2 * 1024 * 1024))))
MAX_TOOL_STDERR_BYTES = max(16 * 1024, int(os.environ.get("PCAP_TOOL_MAX_STDERR_BYTES", str(512 * 1024))))
TSHARK_SAMPLE_LIMIT = max(20, int(os.environ.get("PCAP_TSHARK_SAMPLE_LIMIT", "200")))
PARSER_TIMEOUT_SECONDS = max(60, int(os.environ.get("PCAP_PARSER_TIMEOUT_SECONDS", "900")))
HEAVY_HITTER_CAPACITY = max(SUMMARY_LIMIT, int(os.environ.get("PCAP_HEAVY_HITTER_CAPACITY", "256")))
ICMP_PAIR_STATE_LIMIT = max(128, int(os.environ.get("PCAP_ICMP_PAIR_STATE_LIMIT", "4096")))
QUERY_INDEX_LIMIT = max(
    SUMMARY_LIMIT,
    min(HEAVY_HITTER_CAPACITY, int(os.environ.get("PCAP_QUERY_INDEX_LIMIT", "96"))),
)
ICMP_ABNORMAL_MIN_FRAME_BYTES = max(
    64,
    int(os.environ.get("PCAP_ICMP_ABNORMAL_MIN_FRAME_BYTES", "256")),
)
MAXMIND_GEOIP_MAX_LOOKUPS = max(
    1,
    min(512, int(os.environ.get("MAXMIND_GEOIP_MAX_LOOKUPS", "128"))),
)
MAX_ARCHIVE_MEMBERS = max(1, int(os.environ.get("PCAP_MAX_ARCHIVE_MEMBERS", "2048")))
MAX_EXTRACTED_BYTES = max(1, int(os.environ.get("PCAP_MAX_EXTRACTED_BYTES", str(40 * 1024 * 1024 * 1024))))
MAX_PCAP_FILES = max(1, int(os.environ.get("PCAP_MAX_FILES", "256")))
MAX_REMOTE_ARTIFACT_BYTES = max(
    1,
    int(os.environ.get("PCAP_MAX_REMOTE_ARTIFACT_BYTES", str(40 * 1024 * 1024 * 1024))),
)
REMOTE_FETCH_TIMEOUT_SECONDS = max(30, int(os.environ.get("PCAP_REMOTE_FETCH_TIMEOUT_SECONDS", "3600")))
MAX_CONTROL_RESPONSE_BYTES = 64 * 1024
MAX_SELECTION_WINDOW_SECONDS = max(
    30,
    min(86400, int(os.environ.get("PCAP_EVIDENCE_MAX_SELECTION_WINDOW_SECONDS", "86400"))),
)
# Keep repeated TShark field values distinct without corrupting legitimate
# commas in DNS names, HTTP User-Agent strings, or other evidence text.
TSHARK_OCCURRENCE_SEPARATOR = "\x1f"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Parse PCAP broker artifacts with Zeek and TShark")
    parser.add_argument("--db", type=Path, default=DEFAULT_DB, help="Alert-store SQLite DB")
    parser.add_argument("--artifact-dir", type=Path, default=DEFAULT_ARTIFACT_DIR, help="Runtime-only copied PCAP artifact directory")
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR, help="PCAP analysis JSON/Markdown output directory")
    parser.add_argument("--ai-settings", type=Path, default=DEFAULT_AI_SETTINGS, help="AI/GeoIP settings JSON")
    parser.add_argument(
        "--detection-playbooks",
        type=Path,
        default=DEFAULT_DETECTION_PLAYBOOKS,
        help="Versioned exact-ID detection playbook registry",
    )
    parser.add_argument("--wake-file", type=Path, default=DEFAULT_WAKE, help="Consumable launchd wake marker")
    parser.add_argument("--request-id", help="Process one PCAP broker request id")
    parser.add_argument("--pcap", type=Path, help="Parse a local PCAP directly, without reading pcap_requests")
    parser.add_argument("--alert-id", help="Alert id to attach when --pcap is used")
    parser.add_argument("--group-id", help="Group id to attach when --pcap is used")
    parser.add_argument("--limit", type=int, default=5, help="Maximum fulfilled requests to process per run")
    parser.add_argument("--fetch-remote", action="store_true", help="Fetch fulfilled Security Onion artifacts before parsing")
    parser.add_argument("--ssh-target", default=os.environ.get("PCAP_ARTIFACT_SSH_TARGET", ""), help="SSH target used with --fetch-remote, for example user@security-onion")
    parser.add_argument("--ssh-bin", default=os.environ.get("PCAP_ARTIFACT_SSH_BIN", "ssh"), help="SSH executable for artifact fetch")
    parser.add_argument("--overwrite", action="store_true", help="Rebuild existing analysis artifacts")
    parser.add_argument("--retain-artifact", action="store_true", help="Keep a successfully parsed broker artifact for controlled troubleshooting")
    parser.add_argument("--alert-store-url", default=os.environ.get("ALERT_STORE_URL", "http://127.0.0.1:8787"), help="Alert-store base URL for durable parser status")
    parser.add_argument("--stdout", action="store_true", help="Print JSON summaries after processing")
    args = parser.parse_args()
    if args.limit <= 0:
        parser.error("--limit must be positive")
    if args.request_id and args.pcap:
        parser.error("--request-id and --pcap are mutually exclusive")
    return args


def project_now() -> str:
    return dt.datetime.now().astimezone().replace(microsecond=0).isoformat().replace("T", "  ")


def consume_wake_marker(path: Path) -> None:
    """Remove the current event so arrivals during parsing trigger a rerun."""
    try:
        path.unlink(missing_ok=True)
    except OSError as error:
        print(f"PCAP wake marker could not be consumed: {error}", file=sys.stderr)


def signal_follow_up(path: Path) -> None:
    """Request another bounded pass when this run filled its batch."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_text(f"{project_now()} pcap-batch-remains\n", encoding="utf-8")
        path.chmod(0o600)
    except OSError as error:
        print(f"PCAP follow-up wake failed: {error}", file=sys.stderr)


def safe_filename(value: object) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(value or "pcap")).strip("-")
    return (cleaned or "pcap")[:140]


def configured_maxmind_db_paths(settings_path: Path = DEFAULT_AI_SETTINGS) -> dict[str, Path]:
    """Resolve the three local MMDB paths while migrating the City-only key.

    Environment overrides remain useful for ephemeral deployments. The legacy
    MAXMIND_GEOIP_DB_PATH and maxmind_geoip_db_path values apply only to City so
    an existing operator configuration is never silently discarded.
    """
    try:
        settings = json.loads(settings_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        settings = {}
    settings = settings if isinstance(settings, dict) else {}
    legacy_city = str(
        os.environ.get("MAXMIND_GEOIP_DB_PATH")
        or settings.get("maxmind_geoip_db_path")
        or ""
    ).strip()
    paths: dict[str, Path] = {}
    for database_type, default_path in DEFAULT_MAXMIND_DBS.items():
        environment_key = f"MAXMIND_GEOIP_{database_type.upper()}_DB_PATH"
        setting_key = f"maxmind_geoip_{database_type}_db_path"
        configured = str(os.environ.get(environment_key) or settings.get(setting_key) or "").strip()
        if database_type == "city" and not configured:
            configured = legacy_city
        paths[database_type] = Path(configured or default_path).expanduser()
    return paths


def configured_maxmind_db_path(settings_path: Path = DEFAULT_AI_SETTINGS) -> Path:
    """Return the configured City database path for legacy callers."""
    return configured_maxmind_db_paths(settings_path)["city"]


def public_ip(value: object) -> str:
    """Return a canonical globally routable IP or an empty string.

    Private, loopback, link-local, multicast, documentation, and otherwise
    non-global addresses are deliberately excluded from GeoIP lookup.
    """
    try:
        address = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return ""
    return str(address) if address.is_global else ""


TLS_VERSION_NAMES = {
    "0x0300": "SSL 3.0",
    "0x0301": "TLS 1.0",
    "0x0302": "TLS 1.1",
    "0x0303": "TLS 1.2 (or TLS 1.3 legacy record)",
    "0x0304": "TLS 1.3",
}


def tshark_occurrences(value: object) -> list[str]:
    """Split TShark multi-occurrence fields into bounded, sanitized values."""
    return [
        sanitized
        for item in str(value or "").split(TSHARK_OCCURRENCE_SEPARATOR)[:64]
        if (sanitized := sanitize_evidence_text(item, 512))
    ]


def tls_version_name(value: object) -> tuple[str, str]:
    raw = sanitize_evidence_text(value, 32).lower()
    if not raw:
        return "", ""
    if raw.isdigit():
        raw = f"0x{int(raw):04x}"
    return raw, TLS_VERSION_NAMES.get(raw, f"Unknown ({raw})")


def _maxmind_name(record: object) -> str:
    if not isinstance(record, dict):
        return ""
    names = record.get("names")
    return sanitize_evidence_text(names.get("en"), 160) if isinstance(names, dict) else ""


def compact_maxmind_record(address: str, record: dict[str, Any], roles: list[str], count: int) -> dict[str, Any]:
    """Keep only useful offline GeoIP context; raw MMDB records stay local."""
    country = record.get("country") if isinstance(record.get("country"), dict) else {}
    registered = record.get("registered_country") if isinstance(record.get("registered_country"), dict) else {}
    continent = record.get("continent") if isinstance(record.get("continent"), dict) else {}
    city = record.get("city") if isinstance(record.get("city"), dict) else {}
    location = record.get("location") if isinstance(record.get("location"), dict) else {}
    subdivisions = record.get("subdivisions") if isinstance(record.get("subdivisions"), list) else []
    subdivision = subdivisions[0] if subdivisions and isinstance(subdivisions[0], dict) else {}
    output: dict[str, Any] = {
        "ip": address,
        "roles": sorted(set(roles)),
        "packet_observations": count,
        "continent": _maxmind_name(continent),
        "country_iso_code": sanitize_evidence_text(country.get("iso_code"), 8),
        "country": _maxmind_name(country),
        "registered_country_iso_code": sanitize_evidence_text(registered.get("iso_code"), 8),
        "subdivision": _maxmind_name(subdivision),
        "city": _maxmind_name(city),
        "time_zone": sanitize_evidence_text(location.get("time_zone"), 80),
        "accuracy_radius_km": location.get("accuracy_radius"),
        "latitude": location.get("latitude"),
        "longitude": location.get("longitude"),
        "autonomous_system_number": record.get("autonomous_system_number"),
        "autonomous_system_organization": sanitize_evidence_text(record.get("autonomous_system_organization"), 200),
    }
    return {key: value for key, value in output.items() if value not in (None, "", [], {})}


def maxmind_geoip_summary(
    candidates: BoundedTopCounter,
    database_paths: dict[str, Path] | Path,
) -> dict[str, Any]:
    """Perform bounded, offline ASN, City, and Country lookups.

    Readers are opened only after TShark has finished streaming. Every public IP
    is looked up at most once per ready database, and only compact merged fields
    are retained. A missing optional database never blocks PCAP analysis.
    """
    if isinstance(database_paths, Path):
        database_paths = {"city": database_paths}
    normalized_paths = {
        database_type: Path(path).expanduser()
        for database_type, path in database_paths.items()
        if database_type in DEFAULT_MAXMIND_DBS
    }
    summary: dict[str, Any] = {
        "available": False,
        "network_access": "none-offline-database-only",
        "public_ip_candidates": 0,
        "lookups_attempted": 0,
        "records": [],
        "databases": {},
    }
    candidate_rows = candidates.most_common(("ip", "role"), MAXMIND_GEOIP_MAX_LOOKUPS * 2)
    by_ip: dict[str, dict[str, Any]] = {}
    for item in candidate_rows:
        address = public_ip(item.get("ip"))
        if not address:
            continue
        current = by_ip.setdefault(address, {"count": 0, "roles": []})
        current["count"] += int(item.get("count") or 0)
        role = sanitize_evidence_text(item.get("role"), 24)
        if role:
            current["roles"].append(role)
    summary["public_ip_candidates"] = len(by_ip)
    for database_type in ("asn", "city", "country"):
        path = normalized_paths.get(database_type)
        if path is None:
            continue
        summary["databases"][database_type] = {
            "state": "missing",
            "database": path.name,
            "lookups_attempted": 0,
            "records_found": 0,
            "records_not_found": 0,
            "lookup_errors": 0,
        }
    ready_paths = {
        database_type: path
        for database_type, path in normalized_paths.items()
        if path.is_file()
    }
    if not ready_paths:
        summary["reason"] = "No configured MaxMind MMDB files are installed"
        return summary
    try:
        import maxminddb  # type: ignore
    except ImportError:
        summary["reason"] = "maxminddb Python reader is not installed in the Onion Sentinel runtime"
        return summary
    readers: dict[str, Any] = {}
    try:
        for database_type, path in ready_paths.items():
            database_status = summary["databases"][database_type]
            try:
                reader = maxminddb.open_database(str(path))
                metadata = reader.metadata()
            except Exception as exc:
                database_status["state"] = "unreadable"
                database_status["error"] = sanitize_evidence_text(exc, 240)
                continue
            readers[database_type] = reader
            database_status["state"] = "ready"
            database_status["database_type"] = sanitize_evidence_text(
                getattr(metadata, "database_type", ""),
                120,
            )
        for address, context in sorted(
            by_ip.items(),
            key=lambda item: (-item[1]["count"], item[0]),
        )[:MAXMIND_GEOIP_MAX_LOOKUPS]:
            merged: dict[str, Any] = {
                "ip": address,
                "roles": sorted(set(context["roles"])),
                "packet_observations": context["count"],
            }
            sources: list[str] = []
            for database_type in ("asn", "city", "country"):
                reader = readers.get(database_type)
                if reader is None:
                    continue
                database_status = summary["databases"][database_type]
                database_status["lookups_attempted"] += 1
                summary["lookups_attempted"] += 1
                try:
                    record = reader.get(address)
                except Exception:
                    database_status["lookup_errors"] += 1
                    continue
                if not isinstance(record, dict):
                    database_status["records_not_found"] += 1
                    continue
                database_status["records_found"] += 1
                sources.append(database_type)
                compact = compact_maxmind_record(address, record, context["roles"], context["count"])
                for key, value in compact.items():
                    if key not in {"ip", "roles", "packet_observations"} and key not in merged:
                        merged[key] = value
            if sources:
                merged["database_sources"] = sources
                summary["records"].append(merged)
    finally:
        for reader in readers.values():
            reader.close()
    summary["available"] = bool(readers)
    summary["records_found"] = len(summary["records"])
    summary["records_not_found"] = sum(
        int(status.get("records_not_found") or 0)
        for status in summary["databases"].values()
    )
    summary["lookup_errors"] = sum(
        int(status.get("lookup_errors") or 0)
        for status in summary["databases"].values()
    )
    if not readers:
        summary["reason"] = "Configured MaxMind MMDB files could not be opened"
    return summary


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tool_path(env_name: str, executable: str) -> str | None:
    configured = os.environ.get(env_name)
    if configured:
        return configured if Path(configured).exists() else None
    found = shutil.which(executable)
    if found:
        return found
    for prefix in (Path("/opt/homebrew/bin"), Path("/usr/local/bin")):
        candidate = prefix / executable
        if candidate.exists():
            return str(candidate)
    return None


def run_command(command: list[str], cwd: Path | None = None, timeout: int = 120) -> dict[str, Any]:
    try:
        proc = run_isolated_command(
            command,
            timeout_seconds=timeout,
            max_stdout_bytes=MAX_TOOL_STDOUT_BYTES,
            max_stderr_bytes=MAX_TOOL_STDERR_BYTES,
            cwd=cwd,
        )
    except FileNotFoundError:
        return {"ok": False, "returncode": 127, "stdout": "", "stderr": f"not found: {command[0]}", "command": command}
    except BoundedProcessError as exc:
        return {"ok": False, "returncode": 124, "stdout": "", "stderr": str(exc), "command": command}
    return {
        "ok": proc.returncode == 0,
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "command": command,
    }


def rows(conn: sqlite3.Connection, sql: str, params: Iterable[object] = ()) -> list[sqlite3.Row]:
    return conn.execute(sql, tuple(params)).fetchall()
