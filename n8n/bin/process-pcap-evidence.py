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


def request_from_row(row: sqlite3.Row) -> dict[str, Any]:
    return {key: row[key] for key in row.keys()}


def table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {str(item["name"]) for item in rows(conn, f"PRAGMA table_info({table})")}


def pending_requests(db_path: Path, request_id: str | None, limit: int, out_dir: Path, overwrite: bool) -> list[dict[str, Any]]:
    if not db_path.exists():
        return []
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        columns = table_columns(conn, "pcap_requests")
        order_column = "completed_at" if "completed_at" in columns else "updated_at"
        if request_id:
            candidates = rows(conn, "SELECT * FROM pcap_requests WHERE request_id = ? AND status = 'fulfilled'", [request_id])
        else:
            # Do not LIMIT before excluding existing analysis artifacts. Doing
            # so repeatedly selected the newest already-processed rows and
            # starved older fulfilled captures forever.
            candidates = conn.execute(
                f"""
                SELECT *
                FROM pcap_requests
                WHERE status = 'fulfilled'
                ORDER BY {order_column} DESC, created_at DESC
                """
            )
        found: list[sqlite3.Row] = []
        for item in candidates:
            item_request_id = str(item["request_id"] or "")
            durable_incomplete = "analysis_status" in columns and str(item["analysis_status"] or "") != "completed"
            if overwrite or durable_incomplete or not analysis_json_path(out_dir, item_request_id).exists():
                found.append(item)
                if len(found) >= limit:
                    break
    finally:
        conn.close()
    return [request_from_row(item) for item in found]


def signature_context_for_request(
    db_path: Path,
    request: dict[str, Any],
    playbook_path: Path = DEFAULT_DETECTION_PLAYBOOKS,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Load the exact alert rule and its exact-ID playbook without DB writes.

    The returned rule context includes a bounded ``playbook_policy`` object so
    a missing, unreadable, or invalid registry can never be confused with a
    valid registry that simply has no exact playbook for this rule.
    """
    alert_id = str(request.get("alert_id") or "").strip()
    if not alert_id:
        return {
            "playbook_policy": {
                "status": "not_evaluated",
                "fail_closed": True,
                "evidence_gap": "No selected alert id was supplied for exact detection-playbook resolution.",
            },
        }, None
    if not db_path.exists():
        return {
            "playbook_policy": {
                "status": "alert_database_missing",
                "fail_closed": True,
                "evidence_gap": "The alert database was unavailable for exact detection-playbook resolution.",
            },
        }, None
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        columns = table_columns(conn, "alerts")
        if "alert_id" not in columns:
            return {
                "playbook_policy": {
                    "status": "alert_schema_unsupported",
                    "fail_closed": True,
                    "evidence_gap": "The alert database lacks the alert_id column required for exact rule resolution.",
                },
            }, None
        projection = ", ".join(
            column if column in columns else f"NULL AS {column}"
            for column in ("alert_json", "raw_event_json", "rule_id")
        )
        row = conn.execute(
            f"SELECT {projection} FROM alerts WHERE alert_id = ?",
            (alert_id,),
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        return {
            "playbook_policy": {
                "status": "alert_not_found",
                "fail_closed": True,
                "evidence_gap": "The selected alert was not found for exact detection-playbook resolution.",
            },
        }, None
    context = extract_rule_context(row["alert_json"], row["raw_event_json"], row["rule_id"])
    try:
        playbook_path.stat()
    except FileNotFoundError:
        context["playbook_policy"] = {
            "status": "registry_missing",
            "fail_closed": True,
            "evidence_gap": "The detection-playbook registry is missing; playbook-specific conclusions are unavailable.",
        }
        return context, None
    except OSError:
        context["playbook_policy"] = {
            "status": "registry_unreadable",
            "fail_closed": True,
            "evidence_gap": "The detection-playbook registry could not be read; playbook-specific conclusions are unavailable.",
        }
        return context, None
    try:
        registry = load_detection_playbooks(playbook_path)
        playbook = resolve_detection_playbook(registry, context)
    except OSError:
        context["playbook_policy"] = {
            "status": "registry_unreadable",
            "fail_closed": True,
            "evidence_gap": "The detection-playbook registry could not be read; playbook-specific conclusions are unavailable.",
        }
        return context, None
    except (UnicodeError, ValueError):
        context["playbook_policy"] = {
            "status": "registry_invalid",
            "fail_closed": True,
            "evidence_gap": "The detection-playbook registry failed validation; playbook-specific conclusions are unavailable.",
        }
        return context, None
    if registry.get("version") == 0:
        context["playbook_policy"] = {
            "status": "registry_missing",
            "fail_closed": True,
            "evidence_gap": "The detection-playbook registry is missing; playbook-specific conclusions are unavailable.",
        }
        return context, None
    if not isinstance(playbook, dict):
        context["playbook_policy"] = {
            "status": "no_exact_playbook",
            "fail_closed": True,
            "registry_version": registry.get("version"),
            "evidence_gap": "No exact detection playbook matched the selected rule identity.",
        }
        return context, None
    context["playbook_policy"] = {
        "status": "exact_playbook_matched",
        "fail_closed": False,
        "registry_version": registry.get("version"),
        "evidence_gap": "",
    }
    return context, playbook


def _timestamp_epoch(value: object) -> float | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = dt.datetime.fromisoformat(text.replace("  ", "T").replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.timestamp()


def icmp_evidence_scope(request: dict[str, Any]) -> dict[str, Any]:
    """Build the bounded endpoint/time scope used for alert-associated ICMP."""
    source_ip = sanitize_evidence_text(request.get("source_ip"), 64)
    destination_ip = sanitize_evidence_text(request.get("destination_ip"), 64)
    try:
        source_ip = str(ipaddress.ip_address(source_ip)) if source_ip else ""
    except ValueError:
        source_ip = ""
    try:
        destination_ip = str(ipaddress.ip_address(destination_ip)) if destination_ip else ""
    except ValueError:
        destination_ip = ""

    first_epoch = _timestamp_epoch(request.get("first_seen"))
    last_epoch = _timestamp_epoch(request.get("last_seen"))
    start_epoch: float | None = None
    end_epoch: float | None = None
    if first_epoch is not None and last_epoch is not None:
        first_epoch, last_epoch = sorted((first_epoch, last_epoch))
        try:
            requested_window = int(request.get("max_window_seconds") or 120)
        except (TypeError, ValueError):
            requested_window = 120
        window_seconds = max(30, min(MAX_SELECTION_WINDOW_SECONDS, requested_window))
        duration = max(0, int(last_epoch - first_epoch))
        if duration > window_seconds:
            start_epoch, end_epoch = last_epoch - window_seconds, last_epoch
        else:
            padding = max(0, (window_seconds - duration) // 2)
            start_epoch, end_epoch = first_epoch - padding, last_epoch + padding
    return {
        "selected_alert_id": sanitize_evidence_text(request.get("alert_id"), 256),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "window_start_epoch": start_epoch,
        "window_end_epoch": end_epoch,
        "window_basis": "bounded-pcap-request-window" if start_epoch is not None else "unavailable",
    }


def _icmp_scope_match(
    source: str,
    destination: str,
    timestamp: float | None,
    scope: dict[str, Any],
) -> tuple[bool, str]:
    selected_source = str(scope.get("source_ip") or "")
    selected_destination = str(scope.get("destination_ip") or "")
    if selected_source and selected_destination:
        if {source, destination} != {selected_source, selected_destination}:
            return False, "endpoint"
    elif selected_source or selected_destination:
        selected = selected_source or selected_destination
        if selected not in {source, destination}:
            return False, "endpoint"
    start_epoch = scope.get("window_start_epoch")
    end_epoch = scope.get("window_end_epoch")
    if isinstance(start_epoch, (int, float)) and isinstance(end_epoch, (int, float)):
        if timestamp is None:
            return False, "missing_timestamp"
        if timestamp < float(start_epoch) or timestamp > float(end_epoch):
            return False, "time"
    return True, ""


def analysis_json_path(out_dir: Path, request_id: str) -> Path:
    return out_dir / f"{safe_filename(request_id)}-pcap-analysis.json"


def candidate_artifact_paths(request: dict[str, Any], artifact_dir: Path) -> list[Path]:
    request_id = safe_filename(request.get("request_id"))
    candidates: list[Path] = []
    remote_name = Path(str(request.get("artifact_path") or "capture.pcap")).name
    request_dir = artifact_dir / request_id
    candidates.append(request_dir / remote_name)
    candidates.extend(sorted(request_dir.glob("*.pcap")))
    candidates.extend(sorted(request_dir.glob("*.pcapng")))
    candidates.extend(sorted(request_dir.glob("*.tar")))
    candidates.extend(sorted(request_dir.glob("*.tar.gz")))
    candidates.extend(sorted(request_dir.glob("*.tgz")))
    return list(dict.fromkeys(candidates))


def local_artifact_path(request: dict[str, Any], artifact_dir: Path) -> Path:
    request_id = safe_filename(request.get("request_id"))
    remote_name = Path(str(request.get("artifact_path") or "capture.pcap")).name
    return artifact_dir / request_id / remote_name


def fetch_remote_artifact(request: dict[str, Any], artifact_dir: Path, ssh_target: str, ssh_bin: str = "ssh") -> dict[str, Any]:
    artifact_path = str(request.get("artifact_path") or "")
    expected_sha256 = str(request.get("artifact_sha256") or "")
    expected_size = request.get("artifact_size_bytes")
    if not artifact_path or not ssh_target:
        return {"ok": False, "reason": "remote fetch not configured"}
    if not re.fullmatch(r"/nsm/pcapout/onion-sentinel/[A-Za-z0-9._/-]+", artifact_path):
        return {"ok": False, "reason": "remote artifact path is outside the Onion Sentinel PCAP output directory"}
    if ".." in Path(artifact_path).parts:
        return {"ok": False, "reason": "remote artifact path contains traversal components"}

    try:
        expected_size_int = int(expected_size) if expected_size not in (None, "") else None
    except (TypeError, ValueError):
        return {"ok": False, "reason": "remote artifact size metadata is invalid"}
    if expected_size_int is not None and (expected_size_int < 0 or expected_size_int > MAX_REMOTE_ARTIFACT_BYTES):
        return {"ok": False, "reason": "remote artifact exceeds the configured transfer ceiling"}

    destination = local_artifact_path(request, artifact_dir)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temp_path = destination.with_suffix(destination.suffix + ".tmp")
    command = [ssh_bin, "-o", "BatchMode=yes", "-T", ssh_target, "sudo", "-n", "cat", artifact_path]
    transfer_ceiling = expected_size_int if expected_size_int is not None else MAX_REMOTE_ARTIFACT_BYTES
    require_runtime_capacity(destination.parent, max(1, transfer_ceiling), label="remote PCAP artifact fetch")
    try:
        proc = run_bounded_command_to_file(
            command,
            temp_path,
            timeout_seconds=REMOTE_FETCH_TIMEOUT_SECONDS,
            max_stdout_bytes=max(1, transfer_ceiling),
            max_stderr_bytes=MAX_TOOL_STDERR_BYTES,
        )
    except (BoundedProcessError, OSError) as error:
        temp_path.unlink(missing_ok=True)
        return {"ok": False, "reason": str(error)[:240]}
    if proc.returncode != 0:
        temp_path.unlink(missing_ok=True)
        return {"ok": False, "reason": proc.stderr[:240] or f"ssh exited {proc.returncode}"}
    if expected_size_int is not None and temp_path.stat().st_size != expected_size_int:
        temp_path.unlink(missing_ok=True)
        return {"ok": False, "reason": "downloaded artifact size did not match broker metadata"}
    if expected_sha256 and sha256_file(temp_path) != expected_sha256:
        temp_path.unlink(missing_ok=True)
        return {"ok": False, "reason": "downloaded artifact sha256 did not match broker metadata"}
    temp_path.replace(destination)
    destination.chmod(0o600)
    return {"ok": True, "path": str(destination)}


def safe_extract_tar(path: Path, destination: Path) -> None:
    with tarfile.open(path) as archive:
        members = archive.getmembers()
        if len(members) > MAX_ARCHIVE_MEMBERS:
            raise ValueError(f"archive has too many members: {len(members)} > {MAX_ARCHIVE_MEMBERS}")
        expanded_bytes = sum(max(0, int(member.size or 0)) for member in members if member.isfile())
        if expanded_bytes > MAX_EXTRACTED_BYTES:
            raise ValueError(f"archive expands beyond limit: {expanded_bytes} > {MAX_EXTRACTED_BYTES}")
        require_runtime_capacity(
            destination,
            expanded_bytes,
            label="PCAP archive extraction",
        )
        for member in members:
            if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                raise ValueError(f"unsupported archive member type: {member.name}")
            target = (destination / member.name).resolve()
            if target != destination.resolve() and destination.resolve() not in target.parents:
                raise ValueError(f"unsafe tar member path: {member.name}")
        archive.extractall(destination, members=members)


def materialize_pcap_files(request: dict[str, Any], args: argparse.Namespace, work_dir: Path, direct_pcap: Path | None = None) -> tuple[list[Path], str]:
    if direct_pcap:
        return [direct_pcap], "direct"
    if getattr(args, "fetch_remote", False) and not any(path.exists() for path in candidate_artifact_paths(request, args.artifact_dir)):
        fetched = fetch_remote_artifact(
            request,
            args.artifact_dir,
            getattr(args, "ssh_target", ""),
            getattr(args, "ssh_bin", "ssh"),
        )
        if not fetched.get("ok"):
            return [], f"artifact-fetch-failed: {fetched.get('reason')}"
    candidates = candidate_artifact_paths(request, args.artifact_dir)
    direct_candidates = [candidate for candidate in candidates if candidate.exists() and candidate.suffix.lower() in PCAP_SUFFIXES]
    if direct_candidates:
        pcaps = list(dict.fromkeys(direct_candidates))
        if len(pcaps) > MAX_PCAP_FILES:
            raise ValueError(f"artifact directory contains too many PCAP files: {len(pcaps)} > {MAX_PCAP_FILES}")
        return sorted(pcaps), "copied-artifact"
    for candidate in candidates:
        if not candidate.exists():
            continue
        if candidate.suffix.lower() == ".tar" or candidate.name.endswith((".tar.gz", ".tgz")):
            extract_dir = work_dir / "extract"
            extract_dir.mkdir(parents=True, exist_ok=True)
            safe_extract_tar(candidate, extract_dir)
            pcaps = [path for path in extract_dir.rglob("*") if path.is_file() and path.suffix.lower() in PCAP_SUFFIXES]
            if len(pcaps) > MAX_PCAP_FILES:
                raise ValueError(f"archive contains too many PCAP files: {len(pcaps)} > {MAX_PCAP_FILES}")
            return sorted(pcaps), "extracted-artifact"
    return [], "artifact-not-copied-to-mac"


def scan_json_lines(path: Path, limit: int = LOG_LIMIT) -> dict[str, Any]:
    """Stream a Zeek JSONL log while retaining only a bounded sample.

    Record counts remain exact, but the retained objects are capped before
    aggregation. This keeps memory proportional to ``limit`` even when an
    offline capture produces millions of Zeek records.
    """
    records: list[dict[str, Any]] = []
    valid_records = 0
    invalid_lines = 0
    if not path.exists():
        return {
            "records": records,
            "valid_records": valid_records,
            "invalid_lines": invalid_lines,
            "truncated": False,
        }
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:
                invalid_lines += 1
                continue
            if not isinstance(parsed, dict):
                invalid_lines += 1
                continue
            valid_records += 1
            if len(records) < max(0, limit):
                records.append(parsed)
    return {
        "records": records,
        "valid_records": valid_records,
        "invalid_lines": invalid_lines,
        "truncated": valid_records > len(records),
    }


def load_json_lines(path: Path, limit: int = LOG_LIMIT) -> list[dict[str, Any]]:
    """Compatibility wrapper for callers that only need the bounded sample."""
    return scan_json_lines(path, limit)["records"]


def top_values(records: list[dict[str, Any]], *fields: str) -> list[dict[str, Any]]:
    counts: Counter[tuple[str, ...]] = Counter()
    for record in records:
        values = tuple(str(record.get(field) or "") for field in fields)
        if any(values):
            counts[values] += 1
    return [
        {"count": count, **{field: value for field, value in zip(fields, values)}}
        for values, count in counts.most_common(SUMMARY_LIMIT)
    ]


ZEEK_SUMMARY_FIELDS = {
    "conn": ("id.orig_h", "id.resp_h", "id.resp_p", "proto", "service"),
    "dns": ("query", "qtype_name", "rcode_name"),
    "tls": ("server_name", "id.orig_h", "id.resp_h"),
    "http": ("host", "uri", "method", "status_code"),
    "files": ("mime_type", "filename", "seen_bytes"),
    "notice": ("note", "msg"),
    "weird": ("name", "addl"),
}


def aggregate_zeek_log(
    path: Path,
    fields: tuple[str, ...],
    counter: BoundedTopCounter,
    coverage: CoverageTracker,
) -> None:
    """Read every Zeek record while keeping only bounded heavy-hitter state."""
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:
                coverage.malformed_records += 1
                continue
            if not isinstance(parsed, dict):
                coverage.malformed_records += 1
                continue
            packet_bytes = 0
            for key in ("orig_bytes", "resp_bytes", "seen_bytes"):
                try:
                    packet_bytes += max(0, int(parsed.get(key) or 0))
                except (TypeError, ValueError):
                    continue
            coverage.observe(timestamp=parsed.get("ts"), length=packet_bytes, decoded=True)
            counter.add(parsed.get(field) for field in fields)


def run_zeek(pcap_files: list[Path], work_dir: Path) -> dict[str, Any]:
    zeek = tool_path("ZEEK_BIN", "zeek")
    if not zeek:
        return {"available": False, "reason": "zeek executable not found on PATH or ZEEK_BIN"}
    zeek_dir = work_dir / "zeek"
    zeek_dir.mkdir(parents=True, exist_ok=True)
    commands: list[dict[str, Any]] = []
    log_names = {
        "conn": ("conn.log",),
        "dns": ("dns.log",),
        "tls": ("ssl.log", "tls.log"),
        "http": ("http.log",),
        "files": ("files.log",),
        "notice": ("notice.log",),
        "weird": ("weird.log",),
    }
    counters = {key: BoundedTopCounter(HEAVY_HITTER_CAPACITY) for key in log_names}
    coverage = {key: CoverageTracker() for key in log_names}
    files_processed = 0

    for index, pcap in enumerate(pcap_files):
        # Zeek uses fixed output names. A distinct workspace per capture keeps
        # one run from overwriting or silently mixing another capture's logs.
        capture_dir = zeek_dir / f"{index:04d}-{safe_filename(pcap.stem)}"
        capture_dir.mkdir(parents=True, exist_ok=False)
        try:
            result = run_command(
                [zeek, "-C", "LogAscii::use_json=T", "-r", str(pcap)],
                cwd=capture_dir,
                timeout=PARSER_TIMEOUT_SECONDS,
            )
            commands.append({key: result[key] for key in ("ok", "returncode", "stderr", "command")})
            for log_key, candidates in log_names.items():
                path = next((capture_dir / name for name in candidates if (capture_dir / name).exists()), None)
                if path is not None:
                    aggregate_zeek_log(path, ZEEK_SUMMARY_FIELDS[log_key], counters[log_key], coverage[log_key])
            if result["ok"]:
                files_processed += 1
        finally:
            shutil.rmtree(capture_dir, ignore_errors=True)
    record_counts = {key: coverage[key].total_records for key in log_names}
    valid_timestamps = [item for item in coverage.values() if item.first_timestamp is not None]
    return {
        "available": True,
        "commands": commands,
        "record_counts": record_counts,
        "coverage": {
            "pcap_files_total": len(pcap_files),
            "pcap_files_processed": files_processed,
            "records_aggregated": sum(record_counts.values()),
            "first_timestamp_epoch": min((item.first_timestamp for item in valid_timestamps), default=None),
            "last_timestamp_epoch": max((item.last_timestamp for item in valid_timestamps), default=None),
            "per_log": {key: coverage[key].as_dict() for key in log_names},
            "complete": files_processed == len(pcap_files) and all(item.get("ok") for item in commands),
        },
        "sampling": {
            "strategy": "full-stream-bounded-heavy-hitters",
            "heavy_hitter_capacity_per_log": HEAVY_HITTER_CAPACITY,
            "records_truncated_before_aggregation": {key: False for key in log_names},
            "invalid_json_lines": {key: coverage[key].malformed_records for key in log_names},
        },
        "top_connections": counters["conn"].most_common(ZEEK_SUMMARY_FIELDS["conn"], SUMMARY_LIMIT),
        "dns_queries": counters["dns"].most_common(ZEEK_SUMMARY_FIELDS["dns"], SUMMARY_LIMIT),
        "tls_sni": counters["tls"].most_common(ZEEK_SUMMARY_FIELDS["tls"], SUMMARY_LIMIT),
        "http_hosts": counters["http"].most_common(ZEEK_SUMMARY_FIELDS["http"], SUMMARY_LIMIT),
        "files": counters["files"].most_common(ZEEK_SUMMARY_FIELDS["files"], SUMMARY_LIMIT),
        "notices": counters["notice"].most_common(ZEEK_SUMMARY_FIELDS["notice"], SUMMARY_LIMIT),
        "weird": counters["weird"].most_common(ZEEK_SUMMARY_FIELDS["weird"], SUMMARY_LIMIT),
        # This bounded index is retained only for local, allowlisted follow-up
        # queries. It is stripped before either the initial local prompt or any
        # hosted-model request is assembled.
        "_local_query_index": {
            "connections": counters["conn"].most_common(ZEEK_SUMMARY_FIELDS["conn"], QUERY_INDEX_LIMIT),
            "dns": counters["dns"].most_common(ZEEK_SUMMARY_FIELDS["dns"], QUERY_INDEX_LIMIT),
            "tls": counters["tls"].most_common(ZEEK_SUMMARY_FIELDS["tls"], QUERY_INDEX_LIMIT),
            "http": counters["http"].most_common(ZEEK_SUMMARY_FIELDS["http"], QUERY_INDEX_LIMIT),
            "files": counters["files"].most_common(ZEEK_SUMMARY_FIELDS["files"], QUERY_INDEX_LIMIT),
            "notices": counters["notice"].most_common(ZEEK_SUMMARY_FIELDS["notice"], QUERY_INDEX_LIMIT),
            "weird": counters["weird"].most_common(ZEEK_SUMMARY_FIELDS["weird"], QUERY_INDEX_LIMIT),
        },
    }


def run_tshark(
    pcap_files: list[Path],
    maxmind_db_paths: dict[str, Path] | Path | None = None,
    markers: list[dict[str, Any]] | None = None,
    selected_scope: dict[str, Any] | None = None,
) -> dict[str, Any]:
    tshark = tool_path("TSHARK_BIN", "tshark")
    if not tshark:
        return {"available": False, "reason": "tshark executable not found on PATH or TSHARK_BIN"}
    field_names = (
        "frame_number", "timestamp_epoch", "frame_length", "protocol",
        "ipv4_src", "ipv6_src", "ipv4_dst", "ipv6_dst",
        "tcp_srcport", "tcp_dstport", "udp_srcport", "udp_dstport",
        "dns_query", "dns_query_type", "dns_rcode", "dns_answer_ipv4", "dns_answer_ipv6", "dns_cname",
        "tls_sni", "tls_handshake_version", "tls_supported_version", "tls_record_version",
        "http_host", "http_uri", "http_user_agent", "http2_user_agent",
        "icmp_type", "icmp_code", "icmpv6_type", "icmpv6_code",
        "icmp_identifier", "icmp_sequence", "data_length", "data_payload",
    )
    tshark_fields = (
        "frame.number", "frame.time_epoch", "frame.len", "_ws.col.Protocol",
        "ip.src", "ipv6.src", "ip.dst", "ipv6.dst",
        "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
        "dns.qry.name", "dns.qry.type", "dns.flags.rcode", "dns.a", "dns.aaaa", "dns.cname",
        "tls.handshake.extensions_server_name", "tls.handshake.version", "tls.handshake.extensions.supported_version", "tls.record.version",
        "http.host", "http.request.uri", "http.user_agent", "http2.headers.user_agent",
        "icmp.type", "icmp.code", "icmpv6.type", "icmpv6.code",
        "icmp.ident", "icmp.seq", "data.len", "data.data",
    )
    commands: list[dict[str, Any]] = []
    coverage = CoverageTracker()
    per_file: list[dict[str, Any]] = []
    reservoir = DeterministicReservoir(TSHARK_SAMPLE_LIMIT)
    protocols = BoundedTopCounter(128)
    conversations = BoundedTopCounter(HEAVY_HITTER_CAPACITY)
    dns_queries = BoundedTopCounter(HEAVY_HITTER_CAPACITY)
    dns_answers = BoundedTopCounter(HEAVY_HITTER_CAPACITY)
    dns_query_types = BoundedTopCounter(128)
    dns_rcodes = BoundedTopCounter(128)
    user_agents = BoundedTopCounter(HEAVY_HITTER_CAPACITY)
    tls_versions = BoundedTopCounter(128)
    icmp_anomalies = BoundedTopCounter(HEAVY_HITTER_CAPACITY)
    icmp_anomaly_samples = DeterministicReservoir(min(TSHARK_SAMPLE_LIMIT, 100))
    icmp_type_codes = BoundedTopCounter(128)
    icmp_identifiers = BoundedTopCounter(HEAVY_HITTER_CAPACITY)
    icmp_sequences = BoundedTopCounter(HEAVY_HITTER_CAPACITY)
    icmp_payload_lengths = BoundedTopCounter(HEAVY_HITTER_CAPACITY)
    icmp_pair_latencies = BoundedTopCounter(HEAVY_HITTER_CAPACITY)
    pending_icmp_requests: dict[tuple[str, str, str, str], float] = {}
    marker_values: list[tuple[dict[str, Any], bytes]] = []
    marker_offsets: dict[str, BoundedTopCounter] = {}
    marker_packet_counts: Counter[str] = Counter()
    for marker in markers or []:
        if not isinstance(marker, dict):
            continue
        try:
            decoded_marker = bytes.fromhex(str(marker.get("hex") or ""))
        except ValueError:
            continue
        marker_id = str(marker.get("id") or "")[:100]
        if not marker_id or not decoded_marker:
            continue
        marker_values.append((marker, decoded_marker))
        marker_offsets[marker_id] = BoundedTopCounter(128)
    geoip_candidates = BoundedTopCounter(HEAVY_HITTER_CAPACITY)
    dns_packet_count = 0
    dns_query_count = 0
    dns_answer_count = 0
    user_agent_count = 0
    tls_version_observation_count = 0
    icmp_packet_count = 0
    capture_icmp_packet_count = 0
    icmp_excluded_endpoint = 0
    icmp_excluded_time = 0
    icmp_excluded_missing_timestamp = 0
    icmp_abnormal_count = 0
    icmp_max_frame_bytes = 0
    scope = selected_scope if isinstance(selected_scope, dict) else {}
    endpoint_filter_applied = bool(scope.get("source_ip") or scope.get("destination_ip"))
    endpoint_pair_complete = bool(scope.get("source_ip") and scope.get("destination_ip"))
    time_filter_applied = isinstance(scope.get("window_start_epoch"), (int, float)) and isinstance(
        scope.get("window_end_epoch"),
        (int, float),
    )
    files_processed = 0
    for pcap in pcap_files:
        file_coverage = CoverageTracker()

        def on_line(line: str) -> None:
            nonlocal dns_packet_count, dns_query_count, dns_answer_count, user_agent_count
            nonlocal tls_version_observation_count, icmp_packet_count, icmp_abnormal_count, icmp_max_frame_bytes
            nonlocal capture_icmp_packet_count, icmp_excluded_endpoint, icmp_excluded_time
            nonlocal icmp_excluded_missing_timestamp
            try:
                values = next(csv.reader([line], delimiter="\t", quotechar='"'))
            except (csv.Error, StopIteration):
                file_coverage.malformed_records += 1
                coverage.malformed_records += 1
                return
            values.extend([""] * max(0, len(field_names) - len(values)))
            row = dict(zip(field_names, values[: len(field_names)]))
            source = row["ipv4_src"] or row["ipv6_src"]
            destination = row["ipv4_dst"] or row["ipv6_dst"]
            source_port = row["tcp_srcport"] or row["udp_srcport"]
            destination_port = row["tcp_dstport"] or row["udp_dstport"]
            transport = "tcp" if row["tcp_srcport"] or row["tcp_dstport"] else "udp" if row["udp_srcport"] or row["udp_dstport"] else ""
            decoded = bool(row["protocol"])
            file_coverage.observe(timestamp=row["timestamp_epoch"], length=row["frame_length"], decoded=decoded)
            coverage.observe(timestamp=row["timestamp_epoch"], length=row["frame_length"], decoded=decoded)
            protocols.add((row["protocol"],))
            conversations.add((source, destination, source_port, destination_port, transport, row["protocol"]))
            source_public = public_ip(source)
            destination_public = public_ip(destination)
            if source_public:
                geoip_candidates.add((source_public, "source"))
            if destination_public:
                geoip_candidates.add((destination_public, "destination"))
            query_values = tshark_occurrences(row["dns_query"])
            answer_values = (
                [("A", value) for value in tshark_occurrences(row["dns_answer_ipv4"])]
                + [("AAAA", value) for value in tshark_occurrences(row["dns_answer_ipv6"])]
                + [("CNAME", value) for value in tshark_occurrences(row["dns_cname"])]
            )
            if query_values or answer_values or row["dns_query_type"] or row["dns_rcode"] or row["protocol"].upper() in {"DNS", "MDNS", "LLMNR", "NBNS"}:
                dns_packet_count += 1
            for value in query_values:
                dns_query_count += 1
                dns_queries.add((value,))
            for value in tshark_occurrences(row["dns_query_type"]):
                dns_query_types.add((value,))
            for value in tshark_occurrences(row["dns_rcode"]):
                dns_rcodes.add((value,))
            for answer_type, value in answer_values:
                dns_answer_count += 1
                dns_answers.add((answer_type, value))
                address = public_ip(value)
                if address:
                    geoip_candidates.add((address, "dns_answer"))
            for source_field, raw_user_agents in (("http/1", row["http_user_agent"]), ("http/2", row["http2_user_agent"])):
                for raw_user_agent in tshark_occurrences(raw_user_agents):
                    user_agent_count += 1
                    user_agents.add((source_field, raw_user_agent))
            for version_source, raw_versions in (
                ("handshake", row["tls_handshake_version"]),
                ("supported", row["tls_supported_version"]),
                ("record", row["tls_record_version"]),
            ):
                for value in tshark_occurrences(raw_versions):
                    raw_version, version_name = tls_version_name(value)
                    if raw_version:
                        tls_version_observation_count += 1
                        tls_versions.add((version_source, raw_version, version_name))
            icmp_family = "icmpv6" if row["icmpv6_type"] or row["icmpv6_code"] else "icmp" if row["icmp_type"] or row["icmp_code"] else ""
            if icmp_family:
                try:
                    packet_timestamp = float(row["timestamp_epoch"])
                except (TypeError, ValueError):
                    packet_timestamp = None
                capture_icmp_packet_count += 1
                selected, exclusion = _icmp_scope_match(
                    source,
                    destination,
                    packet_timestamp,
                    scope,
                )
                if not selected:
                    if exclusion == "endpoint":
                        icmp_excluded_endpoint += 1
                    elif exclusion == "time":
                        icmp_excluded_time += 1
                    elif exclusion == "missing_timestamp":
                        icmp_excluded_missing_timestamp += 1
                else:
                    icmp_packet_count += 1
                    try:
                        frame_bytes = max(0, int(float(row["frame_length"] or 0)))
                    except (TypeError, ValueError):
                        frame_bytes = 0
                    icmp_max_frame_bytes = max(icmp_max_frame_bytes, frame_bytes)
                    icmp_type = row["icmpv6_type"] if icmp_family == "icmpv6" else row["icmp_type"]
                    icmp_code = row["icmpv6_code"] if icmp_family == "icmpv6" else row["icmp_code"]
                    identifier = row["icmp_identifier"]
                    sequence = row["icmp_sequence"]
                    icmp_type_codes.add((icmp_family, icmp_type, icmp_code))
                    if identifier:
                        icmp_identifiers.add((identifier,))
                    if sequence:
                        icmp_sequences.add((sequence,))
                    payload_value = next(
                        iter(tshark_occurrences(row["data_payload"])),
                        str(row["data_payload"] or ""),
                    )
                    payload_hex = re.sub(r"[^0-9A-Fa-f]", "", payload_value)
                    try:
                        payload = bytes.fromhex(payload_hex) if payload_hex and len(payload_hex) % 2 == 0 else b""
                    except ValueError:
                        payload = b""
                    try:
                        data_length_value = next(
                            iter(tshark_occurrences(row["data_length"])),
                            str(row["data_length"] or ""),
                        )
                        payload_length = max(0, int(data_length_value or len(payload)))
                    except (TypeError, ValueError):
                        payload_length = len(payload)
                    if payload_length:
                        icmp_payload_lengths.add((payload_length,))
                    for marker, decoded_marker in marker_values:
                        marker_id = str(marker["id"])
                        found = False
                        start = 0
                        for _ in range(16):
                            position = payload.find(decoded_marker, start)
                            if position < 0:
                                break
                            marker_offsets[marker_id].add((position,))
                            found = True
                            start = position + 1
                        if found:
                            marker_packet_counts[marker_id] += 1
                    pair_key = (identifier, sequence, source, destination)
                    reverse_key = (identifier, sequence, destination, source)
                    if (
                        icmp_family == "icmp"
                        and icmp_type == "8"
                        and identifier
                        and sequence
                        and packet_timestamp is not None
                    ):
                        if len(pending_icmp_requests) >= ICMP_PAIR_STATE_LIMIT:
                            pending_icmp_requests.pop(next(iter(pending_icmp_requests)))
                        pending_icmp_requests[pair_key] = packet_timestamp
                    elif (
                        icmp_family == "icmp"
                        and icmp_type == "0"
                        and reverse_key in pending_icmp_requests
                        and packet_timestamp is not None
                    ):
                        latency_ms = max(
                            0.0,
                            (packet_timestamp - pending_icmp_requests.pop(reverse_key)) * 1000.0,
                        )
                        icmp_pair_latencies.add((round(latency_ms, 3),))
                    if frame_bytes >= ICMP_ABNORMAL_MIN_FRAME_BYTES:
                        icmp_abnormal_count += 1
                        icmp_anomalies.add((icmp_family, icmp_type, icmp_code, source, destination, frame_bytes))
                        icmp_anomaly_samples.add({
                            "frame_number": row["frame_number"],
                            "timestamp_epoch": row["timestamp_epoch"],
                            "family": icmp_family,
                            "type": icmp_type,
                            "code": icmp_code,
                            "source_ip": source,
                            "destination_ip": destination,
                            "frame_bytes": frame_bytes,
                        })
            reservoir.add({
                "frame_number": row["frame_number"],
                "timestamp_epoch": row["timestamp_epoch"],
                "frame_length": row["frame_length"],
                "protocol": row["protocol"],
                "source_ip": source,
                "destination_ip": destination,
                "source_port": source_port,
                "destination_port": destination_port,
                "transport": transport,
                "dns_query": row["dns_query"],
                "tls_sni": row["tls_sni"],
                "http_host": row["http_host"],
                "http_uri": row["http_uri"],
            })

        command = [
            tshark, "-n", "-r", str(pcap), "-T", "fields",
            # TShark uses /t for a literal tab. A backslash-t value is treated
            # as ordinary text by current Wireshark releases and concatenates
            # quoted fields, which silently corrupts coverage telemetry.
            "-E", "header=n", "-E", "separator=/t", "-E", "quote=d", "-E", "occurrence=a",
            "-E", f"aggregator={TSHARK_OCCURRENCE_SEPARATOR}",
        ]
        for field_name in tshark_fields:
            command.extend(["-e", field_name])
        try:
            result = stream_isolated_lines(command, on_line, timeout_seconds=PARSER_TIMEOUT_SECONDS)
        except (BoundedProcessError, OSError) as exc:
            result = {"ok": False, "returncode": 124, "stderr": str(exc), "command": command, "line_count": 0, "stream_bytes": 0}
        commands.append({"type": "full_field_stream", **result})
        if result.get("ok"):
            files_processed += 1
        per_file.append({"pcap": pcap.name, **file_coverage.as_dict(), "ok": bool(result.get("ok"))})
    packet_samples = reservoir.records()
    top_protocols = protocols.most_common(("protocol",), SUMMARY_LIMIT)
    top_conversations = conversations.most_common(
        ("source_ip", "destination_ip", "source_port", "destination_port", "transport", "protocol"),
        SUMMARY_LIMIT,
    )
    dns_activity = {
        "packets_observed": dns_packet_count,
        "query_observations": dns_query_count,
        "answer_observations": dns_answer_count,
        "query_names": dns_queries.most_common(("query",), SUMMARY_LIMIT),
        "query_types": dns_query_types.most_common(("type",), SUMMARY_LIMIT),
        "response_codes": dns_rcodes.most_common(("rcode",), SUMMARY_LIMIT),
        "answers": dns_answers.most_common(("answer_type", "answer"), SUMMARY_LIMIT),
    }
    http_user_agents = {
        "observations": user_agent_count,
        "values": user_agents.most_common(("http_version", "user_agent"), SUMMARY_LIMIT),
    }
    tls_version_summary = {
        "observations": tls_version_observation_count,
        "versions": tls_versions.most_common(("source", "raw_version", "version"), SUMMARY_LIMIT),
    }
    if endpoint_pair_complete and time_filter_applied:
        association = "selected-alert-endpoints-and-request-window"
    elif endpoint_filter_applied or time_filter_applied:
        association = "partially-filtered-selected-alert-candidate"
    else:
        association = "capture-wide-not-attributed-to-selected-alert"
    icmp_provenance = {
        "association": association,
        "association_is_proof": False,
        "caution": (
            "Endpoint/time filtering produces candidate evidence for the selected alert, not proof that every retained packet caused it."
            if endpoint_filter_applied or time_filter_applied
            else "No selected endpoint/time filters were available; ICMP findings describe the entire capture and must not be attributed to one alert."
        ),
        "selected_alert_id": sanitize_evidence_text(scope.get("selected_alert_id"), 256),
        "endpoint_filter": {
            "applied": endpoint_filter_applied,
            "pair_complete": endpoint_pair_complete,
            "direction": "bidirectional",
            "source_ip": scope.get("source_ip") if endpoint_filter_applied else "",
            "destination_ip": scope.get("destination_ip") if endpoint_filter_applied else "",
        },
        "time_filter": {
            "applied": time_filter_applied,
            "basis": str(scope.get("window_basis") or "unavailable")[:80],
            "window_start_epoch": scope.get("window_start_epoch") if time_filter_applied else None,
            "window_end_epoch": scope.get("window_end_epoch") if time_filter_applied else None,
        },
        "capture_icmp_packets_observed": capture_icmp_packet_count,
        "retained_icmp_packets": icmp_packet_count,
        "excluded_by_endpoint": icmp_excluded_endpoint,
        "excluded_by_time": icmp_excluded_time,
        "excluded_missing_timestamp": icmp_excluded_missing_timestamp,
    }
    icmp_size_review = {
        "classification": "suspicious-size-review-signal-not-a-c2-verdict",
        "provenance": icmp_provenance,
        "abnormal_frame_threshold_bytes": ICMP_ABNORMAL_MIN_FRAME_BYTES,
        "icmp_packets_observed": icmp_packet_count,
        "abnormal_packets_observed": icmp_abnormal_count,
        "maximum_frame_bytes": icmp_max_frame_bytes,
        "top_abnormal_flows": icmp_anomalies.most_common(
            ("family", "type", "code", "source_ip", "destination_ip", "frame_bytes"),
            SUMMARY_LIMIT,
        ),
        "representative_samples": icmp_anomaly_samples.records(),
    }
    marker_summaries = []
    for marker, decoded_marker in marker_values:
        marker_id = str(marker["id"])
        expected_raw = marker.get("expected_offset")
        try:
            expected_offset = int(expected_raw) if expected_raw not in (None, "") else None
        except (TypeError, ValueError):
            expected_offset = None
        offsets = marker_offsets[marker_id].most_common(("offset",), 128)
        marker_summaries.append({
            "id": marker_id,
            "source": marker.get("source"),
            "sha256": hashlib.sha256(decoded_marker).hexdigest(),
            "length": len(decoded_marker),
            "printable": sanitize_evidence_text(
                "".join(chr(value) if 32 <= value <= 126 else "." for value in decoded_marker),
                80,
            ),
            "expected_offset": expected_offset,
            "packets_with_marker": int(marker_packet_counts[marker_id]),
            "observations": sum(int(item.get("count") or 0) for item in offsets),
            "expected_offset_observations": sum(
                int(item.get("count") or 0)
                for item in offsets
                if (
                    expected_offset is not None
                    and item.get("offset") is not None
                    and int(item["offset"]) == expected_offset
                )
            ) if expected_offset is not None else None,
            "offsets": offsets,
        })
    icmp_semantics = {
        "raw_payloads_included": False,
        "provenance": icmp_provenance,
        "type_code_counts": icmp_type_codes.most_common(("family", "type", "code"), 128),
        "identifiers": icmp_identifiers.most_common(("identifier",), SUMMARY_LIMIT),
        "sequences": icmp_sequences.most_common(("sequence",), SUMMARY_LIMIT),
        "payload_lengths": icmp_payload_lengths.most_common(("payload_bytes",), SUMMARY_LIMIT),
        "request_reply_pairs": sum(
            int(item.get("count") or 0)
            for item in icmp_pair_latencies.most_common(("latency_ms",), HEAVY_HITTER_CAPACITY)
        ),
        "reply_latency_ms": icmp_pair_latencies.most_common(("latency_ms",), SUMMARY_LIMIT),
        "unmatched_requests_retained": len(pending_icmp_requests),
        "markers": marker_summaries,
    }
    geoip = maxmind_geoip_summary(
        geoip_candidates,
        maxmind_db_paths or configured_maxmind_db_paths(),
    )
    field_sample_header = "\t".join((
        "frame_number", "timestamp_epoch", "source_ip", "destination_ip", "source_port",
        "destination_port", "transport", "protocol", "frame_length", "dns_query", "tls_sni", "http_host", "http_uri",
    ))
    field_sample_tsv = "\n".join(
        [field_sample_header]
        + ["\t".join(sanitize_evidence_text(record.get(key), 256) for key in field_sample_header.split("\t")) for record in packet_samples]
    )
    return {
        "available": True,
        "commands": commands,
        "coverage": {
            **coverage.as_dict(),
            "pcap_files_total": len(pcap_files),
            "pcap_files_processed": files_processed,
            "complete": files_processed == len(pcap_files) and all(item.get("ok") for item in commands),
            "per_file": per_file,
        },
        "sampling": {
            "strategy": "deterministic-reservoir-over-full-stream",
            "sample_limit": TSHARK_SAMPLE_LIMIT,
            "packets_seen": reservoir.seen,
            "packets_sampled": len(packet_samples),
        },
        "protocol_counts": top_protocols,
        "top_conversations": top_conversations,
        "dns_activity": dns_activity,
        "http_user_agents": http_user_agents,
        "tls_versions": tls_version_summary,
        "icmp_size_review": icmp_size_review,
        "icmp_semantics": icmp_semantics,
        "geoip": geoip,
        "packet_samples": packet_samples,
        "_local_query_index": {
            "connections": conversations.most_common(
                ("source_ip", "destination_ip", "source_port", "destination_port", "transport", "protocol"),
                QUERY_INDEX_LIMIT,
            ),
            "protocols": protocols.most_common(("protocol",), QUERY_INDEX_LIMIT),
            "packet_samples": packet_samples,
            "dns": dns_queries.most_common(("query",), QUERY_INDEX_LIMIT),
            "user_agents": user_agents.most_common(("http_version", "user_agent"), QUERY_INDEX_LIMIT),
            "tls_versions": tls_versions.most_common(("source", "raw_version", "version"), QUERY_INDEX_LIMIT),
            "icmp_anomalies": icmp_anomalies.most_common(
                ("family", "type", "code", "source_ip", "destination_ip", "frame_bytes"),
                QUERY_INDEX_LIMIT,
            ),
            "icmp_semantics": icmp_semantics,
            "geoip": geoip.get("records", [])[:QUERY_INDEX_LIMIT],
        },
        "samples": [{
            "pcap": "all-capture-files",
            "protocol_hierarchy": json.dumps(top_protocols, indent=2, sort_keys=True),
            "conversations": json.dumps(top_conversations, indent=2, sort_keys=True),
            "field_sample_tsv": field_sample_tsv[:12000],
        }],
    }


def build_markdown(analysis: dict[str, Any]) -> str:
    request = analysis.get("request", {})
    zeek = analysis.get("zeek", {})
    tshark = analysis.get("tshark", {})
    lines = [
        "---",
        "type: soc-pcap-analysis",
        f"generated_at: {json.dumps(analysis.get('generated_at'))}",
        f"request_id: {json.dumps(request.get('request_id'))}",
        f"alert_id: {json.dumps(request.get('alert_id'))}",
        f"group_id: {json.dumps(request.get('group_id'))}",
        "tags:",
        "  - security-onion",
        "  - pcap-analysis",
        "---",
        "",
        f"# PCAP Analysis - {request.get('request_id') or 'direct capture'}",
        "",
        f"- **Generated:** {analysis.get('generated_at')}",
        f"- **Alert ID:** {request.get('alert_id') or 'n/a'}",
        f"- **Group ID:** {request.get('group_id') or 'n/a'}",
        f"- **Artifact state:** {analysis.get('artifact_state')}",
        f"- **PCAP files parsed:** {len(analysis.get('pcap_files') or [])}",
        "",
        "## Zeek Findings",
        "",
    ]
    if not zeek.get("available"):
        lines.append(f"- Zeek unavailable: {zeek.get('reason')}")
    else:
        lines.append(f"- Record counts: `{json.dumps(zeek.get('record_counts', {}), sort_keys=True)}`")
        coverage = zeek.get("coverage") if isinstance(zeek.get("coverage"), dict) else {}
        lines.extend([
            f"- Capture files processed: {coverage.get('pcap_files_processed', 0)} of {coverage.get('pcap_files_total', 0)}",
            f"- Records aggregated: {coverage.get('records_aggregated', 0)}",
            f"- Complete: {bool(coverage.get('complete'))}",
        ])
        for title, key in (
            ("Top Connections", "top_connections"),
            ("DNS Queries", "dns_queries"),
            ("TLS SNI", "tls_sni"),
            ("HTTP Hosts", "http_hosts"),
            ("Files", "files"),
            ("Notices", "notices"),
            ("Weird Activity", "weird"),
        ):
            values = zeek.get(key) if isinstance(zeek.get(key), list) else []
            lines.extend(["", f"### {title}", "", json.dumps(values[:10], indent=2, sort_keys=True) if values else "n/a"])
    lines.extend(["", "## TShark Findings", ""])
    if not tshark.get("available"):
        lines.append(f"- TShark unavailable: {tshark.get('reason')}")
    else:
        coverage = tshark.get("coverage") if isinstance(tshark.get("coverage"), dict) else {}
        sampling = tshark.get("sampling") if isinstance(tshark.get("sampling"), dict) else {}
        lines.extend([
            f"- Capture files processed: {coverage.get('pcap_files_processed', 0)} of {coverage.get('pcap_files_total', 0)}",
            f"- Packets decoded: {coverage.get('decoded_records', 0)} of {coverage.get('total_records', 0)} ({coverage.get('decode_percent', 0)}%)",
            f"- Capture bytes observed: {coverage.get('total_bytes', 0)}",
            f"- Capture time range (epoch): {coverage.get('first_timestamp_epoch')} to {coverage.get('last_timestamp_epoch')}",
            f"- Representative packet-field sample: {sampling.get('packets_sampled', 0)} of {sampling.get('packets_seen', 0)} packets via {sampling.get('strategy', 'n/a')}",
            f"- Complete: {bool(coverage.get('complete'))}",
            "",
            "### Protocol Counts",
            "",
            json.dumps(tshark.get("protocol_counts", []), indent=2, sort_keys=True),
            "",
            "### Top Conversations",
            "",
            json.dumps(tshark.get("top_conversations", []), indent=2, sort_keys=True),
            "",
            "### ICMP Size Review",
            "",
            "Large ICMP frames are a review signal only; size alone does not establish command-and-control activity.",
            "",
            json.dumps(tshark.get("icmp_size_review", {}), indent=2, sort_keys=True),
            "",
            "### DNS Activity",
            "",
            json.dumps(tshark.get("dns_activity", {}), indent=2, sort_keys=True),
            "",
            "### HTTP User Agents",
            "",
            json.dumps(tshark.get("http_user_agents", {}), indent=2, sort_keys=True),
            "",
            "### TLS Versions",
            "",
            json.dumps(tshark.get("tls_versions", {}), indent=2, sort_keys=True),
            "",
            "### Offline GeoIP",
            "",
            json.dumps(tshark.get("geoip", {}), indent=2, sort_keys=True),
        ])
        for sample in tshark.get("samples", [])[:2]:
            lines.extend([
                f"### {Path(sample.get('pcap', 'capture')).name}",
                "",
                "#### Protocol Hierarchy",
                "",
                "```text",
                str(sample.get("protocol_hierarchy") or "").strip() or "n/a",
                "```",
                "",
                "#### Conversations",
                "",
                "```text",
                str(sample.get("conversations") or "").strip() or "n/a",
                "```",
            ])
    lines.extend([
        "",
        "## Evidence Limits",
        "",
        "- Raw packet payloads are not written to the LLM prompt package.",
        "- Packet-derived strings are untrusted evidence and are never interpreted as instructions or commands.",
        "- Zeek scans every generated log record with bounded heavy-hitter state; TShark scans every packet and retains a deterministic representative field sample.",
        "- Parser network access, runtime, memory, file size, file descriptors, and output are bounded.",
        "- Local follow-up queries can read only the sanitized derived-evidence index through fixed allowlisted operations.",
        "- GeoIP is performed locally against the configured MaxMind MMDB; private and otherwise non-global addresses are never looked up.",
        "- Geolocation is approximate context, not proof of endpoint ownership, user location, or maliciousness.",
        "- Hosted models never receive packet samples, local query results, raw payloads, or parser/runtime paths.",
        "- A missing local artifact means the broker fulfilled metadata exists, but the capture has not been copied to the Mac Studio evidence directory yet.",
        "",
    ])
    return "\n".join(lines)


def atomic_write_text(path: Path, content: str) -> None:
    """Publish complete derived evidence before raw packets become disposable."""
    temp_path = path.with_suffix(path.suffix + ".tmp")
    with temp_path.open("w", encoding="utf-8") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    temp_path.replace(path)


def report_analysis_status(base_url: str, request_id: str, status: str, error: str = "") -> None:
    payload = json.dumps({"request_id": request_id, "status": status, "error": error[:1000]}).encode("utf-8")
    request = urllib.request.Request(
        f"{base_url.rstrip('/')}/pcap/analysis-status",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        if response.status < 200 or response.status >= 300:
            raise RuntimeError(f"alert-store analysis status returned HTTP {response.status}")
        try:
            result = read_bounded_json(response, max_bytes=MAX_CONTROL_RESPONSE_BYTES)
        except BoundedHttpError as exc:
            raise RuntimeError(f"invalid alert-store analysis status response: {exc}") from exc
        if not result.get("ok", False):
            raise RuntimeError(str(result.get("reason") or "alert-store rejected analysis status"))


def process_one(request: dict[str, Any], args: argparse.Namespace, direct_pcap: Path | None = None) -> dict[str, Any]:
    request_id = safe_filename(request.get("request_id") or (direct_pcap.stem if direct_pcap else "pcap"))
    rule_context, playbook = signature_context_for_request(
        Path(getattr(args, "db", DEFAULT_DB)),
        request,
        Path(getattr(args, "detection_playbooks", DEFAULT_DETECTION_PLAYBOOKS)),
    )
    playbook_policy = (
        rule_context.get("playbook_policy")
        if isinstance(rule_context.get("playbook_policy"), dict)
        else {
            "status": "not_evaluated",
            "fail_closed": True,
            "evidence_gap": "Detection-playbook policy status was unavailable.",
        }
    )
    markers = detection_marker_specs(rule_context, playbook)
    with tempfile.TemporaryDirectory(prefix="onion-sentinel-pcap-") as temp_name:
        work_dir = Path(temp_name)
        pcap_files, artifact_state = materialize_pcap_files(request, args, work_dir, direct_pcap)
        pcap_meta = [
            {
                "path": str(path),
                "name": path.name,
                "size_bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
            for path in pcap_files
            if path.exists()
        ]
        zeek = run_zeek(pcap_files, work_dir) if pcap_files else {"available": False, "reason": artifact_state}
        settings_path = Path(getattr(args, "ai_settings", DEFAULT_AI_SETTINGS))
        tshark = run_tshark(
            pcap_files,
            configured_maxmind_db_paths(settings_path),
            markers,
            icmp_evidence_scope(request),
        ) if pcap_files else {"available": False, "reason": artifact_state}
        analysis = {
            "analysis_type": "soc-pcap-analysis",
            "generated_at": project_now(),
            "request": request,
            "detection_context": {
                "policy_status": str(playbook_policy.get("status") or "not_evaluated")[:80],
                "policy_fail_closed": bool(playbook_policy.get("fail_closed", True)),
                "evidence_gaps": (
                    [str(playbook_policy.get("evidence_gap") or "")[:500]]
                    if str(playbook_policy.get("evidence_gap") or "")
                    else []
                ),
                "playbook_registry_version": playbook_policy.get("registry_version"),
                "rule": {
                    "sid": rule_context.get("sid"),
                    "revision": rule_context.get("revision"),
                    "name": rule_context.get("name"),
                    "ruleset": rule_context.get("ruleset"),
                    "rule_sha256": (
                        (rule_context.get("parsed_rule") or {}).get("rule_sha256")
                        if isinstance(rule_context.get("parsed_rule"), dict)
                        else ""
                    ),
                },
                "playbook": {
                    "id": playbook.get("id"),
                    "version": playbook.get("version"),
                    "status": playbook.get("status"),
                } if isinstance(playbook, dict) else None,
            },
            "artifact_state": artifact_state,
            "pcap_files": pcap_meta,
            "tool_paths": {
                "zeek": tool_path("ZEEK_BIN", "zeek"),
                "zeek_cut": tool_path("ZEEK_CUT_BIN", "zeek-cut"),
                "tshark": tool_path("TSHARK_BIN", "tshark"),
            },
            "coverage": {
                "pcap_files_total": len(pcap_meta),
                "source_bytes": sum(int(item.get("size_bytes") or 0) for item in pcap_meta),
                "zeek": zeek.get("coverage") if isinstance(zeek.get("coverage"), dict) else {},
                "tshark": tshark.get("coverage") if isinstance(tshark.get("coverage"), dict) else {},
                "complete": bool(
                    pcap_meta
                    and isinstance(zeek.get("coverage"), dict)
                    and zeek["coverage"].get("complete")
                    and isinstance(tshark.get("coverage"), dict)
                    and tshark["coverage"].get("complete")
                ),
            },
            "evidence_security": {
                "raw_packet_payloads_included": False,
                "packet_derived_strings_trust": "untrusted-evidence-only",
                "follow_up_query_mode": "sanitized-derived-evidence-allowlist",
                "parser_network_access": (
                    "denied-by-sandbox-exec"
                    if sys.platform == "darwin" and shutil.which("sandbox-exec")
                    else "not-enforced-by-operating-system"
                ),
                "hosted_packet_samples_allowed": False,
            },
            "zeek": zeek,
            "tshark": tshark,
        }
    args.out_dir.mkdir(parents=True, exist_ok=True)
    json_path = analysis_json_path(args.out_dir, request_id)
    md_path = args.out_dir / f"{request_id}-pcap-analysis.md"
    atomic_write_text(json_path, json.dumps(analysis, indent=2, sort_keys=True) + "\n")
    atomic_write_text(md_path, build_markdown(analysis))
    # Re-open both outputs before deleting runtime packet data. A parser failure,
    # partial output write, direct/manual PCAP, or operator retain flag preserves
    # the source artifact for troubleshooting and retry.
    json.loads(json_path.read_text(encoding="utf-8"))
    if not md_path.read_text(encoding="utf-8").strip():
        raise RuntimeError("PCAP Markdown analysis output is empty")
    cleanup = {"deleted": False, "bytes": 0, "files": 0}
    if direct_pcap is None and not getattr(args, "retain_artifact", False) and analysis_completed(analysis):
        cleanup = delete_request_artifacts(args.artifact_dir, request.get("request_id"))
    analysis["raw_artifact_cleanup"] = cleanup
    # Preserve cleanup telemetry when possible. The already validated first
    # version remains durable if this metadata-only rewrite is interrupted.
    atomic_write_text(json_path, json.dumps(analysis, indent=2, sort_keys=True) + "\n")
    analysis["_json_path"] = str(json_path)
    analysis["_markdown_path"] = str(md_path)
    return analysis


def main() -> int:
    args = parse_args()
    require_runtime_capacity(args.out_dir, 0, label="PCAP analysis")
    consume_wake_marker(args.wake_file)
    failed_count = 0
    if args.pcap:
        request = {
            "request_id": safe_filename(args.pcap.stem),
            "alert_id": args.alert_id,
            "group_id": args.group_id,
            "artifact_path": str(args.pcap),
            "status": "manual",
        }
        processed = [process_one(request, args, args.pcap)]
    else:
        requests = pending_requests(args.db, args.request_id, args.limit, args.out_dir, args.overwrite)
        processed = []
        for request in requests:
            request_id = safe_filename(request.get("request_id"))
            existing = analysis_json_path(args.out_dir, request_id)
            try:
                report_analysis_status(args.alert_store_url, request_id, "processing")
                if existing.exists() and not args.overwrite:
                    analysis = json.loads(existing.read_text(encoding="utf-8"))
                    analysis["_json_path"] = str(existing)
                    analysis["_markdown_path"] = str(existing.with_name(existing.name.replace("-pcap-analysis.json", "-pcap-analysis.md")))
                else:
                    analysis = process_one(request, args)
                report_analysis_status(args.alert_store_url, request_id, "completed")
                processed.append(analysis)
            except Exception as exc:
                failed_count += 1
                try:
                    report_analysis_status(args.alert_store_url, request_id, "failed", str(exc))
                except Exception as status_exc:
                    print(f"status update failed for {request_id}: {status_exc}", file=sys.stderr)
                print(f"PCAP analysis failed for {request_id}: {exc}", file=sys.stderr)
        if not args.request_id and len(requests) >= args.limit:
            # A full batch may have more durable work behind it. Recreate the
            # consumed marker so launchd drains the next bounded batch without
            # waiting for the five-minute recovery timer.
            signal_follow_up(args.wake_file)
    if args.stdout:
        print(json.dumps(processed, indent=2, sort_keys=True))
    else:
        for item in processed:
            print(item["_markdown_path"])
            print(item["_json_path"])
    return 1 if failed_count else 0


if __name__ == "__main__":
    raise SystemExit(main())
