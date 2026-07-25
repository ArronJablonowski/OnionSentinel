#!/usr/bin/env python3
"""Collect a bounded, read-only Security Onion evidence pack through the relay.

The collector accepts one alert id, derives exact observables from the complete
duplicate group, and sends only a fixed JSON protocol to a forced SSH command
on the relay.  The relay and Security Onion wrappers independently enforce the
same least-privilege boundary, so neither an LLM nor a compromised dashboard
can submit arbitrary KQL, Query DSL, indices, fields, paths, or shell commands.
"""
from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import os
import re
import sqlite3
import sys
import tempfile
from pathlib import Path
from typing import Iterable


BIN_DIR = Path(__file__).resolve().parent
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))
from bounded_process import BoundedProcessError, run_bounded_command
from incident_evidence_contract import (
    INCIDENT_EVIDENCE_CONTRACT,
    OSQUERY_PACKS,
    validate_incident_evidence_artifact,
)


HOME = Path.home()
DEFAULT_DB = HOME / "n8n-local" / "alert_store_data" / "alerts.sqlite3"
DEFAULT_CONFIG = HOME / "n8n-local" / "config" / "incident-evidence.json"
DEFAULT_OUT = HOME / "n8n-local" / "soc-alerts" / "incident-evidence"
MAX_CONFIG_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_OBSERVABLES = 16
MAX_WINDOWS = 4
WINDOW_DURATION = dt.timedelta(hours=24)
WINDOW_PADDING = dt.timedelta(minutes=5)
DOMAIN_RE = re.compile(r"(?i)^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
SAFE_ATOM_RE = re.compile(r"^[A-Za-z0-9_.:@-]{1,255}$")
SAFE_ELASTIC_ID_RE = re.compile(r"^[A-Za-z0-9_.:@+=-]{1,512}$")
ALERT_INDEX_RE = re.compile(
    r"^(?:"
    r"logs-(?:suricata\.alerts|detections\.alerts)-so"
    r"|\.ds-logs-(?:suricata\.alerts|detections\.alerts)-so-\d{4}\.\d{2}\.\d{2}-\d{6}"
    r")$"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Collect restricted incident evidence through the relay")
    parser.add_argument("--alert-id", required=True)
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--size", type=int, default=50)
    args = parser.parse_args()
    if args.size < 1 or args.size > 200:
        parser.error("--size must be between 1 and 200")
    return args


def parse_time(value: object) -> dt.datetime | None:
    text = str(value or "").strip().replace("  ", "T")
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(dt.timezone.utc)


def iso_utc(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {str(item["name"]) for item in conn.execute(f"PRAGMA table_info({table})")}


def selected_group(conn: sqlite3.Connection, alert_id: str) -> tuple[sqlite3.Row, list[sqlite3.Row]]:
    selected = conn.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
    if selected is None:
        raise RuntimeError("alert id was not found")
    columns = table_columns(conn, "alerts")
    group_id = str(selected["stable_group_id"] or "").strip() if "stable_group_id" in columns else ""
    suppression_key = str(selected["suppression_key"] or "").strip() if "suppression_key" in columns else ""
    if group_id:
        grouped = conn.execute(
            "SELECT * FROM alerts WHERE stable_group_id = ? ORDER BY last_seen ASC, alert_id ASC",
            (group_id,),
        ).fetchall()
    elif suppression_key:
        grouped = conn.execute(
            "SELECT * FROM alerts WHERE suppression_key = ? ORDER BY last_seen ASC, alert_id ASC",
            (suppression_key,),
        ).fetchall()
    else:
        grouped = [selected]
    return selected, grouped or [selected]


def representative_alert_anchor(selected: sqlite3.Row | dict) -> dict[str, str] | None:
    """Recover the collector-owned Elasticsearch index/id from alert intake.

    `export-recent-alerts` constructs these values from hit metadata outside
    `_source`, so they are stronger anchors than any attacker-controlled packet
    or message field. Older rows can fall back to the canonical `index:id`
    alert identifier produced by the same wrapper.
    """
    keys = set(selected.keys())
    index_name = ""
    document_id = ""
    if "alert_json" in keys:
        try:
            payload = json.loads(selected["alert_json"] or "{}")
        except (TypeError, json.JSONDecodeError):
            payload = {}
        if isinstance(payload, dict):
            index_name = str(payload.get("elastic_index") or "").strip()
            document_id = str(payload.get("elastic_id") or "").strip()
    if not index_name or not document_id:
        alert_id = str(selected["alert_id"] if "alert_id" in keys else "").strip()
        candidate_index, separator, candidate_id = alert_id.rpartition(":")
        if separator:
            index_name = index_name or candidate_index
            document_id = document_id or candidate_id
    if not ALERT_INDEX_RE.fullmatch(index_name) or not SAFE_ELASTIC_ID_RE.fullmatch(document_id):
        return None
    return {"index": index_name, "id": document_id}


def add_unique(target: list[str], value: object, validator) -> None:
    text = str(value or "").strip().rstrip(".")
    if text and text not in target and len(target) < MAX_OBSERVABLES and validator(text):
        target.append(text)


def valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def valid_domain(value: str) -> bool:
    return bool(DOMAIN_RE.fullmatch(value))


def valid_atom(value: str) -> bool:
    return bool(SAFE_ATOM_RE.fullmatch(value))


def nested_values(value: object, path: tuple[str, ...] = ()) -> Iterable[tuple[tuple[str, ...], object]]:
    if isinstance(value, dict):
        for key, child in value.items():
            yield from nested_values(child, (*path, str(key).lower()))
    elif isinstance(value, list):
        for child in value[:64]:
            yield from nested_values(child, path)
    else:
        yield path, value


def observables(grouped: list[sqlite3.Row]) -> dict[str, list[str]]:
    found = {"ips": [], "domains": [], "hosts": [], "users": []}
    ip_leafs = {"ip", "source_ip", "destination_ip", "client_ip", "server_ip"}
    domain_leafs = {"domain", "hostname", "sni", "query", "question_name", "server_name"}
    host_leafs = {"host_id", "host_name", "agent_id"}
    user_leafs = {"user_id", "user_name", "username"}
    for item in grouped:
        keys = set(item.keys())
        add_unique(found["ips"], item["source_ip"] if "source_ip" in keys else None, valid_ip)
        add_unique(found["ips"], item["destination_ip"] if "destination_ip" in keys else None, valid_ip)
        for json_column in ("alert_json", "raw_event_json"):
            if json_column not in keys:
                continue
            try:
                payload = json.loads(item[json_column] or "{}")
            except json.JSONDecodeError:
                continue
            for path, value in nested_values(payload):
                leaf = path[-1] if path else ""
                if leaf in ip_leafs or (leaf == "address" and any(part in {"source", "destination", "host"} for part in path)):
                    values = value if isinstance(value, list) else [value]
                    for candidate in values:
                        add_unique(found["ips"], candidate, valid_ip)
                elif leaf in domain_leafs:
                    add_unique(found["domains"], value, valid_domain)
                elif leaf in host_leafs:
                    add_unique(found["hosts"], value, valid_atom)
                elif leaf in user_leafs:
                    add_unique(found["users"], value, valid_atom)
    return found


def evidence_windows(grouped: list[sqlite3.Row]) -> tuple[list[dict[str, str]], str]:
    timestamps: list[dt.datetime] = []
    for item in grouped:
        for column in ("first_seen", "last_seen", "timestamp"):
            if column in item.keys():
                parsed = parse_time(item[column])
                if parsed:
                    timestamps.append(parsed)
    if not timestamps:
        now = dt.datetime.now(dt.timezone.utc)
        return [{"start": iso_utc(now - dt.timedelta(hours=1)), "end": iso_utc(now)}], "fallback one-hour window"
    start, end = min(timestamps) - WINDOW_PADDING, max(timestamps) + WINDOW_PADDING
    if end <= start:
        end = start + dt.timedelta(minutes=10)
    windows: list[dict[str, str]] = []
    coverage = end - start
    if coverage <= WINDOW_DURATION * MAX_WINDOWS:
        cursor = start
        while cursor < end and len(windows) < MAX_WINDOWS:
            boundary = min(cursor + WINDOW_DURATION, end)
            windows.append({"start": iso_utc(cursor), "end": iso_utc(boundary)})
            cursor = boundary
        note = "complete alert firing window"
    else:
        windows.append({"start": iso_utc(start), "end": iso_utc(start + WINDOW_DURATION)})
        tail_start = end - WINDOW_DURATION * (MAX_WINDOWS - 1)
        for index in range(MAX_WINDOWS - 1):
            boundary = tail_start + WINDOW_DURATION * index
            windows.append({"start": iso_utc(boundary), "end": iso_utc(min(boundary + WINDOW_DURATION, end))})
        note = "bounded first-day and latest-three-day coverage; middle interval is an explicit evidence gap"
    return windows, note


def load_config(path: Path) -> dict:
    raw = path.read_bytes()
    if len(raw) > MAX_CONFIG_BYTES:
        raise RuntimeError("incident evidence config exceeds its byte limit")
    config = json.loads(raw.decode("utf-8"))
    if not isinstance(config, dict):
        raise RuntimeError("incident evidence config root must be an object")
    for key in ("host", "ssh_user", "ssh_key", "known_hosts"):
        if not str(config.get(key) or "").strip():
            raise RuntimeError(f"incident evidence config is missing {key}")
    return config


def atomic_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
        temporary = Path(handle.name)
    temporary.chmod(0o600)
    os.replace(temporary, path)


def main() -> int:
    args = parse_args()
    config = load_config(args.config)
    conn = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        selected, grouped = selected_group(conn, args.alert_id)
    finally:
        conn.close()
    exact_observables = observables(grouped)
    if not any(exact_observables.values()):
        raise RuntimeError("no validated exact observables were available for restricted evidence queries")
    windows, coverage_note = evidence_windows(grouped)
    anchor = representative_alert_anchor(selected)
    request = {
        "packs": [
            "alert_context",
            "network_flow",
            "dns_activity",
            "osquery_history",
            "cross_sensor_timeline",
        ],
        "osquery_packs": list(OSQUERY_PACKS),
        "windows": windows,
        "observables": exact_observables,
        "size": args.size,
        "anchor": anchor,
    }
    key = Path(os.path.expandvars(os.path.expanduser(str(config["ssh_key"]))))
    known_hosts = Path(os.path.expandvars(os.path.expanduser(str(config["known_hosts"]))))
    command = [
        "/usr/bin/ssh", "-T", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
        "-o", f"ConnectTimeout={int(config.get('connect_timeout_seconds', 20))}",
        "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={known_hosts}",
        "-i", str(key), f"{config['ssh_user']}@{config['host']}",
    ]
    proc = run_bounded_command(
        command,
        stdin_text=json.dumps(request, separators=(",", ":")),
        timeout_seconds=float(config.get("timeout_seconds", 420)),
        max_stdout_bytes=int(config.get("max_response_bytes", MAX_RESPONSE_BYTES)),
        max_stderr_bytes=int(config.get("max_stderr_bytes", 256 * 1024)),
    )
    if proc.returncode != 0:
        raise RuntimeError(f"restricted incident evidence transport failed rc={proc.returncode}: {proc.stderr[:1000]}")
    response = json.loads(proc.stdout)
    if not isinstance(response, dict) or not response.get("ok"):
        raise RuntimeError("restricted incident evidence response failed its protocol contract")
    group_id = str(selected["stable_group_id"] or "") if "stable_group_id" in selected.keys() else ""
    artifact = {
        "schema": INCIDENT_EVIDENCE_CONTRACT,
        "generated_at": dt.datetime.now().astimezone().replace(microsecond=0).isoformat().replace("T", "  "),
        "alert_id": args.alert_id,
        "group_id": group_id,
        "group_alert_rows": len(grouped),
        "coverage_note": coverage_note,
        "request": request,
        "security_onion_response": response,
    }
    validate_incident_evidence_artifact(artifact)
    filename = f"{(group_id or args.alert_id).replace('/', '-')[:96]}-incident-evidence.json"
    destination = args.out_dir / filename
    atomic_json(destination, artifact)
    print(destination)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (BoundedProcessError, OSError, ValueError, RuntimeError, json.JSONDecodeError, sqlite3.Error) as exc:
        print(f"incident evidence collection failed: {exc}", file=sys.stderr)
        raise SystemExit(2)
