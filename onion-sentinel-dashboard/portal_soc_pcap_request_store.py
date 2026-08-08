"""Schema-adaptive SQLite repository for SOC PCAP evidence requests."""
from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class PcapRequestStoreSources:
    table_exists: Callable[[sqlite3.Connection, str], bool]
    table_columns: Callable[[sqlite3.Connection, str], set[str]]
    now_iso: Callable[[], str]


def pcap_capture_file_from_json(*values: object) -> str | None:
    for value in values:
        if not value:
            continue
        try:
            parsed = json.loads(str(value))
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
        if not isinstance(parsed, dict):
            continue
        direct = parsed.get("capture_file")
        suricata = parsed.get("suricata")
        nested = suricata.get("capture_file") if isinstance(suricata, dict) else None
        capture_file = nested or direct
        if capture_file:
            return str(capture_file)[:512]
    return None


def _summary_candidate(
    sources: PcapRequestStoreSources,
    conn: sqlite3.Connection,
    group_id: str,
) -> tuple[dict, object]:
    if not sources.table_exists(conn, "alert_group_summary"):
        return {}, None
    columns = sources.table_columns(conn, "alert_group_summary")
    protocol = (
        "network_protocol"
        if "network_protocol" in columns
        else "NULL AS network_protocol"
    )
    row = conn.execute(
        f"""
        SELECT group_id, group_key, representative_alert_id, first_seen,
               last_seen, timestamp, source_ip, source_port, destination_ip,
               destination_port, {protocol}, transport_protocol
        FROM alert_group_summary
        WHERE group_id = ?
        """,
        (group_id,),
    ).fetchone()
    if not row:
        return {}, None
    return {
        "alert_id": row["representative_alert_id"],
        "group_id": row["group_id"],
        "group_key": row["group_key"],
        "first_seen": row["first_seen"] or row["timestamp"],
        "last_seen": row["last_seen"] or row["timestamp"],
        "source_ip": row["source_ip"],
        "source_port": row["source_port"],
        "destination_ip": row["destination_ip"],
        "destination_port": row["destination_port"],
        "network_protocol": row["network_protocol"],
        "transport_protocol": row["transport_protocol"],
        "community_id": None,
    }, row


def _optional_select(columns: set[str], name: str) -> str:
    return name if name in columns else f"NULL AS {name}"


def _representative_alert(
    sources: PcapRequestStoreSources,
    conn: sqlite3.Connection,
    alert_id: object,
) -> object:
    if not alert_id or not sources.table_exists(conn, "alerts"):
        return None
    columns = sources.table_columns(conn, "alerts")
    select_parts = ["alert_id"] + [
        _optional_select(columns, name)
        for name in (
            "first_seen", "last_seen", "timestamp", "source_ip",
            "source_port", "destination_ip", "destination_port",
            "network_protocol", "transport_protocol", "alert_json",
            "raw_event_json",
        )
    ]
    return conn.execute(
        f"SELECT {', '.join(select_parts)} FROM alerts WHERE alert_id = ?",
        (alert_id,),
    ).fetchone()


def _prefer(value: object, fallback: object) -> object:
    return value if value not in (None, "") else fallback


def _merge_representative(candidate: dict, row: object) -> dict:
    if not row:
        return candidate
    timestamp = row["timestamp"]
    candidate.update({
        "alert_id": _prefer(row["alert_id"], candidate["alert_id"]),
        "first_seen": _prefer(
            row["first_seen"] or timestamp, candidate["first_seen"]
        ),
        "last_seen": _prefer(
            row["last_seen"] or timestamp, candidate["last_seen"]
        ),
        "source_ip": _prefer(row["source_ip"], candidate["source_ip"]),
        "source_port": _prefer(row["source_port"], candidate["source_port"]),
        "destination_ip": _prefer(
            row["destination_ip"], candidate["destination_ip"]
        ),
        "destination_port": _prefer(
            row["destination_port"], candidate["destination_port"]
        ),
        "network_protocol": _prefer(
            row["network_protocol"], candidate["network_protocol"]
        ),
        "transport_protocol": _prefer(
            row["transport_protocol"], candidate["transport_protocol"]
        ),
        "capture_file": pcap_capture_file_from_json(
            row["raw_event_json"], row["alert_json"]
        ),
    })
    return candidate


def read_pcap_request_candidate(
    sources: PcapRequestStoreSources,
    conn: sqlite3.Connection,
    group_id: str,
) -> dict:
    candidate, summary_row = _summary_candidate(sources, conn, group_id)
    if not candidate:
        return {}
    alert_row = _representative_alert(
        sources, conn, summary_row["representative_alert_id"]
    )
    return _merge_representative(candidate, alert_row)


def _request_values(request: dict, now: str) -> dict:
    return {
        "request_id": request["request_id"],
        "status": "pending",
        "alert_id": request["alert_id"],
        "group_id": request["group_id"],
        "group_key": request["group_key"],
        "first_seen": request["first_seen"],
        "last_seen": request["last_seen"],
        "source_ip": request["source_ip"],
        "source_port": request["source_port"],
        "destination_ip": request["destination_ip"],
        "destination_port": request["destination_port"],
        "network_protocol": request["network_protocol"],
        "transport_protocol": request["transport_protocol"],
        "community_id": request["community_id"],
        "requested_by": request["requested_by"],
        "reason": request["reason"],
        "max_window_seconds": request["max_window_seconds"],
        "request_json": json.dumps(
            request, separators=(",", ":"), sort_keys=True
        ),
        "created_at": now,
        "updated_at": now,
        "claimed_at": None,
        "completed_at": None,
        "error": None,
        "artifact_path": None,
        "artifact_sha256": None,
        "artifact_size_bytes": None,
    }


def insert_pcap_request(
    sources: PcapRequestStoreSources,
    conn: sqlite3.Connection,
    request: dict,
) -> sqlite3.Row | None:
    columns = sources.table_columns(conn, "pcap_requests")
    if not columns:
        raise sqlite3.Error("pcap_requests table is unavailable")
    values = _request_values(request, sources.now_iso())
    insert_columns = [column for column in values if column in columns]
    update_columns = [
        column for column in (
            "status", "reason", "requested_by", "max_window_seconds",
            "request_json", "updated_at", "claimed_at", "completed_at",
            "error", "artifact_path", "artifact_sha256",
            "artifact_size_bytes",
        )
        if column in columns
    ]
    conflict = (
        "DO UPDATE SET "
        + ", ".join(f"{column} = excluded.{column}" for column in update_columns)
        if update_columns
        else "DO NOTHING"
    )
    conn.execute(
        f"INSERT INTO pcap_requests ({', '.join(insert_columns)}) "
        f"VALUES ({', '.join('?' for _ in insert_columns)}) "
        f"ON CONFLICT(request_id) {conflict}",
        [values[column] for column in insert_columns],
    )
    return conn.execute(
        "SELECT * FROM pcap_requests WHERE request_id = ?",
        (request["request_id"],),
    ).fetchone()
