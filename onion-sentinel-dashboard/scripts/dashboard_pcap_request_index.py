"""One-pass PCAP request indexing for dashboard builds.

PCAP artifacts live on disk while broker/request state lives in SQLite. The
builder previously opened SQLite twice per alert group to join those views,
which amplified a 500-group build into roughly 1,000 connections and queries.
This module scans the small request table once and exposes constant-time maps.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any


EMPTY_REQUEST_INDEX: dict[str, dict[str, dict[str, Any]]] = {
    "requests_by_group_id": {},
    "requests_by_alert_id": {},
    "requests_by_request_id": {},
}


def build_pcap_request_index(conn: sqlite3.Connection) -> dict[str, dict[str, dict[str, Any]]]:
    """Read newest-first request state once from an existing connection."""
    exists = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'pcap_requests'"
    ).fetchone()
    if not exists:
        return _empty_index()
    columns = {str(row[1]) for row in conn.execute("PRAGMA table_info(pcap_requests)")}
    if "request_id" not in columns:
        return _empty_index()

    def expression(name: str, fallback: str = "''") -> str:
        return name if name in columns else f"{fallback} AS {name}"

    timestamps = [name for name in ("completed_at", "updated_at", "created_at") if name in columns]
    newest = f"COALESCE({', '.join(timestamps)})" if timestamps else "request_id"
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        f"""
        SELECT request_id, {expression('group_id')}, {expression('alert_id')},
               {expression('status')}, {expression('error')}, {expression('request_json', "'{}'")},
               {expression('completed_at')}, {expression('updated_at')}, {expression('created_at')}
        FROM pcap_requests
        ORDER BY {newest} DESC, request_id DESC
        """
    ).fetchall()
    index = _empty_index()
    for row in rows:
        record = _record_from_row(row)
        request_id = record["request_id"]
        group_id = str(row["group_id"] or "").strip()
        alert_id = str(row["alert_id"] or "").strip()
        if request_id:
            index["requests_by_request_id"].setdefault(request_id, record)
        if group_id:
            index["requests_by_group_id"].setdefault(group_id, record)
        if alert_id:
            index["requests_by_alert_id"].setdefault(alert_id, record)
    return index


def load_pcap_request_index(db_path: Path, *, timeout: float = 2.0) -> dict[str, dict[str, dict[str, Any]]]:
    """Load an index from a read-only database and always close its handle."""
    path = Path(db_path)
    if not path.exists():
        return _empty_index()
    try:
        with closing(sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=timeout)) as conn:
            return build_pcap_request_index(conn)
    except sqlite3.Error:
        return _empty_index()


def request_for_alert(
    index: dict[str, object], *, group_id: str = "", alert_id: str = ""
) -> dict[str, Any]:
    """Resolve the newest request using the stable group ID first."""
    for bucket_name, key in (
        ("requests_by_group_id", group_id),
        ("requests_by_alert_id", alert_id),
    ):
        bucket = index.get(bucket_name)
        if key and isinstance(bucket, dict):
            value = bucket.get(key)
            if isinstance(value, dict):
                return value
    return {}


def _record_from_row(row: sqlite3.Row) -> dict[str, Any]:
    try:
        request_payload = json.loads(str(row["request_json"] or "{}"))
    except (TypeError, ValueError, json.JSONDecodeError):
        request_payload = {}
    return {
        "request_id": str(row["request_id"] or "").strip(),
        "status": str(row["status"] or "").strip().lower(),
        "error": str(row["error"] or "").strip(),
        "updated_at": str(row["completed_at"] or row["updated_at"] or row["created_at"] or "").strip(),
        "used_capture_file": bool(request_payload.get("capture_file")) if isinstance(request_payload, dict) else False,
    }


def _empty_index() -> dict[str, dict[str, dict[str, Any]]]:
    return {name: {} for name in EMPTY_REQUEST_INDEX}
