"""Page-bounded PCAP request aggregation and analyst-facing status policy."""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from typing import Callable


JsonObject = dict[str, object]
Row = sqlite3.Row | dict


@dataclass(frozen=True)
class SocPcapStatusDependencies:
    table_exists: Callable[[sqlite3.Connection, str], bool]
    dashboard_group_id: Callable[[str], str]


def _row_value(row: Row, key: str, default: str = "") -> str:
    if isinstance(row, dict):
        return str(row.get(key, default) or "")
    return str(row[key] or "") if key in row.keys() else str(default or "")


def _request_terms(rows: list[Row], dashboard_group_id: Callable[[str], str]) -> list[str]:
    group_ids: set[str] = set()
    alert_ids: set[str] = set()
    for row in rows:
        group_id = _row_value(row, "group_id").strip()
        group_key = _row_value(row, "group_key")
        if not group_id and group_key:
            group_id = dashboard_group_id(group_key).strip()
        if group_id:
            group_ids.add(group_id)
        alert_id = _row_value(row, "alert_id").strip()
        if alert_id:
            alert_ids.add(alert_id)
    return sorted(group_ids | alert_ids)


def _load_requests(conn: sqlite3.Connection, terms: list[str]) -> list[sqlite3.Row]:
    placeholders = ",".join("?" for _ in terms)
    try:
        return conn.execute(
            "SELECT request_id, alert_id, group_id, status, error, request_json, "
            "updated_at, completed_at FROM pcap_requests "
            f"WHERE group_id IN ({placeholders}) OR alert_id IN ({placeholders}) "
            f"OR request_id IN ({placeholders}) "
            "ORDER BY COALESCE(completed_at, updated_at, created_at) DESC",
            [*terms, *terms, *terms],
        ).fetchall()
    except sqlite3.Error:
        return []


def _used_capture_file(value: object) -> bool:
    try:
        request = json.loads(str(value or "{}"))
    except (TypeError, ValueError, json.JSONDecodeError):
        return False
    return bool(str(request.get("capture_file") or "").strip()) if isinstance(request, dict) else False


def _request_record(item: sqlite3.Row) -> JsonObject:
    return {
        "request_id": str(item["request_id"] or "").strip(),
        "status": str(item["status"] or "").strip().lower(),
        "error": str(item["error"] or "").strip(),
        "updated_at": str(item["completed_at"] or item["updated_at"] or "").strip(),
        "used_capture_file": _used_capture_file(item["request_json"]),
    }


def load_pcap_request_statuses(conn: sqlite3.Connection, rows: list[Row],
                               dependencies: SocPcapStatusDependencies) -> dict[str, JsonObject]:
    """Return the newest request status keyed by group, alert, and request ID."""
    if not dependencies.table_exists(conn, "pcap_requests"):
        return {}
    terms = _request_terms(rows, dependencies.dashboard_group_id)
    if not terms:
        return {}
    statuses: dict[str, JsonObject] = {}
    for item in _load_requests(conn, terms):
        record = _request_record(item)
        for key in ("group_id", "alert_id", "request_id"):
            value = str(item[key] or "").strip()
            if value:
                statuses.setdefault(value, record)
    return statuses


def _status(key: str, label: str, detail: str) -> JsonObject:
    return {"pcap_status_key": key, "pcap_status_label": label, "pcap_status_detail": detail}


def _parsed_analysis_available(group_id: str, alert_id: str, analysis_index: object) -> bool:
    index = analysis_index if isinstance(analysis_index, dict) else {}
    return group_id in index.get("group_ids", set()) or alert_id in index.get("alert_ids", set())


def _request_record_for(group_id: str, alert_id: str, statuses: object) -> object:
    records = statuses if isinstance(statuses, dict) else {}
    return records.get(group_id) or records.get(alert_id) or {}


def _failed_status(record: object) -> JsonObject:
    error = str(record.get("error") or "").strip() if isinstance(record, dict) else ""
    if "no matching packets" not in error.lower():
        detail = error[:180] if error else "PCAP request failed before parsed analysis was produced"
        return _status("error", "Failed", detail)
    if isinstance(record, dict) and not record.get("used_capture_file"):
        return _status(
            "error", "Retry",
            "Older PCAP request did not include the Security Onion capture file hint; retry the request before treating this as no packets",
        )
    return _status(
        "no-packets", "No Packets",
        "Security Onion found no matching packets for the requested flow/window",
    )


def compose_pcap_status(group_id: str, alert_id: str, analysis_index: object,
                        request_statuses: object) -> JsonObject:
    """Return a truthful compact PCAP state for one detection group."""
    group_id = str(group_id or "").strip()
    alert_id = str(alert_id or "").strip()
    if _parsed_analysis_available(group_id, alert_id, analysis_index):
        return _status(
            "analyzed", "Analyzed",
            "Parsed Zeek/TShark PCAP analysis is available for this detection group",
        )
    record = _request_record_for(group_id, alert_id, request_statuses)
    status = str(record.get("status") or "").strip().lower() if isinstance(record, dict) else str(record or "").strip().lower()
    if status in {"pending", "claimed", "fulfilled"}:
        label = "Queued" if status in {"pending", "claimed"} else "Parsing"
        return _status(
            "queued", label,
            f"PCAP request is {status}; parsed analysis is not available yet",
        )
    if status != "failed":
        return _status(
            "none", "None", "No parsed PCAP analysis is available for this detection group",
        )
    return _failed_status(record)
