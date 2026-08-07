"""Page-bounded Incident Response routing metadata for SOC alert rows."""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Callable


JsonObject = dict[str, object]


@dataclass(frozen=True)
class SocIncidentDependencies:
    table_exists: Callable[[sqlite3.Connection, str], bool]
    table_columns: Callable[[sqlite3.Connection, str], set[str]]


def incident_defaults() -> JsonObject:
    """Return an explicit not-routed state for the SOC Alerts API."""
    return {
        "incident_case_id": "",
        "incident_status": "not_escalated",
        "incident_agent_status": "not_queued",
        "incident_escalated_at": "",
        "incident_escalated_by": "",
        "incident_reason": "",
    }


def _alias_stable_groups(conn: sqlite3.Connection, group_ids: list[str],
                         deps: SocIncidentDependencies) -> dict[str, str]:
    if not deps.table_exists(conn, "alert_group_alias"):
        return {}
    columns = deps.table_columns(conn, "alert_group_alias")
    if not {"legacy_group_id", "stable_group_id"}.issubset(columns):
        return {}
    placeholders = ",".join("?" for _ in group_ids)
    try:
        rows = conn.execute(
            "SELECT legacy_group_id, stable_group_id FROM alert_group_alias "
            f"WHERE legacy_group_id IN ({placeholders})",
            group_ids,
        )
        return {
            str(item["legacy_group_id"]): str(item["stable_group_id"] or "")
            for item in rows
        }
    except sqlite3.Error:
        return {}


def _merge_alert_stable_groups(conn: sqlite3.Connection, stable: dict[str, str],
                               group_by_alert: dict[str, str],
                               deps: SocIncidentDependencies) -> None:
    if not group_by_alert:
        return
    if "stable_group_id" not in deps.table_columns(conn, "alerts"):
        return
    alert_ids = sorted(group_by_alert)
    placeholders = ",".join("?" for _ in alert_ids)
    try:
        rows = conn.execute(
            f"SELECT alert_id, stable_group_id FROM alerts WHERE alert_id IN ({placeholders})",
            alert_ids,
        )
        for item in rows:
            dashboard_id = group_by_alert.get(str(item["alert_id"] or ""))
            if dashboard_id and item["stable_group_id"]:
                stable[dashboard_id] = str(item["stable_group_id"])
    except sqlite3.Error:
        pass


def _dashboards_by_stable(stable: dict[str, str]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for dashboard_id, stable_id in stable.items():
        if stable_id:
            result.setdefault(stable_id, []).append(dashboard_id)
    return result


def _selected_column(columns: set[str], column: str, fallback: str) -> str:
    return column if column in columns else f"{fallback} AS {column}"


def _case_query(group_ids: list[str], stable_ids: list[str], columns: set[str]) -> tuple[str, list[object]]:
    clauses = [f"dashboard_group_id IN ({','.join('?' for _ in group_ids)})"]
    arguments: list[object] = list(group_ids)
    if stable_ids:
        clauses.append(f"group_id IN ({','.join('?' for _ in stable_ids)})")
        arguments.extend(stable_ids)
    selected = [
        _selected_column(columns, "status", "'open'"),
        _selected_column(columns, "agent_status", "'queued'"),
        _selected_column(columns, "escalated_at", "''"),
        _selected_column(columns, "escalated_by", "''"),
        _selected_column(columns, "reason", "''"),
    ]
    ordering = "updated_at DESC, rowid DESC" if "updated_at" in columns else "rowid DESC"
    sql = (
        "SELECT case_id, group_id, dashboard_group_id, " + ", ".join(selected)
        + " FROM incident_response_cases WHERE " + " OR ".join(clauses)
        + f" ORDER BY {ordering}"
    )
    return sql, arguments


def _load_cases(conn: sqlite3.Connection, group_ids: list[str], stable_ids: list[str],
                columns: set[str]) -> list[sqlite3.Row]:
    sql, arguments = _case_query(group_ids, stable_ids, columns)
    try:
        return conn.execute(sql, arguments).fetchall()
    except sqlite3.Error:
        return []


def _target_ids(case: sqlite3.Row, metadata: dict[str, JsonObject],
                dashboards_by_stable: dict[str, list[str]]) -> list[str]:
    direct_id = str(case["dashboard_group_id"] or "")
    stable_id = str(case["group_id"] or "")
    targets = [direct_id] if direct_id in metadata else []
    targets.extend(dashboards_by_stable.get(stable_id, []))
    return list(dict.fromkeys(targets))


def _case_metadata(case: sqlite3.Row) -> JsonObject:
    return {
        "incident_case_id": str(case["case_id"] or ""),
        "incident_status": str(case["status"] or "open"),
        "incident_agent_status": str(case["agent_status"] or "queued"),
        "incident_escalated_at": str(case["escalated_at"] or ""),
        "incident_escalated_by": str(case["escalated_by"] or ""),
        "incident_reason": str(case["reason"] or ""),
    }


def apply_soc_incident_metadata(conn: sqlite3.Connection, metadata: dict[str, JsonObject],
                                group_by_alert: dict[str, str],
                                dependencies: SocIncidentDependencies) -> None:
    """Attach the newest matching durable incident state to each SOC group."""
    if not metadata or not dependencies.table_exists(conn, "incident_response_cases"):
        return
    group_ids = sorted(metadata)
    stable = _alias_stable_groups(conn, group_ids, dependencies)
    _merge_alert_stable_groups(conn, stable, group_by_alert, dependencies)
    dashboards = _dashboards_by_stable(stable)
    columns = dependencies.table_columns(conn, "incident_response_cases")
    if not {"case_id", "group_id", "dashboard_group_id"}.issubset(columns):
        return
    cases = _load_cases(conn, group_ids, sorted(dashboards), columns)
    resolved: set[str] = set()
    for case in cases:
        for group_id in _target_ids(case, metadata, dashboards):
            if group_id in resolved:
                continue
            resolved.add(group_id)
            metadata[group_id].update(_case_metadata(case))
