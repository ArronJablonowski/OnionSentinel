"""Read-only SQLite repository for the Incident Response list."""
from __future__ import annotations

from dataclasses import dataclass
import sqlite3

from portal_incident_read_model import (
    IncidentListRequest,
    incident_order_sql,
    optional_case_selects,
)


@dataclass(frozen=True)
class IncidentListRecords:
    total: int
    page: int
    pages: int
    rows: list[sqlite3.Row]
    status_counts: dict[str, int]
    agent_status_counts: dict[str, int]
    analyses: dict[str, dict]
    run_columns: set[str]
    second_opinions: dict[str, dict]
    adjudications: dict[tuple[str, str], dict]


def _table_exists(conn: sqlite3.Connection, table_name: str) -> bool:
    try:
        row = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
            (table_name,),
        ).fetchone()
    except sqlite3.Error:
        return False
    return bool(row)


def _table_columns(conn: sqlite3.Connection, table_name: str) -> set[str]:
    try:
        rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    except sqlite3.Error:
        return set()
    return {str(row[1]) for row in rows}


def incident_schema_ready(conn: sqlite3.Connection) -> bool:
    return _table_exists(conn, "incident_response_cases")


def _count_by(conn: sqlite3.Connection, column: str) -> dict[str, int]:
    rows = conn.execute(
        f"SELECT {column}, COUNT(*) FROM incident_response_cases GROUP BY {column}"
    ).fetchall()
    return {str(row[0] or "unknown"): int(row[1] or 0) for row in rows}


def _summary_case_rows(
    conn: sqlite3.Connection,
    request: IncidentListRequest,
    offset: int,
    optional_selects: tuple[str, str, str],
) -> list[sqlite3.Row]:
    resolution_reason, resolved_at, resolved_by = optional_selects
    order_sql = incident_order_sql(request, True)
    return conn.execute(
        f"""
        SELECT c.case_id, c.group_id, c.dashboard_group_id,
               c.representative_alert_id, c.status, c.agent_status,
               c.escalated_at, c.updated_at, c.escalated_by, c.reason,
               c.latest_analysis_id, c.latest_model,
               c.latest_generated_at, c.latest_error,
               {resolution_reason}, {resolved_at}, {resolved_by},
               COALESCE(g.rule_name, a.rule_name) AS rule_name,
               COALESCE(g.severity, a.severity) AS severity,
               COALESCE(g.severity_label, a.severity_label) AS severity_label,
               COALESCE(g.triage_level, a.triage_level) AS triage_level,
               COALESCE(g.source_ip, a.source_ip) AS source_ip,
               COALESCE(g.destination_ip, a.destination_ip) AS destination_ip,
               COALESCE(g.destination_port, a.destination_port) AS destination_port,
               COALESCE(g.raw_alert_count, a.seen_count, 0) AS raw_alert_count,
               COALESCE(g.total_seen_count, a.seen_count, 0) AS total_seen_count,
               COALESCE(g.first_seen, a.first_seen) AS first_seen,
               COALESCE(g.last_seen, a.last_seen) AS last_seen
        FROM incident_response_cases c
        LEFT JOIN alert_group_summary g ON g.group_id = c.dashboard_group_id
        LEFT JOIN alerts a ON a.alert_id = c.representative_alert_id
        {request.where_sql}
        ORDER BY {order_sql}
        LIMIT ? OFFSET ?
        """,
        [*request.where_arguments, request.per_page, offset],
    ).fetchall()


def _legacy_case_rows(
    conn: sqlite3.Connection,
    request: IncidentListRequest,
    offset: int,
    optional_selects: tuple[str, str, str],
) -> list[sqlite3.Row]:
    resolution_reason, resolved_at, resolved_by = optional_selects
    order_sql = incident_order_sql(request, False)
    return conn.execute(
        f"""
        SELECT c.case_id, c.group_id, c.dashboard_group_id,
               c.representative_alert_id, c.status, c.agent_status,
               c.escalated_at, c.updated_at, c.escalated_by, c.reason,
               c.latest_analysis_id, c.latest_model,
               c.latest_generated_at, c.latest_error,
               {resolution_reason}, {resolved_at}, {resolved_by}
        FROM incident_response_cases c
        {request.where_sql}
        ORDER BY {order_sql}
        LIMIT ? OFFSET ?
        """,
        [*request.where_arguments, request.per_page, offset],
    ).fetchall()


def _case_rows(
    conn: sqlite3.Connection,
    request: IncidentListRequest,
    offset: int,
) -> list[sqlite3.Row]:
    optional_selects = optional_case_selects(
        _table_columns(conn, "incident_response_cases")
    )
    if _table_exists(conn, "alert_group_summary"):
        return _summary_case_rows(conn, request, offset, optional_selects)
    return _legacy_case_rows(conn, request, offset, optional_selects)


def _analysis_ids(rows: list[sqlite3.Row]) -> list[str]:
    return sorted({
        str(row["latest_analysis_id"] or "")
        for row in rows
        if row["latest_analysis_id"]
    })


def _analysis_runs(
    conn: sqlite3.Connection,
    analysis_ids: list[str],
) -> tuple[dict[str, dict], set[str]]:
    if not analysis_ids or not _table_exists(conn, "ai_analysis_runs"):
        return {}, set()
    columns = _table_columns(conn, "ai_analysis_runs")
    selected = [
        column
        for column in (
            "analysis_id", "group_id", "agent_role", "generated_at",
            "created_at", "model", "detection_outcome", "bluf", "summary",
            "confidence", "evidence_hash", "response_json",
        )
        if column in columns
    ]
    placeholders = ",".join("?" for _ in analysis_ids)
    role_filter = (
        " AND agent_role = 'incident-responder'"
        if "agent_role" in columns
        else ""
    )
    rows = conn.execute(
        f"SELECT {', '.join(selected)} FROM ai_analysis_runs "
        f"WHERE analysis_id IN ({placeholders}){role_filter}",
        analysis_ids,
    ).fetchall()
    return {str(row["analysis_id"]): dict(row) for row in rows}, columns


def _second_opinions(
    conn: sqlite3.Connection,
    analysis_ids: list[str],
) -> dict[str, dict]:
    if not analysis_ids or not _table_exists(conn, "ai_second_opinion_runs"):
        return {}
    placeholders = ",".join("?" for _ in analysis_ids)
    error_select = (
        "reviewer_error"
        if "reviewer_error" in _table_columns(conn, "ai_second_opinion_runs")
        else "'' AS reviewer_error"
    )
    rows = conn.execute(
        f"""
        SELECT analysis_id, status, primary_outcome, primary_confidence,
               reviewer_outcome, reviewer_confidence, agreement,
               material_disagreement, disputed_fields_json,
               {error_select}, generated_at
        FROM ai_second_opinion_runs
        WHERE analysis_id IN ({placeholders})
        """,
        analysis_ids,
    ).fetchall()
    return {str(row["analysis_id"]): dict(row) for row in rows}


def _adjudications(
    conn: sqlite3.Connection,
    analysis_ids: list[str],
) -> dict[tuple[str, str], dict]:
    if not analysis_ids or not _table_exists(conn, "analyst_adjudications"):
        return {}
    placeholders = ",".join("?" for _ in analysis_ids)
    rows = conn.execute(
        f"""
        SELECT adjudication_id, dashboard_group_id, case_id, analysis_id,
               outcome_override, confidence, rationale, evidence_gap,
               next_action, reviewer, event_status, detection_validity,
               activity_disposition, handling, duplicate_of,
               case_resolution_reason, created_at
        FROM analyst_adjudications
        WHERE analysis_id IN ({placeholders})
        ORDER BY created_at DESC, rowid DESC
        """,
        analysis_ids,
    ).fetchall()
    latest: dict[tuple[str, str], dict] = {}
    for row in rows:
        key = (str(row["case_id"] or ""), str(row["analysis_id"] or ""))
        if all(key) and key not in latest:
            latest[key] = dict(row)
    return latest


def load_incident_list_records(
    conn: sqlite3.Connection,
    request: IncidentListRequest,
) -> IncidentListRecords:
    total = int(conn.execute(
        f"SELECT COUNT(*) FROM incident_response_cases c {request.where_sql}",
        request.where_arguments,
    ).fetchone()[0])
    page, pages, offset = request.pagination(total)
    rows = _case_rows(conn, request, offset)
    analysis_ids = _analysis_ids(rows)
    analyses, run_columns = _analysis_runs(conn, analysis_ids)
    return IncidentListRecords(
        total=total,
        page=page,
        pages=pages,
        rows=rows,
        status_counts=_count_by(conn, "status"),
        agent_status_counts=_count_by(conn, "agent_status"),
        analyses=analyses,
        run_columns=run_columns,
        second_opinions=_second_opinions(conn, analysis_ids),
        adjudications=_adjudications(conn, analysis_ids),
    )
