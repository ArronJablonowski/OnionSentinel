"""Schema-aware, read-only analyst adjudication history service."""
from __future__ import annotations

import re
import sqlite3
from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass
from http import HTTPStatus


@dataclass(frozen=True)
class SocAdjudicationHistorySources:
    connect: Callable[[], AbstractContextManager[sqlite3.Connection]]
    table_exists: Callable[[sqlite3.Connection, str], bool]
    table_columns: Callable[[sqlite3.Connection, str], set[str]]
    review_defaults: Callable[[], dict]
    alert_review_state: Callable[[sqlite3.Connection, str], dict]
    current_incident_analysis: Callable[[sqlite3.Connection, dict], dict]
    parse_review_json: Callable[[object], dict]
    incident_review_state: Callable[
        [sqlite3.Connection, dict, dict, dict], dict
    ]


def _api_error(message: str, status: int = 400) -> tuple[int, dict]:
    return status, {"ok": False, "error": message}


def _validated_request(
    group_id: object,
    case_id: object,
    limit: object,
) -> tuple[str, str, int, str]:
    group = str(group_id or "").strip().lower()
    case = str(case_id or "").strip().lower()
    if not re.fullmatch(r"[a-f0-9]{12}", group):
        return "", "", 0, "Invalid SOC alert group id"
    if case and not re.fullmatch(r"ir-[a-z0-9_-]{1,64}", case):
        return "", "", 0, "Invalid incident case id"
    try:
        bounded_limit = max(1, min(100, int(limit or 25)))
    except (TypeError, ValueError, OverflowError):
        bounded_limit = 25
    return group, case, bounded_limit, ""


def _alias_stable_group_id(
    conn: sqlite3.Connection,
    group_id: str,
    sources: SocAdjudicationHistorySources,
) -> str:
    if not sources.table_exists(conn, "alert_group_alias"):
        return ""
    row = conn.execute(
        "SELECT stable_group_id FROM alert_group_alias "
        "WHERE legacy_group_id = ?",
        (group_id,),
    ).fetchone()
    return str(row["stable_group_id"] or "") if row else ""


def _summary_stable_group_id(
    conn: sqlite3.Connection,
    group_id: str,
    sources: SocAdjudicationHistorySources,
) -> str:
    if not sources.table_exists(conn, "alert_group_summary"):
        return ""
    if "stable_group_id" not in sources.table_columns(conn, "alerts"):
        return ""
    row = conn.execute(
        """
        SELECT a.stable_group_id
        FROM alert_group_summary AS g
        JOIN alerts AS a ON a.alert_id = g.representative_alert_id
        WHERE g.group_id = ?
        """,
        (group_id,),
    ).fetchone()
    return str(row["stable_group_id"] or "") if row else ""


def _history_filter(
    conn: sqlite3.Connection,
    group_id: str,
    case_id: str,
    sources: SocAdjudicationHistorySources,
) -> tuple[str, list[object]]:
    if case_id:
        return " WHERE case_id = ?", [case_id]
    stable_group = _alias_stable_group_id(conn, group_id, sources)
    if not stable_group:
        stable_group = _summary_stable_group_id(conn, group_id, sources)
    return (
        (" WHERE stable_group_id = ?", [stable_group])
        if stable_group
        else (" WHERE dashboard_group_id = ?", [group_id])
    )


def _read_history(
    conn: sqlite3.Connection,
    group_id: str,
    case_id: str,
    limit: int,
    sources: SocAdjudicationHistorySources,
) -> list[dict]:
    where, arguments = _history_filter(conn, group_id, case_id, sources)
    arguments.append(limit)
    rows = conn.execute(
        """
        SELECT adjudication_id, dashboard_group_id, stable_group_id,
               case_id, analysis_id, outcome_override, confidence,
               rationale, evidence_gap, next_action, reviewer,
               event_status, detection_validity, activity_disposition,
               handling, duplicate_of,
               case_resolution_reason, created_at
        FROM analyst_adjudications
        """ + where + " ORDER BY created_at DESC, rowid DESC LIMIT ?",
        arguments,
    ).fetchall()
    return [dict(row) for row in rows]


def _case_review(
    conn: sqlite3.Connection,
    case_id: str,
    review: dict,
    sources: SocAdjudicationHistorySources,
) -> dict:
    if not case_id or not sources.table_exists(conn, "incident_response_cases"):
        return review
    row = conn.execute(
        "SELECT * FROM incident_response_cases WHERE case_id = ?", (case_id,)
    ).fetchone()
    if not row:
        return review
    case = dict(row)
    analysis = sources.current_incident_analysis(conn, case)
    response = sources.parse_review_json(analysis.get("response_json"))
    return sources.incident_review_state(conn, case, analysis, response)


def read_soc_adjudication_history(
    sources: SocAdjudicationHistorySources,
    group_id: object,
    *,
    case_id: object = "",
    limit: object = 25,
) -> tuple[int, dict]:
    group, case, bounded_limit, error = _validated_request(
        group_id, case_id, limit
    )
    if error:
        return _api_error(error)
    try:
        with sources.connect() as conn:
            if not sources.table_exists(conn, "analyst_adjudications"):
                return HTTPStatus.OK, {
                    "ok": True,
                    "review": sources.review_defaults(),
                    "history": [],
                }
            history = _read_history(
                conn, group, case, bounded_limit, sources
            )
            review = sources.alert_review_state(conn, group)
            review = _case_review(conn, case, review, sources)
    except (FileNotFoundError, sqlite3.Error) as exc:
        return _api_error(
            f"Analyst review history unavailable: {exc}",
            HTTPStatus.SERVICE_UNAVAILABLE,
        )
    return HTTPStatus.OK, {"ok": True, "review": review, "history": history}
