"""Schema-adaptive read-only SQLite access for durable LLM history."""
from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass
import sqlite3


@dataclass(frozen=True)
class LlmHistoryStoreSources:
    connect: Callable[[], AbstractContextManager]
    history_limit: int


def _bounded_limit(limit: object, maximum: int) -> int:
    try:
        return max(1, min(maximum, int(limit)))
    except (TypeError, ValueError):
        return maximum


def _table_exists(connection: object, table_name: str) -> bool:
    row = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ? LIMIT 1",
        (table_name,),
    ).fetchone()
    return row is not None


def _table_columns(connection: object, table_name: str) -> set[str]:
    escaped = table_name.replace('"', '""')
    return {
        str(row[1])
        for row in connection.execute(f'PRAGMA table_info("{escaped}")').fetchall()
    }


def _optional_column(columns: set[str], name: str, expression: str) -> str:
    return expression if name in columns else "NULL"


def _alert_projection(columns: set[str]) -> dict[str, str]:
    return {
        "rule_name": _optional_column(columns, "rule_name", "a.rule_name"),
        "source_ip": _optional_column(columns, "source_ip", "a.source_ip"),
        "destination_ip": _optional_column(
            columns, "destination_ip", "a.destination_ip"
        ),
        "destination_port": _optional_column(
            columns, "destination_port", "a.destination_port"
        ),
        "seen_count": _optional_column(columns, "seen_count", "a.seen_count")
        if columns
        else "1",
    }


def _read_primary_rows(connection: object, limit: int) -> list[dict]:
    if not _table_exists(connection, "ai_analysis_runs"):
        return []
    columns = _table_columns(connection, "ai_analysis_runs")
    if not {"analysis_id", "alert_id", "generated_at"}.issubset(columns):
        return []
    role = (
        "COALESCE(NULLIF(TRIM(r.agent_role), ''), 'soc-analyst')"
        if "agent_role" in columns
        else "'soc-analyst'"
    )
    model = _optional_column(columns, "model", "r.model")
    model_path = _optional_column(columns, "model_path", "r.model_path")
    alert_columns = (
        _table_columns(connection, "alerts")
        if _table_exists(connection, "alerts")
        else set()
    )
    alert = _alert_projection(alert_columns)
    join = "LEFT JOIN alerts AS a ON a.alert_id = r.alert_id" if alert_columns else ""
    rows = connection.execute(
        f"""
        SELECT r.analysis_id, r.alert_id, r.generated_at,
               {role} AS agent_role, {model} AS model,
               {model_path} AS model_path,
               {alert['rule_name']} AS rule_name,
               {alert['source_ip']} AS source_ip,
               {alert['destination_ip']} AS destination_ip,
               {alert['destination_port']} AS destination_port,
               {alert['seen_count']} AS seen_count
        FROM ai_analysis_runs AS r
        {join}
        ORDER BY r.generated_at DESC, r.analysis_id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return [dict(row) for row in rows]


def read_primary_history_rows(
    sources: LlmHistoryStoreSources, *, limit: object
) -> list[dict]:
    try:
        with sources.connect() as connection:
            return _read_primary_rows(
                connection, _bounded_limit(limit, sources.history_limit)
            )
    except (FileNotFoundError, sqlite3.Error, TypeError, ValueError):
        return []


def _read_second_opinion_rows(connection: object, limit: int) -> list[dict]:
    if not _table_exists(connection, "ai_second_opinion_runs"):
        return []
    columns = _table_columns(connection, "ai_second_opinion_runs")
    reviewer_error = (
        "reviewer_error" if "reviewer_error" in columns else "NULL AS reviewer_error"
    )
    rows = connection.execute(
        f"""
        SELECT analysis_id, alert_id, agent_role, trigger, status,
               {reviewer_error}, reviewer_model, reviewer_model_path,
               reviewer_outcome, reviewer_confidence, agreement,
               material_disagreement, reviewer_runtime_seconds, generated_at
        FROM ai_second_opinion_runs
        ORDER BY generated_at DESC, analysis_id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return [dict(row) for row in rows]


def read_second_opinion_history_rows(
    sources: LlmHistoryStoreSources, *, limit: object
) -> list[dict]:
    try:
        with sources.connect() as connection:
            return _read_second_opinion_rows(
                connection, _bounded_limit(limit, sources.history_limit)
            )
    except (FileNotFoundError, sqlite3.Error, TypeError, ValueError):
        return []


def _read_adjudication_rows(connection: object, limit: int) -> list[dict]:
    if not _table_exists(connection, "ai_disagreement_adjudication_runs"):
        return []
    rows = connection.execute(
        """
        SELECT analysis_id, alert_id, agent_role, status, mode,
               adjudicator_error, model_route, decision, confidence,
               confidence_score, adjudicator_runtime_seconds,
               human_adjudication_required, generated_at
        FROM ai_disagreement_adjudication_runs
        ORDER BY generated_at DESC, analysis_id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return [dict(row) for row in rows]


def read_adjudication_history_rows(
    sources: LlmHistoryStoreSources, *, limit: object
) -> list[dict]:
    try:
        with sources.connect() as connection:
            return _read_adjudication_rows(
                connection, _bounded_limit(limit, sources.history_limit)
            )
    except (FileNotFoundError, sqlite3.Error, TypeError, ValueError):
        return []
