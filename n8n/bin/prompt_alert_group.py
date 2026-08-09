#!/usr/bin/env python3
"""Select and summarize one bounded duplicate-alert group."""
from __future__ import annotations

from dataclasses import dataclass
import sqlite3
from typing import Any, Callable, Iterable


BASE_GROUP_COLUMNS = (
    "alert_id",
    "first_seen",
    "last_seen",
    "seen_count",
    "rule_name",
    "source_ip",
    "destination_ip",
    "destination_port",
    "triage_level",
    "triage_score",
    "filter_status",
    "suppression_key",
    "stable_group_id",
)
FALLBACK_IDENTITY_COLUMNS = (
    "triage_level",
    "rule_name",
    "source_ip",
    "destination_ip",
    "filter_status",
)
ADMITTED_FILTER_STATUSES = "('accepted', 'escalated', 'unknown', 'suppressed')"


@dataclass(frozen=True)
class AlertGroupSources:
    """Schema, query, row, and identity operations supplied by the facade."""

    table_columns: Callable[[Any, str], set[str]]
    row_value: Callable[[Any, str], Any]
    query_row: Callable[[Any, str, Iterable[Any]], Any]
    query_rows: Callable[[Any, str, Iterable[Any]], list[Any]]
    test_filter_sql: Callable[[str], tuple[str, list[Any]]]
    safe_int: Callable[[Any], int]
    alert_group_key: Callable[[Any], str]
    alert_group_id: Callable[[str], str]


@dataclass(frozen=True)
class AlertGroupRowsRequest:
    """Selected alert and explicit duplicate-group query bounds."""

    connection: Any
    selected: Any
    include_tests: bool
    maximum_group_rows: int
    extra_columns: tuple[str, ...] = ()
    row_limit: int | None = None


def _selected_columns(available: set[str], extra: tuple[str, ...]) -> list[str]:
    return [name for name in (*BASE_GROUP_COLUMNS, *extra) if name in available]


def _preferred_identity(
    sources: AlertGroupSources,
    selected: Any,
    available: set[str],
) -> tuple[str, list[Any]] | None:
    stable_group_id = str(sources.row_value(selected, "stable_group_id") or "").strip()
    suppression_key = str(sources.row_value(selected, "suppression_key") or "").strip()
    if stable_group_id and "stable_group_id" in available:
        return "stable_group_id = ?", [stable_group_id]
    if suppression_key and "suppression_key" in available:
        return "suppression_key = ?", [suppression_key]
    return None


def _legacy_identity(
    sources: AlertGroupSources,
    selected: Any,
    available: set[str],
) -> tuple[str, list[Any]]:
    columns = [name for name in FALLBACK_IDENTITY_COLUMNS if name in available]
    clause = " AND ".join(f"COALESCE({name}, '') = ?" for name in columns)
    params = [str(sources.row_value(selected, name) or "") for name in columns]
    return clause, params


def _identity_clause(
    sources: AlertGroupSources,
    selected: Any,
    available: set[str],
) -> tuple[str, list[Any]]:
    preferred = _preferred_identity(sources, selected, available)
    return preferred or _legacy_identity(sources, selected, available)


def _conditions(
    sources: AlertGroupSources,
    available: set[str],
    identity_sql: str,
    include_tests: bool,
) -> tuple[list[str], list[Any]]:
    conditions = [identity_sql]
    params: list[Any] = []
    if "filter_status" in available:
        conditions.append(
            f"COALESCE(filter_status, 'accepted') IN {ADMITTED_FILTER_STATUSES}"
        )
    if not include_tests and "alert_id" in available:
        test_sql, test_params = sources.test_filter_sql("alert_id")
        conditions.append(test_sql)
        params.extend(test_params)
    return conditions, params


def _limit_clause(row_limit: int | None, maximum_group_rows: int) -> str:
    if row_limit is None:
        return ""
    bounded = max(1, min(int(row_limit), maximum_group_rows + 1))
    return f" LIMIT {bounded}"


def fetch_alert_group_rows(
    sources: AlertGroupSources,
    request: AlertGroupRowsRequest,
) -> list[Any]:
    """Fetch one group by stable, suppression, or exact legacy identity."""
    available = sources.table_columns(request.connection, "alerts")
    selected_columns = _selected_columns(available, request.extra_columns)
    if not selected_columns:
        return [request.selected]
    identity_sql, params = _identity_clause(sources, request.selected, available)
    if not identity_sql:
        return [request.selected]
    conditions, filter_params = _conditions(
        sources,
        available,
        identity_sql,
        request.include_tests,
    )
    params.extend(filter_params)
    try:
        found = sources.query_rows(
            request.connection,
            f"SELECT {', '.join(selected_columns)} FROM alerts "
            f"WHERE {' AND '.join(f'({item})' for item in conditions)} "
            "ORDER BY last_seen DESC, alert_id DESC"
            f"{_limit_clause(request.row_limit, request.maximum_group_rows)}",
            params,
        )
    except sqlite3.Error:
        return [request.selected]
    return found or [request.selected]


def _timeline_entry(sources: AlertGroupSources, item: Any) -> dict:
    value = sources.row_value
    return {
        "alert_id": item["alert_id"],
        "first_seen": value(item, "first_seen"),
        "last_seen": value(item, "last_seen"),
        "seen_count": max(1, sources.safe_int(value(item, "seen_count"))),
        "source_ip": value(item, "source_ip"),
        "destination_ip": value(item, "destination_ip"),
        "destination_port": value(item, "destination_port"),
        "triage_level": value(item, "triage_level"),
        "triage_score": value(item, "triage_score"),
        "filter_status": value(item, "filter_status"),
    }


def build_grouped_alert_context(
    sources: AlertGroupSources,
    request: AlertGroupRowsRequest,
    timeline_limit: int,
) -> dict:
    """Summarize group frequency and a bounded newest-first timeline."""
    group_rows = fetch_alert_group_rows(sources, request)
    value = sources.row_value
    first_seen = [str(value(item, "first_seen")) for item in group_rows if value(item, "first_seen")]
    last_seen = [str(value(item, "last_seen")) for item in group_rows if value(item, "last_seen")]
    return {
        "group_key": sources.alert_group_key(request.selected),
        "raw_alert_rows": len(group_rows),
        "total_observations": sum(
            max(1, sources.safe_int(value(item, "seen_count"))) for item in group_rows
        ),
        "first_seen": min(first_seen) if first_seen else value(request.selected, "first_seen"),
        "last_seen": max(last_seen) if last_seen else value(request.selected, "last_seen"),
        "timeline_sample": [
            _timeline_entry(sources, item) for item in group_rows[:timeline_limit]
        ],
        "timeline_sample_limit": timeline_limit,
        "frequency_guidance": (
            "Use total_observations and raw_alert_rows to judge urgency, recurrence, and tuning. "
            "A high count may indicate active behavior, noisy expected software, or a rule that needs suppression/drop/tuning."
        ),
    }


def build_execution_lineage(
    sources: AlertGroupSources,
    selected: Any,
    *,
    blind_reanalysis: bool,
) -> dict[str, Any]:
    """Return stable collector-owned identity for the durable harness trace."""
    stable_group_id = str(
        sources.row_value(selected, "stable_group_id") or ""
    ).strip().lower()
    if not stable_group_id:
        stable_group_id = sources.alert_group_id(sources.alert_group_key(selected))
    return {
        "group_id": stable_group_id,
        "manual_reanalysis": bool(blind_reanalysis),
    }


def build_analyst_state_context(
    sources: AlertGroupSources,
    connection: Any,
    selected: Any,
) -> dict:
    """Project the latest analyst decision for the selected duplicate group."""
    group_key = sources.alert_group_key(selected)
    group_id = sources.alert_group_id(group_key)
    try:
        state = sources.query_row(
            connection,
            """SELECT status, repeat_count, reason, updated_at, updated_by
               FROM analyst_alert_group_state WHERE group_id = ? OR group_key = ?
               ORDER BY updated_at DESC LIMIT 1""",
            [group_id, group_key],
        )
    except sqlite3.OperationalError:
        state = None
    value = sources.row_value
    return {
        "group_id": group_id,
        "group_key": group_key,
        "status": value(state, "status") if state else "open",
        "repeat_count_at_decision": value(state, "repeat_count") if state else 0,
        "reason": value(state, "reason") if state else None,
        "updated_at": value(state, "updated_at") if state else None,
        "updated_by": value(state, "updated_by") if state else None,
    }
