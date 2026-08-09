#!/usr/bin/env python3
"""Select prompt alerts and project bounded related-alert history."""
from __future__ import annotations

from dataclasses import dataclass
import datetime as dt
from typing import Any, Callable, Iterable


@dataclass(frozen=True)
class AlertQuerySources:
    """Clock, query, filtering, and row operations supplied by the facade."""

    query_row: Callable[[Any, str, Iterable[Any]], Any]
    query_rows: Callable[[Any, str, Iterable[Any]], list[Any]]
    test_filter_sql: Callable[[str], tuple[str, list[Any]]]
    row_value: Callable[[Any, str], Any]
    now_local: Callable[[], dt.datetime]


@dataclass(frozen=True)
class AlertSelectionRequest:
    """Explicit or priority-based alert selection inputs."""

    connection: Any
    alert_id: str
    levels_csv: str
    hours: int
    include_tests: bool


def _explicit_alert(sources: AlertQuerySources, request: AlertSelectionRequest):
    if not request.alert_id:
        return None
    selected = sources.query_row(
        request.connection,
        "SELECT * FROM alerts WHERE alert_id = ?",
        [request.alert_id],
    )
    if not selected:
        raise SystemExit(f"alert_id not found: {request.alert_id}")
    return selected


def _selection_filter(
    sources: AlertQuerySources,
    include_tests: bool,
) -> tuple[str, list[Any]]:
    if include_tests:
        return "", []
    test_sql, params = sources.test_filter_sql("alert_id")
    return f"AND {test_sql}", params


def _selection_since(sources: AlertQuerySources, hours: int) -> str:
    return (
        sources.now_local() - dt.timedelta(hours=hours)
    ).replace(microsecond=0).isoformat().replace("T", "  ")


def select_prompt_alert(
    sources: AlertQuerySources,
    request: AlertSelectionRequest,
):
    """Select an exact alert or the newest highest-priority eligible alert."""
    explicit = _explicit_alert(sources, request)
    if explicit is not None:
        return explicit
    levels = [
        level.strip().lower()
        for level in request.levels_csv.split(",")
        if level.strip()
    ]
    if not levels:
        raise SystemExit("--levels must contain at least one level")
    filter_sql, filter_params = _selection_filter(sources, request.include_tests)
    placeholders = ", ".join("?" for _ in levels)
    selected = sources.query_row(
        request.connection,
        f"""
        SELECT *
        FROM alerts
        WHERE replace(replace(last_seen, 'T', ' '), 'Z', '') >= replace(replace(?, 'T', ' '), 'Z', '')
          AND triage_level IN ({placeholders})
          AND COALESCE(filter_status, 'accepted') IN ('accepted', 'escalated', 'unknown')
          {filter_sql}
        ORDER BY
          CASE triage_level WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END,
          triage_score DESC,
          replace(replace(last_seen, 'T', ' '), 'Z', '') DESC
        LIMIT 1
        """,
        [_selection_since(sources, request.hours), *levels, *filter_params],
    )
    if not selected:
        raise SystemExit("no matching alert found")
    return selected


def related_alert_context(
    sources: AlertQuerySources,
    connection: Any,
    selected: Any,
    limit: int,
    include_tests: bool,
) -> list[dict]:
    """Return bounded alerts sharing rule or endpoint observables."""
    filter_sql, filter_params = _selection_filter(sources, include_tests)
    value = sources.row_value
    found = sources.query_rows(
        connection,
        f"""
        SELECT alert_id, last_seen, rule_name, source_ip, destination_ip,
               triage_level, triage_score, filter_status, routing, seen_count
        FROM alerts
        WHERE alert_id != ?
          AND (
            rule_name = ?
            OR source_ip = ?
            OR destination_ip = ?
            OR (source_ip = ? AND destination_ip = ?)
          )
          {filter_sql}
        ORDER BY last_seen DESC
        LIMIT ?
        """,
        [
            value(selected, "alert_id"),
            value(selected, "rule_name"),
            value(selected, "source_ip"),
            value(selected, "destination_ip"),
            value(selected, "source_ip"),
            value(selected, "destination_ip"),
            *filter_params,
            limit,
        ],
    )
    return [dict(item) for item in found]
