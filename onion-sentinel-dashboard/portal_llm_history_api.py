"""Cached, paginated API composition for durable LLM activity history."""
from __future__ import annotations

import math
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol


class SnapshotCache(Protocol):
    def get_or_compute(self, key: object, compute: Callable[[], dict]) -> dict:
        """Return the cached value or atomically compute it."""


@dataclass(frozen=True)
class LlmHistoryApiSources:
    telemetry_page: Callable[[int, int], tuple[int, int, list[dict]]]
    read_database_primary: Callable[[], list[dict]]
    reconcile_primary: Callable[[list[dict], list[dict]], tuple[list[dict], int]]
    read_reviewer: Callable[[list[dict]], list[dict]]
    read_adjudication: Callable[[list[dict]], list[dict]]
    compose_snapshot: Callable[..., dict]
    read_active: Callable[[], list[dict]]
    decorate: Callable[[object, bool], dict]
    cache: SnapshotCache
    history_limit: int


def llm_analysis_log_limit(raw: object) -> int:
    try:
        value = int(str(raw or 25))
    except ValueError:
        value = 25
    return max(1, min(50, value))


def llm_analysis_log_page(raw: object) -> int:
    try:
        value = int(str(raw or 1))
    except ValueError:
        value = 1
    return max(1, value)


def build_llm_agent_activity_snapshot(sources: LlmHistoryApiSources) -> dict:
    telemetry_total, _, telemetry_logs = sources.telemetry_page(
        1, sources.history_limit
    )
    database_logs = sources.read_database_primary()
    primary_logs, database_recovered = sources.reconcile_primary(
        telemetry_logs, database_logs
    )
    reviewer_logs = sources.read_reviewer(primary_logs)
    adjudication_logs = sources.read_adjudication(primary_logs)
    return sources.compose_snapshot(
        telemetry_total,
        len(telemetry_logs),
        primary_logs,
        len(database_logs),
        database_recovered,
        reviewer_logs,
        adjudication_logs,
        sources.history_limit,
    )


def read_llm_agent_activity_snapshot(sources: LlmHistoryApiSources) -> dict:
    return sources.cache.get_or_compute(
        "role-complete-history",
        lambda: build_llm_agent_activity_snapshot(sources),
    )


def llm_analysis_logs_response(
    sources: LlmHistoryApiSources,
    query: dict[str, list[str]],
) -> dict:
    requested_page = llm_analysis_log_page((query.get("page") or ["1"])[0])
    limit = llm_analysis_log_limit((query.get("limit") or ["25"])[0])
    activity = read_llm_agent_activity_snapshot(sources)
    primary_logs = activity["primary_logs"]
    reviewer_logs = activity["reviewer_logs"]
    adjudication_logs = activity["adjudication_logs"]
    primary_total = len(primary_logs)
    total = primary_total + len(reviewer_logs) + len(adjudication_logs)
    total_pages = max(1, math.ceil(total / limit)) if total else 1
    page = min(requested_page, total_pages)
    start = (page - 1) * limit
    logs = activity["combined"][start:start + limit]
    return {
        "ok": True,
        "page": page,
        "limit": limit,
        "total": total,
        "primary_total": primary_total,
        "telemetry_total": activity["telemetry_total"],
        "database_recovered_total": activity["database_recovered_total"],
        "second_opinion_total": len(reviewer_logs),
        "disagreement_adjudication_total": len(adjudication_logs),
        "agent_totals": activity["agent_totals"],
        "history_truncated": activity["history_truncated"],
        "total_pages": total_pages,
        "logs": [sources.decorate(record, False) for record in logs],
        "active_runs": (
            [sources.decorate(record, True) for record in sources.read_active()]
            if page == 1
            else []
        ),
    }
