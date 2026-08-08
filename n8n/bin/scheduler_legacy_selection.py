"""Legacy artifact-backed alert selection for pre-indexed deployments."""
from __future__ import annotations

import datetime as dt
import re
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class LegacySelectionRequest:
    levels: str
    hours: int
    include_tests: bool
    only_group_id: str
    analysis_dir: Path | None
    pcap_analysis_dir: Path | None
    prompt_dir: Path | None
    already_analyzed: frozenset[str]
    already_selected_groups: frozenset[str]


@dataclass(frozen=True)
class LegacySelectionSources:
    now: Callable[[], dt.datetime]
    alert_time_sql: Callable[[], str]
    alert_group_key_sql: Callable[[], str]
    severity_priority_sql: Callable[[], str]
    test_filter_sql: Callable[[], tuple[str, list[object]]]
    latest_prompt_mtimes: Callable[[Path], dict[str, float]]
    latest_analysis_mtimes: Callable[[Path], dict[str, float]]
    analyzed_alert_groups: Callable[..., set[str]]
    pending_ai_job_ids: Callable[[sqlite3.Connection], set[str]]
    alert_group_key: Callable[[sqlite3.Row], str]
    alert_group_id: Callable[[str], str]
    eligible_filter_statuses: tuple[str, ...]


@dataclass(frozen=True)
class _ArtifactState:
    prompt_override_ids: tuple[str, ...]
    analyzed_groups: frozenset[str]
    pending_group_ids: frozenset[str]


LEGACY_SELECTION_SQL = """
WITH eligible AS (
  SELECT alert_id, first_seen, last_seen, timestamp, rule_name,
         source_ip, destination_ip, triage_level, triage_score,
         COALESCE(NULLIF(filter_status, ''), 'accepted') AS filter_status,
         {stable_group_select},
         routing, suppression_key,
         {newest_alert_time} AS queue_time,
         replace(replace({newest_alert_time}, 'T', ' '), 'Z', '') AS queue_time_sort,
         {group_key_expr} AS queue_group_key,
         {severity_priority} AS severity_rank
  FROM alerts
  WHERE (
      (
        replace(replace({newest_alert_time}, 'T', ' '), 'Z', '') >=
            replace(replace(?, 'T', ' '), 'Z', '')
        AND triage_level IN ({level_placeholders})
        AND COALESCE(NULLIF(filter_status, ''), 'accepted')
            IN ({status_placeholders})
        {filter_sql}
      )
      {prompt_override_sql}
    )
),
ranked_groups AS (
  SELECT *,
         ROW_NUMBER() OVER (
           PARTITION BY queue_group_key
           ORDER BY queue_time_sort DESC, COALESCE(triage_score, 0) DESC,
                    alert_id DESC
         ) AS group_row_rank
  FROM eligible
)
SELECT alert_id, first_seen, last_seen, timestamp, rule_name,
       source_ip, destination_ip, triage_level, triage_score,
       filter_status, stable_group_id, routing, suppression_key, queue_time,
       queue_group_key
FROM ranked_groups
WHERE group_row_rank = 1
ORDER BY severity_rank ASC, queue_time_sort DESC,
         COALESCE(triage_score, 0) DESC, alert_id DESC
"""


def _normalized_levels(levels: str) -> tuple[str, ...]:
    normalized = tuple(
        level.strip().lower()
        for level in str(levels or "").split(",")
        if level.strip()
    )
    if not normalized:
        raise SystemExit("--levels must contain at least one level")
    return normalized


def _exact_group_id(group_id: str) -> str:
    normalized = str(group_id or "").strip().lower()
    if normalized and not re.fullmatch(r"[a-f0-9]{20}", normalized):
        raise SystemExit("--only-group-id must be one exact 20-hex stable group id")
    return normalized


def _artifact_state(
    conn: sqlite3.Connection,
    request: LegacySelectionRequest,
    sources: LegacySelectionSources,
) -> _ArtifactState:
    prompt_mtimes = (
        sources.latest_prompt_mtimes(request.prompt_dir)
        if request.prompt_dir
        else {}
    )
    ai_mtimes = (
        sources.latest_analysis_mtimes(request.analysis_dir)
        if request.analysis_dir
        else {}
    )
    override_ids = tuple(sorted(
        alert_id
        for alert_id, prompt_mtime in prompt_mtimes.items()
        if prompt_mtime > ai_mtimes.get(alert_id, 0)
    ))
    analyzed_groups = sources.analyzed_alert_groups(
        conn,
        set(request.already_analyzed),
        request.analysis_dir,
        request.pcap_analysis_dir,
        request.prompt_dir,
    )
    return _ArtifactState(
        prompt_override_ids=override_ids,
        analyzed_groups=frozenset(analyzed_groups),
        pending_group_ids=frozenset(sources.pending_ai_job_ids(conn)),
    )


def _legacy_sql(
    conn: sqlite3.Connection,
    levels: tuple[str, ...],
    state: _ArtifactState,
    request: LegacySelectionRequest,
    sources: LegacySelectionSources,
) -> tuple[str, list[object]]:
    filter_sql = ""
    filter_params: list[object] = []
    if not request.include_tests:
        filter_clause, filter_params = sources.test_filter_sql()
        filter_sql = f"AND {filter_clause}"
    prompt_override_sql = ""
    if state.prompt_override_ids:
        placeholders = ", ".join("?" for _ in state.prompt_override_ids)
        prompt_override_sql = f" OR alert_id IN ({placeholders})"
    alert_columns = {
        str(row[1]) for row in conn.execute("PRAGMA table_info(alerts)").fetchall()
    }
    stable_group_select = (
        "stable_group_id"
        if "stable_group_id" in alert_columns
        else "NULL AS stable_group_id"
    )
    sql = LEGACY_SELECTION_SQL.format(
        stable_group_select=stable_group_select,
        newest_alert_time=sources.alert_time_sql(),
        group_key_expr=sources.alert_group_key_sql(),
        severity_priority=sources.severity_priority_sql(),
        level_placeholders=", ".join("?" for _ in levels),
        status_placeholders=", ".join(
            "?" for _ in sources.eligible_filter_statuses
        ),
        filter_sql=filter_sql,
        prompt_override_sql=prompt_override_sql,
    )
    since = (
        sources.now() - dt.timedelta(hours=request.hours)
    ).replace(microsecond=0).isoformat().replace("T", "  ")
    params = [
        since,
        *levels,
        *sources.eligible_filter_statuses,
        *filter_params,
        *state.prompt_override_ids,
    ]
    return sql, params


def _manual_first(
    candidates: list[sqlite3.Row],
    override_ids: tuple[str, ...],
) -> list[sqlite3.Row]:
    if not override_ids:
        return candidates
    overrides = set(override_ids)
    return sorted(
        candidates,
        key=lambda candidate: (
            0 if str(candidate["alert_id"] or "") in overrides else 1
        ),
    )


def _eligible_candidate(
    candidate: sqlite3.Row,
    state: _ArtifactState,
    request: LegacySelectionRequest,
    sources: LegacySelectionSources,
    only_group_id: str,
) -> bool:
    group_key = candidate["queue_group_key"] or sources.alert_group_key(candidate)
    stable_id = str(candidate["stable_group_id"] or "").strip()
    queue_group_id = stable_id or sources.alert_group_id(str(group_key))
    if only_group_id and queue_group_id != only_group_id:
        return False
    if group_key in request.already_selected_groups:
        return False
    if queue_group_id in state.pending_group_ids:
        return True
    return (
        candidate["alert_id"] not in request.already_analyzed
        and group_key not in state.analyzed_groups
    )


def select_next_legacy_alert(
    conn: sqlite3.Connection,
    request: LegacySelectionRequest,
    sources: LegacySelectionSources,
) -> sqlite3.Row | None:
    """Select the next legacy group using artifacts and durable rerun intent."""
    levels = _normalized_levels(request.levels)
    only_group_id = _exact_group_id(request.only_group_id)
    state = _artifact_state(conn, request, sources)
    sql, params = _legacy_sql(conn, levels, state, request, sources)
    candidates = _manual_first(
        conn.execute(sql, params).fetchall(),
        state.prompt_override_ids,
    )
    for candidate in candidates:
        if _eligible_candidate(
            candidate,
            state,
            request,
            sources,
            only_group_id,
        ):
            return candidate
    return None
