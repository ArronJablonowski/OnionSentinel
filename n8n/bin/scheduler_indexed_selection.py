"""Indexed durable-job selection and provider-lane policy."""
from __future__ import annotations

import datetime as dt
import re
import sqlite3
from collections.abc import Callable, Sequence
from dataclasses import dataclass


@dataclass(frozen=True)
class IndexedSelectionRequest:
    levels: str
    hours: int
    include_tests: bool
    only_group_id: str
    lane_sql: str
    lane_params: tuple[object, ...]


@dataclass(frozen=True)
class IndexedSelectionSources:
    now: Callable[[], dt.datetime]
    precise_now: Callable[[], str]
    alert_time_sql: Callable[[str], str]
    severity_priority_sql: Callable[[str], str]
    test_filter_sql: Callable[[str], tuple[str, list[object]]]
    eligible_filter_statuses: tuple[str, ...]
    fairness_age_seconds: int


@dataclass(frozen=True)
class _SelectionFragments:
    levels: tuple[str, ...]
    since: str
    test_sql: str
    test_params: tuple[object, ...]
    run_role_sql: str
    group_filter_sql: str
    group_filter_params: tuple[object, ...]


ROLE_SQL = """
  CASE
    WHEN p.id IS NULL THEN 'soc-analyst'
    WHEN json_valid(COALESCE(p.payload_json, '')) THEN
      COALESCE(
        NULLIF(TRIM(CAST(json_extract(p.payload_json, '$.agent_role') AS TEXT)), ''),
        CASE WHEN p.job_type = 'incident_response_analysis'
             THEN 'incident-responder' ELSE 'soc-analyst' END
      )
    WHEN p.job_type = 'incident_response_analysis' THEN 'incident-responder'
    ELSE 'soc-analyst'
  END
"""


INDEXED_SELECTION_SQL = """
WITH due_jobs_ranked AS (
  SELECT id, job_type, dedupe_key, payload_json, priority,
         requested_at,
         ROW_NUMBER() OVER (
           PARTITION BY dedupe_key
           ORDER BY CASE job_type WHEN 'incident_response_analysis' THEN 0 ELSE 1 END,
                    priority DESC, requested_at ASC, id ASC
         ) AS job_rank
  FROM durable_jobs
  WHERE job_type IN ('incident_response_analysis', 'ai_analysis')
    AND status = 'pending'
    AND attempt_count < max_attempts
    AND julianday(replace(next_attempt_at, '  ', 'T')) <=
        julianday(replace(?, '  ', 'T'))
),
due_jobs AS (
  SELECT id, job_type, dedupe_key, payload_json, priority,
         requested_at
  FROM due_jobs_ranked WHERE job_rank = 1
),
ranked AS (
  SELECT a.*,
         {newest_alert_time} AS queue_time,
         julianday(replace({newest_alert_time}, '  ', 'T')) AS queue_time_sort,
         {severity_priority} AS severity_rank,
         ROW_NUMBER() OVER (
           PARTITION BY a.stable_group_id
           ORDER BY julianday(replace({newest_alert_time}, '  ', 'T')) DESC,
                    COALESCE(a.triage_score, 0) DESC, a.alert_id DESC
         ) AS group_row_rank
  FROM alerts AS a
  WHERE a.stable_group_id IS NOT NULL AND a.stable_group_id != ''
)
SELECT r.alert_id, r.first_seen, r.last_seen, r.timestamp, r.rule_name,
       r.source_ip, r.destination_ip, r.triage_level, r.triage_score,
       COALESCE(NULLIF(r.filter_status, ''), 'accepted') AS filter_status,
       r.stable_group_id, r.routing, r.suppression_key, r.queue_time,
       COALESCE(NULLIF(r.stable_group_key, ''), r.stable_group_id) AS queue_group_key,
       p.id AS durable_job_id,
       p.payload_json AS durable_payload_json,
       p.job_type AS durable_job_type,
       p.requested_at AS durable_requested_at,
       CASE WHEN p.id IS NOT NULL THEN 1 ELSE 0 END AS has_durable_intent,
       CASE
         WHEN p.id IS NOT NULL
           AND instr(replace(p.payload_json, ' ', ''), '"manual_reanalysis":true') > 0 THEN 0
         WHEN p.id IS NOT NULL THEN 1
         ELSE 2
       END AS request_bucket,
       CASE
         WHEN p.id IS NOT NULL
           AND julianday(replace(p.requested_at, '  ', 'T')) <=
               julianday(replace(?, '  ', 'T')) - (? / 86400.0)
         THEN 0
         ELSE 1
       END AS fairness_bucket,
       r.severity_rank, r.queue_time_sort
FROM ranked AS r
LEFT JOIN due_jobs AS p ON p.dedupe_key = r.stable_group_id
WHERE r.group_row_rank = 1
  AND (
    p.id IS NOT NULL
    OR (
      NOT EXISTS (
        SELECT 1 FROM durable_jobs AS existing
        WHERE existing.job_type = 'ai_analysis'
          AND existing.dedupe_key = r.stable_group_id
          AND existing.status != 'completed'
      )
      AND NOT EXISTS (
        SELECT 1 FROM ai_analysis_runs AS ar
        WHERE ar.group_id = r.stable_group_id
          {run_role_sql}
      )
      AND EXISTS (
        SELECT 1 FROM alerts AS eligible
        WHERE eligible.stable_group_id = r.stable_group_id
          AND julianday(replace({eligible_alert_time}, '  ', 'T')) >=
              julianday(replace(?, '  ', 'T'))
          AND eligible.triage_level IN ({level_placeholders})
          AND COALESCE(NULLIF(eligible.filter_status, ''), 'accepted')
              IN ({status_placeholders})
          {test_sql}
      )
    )
  )
  {group_filter_sql}
  {lane_sql}
ORDER BY request_bucket ASC, severity_rank ASC,
         fairness_bucket ASC,
         CASE WHEN fairness_bucket = 0
              THEN julianday(replace(p.requested_at, '  ', 'T'))
              ELSE NULL END ASC,
         COALESCE(p.priority, 0) DESC,
         julianday(replace(p.requested_at, '  ', 'T')) ASC,
         CASE p.job_type WHEN 'incident_response_analysis' THEN 0 ELSE 1 END,
         queue_time_sort DESC,
         COALESCE(r.triage_score, 0) DESC, r.alert_id DESC
LIMIT 1
"""


def provider_lane_predicate(
    provider_lane: str,
    cli_roles: Sequence[str],
) -> tuple[str, list[object]]:
    """Build an allowlisted indexed-query predicate for one provider lane."""
    if provider_lane == "any":
        return "", []
    normalized_roles = sorted({str(role).strip() for role in cli_roles if str(role).strip()})
    if not normalized_roles:
        return ("AND 0 = 1", []) if provider_lane == "cli" else ("", [])
    placeholders = ", ".join("?" for _ in normalized_roles)
    operator = "IN" if provider_lane == "cli" else "NOT IN"
    return f"AND ({ROLE_SQL}) {operator} ({placeholders})", list(normalized_roles)


def _normalized_levels(levels: str) -> tuple[str, ...]:
    normalized = tuple(
        level.strip().lower()
        for level in str(levels or "").split(",")
        if level.strip()
    )
    if not normalized:
        raise SystemExit("--levels must contain at least one level")
    return normalized


def _exact_group_filter(group_id: str) -> tuple[str, tuple[object, ...]]:
    normalized = str(group_id or "").strip().lower()
    if normalized and not re.fullmatch(r"[a-f0-9]{20}", normalized):
        raise SystemExit("--only-group-id must be one exact 20-hex stable group id")
    if not normalized:
        return "", ()
    return "AND r.stable_group_id = ?", (normalized,)


def _selection_fragments(
    conn: sqlite3.Connection,
    request: IndexedSelectionRequest,
    sources: IndexedSelectionSources,
) -> _SelectionFragments:
    levels = _normalized_levels(request.levels)
    since = (
        sources.now() - dt.timedelta(hours=request.hours)
    ).replace(microsecond=0).isoformat().replace("T", "  ")
    test_sql = ""
    test_params: list[object] = []
    if not request.include_tests:
        clause, test_params = sources.test_filter_sql("eligible.alert_id")
        test_sql = f"AND {clause}"
    run_columns = {
        str(row[1]) for row in conn.execute("PRAGMA table_info(ai_analysis_runs)")
    }
    run_role_sql = (
        "AND COALESCE(ar.agent_role, 'soc-analyst') = 'soc-analyst'"
        if "agent_role" in run_columns
        else ""
    )
    group_filter_sql, group_filter_params = _exact_group_filter(
        request.only_group_id
    )
    return _SelectionFragments(
        levels=levels,
        since=since,
        test_sql=test_sql,
        test_params=tuple(test_params),
        run_role_sql=run_role_sql,
        group_filter_sql=group_filter_sql,
        group_filter_params=group_filter_params,
    )


def _selection_sql(
    fragments: _SelectionFragments,
    request: IndexedSelectionRequest,
    sources: IndexedSelectionSources,
) -> str:
    return INDEXED_SELECTION_SQL.format(
        newest_alert_time=sources.alert_time_sql("a"),
        eligible_alert_time=sources.alert_time_sql("eligible"),
        severity_priority=sources.severity_priority_sql("a.triage_level"),
        run_role_sql=fragments.run_role_sql,
        level_placeholders=", ".join("?" for _ in fragments.levels),
        status_placeholders=", ".join(
            "?" for _ in sources.eligible_filter_statuses
        ),
        test_sql=fragments.test_sql,
        group_filter_sql=fragments.group_filter_sql,
        lane_sql=request.lane_sql,
    )


def select_next_indexed_alert(
    conn: sqlite3.Connection,
    request: IndexedSelectionRequest,
    sources: IndexedSelectionSources,
) -> sqlite3.Row | None:
    """Select the next indexed group under durable priority and lane policy."""
    fragments = _selection_fragments(conn, request, sources)
    sql = _selection_sql(fragments, request, sources)
    params = [
        sources.precise_now(),
        sources.precise_now(),
        sources.fairness_age_seconds,
        fragments.since,
        *fragments.levels,
        *sources.eligible_filter_statuses,
        *fragments.test_params,
        *fragments.group_filter_params,
        *request.lane_params,
    ]
    return conn.execute(sql, params).fetchone()
