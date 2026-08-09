#!/usr/bin/env python3
"""Read-only cohort summary, job, analysis, and frozen pre-state queries."""
from __future__ import annotations

from dataclasses import dataclass
import sqlite3
from typing import Any, Mapping

from cohort_storage_core import (
    CohortStoragePolicy,
    require_columns,
    resolve_alias,
    table_columns,
    table_exists,
)


SUMMARY_EXPORT_COLUMNS = (
    "group_id",
    "representative_alert_id",
    "first_seen",
    "last_seen",
    "timestamp",
    "rule_name",
    "event_dataset",
    "severity",
    "severity_label",
    "source_ip",
    "source_port",
    "destination_ip",
    "destination_port",
    "network_protocol",
    "transport_protocol",
    "traffic_direction",
    "triage_score",
    "triage_level",
    "raw_alert_count",
    "total_seen_count",
)

CASE_COLUMNS = (
    "case_id",
    "group_id",
    "dashboard_group_id",
    "representative_alert_id",
    "status",
    "agent_status",
    "escalated_at",
    "updated_at",
    "latest_analysis_id",
    "latest_model",
    "latest_generated_at",
)

SUPPORTED_JOB_TYPES = frozenset({"incident_response_analysis", "ai_analysis"})


@dataclass(frozen=True)
class CohortStatePolicy:
    error: type[RuntimeError]
    ambiguous_error: type[RuntimeError]
    storage: CohortStoragePolicy
    active_agent_states: frozenset[str]


def _require_job_type(job_type: str, policy: CohortStatePolicy) -> None:
    if job_type not in SUPPORTED_JOB_TYPES:
        raise policy.error(f"unsupported durable job type: {job_type}")


def summary_rows(
    connection: sqlite3.Connection,
    policy: CohortStatePolicy,
) -> list[dict[str, Any]]:
    columns = require_columns(
        connection,
        "alert_group_summary",
        {"group_id", "representative_alert_id", "last_seen"},
        policy.storage,
    )
    selected = [item for item in SUMMARY_EXPORT_COLUMNS if item in columns]
    time_candidates = [
        item
        for item in ("last_seen", "timestamp", "first_seen", "updated_at")
        if item in columns
    ]
    time_expression = "COALESCE(" + ", ".join(
        f"NULLIF({item}, '')" for item in time_candidates
    ) + ")"
    sql = (
        "SELECT "
        + ", ".join(selected)
        + f", {time_expression} AS cohort_seen_at "
        + "FROM alert_group_summary "
        + f"ORDER BY replace(replace({time_expression}, 'T', ' '), 'Z', '') DESC, "
        + "group_id DESC"
    )
    return [dict(row) for row in connection.execute(sql).fetchall()]


def incident_cases(
    connection: sqlite3.Connection,
    aliases: Mapping[str, str],
    policy: CohortStatePolicy,
) -> dict[str, list[dict[str, Any]]]:
    columns = require_columns(
        connection,
        "incident_response_cases",
        {
            "case_id",
            "group_id",
            "dashboard_group_id",
            "representative_alert_id",
            "status",
            "agent_status",
            "latest_analysis_id",
        },
        policy.storage,
    )
    selected = [item for item in CASE_COLUMNS if item in columns]
    by_stable: dict[str, list[dict[str, Any]]] = {}
    for row in connection.execute(
        "SELECT " + ", ".join(selected) + " FROM incident_response_cases"
    ):
        item = dict(row)
        stable = resolve_alias(str(item.get("group_id") or ""), aliases, policy.storage)
        by_stable.setdefault(stable, []).append(item)
    return by_stable


def active_jobs(
    connection: sqlite3.Connection,
    stable_group_id: str,
    aliases: Mapping[str, str],
    policy: CohortStatePolicy,
    *,
    job_type: str = "incident_response_analysis",
) -> list[dict[str, Any]]:
    _require_job_type(job_type, policy)
    require_columns(
        connection,
        "durable_jobs",
        {
            "id", "job_type", "dedupe_key", "status", "attempt_count",
            "requested_at", "updated_at",
        },
        policy.storage,
    )
    rows = connection.execute(
        """
        SELECT id, job_type, dedupe_key, status, attempt_count,
               requested_at, updated_at
        FROM durable_jobs
        WHERE job_type = ?
          AND status IN ('pending', 'processing')
        ORDER BY id
        """,
        (job_type,),
    ).fetchall()
    return [
        dict(row)
        for row in rows
        if resolve_alias(str(row["dedupe_key"] or ""), aliases, policy.storage)
        == stable_group_id
    ]


def durable_dispatch_job(
    connection: sqlite3.Connection,
    *,
    job_type: str,
    stable_group_id: str,
    policy: CohortStatePolicy,
) -> dict[str, Any]:
    _require_job_type(job_type, policy)
    require_columns(
        connection,
        "durable_jobs",
        {
            "id", "job_type", "dedupe_key", "payload_json", "status",
            "attempt_count", "requested_at", "updated_at", "completed_at",
            "last_completed_at",
        },
        policy.storage,
    )
    row = connection.execute(
        """
        SELECT id, job_type, dedupe_key, payload_json, status, attempt_count,
               requested_at, updated_at, completed_at, last_completed_at
        FROM durable_jobs
        WHERE job_type = ? AND dedupe_key = ?
        """,
        (job_type, stable_group_id),
    ).fetchone()
    if row is None:
        raise policy.ambiguous_error(
            "dashboard accepted the request but exact durable job readback failed"
        )
    return dict(row)


def durable_job_snapshot(
    connection: sqlite3.Connection,
    *,
    job_type: str,
    stable_group_id: str,
    policy: CohortStatePolicy,
) -> dict[str, Any] | None:
    _require_job_type(job_type, policy)
    require_columns(
        connection,
        "durable_jobs",
        {
            "id", "job_type", "dedupe_key", "status", "attempt_count",
            "requested_at", "updated_at",
        },
        policy.storage,
    )
    row = connection.execute(
        """
        SELECT id, job_type, dedupe_key, status, attempt_count,
               requested_at, updated_at, completed_at, last_completed_at
        FROM durable_jobs
        WHERE job_type = ? AND dedupe_key = ?
        """,
        (job_type, stable_group_id),
    ).fetchone()
    return dict(row) if row else None


def active_reanalysis(
    connection: sqlite3.Connection,
    stable_group_id: str,
    case_id: str,
    aliases: Mapping[str, str],
    policy: CohortStatePolicy,
) -> list[dict[str, Any]]:
    require_columns(
        connection,
        "incident_reanalysis_run_cases",
        {
            "run_id", "case_id", "group_id", "dashboard_group_id",
            "representative_alert_id", "status", "updated_at",
        },
        policy.storage,
    )
    rows = connection.execute(
        """
        SELECT run_id, case_id, group_id, dashboard_group_id,
               representative_alert_id, status, updated_at
        FROM incident_reanalysis_run_cases
        WHERE status IN ('queued', 'running')
        ORDER BY updated_at, run_id
        """
    ).fetchall()
    return [
        dict(row)
        for row in rows
        if (case_id and str(row["case_id"] or "") == case_id)
        or resolve_alias(str(row["group_id"] or ""), aliases, policy.storage)
        == stable_group_id
    ]


def analysis_ids_for_group(
    connection: sqlite3.Connection,
    stable_group_id: str,
    *,
    agent_role: str,
    policy: CohortStatePolicy,
) -> list[str]:
    require_columns(
        connection,
        "ai_analysis_runs",
        {"analysis_id", "group_id", "agent_role", "generated_at"},
        policy.storage,
    )
    rows = connection.execute(
        """
        SELECT analysis_id
        FROM ai_analysis_runs
        WHERE group_id = ? AND agent_role = ?
        ORDER BY generated_at, analysis_id
        LIMIT 10001
        """,
        (stable_group_id, agent_role),
    ).fetchall()
    if len(rows) > 10000:
        raise policy.error(
            f"stable group {stable_group_id} has too many prior analyses "
            "for an exact bounded cohort"
        )
    identities = [str(row["analysis_id"] or "") for row in rows]
    if any(not item for item in identities) or len(identities) != len(set(identities)):
        raise policy.error(
            f"stable group {stable_group_id} has invalid analysis identities"
        )
    return identities


def frozen_analysis_ids(
    member: Mapping[str, Any],
    *,
    agent_role: str,
    pre_state_field: str,
    policy: CohortStatePolicy,
) -> set[str]:
    pre_state = member.get("pre_state")
    if not isinstance(pre_state, dict):
        raise policy.error("frozen member pre-state is missing or malformed")
    prior_value = pre_state.get(pre_state_field)
    if not _valid_identity_list(prior_value):
        raise policy.error(f"frozen {agent_role} analysis identity set is malformed")
    return set(prior_value)


def _valid_identity_list(value: Any) -> bool:
    return bool(
        isinstance(value, list)
        and all(isinstance(item, str) and item for item in value)
        and len(value) == len(set(value))
    )


def verify_zero_fresh_analyses(
    connection: sqlite3.Connection,
    member: Mapping[str, Any],
    stable_group_id: str,
    *,
    agent_role: str,
    pre_state_field: str,
    policy: CohortStatePolicy,
) -> list[str]:
    """Prove no worker result raced the controlled dispatch readback."""
    prior_ids = frozen_analysis_ids(
        member,
        agent_role=agent_role,
        pre_state_field=pre_state_field,
        policy=policy,
    )
    current_ids = set(
        analysis_ids_for_group(
            connection, stable_group_id, agent_role=agent_role, policy=policy
        )
    )
    if not prior_ids.issubset(current_ids):
        raise policy.ambiguous_error(
            f"prior {agent_role} analysis identities changed during dispatch"
        )
    if current_ids - prior_ids:
        raise policy.ambiguous_error(
            f"a fresh {agent_role} analysis appeared during the dispatch/readback window"
        )
    return sorted(current_ids)


def latest_analysis_metadata(
    connection: sqlite3.Connection,
    analysis_id: str,
) -> dict[str, Any] | None:
    if not analysis_id or not table_exists(connection, "ai_analysis_runs"):
        return None
    columns = table_columns(connection, "ai_analysis_runs")
    allowed = [
        item
        for item in (
            "analysis_id", "group_id", "alert_id", "agent_role", "generated_at",
            "model", "model_path", "detection_outcome", "confidence",
            "evidence_hash", "created_at",
        )
        if item in columns
    ]
    if "analysis_id" not in allowed:
        return None
    row = connection.execute(
        "SELECT " + ", ".join(allowed) + " FROM ai_analysis_runs WHERE analysis_id = ?",
        (analysis_id,),
    ).fetchone()
    return dict(row) if row else None


def soc_pre_state(
    connection: sqlite3.Connection,
    stable_group_id: str,
    aliases: Mapping[str, str],
    policy: CohortStatePolicy,
) -> dict[str, Any]:
    if active_jobs(
        connection, stable_group_id, aliases, policy, job_type="ai_analysis"
    ):
        raise policy.error(
            f"stable group {stable_group_id} already has a pending/processing "
            "SOC Analyst job"
        )
    analysis_ids = analysis_ids_for_group(
        connection, stable_group_id, agent_role="soc-analyst", policy=policy
    )
    latest = latest_analysis_metadata(connection, analysis_ids[-1]) if analysis_ids else None
    return {
        "soc_analysis_ids": analysis_ids,
        "latest_analysis": latest,
        "active_ai_jobs": [],
    }


def _single_incident_case(
    stable_group_id: str,
    cases_by_stable: Mapping[str, list[dict[str, Any]]],
    policy: CohortStatePolicy,
) -> dict[str, Any] | None:
    cases = list(cases_by_stable.get(stable_group_id, []))
    if len(cases) > 1:
        raise policy.error(
            f"multiple incident cases resolve to stable group {stable_group_id}"
        )
    case = cases[0] if cases else None
    if case and str(case.get("agent_status") or "") in policy.active_agent_states:
        raise policy.error(
            f"incident case {case.get('case_id')} is already {case.get('agent_status')}"
        )
    return case


def _require_idle_incident_state(
    connection: sqlite3.Connection,
    stable_group_id: str,
    case: Mapping[str, Any] | None,
    aliases: Mapping[str, str],
    policy: CohortStatePolicy,
) -> None:
    if active_jobs(connection, stable_group_id, aliases, policy):
        raise policy.error(
            f"stable group {stable_group_id} already has a pending/processing "
            "Incident Responder job"
        )
    if active_reanalysis(
        connection,
        stable_group_id,
        str((case or {}).get("case_id") or ""),
        aliases,
        policy,
    ):
        raise policy.error(
            f"stable group {stable_group_id} already has a queued/running reanalysis"
        )


def incident_pre_state(
    connection: sqlite3.Connection,
    stable_group_id: str,
    aliases: Mapping[str, str],
    cases_by_stable: Mapping[str, list[dict[str, Any]]],
    policy: CohortStatePolicy,
) -> dict[str, Any]:
    case = _single_incident_case(stable_group_id, cases_by_stable, policy)
    _require_idle_incident_state(connection, stable_group_id, case, aliases, policy)
    latest_analysis_id = str((case or {}).get("latest_analysis_id") or "")
    return {
        "incident_case": case,
        "incident_analysis_ids": analysis_ids_for_group(
            connection,
            stable_group_id,
            agent_role="incident-responder",
            policy=policy,
        ),
        "latest_analysis": latest_analysis_metadata(connection, latest_analysis_id),
        "active_incident_jobs": [],
        "active_reanalysis_cases": [],
    }
