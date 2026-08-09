#!/usr/bin/env python3
"""Read-only durable dispatch acceptance proofs for frozen cohort members."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping


@dataclass(frozen=True)
class CohortDispatchReadbackSources:
    ambiguous_dispatch_error: type[RuntimeError]
    active_job_states: frozenset[str]
    active_agent_states: frozenset[str]
    active_reanalysis_states: frozenset[str]
    connect_read_only: Callable[[Path], Any]
    load_aliases: Callable[[Any], Mapping[str, str]]
    member_stable_group_key: Callable[[Mapping[str, Any]], str]
    durable_dispatch_job: Callable[..., dict[str, Any]]
    validate_dispatch_job_payload: Callable[..., dict[str, Any]]
    verify_zero_fresh_analyses: Callable[..., None]
    deterministic_dispatch_id: Callable[[Mapping[str, Any], Mapping[str, Any]], str]
    case_for_stable: Callable[[Any, str, Mapping[str, str]], dict[str, Any] | None]
    resolve_alias: Callable[[str, Mapping[str, str]], str]


def _common_readback(
    manifest: Mapping[str, Any],
    member: Mapping[str, Any],
    stable_id: str,
    stable_key: str,
) -> dict[str, Any]:
    contract = manifest["execution_contract"]
    return {
        "stable_group_id": stable_id,
        "stable_group_key": stable_key,
        "dashboard_group_id": str(member["dashboard_group_id"]),
        "representative_alert_id": str(member["representative_alert_id"]),
        "release_id": str(contract["expected_release_id"]),
        "expected_assigned_route": contract["expected_assigned_route"],
        "expected_reviewer_route": contract["expected_reviewer_route"],
        "reviewer_required": contract["reviewer_required"],
        "fresh_analysis_count": 0,
    }


def _require_active_job(
    sources: CohortDispatchReadbackSources,
    job: Mapping[str, Any],
    message: str,
) -> str:
    status = str(job.get("status") or "")
    if status not in sources.active_job_states:
        raise sources.ambiguous_dispatch_error(message)
    return status


def _analysis_readback(
    sources: CohortDispatchReadbackSources,
    connection: Any,
    manifest: Mapping[str, Any],
    member: Mapping[str, Any],
    stable_id: str,
    stable_key: str,
) -> dict[str, Any]:
    job = sources.durable_dispatch_job(
        connection, job_type="ai_analysis", stable_group_id=stable_id
    )
    binding = sources.validate_dispatch_job_payload(
        manifest, member, job, manual_reanalysis=True
    )
    sources.verify_zero_fresh_analyses(
        connection,
        member,
        stable_id,
        agent_role="soc-analyst",
        pre_state_field="soc_analysis_ids",
    )
    job_status = _require_active_job(
        sources,
        job,
        "SOC analysis acceptance did not leave one exact active job",
    )
    return {
        **_common_readback(manifest, member, stable_id, stable_key),
        "cohort_id": str(manifest["cohort_id"]),
        "dispatch_id": sources.deterministic_dispatch_id(manifest, member),
        "expected_assigned_route": binding["expected_assigned_route"],
        "expected_reviewer_route": binding["expected_reviewer_route"],
        "reviewer_required": binding["reviewer_required"],
        "job_id": int(job["id"]),
        "job_status": job_status,
        "job_payload_sha256": binding["payload_sha256"],
        "analysis_id": "",
    }


def _require_case_readback(
    sources: CohortDispatchReadbackSources,
    connection: Any,
    aliases: Mapping[str, str],
    member: Mapping[str, Any],
    stable_id: str,
    case_id: str,
) -> dict[str, Any]:
    case = sources.case_for_stable(connection, stable_id, aliases)
    valid = bool(
        case
        and str(case.get("case_id") or "") == case_id
        and str(case.get("dashboard_group_id") or "")
        == str(member["dashboard_group_id"])
        and str(case.get("representative_alert_id") or "")
        == str(member["representative_alert_id"])
        and str(case.get("agent_status") or "") in sources.active_agent_states
    )
    if not valid:
        raise sources.ambiguous_dispatch_error(
            "dashboard accepted the request but exact case readback failed"
        )
    return dict(case)


def _escalation_readback(
    sources: CohortDispatchReadbackSources,
    connection: Any,
    manifest: Mapping[str, Any],
    member: Mapping[str, Any],
    stable_id: str,
    case_id: str,
) -> dict[str, Any]:
    job = sources.durable_dispatch_job(
        connection,
        job_type="incident_response_analysis",
        stable_group_id=stable_id,
    )
    binding = sources.validate_dispatch_job_payload(
        manifest,
        member,
        job,
        manual_reanalysis=False,
        expected_case_id=case_id,
    )
    status = _require_active_job(
        sources,
        job,
        "escalation acceptance did not leave one exact active job",
    )
    return {
        "cohort_id": str(manifest["cohort_id"]),
        "dispatch_id": sources.deterministic_dispatch_id(manifest, member),
        "job_id": int(job["id"]),
        "job_status": status,
        "job_payload_sha256": binding["payload_sha256"],
    }


def _reanalysis_row(
    sources: CohortDispatchReadbackSources,
    connection: Any,
    aliases: Mapping[str, str],
    member: Mapping[str, Any],
    stable_id: str,
    run_id: str,
    case_id: str,
) -> dict[str, Any]:
    row = connection.execute(
        """
        SELECT run_id, case_id, group_id, dashboard_group_id,
               representative_alert_id, status, queued_at, updated_at
        FROM incident_reanalysis_run_cases
        WHERE run_id = ? AND case_id = ?
        """,
        (run_id, case_id),
    ).fetchone()
    valid = bool(
        row
        and sources.resolve_alias(str(row["group_id"] or ""), aliases) == stable_id
        and str(row["dashboard_group_id"] or "") == str(member["dashboard_group_id"])
        and str(row["representative_alert_id"] or "")
        == str(member["representative_alert_id"])
        and str(row["status"] or "") in sources.active_reanalysis_states
    )
    if not valid:
        raise sources.ambiguous_dispatch_error(
            "dashboard accepted reanalysis but exact run readback failed"
        )
    return dict(row)


def _reanalysis_readback(
    sources: CohortDispatchReadbackSources,
    connection: Any,
    aliases: Mapping[str, str],
    manifest: Mapping[str, Any],
    member: Mapping[str, Any],
    stable_id: str,
    case_id: str,
    run_id: str,
) -> dict[str, Any]:
    row = _reanalysis_row(
        sources, connection, aliases, member, stable_id, run_id, case_id
    )
    job = sources.durable_dispatch_job(
        connection,
        job_type="incident_response_analysis",
        stable_group_id=stable_id,
    )
    binding = sources.validate_dispatch_job_payload(
        manifest,
        member,
        job,
        manual_reanalysis=True,
        expected_case_id=case_id,
        expected_reanalysis_run_id=run_id,
    )
    status = _require_active_job(
        sources,
        job,
        "reanalysis acceptance did not leave one exact active job",
    )
    return {
        "run_id": run_id,
        "run_case_status": str(row["status"]),
        "queued_at": str(row["queued_at"] or ""),
        "cohort_id": str(manifest["cohort_id"]),
        "dispatch_id": sources.deterministic_dispatch_id(manifest, member),
        "job_id": int(job["id"]),
        "job_status": status,
        "job_payload_sha256": binding["payload_sha256"],
    }


def _incident_readback(
    sources: CohortDispatchReadbackSources,
    connection: Any,
    aliases: Mapping[str, str],
    manifest: Mapping[str, Any],
    member: Mapping[str, Any],
    accepted: Mapping[str, Any],
    stable_id: str,
    stable_key: str,
) -> dict[str, Any]:
    sources.verify_zero_fresh_analyses(
        connection,
        member,
        stable_id,
        agent_role="incident-responder",
        pre_state_field="incident_analysis_ids",
    )
    case_id = str(accepted["case_id"])
    case = _require_case_readback(
        sources, connection, aliases, member, stable_id, case_id
    )
    output = {
        **_common_readback(manifest, member, stable_id, stable_key),
        "case_id": case_id,
        "agent_status": str(case.get("agent_status") or ""),
    }
    kind = str((member.get("dispatch") or {}).get("kind") or "")
    if kind == "escalate":
        output.update(
            _escalation_readback(
                sources, connection, manifest, member, stable_id, case_id
            )
        )
    if kind == "reanalyze":
        output.update(
            _reanalysis_readback(
                sources, connection, aliases, manifest, member, stable_id,
                case_id, str(accepted.get("run_id") or ""),
            )
        )
    return output


def verify_dispatch_readback(
    sources: CohortDispatchReadbackSources,
    database_path: Path,
    manifest: Mapping[str, Any],
    member: Mapping[str, Any],
    accepted: Mapping[str, Any],
) -> dict[str, Any]:
    connection = sources.connect_read_only(database_path)
    try:
        aliases = sources.load_aliases(connection)
        stable_id = str(member["stable_group_id"])
        stable_key = sources.member_stable_group_key(member)
        kind = str((member.get("dispatch") or {}).get("kind") or "")
        if kind == "analyze":
            return _analysis_readback(
                sources, connection, manifest, member, stable_id, stable_key
            )
        return _incident_readback(
            sources, connection, aliases, manifest, member, accepted,
            stable_id, stable_key,
        )
    finally:
        connection.close()
