#!/usr/bin/env python3
"""Terminal cohort member observation over injected read-only evidence ports."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping


@dataclass(frozen=True)
class CohortMonitorSources:
    cohort_error: type[RuntimeError]
    terminal_monitor_states: frozenset[str]
    monitor_dispatch_job_binding: Callable[[Any, Mapping[str, Any], Mapping[str, Any]], dict[str, Any]]
    durable_job_monitor_state: Callable[[Mapping[str, Any]], str]
    analysis_ids_for_group: Callable[..., list[str]]
    analysis_metadata: Callable[..., dict[str, Any]]
    validate_completed_analysis_job_window: Callable[..., None]
    second_opinion_metadata: Callable[[Any, str], dict[str, Any] | None]
    utc_now: Callable[[], str]
    load_aliases: Callable[[Any], Mapping[str, str]]
    case_for_stable: Callable[[Any, str, Mapping[str, str]], dict[str, Any] | None]
    reanalysis_run_case: Callable[[Any, str, str], dict[str, Any] | None]
    resolve_alias: Callable[[str, Mapping[str, str]], str]
    frozen_analysis_ids: Callable[..., set[str]]
    load_private_manifest: Callable[[Path], dict[str, Any]]
    connect_read_only: Callable[[Path], Any]
    write_private_json: Callable[..., dict[str, Any]]
    monotonic: Callable[[], float]
    sleep: Callable[[float], None]


def _fresh_analysis_ids(
    sources: CohortMonitorSources,
    connection: Any,
    stable_id: str,
    prior_ids: set[str],
    agent_role: str,
    label: str,
) -> list[str]:
    current_ids = set(
        sources.analysis_ids_for_group(
            connection, stable_id, agent_role=agent_role
        )
    )
    if not prior_ids.issubset(current_ids):
        raise sources.cohort_error(
            f"prior {label} analysis identity disappeared for {stable_id}"
        )
    fresh_ids = sorted(current_ids - prior_ids)
    if len(fresh_ids) > 1:
        raise sources.cohort_error(
            f"more than one new {label} analysis exists for {stable_id}; "
            "the cohort result is ambiguous"
        )
    return fresh_ids


def _analysis_result(
    sources: CohortMonitorSources,
    connection: Any,
    member: Mapping[str, Any],
    stable_id: str,
    analysis_id: str,
    agent_role: str,
) -> dict[str, Any]:
    return sources.analysis_metadata(
        connection,
        analysis_id,
        stable_id,
        expected_alert_id=str(member["representative_alert_id"]),
        expected_agent_role=agent_role,
    )


def _second_opinion(
    sources: CohortMonitorSources,
    connection: Any,
    analysis_id: str,
) -> dict[str, Any] | None:
    if not analysis_id:
        return None
    return sources.second_opinion_metadata(connection, analysis_id)


def _soc_analysis_id(
    sources: CohortMonitorSources,
    stable_id: str,
    fresh_ids: list[str],
    job_state: str,
) -> str:
    if fresh_ids and job_state == "failed":
        raise sources.cohort_error(
            f"SOC job for {stable_id} failed but a fresh analysis exists"
        )
    if job_state == "completed" and not fresh_ids:
        raise sources.cohort_error(
            f"SOC job for {stable_id} is completed without one exact new analysis"
        )
    if fresh_ids and job_state == "completed":
        return fresh_ids[0]
    return ""


def _monitor_soc_member(
    sources: CohortMonitorSources,
    connection: Any,
    member: Mapping[str, Any],
    dispatch: Mapping[str, Any],
    stable_id: str,
    job: Mapping[str, Any],
    job_state: str,
) -> dict[str, Any]:
    prior_ids = set((member.get("pre_state") or {}).get("soc_analysis_ids") or [])
    fresh_ids = _fresh_analysis_ids(
        sources, connection, stable_id, prior_ids, "soc-analyst", "SOC"
    )
    analysis_id = _soc_analysis_id(sources, stable_id, fresh_ids, job_state)
    analysis = (
        _analysis_result(
            sources, connection, member, stable_id, analysis_id, "soc-analyst"
        )
        if analysis_id
        else None
    )
    if analysis is not None:
        sources.validate_completed_analysis_job_window(
            dispatch=dispatch, job=job, analysis=analysis
        )
    return {
        "state": "completed" if analysis_id else job_state,
        "checked_at": sources.utc_now(),
        "case_id": "",
        "run_id": "",
        "analysis_id": analysis_id,
        "job": job,
        "analysis": analysis,
        "second_opinion": _second_opinion(sources, connection, analysis_id),
    }


def _incident_case(
    sources: CohortMonitorSources,
    connection: Any,
    member: Mapping[str, Any],
    stable_id: str,
    accepted: Mapping[str, Any],
) -> tuple[str, Mapping[str, str], dict[str, Any]]:
    case_id = str(accepted.get("case_id") or "")
    aliases = sources.load_aliases(connection)
    case = sources.case_for_stable(connection, stable_id, aliases)
    if not case or str(case.get("case_id") or "") != case_id:
        raise sources.cohort_error(
            f"exact incident case identity was lost: {case_id}"
        )
    if (
        str(case.get("dashboard_group_id") or "")
        != str(member["dashboard_group_id"])
        or str(case.get("representative_alert_id") or "")
        != str(member["representative_alert_id"])
    ):
        raise sources.cohort_error(f"incident case identity drifted: {case_id}")
    return case_id, aliases, case


def _escalation_source_state(
    case: Mapping[str, Any],
) -> tuple[str, str, None]:
    agent_status = str(case.get("agent_status") or "")
    source_status = {
        "queued": "queued",
        "analyzing": "running",
        "analyzed": "completed",
        "failed": "failed",
    }.get(agent_status, agent_status or "unknown")
    return source_status, str(case.get("latest_analysis_id") or ""), None


def _reanalysis_source_state(
    sources: CohortMonitorSources,
    connection: Any,
    member: Mapping[str, Any],
    accepted: Mapping[str, Any],
    aliases: Mapping[str, str],
    case_id: str,
    stable_id: str,
) -> tuple[str, str, dict[str, Any] | None]:
    run_id = str(accepted.get("run_id") or "")
    run_case = sources.reanalysis_run_case(connection, run_id, case_id)
    if not run_case:
        raise sources.cohort_error(
            f"exact reanalysis run case is missing: {run_id}/{case_id}"
        )
    _validate_reanalysis_identity(
        sources, member, aliases, run_case, run_id, case_id, stable_id
    )
    return (
        str(run_case.get("status") or ""),
        str(run_case.get("analysis_id") or ""),
        run_case,
    )


def _validate_reanalysis_identity(
    sources: CohortMonitorSources,
    member: Mapping[str, Any],
    aliases: Mapping[str, str],
    run_case: Mapping[str, Any],
    run_id: str,
    case_id: str,
    stable_id: str,
) -> None:
    resolved_group = sources.resolve_alias(
        str(run_case.get("group_id") or ""), aliases
    )
    dashboard_group = str(run_case.get("dashboard_group_id") or "")
    representative = str(run_case.get("representative_alert_id") or "")
    if resolved_group != stable_id:
        raise sources.cohort_error(
            f"exact reanalysis identity drifted: {run_id}/{case_id}"
        )
    if dashboard_group != str(member["dashboard_group_id"]):
        raise sources.cohort_error(
            f"exact reanalysis identity drifted: {run_id}/{case_id}"
        )
    if representative != str(member["representative_alert_id"]):
        raise sources.cohort_error(
            f"exact reanalysis identity drifted: {run_id}/{case_id}"
        )


def _incident_source_state(
    sources: CohortMonitorSources,
    connection: Any,
    member: Mapping[str, Any],
    accepted: Mapping[str, Any],
    aliases: Mapping[str, str],
    case: Mapping[str, Any],
    case_id: str,
    stable_id: str,
    kind: str,
) -> tuple[str, str, dict[str, Any] | None]:
    if kind == "escalate":
        return _escalation_source_state(case)
    if kind == "reanalyze":
        return _reanalysis_source_state(
            sources,
            connection,
            member,
            accepted,
            aliases,
            case_id,
            stable_id,
        )
    raise sources.cohort_error(f"unsupported dispatch kind: {kind!r}")


def _incident_terminal_state(
    sources: CohortMonitorSources,
    stable_id: str,
    source_status: str,
    job_state: str,
    analysis_id: str,
    fresh_analysis_id: str,
) -> tuple[str, str]:
    if analysis_id and analysis_id != fresh_analysis_id:
        raise sources.cohort_error(
            f"incident result pointer is not the exact fresh analysis for {stable_id}"
        )
    if job_state in {"queued", "running"}:
        return job_state, ""
    if job_state == "failed":
        _validate_failed_incident(
            sources, stable_id, source_status, fresh_analysis_id
        )
        return "failed", ""
    if source_status == "skipped" and not fresh_analysis_id:
        return "skipped", ""
    if _is_completed_incident(source_status, fresh_analysis_id, analysis_id):
        return "completed", analysis_id
    raise sources.cohort_error(
        f"incident result state does not agree with completed accepted job for {stable_id}"
    )


def _validate_failed_incident(
    sources: CohortMonitorSources,
    stable_id: str,
    source_status: str,
    fresh_analysis_id: str,
) -> None:
    if source_status == "failed" and not fresh_analysis_id:
        return
    raise sources.cohort_error(
        f"incident result state disagrees with failed accepted job for {stable_id}"
    )


def _is_completed_incident(
    source_status: str,
    fresh_analysis_id: str,
    analysis_id: str,
) -> bool:
    return bool(
        source_status == "completed"
        and fresh_analysis_id
        and analysis_id == fresh_analysis_id
    )


def _incident_analysis_snapshot(
    sources: CohortMonitorSources,
    connection: Any,
    member: Mapping[str, Any],
    dispatch: Mapping[str, Any],
    job: Mapping[str, Any],
    stable_id: str,
    analysis_id: str,
) -> dict[str, Any] | None:
    if not analysis_id:
        return None
    analysis = _analysis_result(
        sources,
        connection,
        member,
        stable_id,
        analysis_id,
        "incident-responder",
    )
    sources.validate_completed_analysis_job_window(
        dispatch=dispatch,
        job=job,
        analysis=analysis,
    )
    return analysis


def _public_run_case(
    run_case: Mapping[str, Any] | None,
) -> dict[str, Any] | None:
    if not run_case:
        return None
    private_fields = {"latest_error", "skip_reason"}
    return {
        key: value
        for key, value in run_case.items()
        if key not in private_fields
    }


def _incident_monitor_result(
    sources: CohortMonitorSources,
    connection: Any,
    accepted: Mapping[str, Any],
    case: Mapping[str, Any],
    case_id: str,
    status: str,
    analysis_id: str,
    job: Mapping[str, Any],
    run_case: Mapping[str, Any] | None,
    analysis: Mapping[str, Any] | None,
) -> dict[str, Any]:
    return {
        "state": status,
        "checked_at": sources.utc_now(),
        "case_id": case_id,
        "run_id": str(accepted.get("run_id") or ""),
        "analysis_id": analysis_id,
        "job": job,
        "case_agent_status": str(case.get("agent_status") or ""),
        "run_case": _public_run_case(run_case),
        "analysis": analysis,
        "second_opinion": _second_opinion(sources, connection, analysis_id),
    }


def _monitor_incident_member(
    sources: CohortMonitorSources,
    connection: Any,
    member: Mapping[str, Any],
    dispatch: Mapping[str, Any],
    accepted: Mapping[str, Any],
    stable_id: str,
    kind: str,
    job: Mapping[str, Any],
    job_state: str,
) -> dict[str, Any]:
    case_id, aliases, case = _incident_case(
        sources, connection, member, stable_id, accepted)
    source_status, analysis_id, run_case = _incident_source_state(
        sources, connection, member, accepted, aliases, case, case_id,
        stable_id, kind,
    )
    prior_ids = sources.frozen_analysis_ids(
        member, agent_role="incident-responder",
        pre_state_field="incident_analysis_ids",
    )
    fresh_ids = _fresh_analysis_ids(
        sources, connection, stable_id, prior_ids, "incident-responder",
        "Incident Responder",
    )
    fresh_id = fresh_ids[0] if fresh_ids else ""
    status, analysis_id = _incident_terminal_state(
        sources, stable_id, source_status, job_state, analysis_id, fresh_id
    )
    analysis = _incident_analysis_snapshot(
        sources,
        connection,
        member,
        dispatch,
        job,
        stable_id,
        analysis_id,
    )
    return _incident_monitor_result(
        sources,
        connection,
        accepted,
        case,
        case_id,
        status,
        analysis_id,
        job,
        run_case,
        analysis,
    )


def monitor_member(
    sources: CohortMonitorSources,
    connection: Any,
    manifest: Mapping[str, Any],
    member: Mapping[str, Any],
) -> dict[str, Any]:
    dispatch = member.get("dispatch") or {}
    if dispatch.get("state") != "accepted":
        raise sources.cohort_error(
            f"member {member.get('rank')} was not unambiguously accepted"
        )
    accepted = dispatch.get("accepted") or {}
    stable_id = str(member["stable_group_id"])
    kind = str(dispatch.get("kind") or "")
    job = sources.monitor_dispatch_job_binding(connection, manifest, member)
    job_state = sources.durable_job_monitor_state(job)
    if kind == "analyze":
        return _monitor_soc_member(
            sources, connection, member, dispatch, stable_id, job, job_state
        )
    return _monitor_incident_member(
        sources, connection, member, dispatch, accepted,
        stable_id, kind, job, job_state,
    )


def monitor_cohort_once(
    sources: CohortMonitorSources,
    database_path: Path,
    manifest_path: Path,
) -> tuple[dict[str, Any], bool]:
    manifest = sources.load_private_manifest(manifest_path)
    connection = sources.connect_read_only(database_path)
    try:
        connection.execute("BEGIN")
        terminal = True
        for index, member in enumerate(manifest["members"]):
            monitor = monitor_member(sources, connection, manifest, member)
            member["monitor"] = monitor
            manifest["members"][index] = member
            terminal = terminal and monitor["state"] in sources.terminal_monitor_states
    finally:
        connection.close()
    manifest["last_monitored_at"] = sources.utc_now()
    manifest["state"] = "terminal" if terminal else "monitoring"
    manifest = sources.write_private_json(
        manifest_path, manifest, digest_field="manifest_sha256"
    )
    return manifest, terminal


def monitor_cohort(
    sources: CohortMonitorSources,
    database_path: Path,
    manifest_path: Path,
    *,
    timeout: float,
    poll_interval: float,
) -> tuple[dict[str, Any], bool]:
    if timeout < 0:
        raise sources.cohort_error("monitor timeout must not be negative")
    if poll_interval < 0.2 or poll_interval > 60:
        raise sources.cohort_error(
            "poll interval must be between 0.2 and 60 seconds"
        )
    deadline = sources.monotonic() + timeout
    while True:
        manifest, terminal = monitor_cohort_once(
            sources, database_path, manifest_path
        )
        if terminal or timeout == 0 or sources.monotonic() >= deadline:
            return manifest, terminal
        sources.sleep(
            min(poll_interval, max(0.0, deadline - sources.monotonic()))
        )
