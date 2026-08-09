#!/usr/bin/env python3
"""Fresh result, exactly-once dispatch, and assigned-route proof context."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping


@dataclass(frozen=True)
class ResultExecutionPolicy:
    cohort_error: type[RuntimeError]
    parse_timestamp: Callable[[Any, str], Any]


@dataclass(frozen=True)
class ResultExecutionContext:
    role: str
    contract: dict[str, Any]
    dispatch: Mapping[str, Any]
    analysis: Mapping[str, Any]
    analysis_id: str
    expected_route: str
    expected_reviewer_route: str
    dispatch_started: Any
    analysis_generated: Any
    failures: tuple[str, ...]


def _listed_prior_ids(pre_state: Mapping[str, Any]) -> set[str]:
    identities: set[str] = set()
    for field in ("soc_analysis_ids", "incident_analysis_ids"):
        values = pre_state.get(field)
        if isinstance(values, list):
            identities.update(str(item) for item in values if str(item))
    return identities


def _pointed_prior_ids(pre_state: Mapping[str, Any]) -> set[str]:
    identities: set[str] = set()
    for source in (
        pre_state.get("latest_analysis"),
        pre_state.get("incident_case"),
    ):
        if not isinstance(source, dict):
            continue
        identity = str(
            source.get("analysis_id")
            or source.get("latest_analysis_id")
            or ""
        )
        if identity:
            identities.add(identity)
    return identities


def prior_analysis_ids(member: Mapping[str, Any]) -> set[str]:
    pre_state = member.get("pre_state")
    pre_state = pre_state if isinstance(pre_state, dict) else {}
    return _listed_prior_ids(pre_state) | _pointed_prior_ids(pre_state)


def expected_task_kind(
    role: str,
    dispatch_kind: str,
    cohort_error: type[RuntimeError],
) -> str:
    if role == "soc-analyst" and dispatch_kind == "analyze":
        return "reanalysis"
    if role == "incident-responder" and dispatch_kind == "reanalyze":
        return "reanalysis"
    if role == "incident-responder" and dispatch_kind == "escalate":
        return "incident-response"
    raise cohort_error(
        f"dispatch {dispatch_kind!r} is invalid for agent role {role!r}"
    )


def _identity_failures(
    role: str,
    member: Mapping[str, Any],
    monitor: Mapping[str, Any],
    dispatch: Mapping[str, Any],
    analysis: Mapping[str, Any],
    analysis_id: str,
) -> list[str]:
    analysis_binding = (
        bool(analysis_id)
        and str(analysis.get("analysis_id") or "") == analysis_id
    )
    dispatch_once = (
        dispatch.get("state") == "accepted"
        and int(dispatch.get("attempt_count") or 0) == 1
    )
    checks = (
        (str(monitor.get("state") or "") == "completed", "result-not-completed"),
        (analysis_binding, "analysis-id-binding-failed"),
        (analysis_id not in prior_analysis_ids(member), "analysis-id-is-not-fresh"),
        (str(analysis.get("agent_role") or "") == role, "analysis-role-mismatch"),
        (dispatch_once, "dispatch-not-exactly-once"),
    )
    return [failure for valid, failure in checks if not valid]


def _freshness(
    dispatch: Mapping[str, Any],
    analysis: Mapping[str, Any],
    policy: ResultExecutionPolicy,
) -> tuple[Any, Any, list[str]]:
    try:
        dispatch_started = policy.parse_timestamp(
            dispatch.get("started_at"), "dispatch started_at"
        )
        analysis_generated = policy.parse_timestamp(
            analysis.get("generated_at"), "analysis generated_at"
        )
    except policy.cohort_error:
        return None, None, ["freshness-timestamp-invalid"]
    failures = (
        ["analysis-predates-dispatch"]
        if analysis_generated < dispatch_started
        else []
    )
    return dispatch_started, analysis_generated, failures


def _route_failures(
    result: Mapping[str, Any],
    contract: Mapping[str, Any],
    expected_route: str,
    expected_reviewer_route: str,
) -> list[str]:
    failures: list[str] = []
    if result.get("_analysis_evaluation_memory_frozen") is not True:
        failures.append("analysis-memory-freeze-not-attested")
    if str(result.get("_analysis_model_route") or "") != expected_route:
        failures.append("analysis-route-mismatch")
    second_opinion = result.get("_second_opinion")
    second_opinion = second_opinion if isinstance(second_opinion, dict) else {}
    reviewer_response = second_opinion.get("response")
    reviewer_response = reviewer_response if isinstance(reviewer_response, dict) else {}
    reviewer_valid = (
        second_opinion.get("status") == "completed"
        and second_opinion.get("model_route") == expected_reviewer_route
        and reviewer_response.get("_analysis_model_route")
        == expected_reviewer_route
    )
    if contract.get("reviewer_required") is True and not reviewer_valid:
        failures.append("analysis-reviewer-route-mismatch")
    return failures


def evaluate_result_execution(
    manifest: Mapping[str, Any],
    member: Mapping[str, Any],
    monitor: Mapping[str, Any],
    policy: ResultExecutionPolicy,
) -> ResultExecutionContext:
    role = str(manifest.get("agent_role") or "")
    contract = manifest.get("execution_contract")
    if not isinstance(contract, dict):
        raise policy.cohort_error("manifest has no execution contract")
    dispatch = member.get("dispatch")
    dispatch = dispatch if isinstance(dispatch, dict) else {}
    analysis = monitor.get("analysis")
    analysis = analysis if isinstance(analysis, dict) else {}
    result = analysis.get("result")
    result = result if isinstance(result, dict) else {}
    analysis_id = str(monitor.get("analysis_id") or "")
    expected_route = str(contract.get("expected_assigned_route") or "")
    reviewer_route = str(contract.get("expected_reviewer_route") or "")
    failures = _identity_failures(
        role, member, monitor, dispatch, analysis, analysis_id
    )
    dispatch_started, analysis_generated, freshness_failures = _freshness(
        dispatch, analysis, policy
    )
    failures.extend(freshness_failures)
    failures.extend(
        _route_failures(result, contract, expected_route, reviewer_route)
    )
    return ResultExecutionContext(
        role=role,
        contract=contract,
        dispatch=dispatch,
        analysis=analysis,
        analysis_id=analysis_id,
        expected_route=expected_route,
        expected_reviewer_route=reviewer_route,
        dispatch_started=dispatch_started,
        analysis_generated=analysis_generated,
        failures=tuple(failures),
    )
