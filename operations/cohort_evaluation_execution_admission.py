#!/usr/bin/env python3
"""Admit and bind one fresh cohort analysis to its public execution proof."""
from __future__ import annotations

from dataclasses import dataclass
import datetime as dt
from typing import Any, Callable, Mapping, Pattern


@dataclass(frozen=True)
class ExecutionAdmission:
    result: Mapping[str, Any]
    analysis: Mapping[str, Any]
    analysis_result: Mapping[str, Any]
    dispatch: Mapping[str, Any]
    analysis_id: str
    dispatch_started: dt.datetime
    generated_at: dt.datetime


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, dict) else {}


def _completed_analysis_valid(
    raw_result: Any,
    result: Mapping[str, Any],
    analysis_id: str,
) -> bool:
    checks = (
        isinstance(raw_result, dict),
        str(result.get("state") or "") == "completed",
        bool(analysis_id),
        str(result.get("analysis_id") or "") == analysis_id,
    )
    return all(checks)


def admit_fresh_analysis(
    *,
    member: Mapping[str, Any],
    label: str,
    prior_analysis_ids: Callable[[Mapping[str, Any]], set[str]],
    parse_timestamp: Callable[[Any, str], dt.datetime],
    error: type[RuntimeError],
) -> ExecutionAdmission:
    """Require one accepted, completed analysis not present before dispatch."""
    raw_result = member.get("result")
    result = _mapping(raw_result)
    analysis = _mapping(result.get("analysis"))
    analysis_result = _mapping(analysis.get("result"))
    analysis_id = str(analysis.get("analysis_id") or "")
    if not _completed_analysis_valid(raw_result, result, analysis_id):
        raise error(f"{label} is not one exact completed analysis")
    if analysis_id in prior_analysis_ids(member):
        raise error(f"{label} reuses an old analysis ID")
    dispatch = _mapping(member.get("dispatch"))
    accepted_once = all(
        (
            dispatch.get("state") == "accepted",
            int(dispatch.get("attempt_count") or 0) == 1,
        )
    )
    if not accepted_once:
        raise error(f"{label} was not accepted exactly once")
    dispatch_started = parse_timestamp(
        dispatch.get("started_at"), f"{label} dispatch started_at"
    )
    generated_at = parse_timestamp(
        analysis.get("generated_at"), f"{label} analysis generated_at"
    )
    if generated_at < dispatch_started:
        raise error(f"{label} predates its dispatch")
    return ExecutionAdmission(
        result=result,
        analysis=analysis,
        analysis_result=analysis_result,
        dispatch=dispatch,
        analysis_id=analysis_id,
        dispatch_started=dispatch_started,
        generated_at=generated_at,
    )


def _primary_response_valid(
    admission: ExecutionAdmission,
    expected_route: str,
) -> bool:
    return all(
        (
            str(admission.analysis_result.get("_analysis_model_route") or "")
            == expected_route,
            admission.analysis_result.get("_analysis_evaluation_memory_frozen")
            is True,
        )
    )


def _reviewer_response_valid(
    admission: ExecutionAdmission,
    reviewer_route: str,
) -> bool:
    second_opinion = _mapping(admission.analysis_result.get("_second_opinion"))
    response = _mapping(second_opinion.get("response"))
    return all(
        (
            second_opinion.get("status") == "completed",
            second_opinion.get("model_route") == reviewer_route,
            response.get("_analysis_model_route") == reviewer_route,
        )
    )


def validate_response_binding(
    *,
    admission: ExecutionAdmission,
    role: str,
    contract: Mapping[str, Any],
    digest_pattern: Pattern[str],
    label: str,
    error: type[RuntimeError],
) -> str:
    """Bind role, primary route, frozen memory, reviewer route, and digest."""
    if str(admission.analysis.get("agent_role") or "") != role:
        raise error(f"{label} agent role does not match")
    expected_route = str(contract["expected_assigned_route"])
    if not _primary_response_valid(admission, expected_route):
        raise error(f"{label} response route/freeze attestation does not match")
    reviewer_route = str(contract["expected_reviewer_route"])
    if not _reviewer_response_valid(admission, reviewer_route):
        raise error(f"{label} response reviewer route attestation does not match")
    digest = str(admission.analysis.get("response_canonical_sha256") or "")
    if digest_pattern.fullmatch(digest) is None:
        raise error(f"{label} canonical response digest is missing")
    return digest


def _public_proof_valid(
    proof: Mapping[str, Any],
    admission: ExecutionAdmission,
    contract: Mapping[str, Any],
) -> bool:
    checks = (
        proof.get("status") == "passed",
        proof.get("fresh_analysis") is True,
        proof.get("dispatch_accepted_once") is True,
        str(proof.get("analysis_id") or "") == admission.analysis_id,
        str(proof.get("release_id") or "")
        == str(contract["expected_release_id"]),
    )
    return all(checks)


def admit_public_proof(
    *,
    member: Mapping[str, Any],
    admission: ExecutionAdmission,
    contract: Mapping[str, Any],
    label: str,
    validate_embedded_digest: Callable[[Mapping[str, Any], str], None],
    parse_timestamp: Callable[[Any, str], dt.datetime],
    error: type[RuntimeError],
) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    """Require a passed public proof bound to the exact fresh analysis."""
    proof = member.get("execution_proof")
    if not isinstance(proof, dict):
        raise error(f"{label} has no execution proof")
    validate_embedded_digest(proof, "proof_sha256")
    if not _public_proof_valid(proof, admission, contract):
        raise error(f"{label} execution proof did not pass")
    proof_generated = parse_timestamp(
        proof.get("analysis_generated_at"), f"{label} proof generated_at"
    )
    if proof_generated != admission.generated_at:
        raise error(f"{label} proof generated_at does not match the analysis")
    harness = proof.get("harness")
    if not isinstance(harness, dict):
        raise error(f"{label} has no harness proof")
    return proof, harness


def validate_harness_identity(
    *,
    harness: Mapping[str, Any],
    member: Mapping[str, Any],
    admission: ExecutionAdmission,
    role: str,
    contract: Mapping[str, Any],
    expected_task_kind: Callable[[str, str], str],
    label: str,
    error: type[RuntimeError],
) -> None:
    expected = {
        "run_id": admission.analysis_id,
        "status": "succeeded",
        "stage": "complete",
        "role": role,
        "task_kind": expected_task_kind(
            role, str(admission.dispatch.get("kind") or "")
        ),
        "policy_mode": "shadow",
        "assigned_route": str(contract["expected_assigned_route"]),
        "assigned_reviewer_route": str(contract["expected_reviewer_route"]),
        "stable_group_id": str(member.get("stable_group_id") or ""),
        "representative_alert_id": str(member.get("representative_alert_id") or ""),
    }
    for field, value in expected.items():
        if str(harness.get(field) or "") != str(value):
            raise error(f"{label} harness {field} does not match")


def validate_harness_freshness(
    *,
    harness: Mapping[str, Any],
    admission: ExecutionAdmission,
    label: str,
    parse_timestamp: Callable[[Any, str], dt.datetime],
    error: type[RuntimeError],
) -> None:
    started = parse_timestamp(harness.get("started_at"), f"{label} harness started_at")
    completed = parse_timestamp(
        harness.get("completed_at"), f"{label} harness completed_at"
    )
    if started < admission.dispatch_started or completed < admission.generated_at:
        raise error(f"{label} harness timestamps do not prove a fresh run")
