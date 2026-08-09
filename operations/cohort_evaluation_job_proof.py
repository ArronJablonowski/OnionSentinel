#!/usr/bin/env python3
"""Validate deterministic dispatch identity and durable cohort job proof."""
from __future__ import annotations

from dataclasses import dataclass
import datetime as dt
from typing import Any, Callable, Mapping, Pattern


@dataclass(frozen=True)
class DurableJobPolicy:
    cohort_id_pattern: Pattern[str]
    frozen_digest_pattern: Pattern[str]
    dashboard_group_id_pattern: Pattern[str]
    stable_group_id_pattern: Pattern[str]
    representative_alert_id_pattern: Pattern[str]
    payload_digest_pattern: Pattern[str]
    dispatch_id_schema: str
    hash_value: Callable[[Any], str]
    stable_group_key: Callable[[Any, str], str]
    parse_timestamp: Callable[[Any, str], dt.datetime]


@dataclass(frozen=True)
class _DurableJobContext:
    dispatch: Mapping[str, Any]
    readback: Mapping[str, Any]
    job: Mapping[str, Any]
    sources: tuple[tuple[str, Mapping[str, Any]], ...]
    expected: Mapping[str, str]
    stable_group_id: str
    representative_alert_id: str
    expected_job_type: str


def _dispatch_identity_fields(
    member: Mapping[str, Any],
    policy: DurableJobPolicy,
    error: type[RuntimeError],
) -> dict[str, Any]:
    try:
        rank = int(member.get("rank"))
    except (TypeError, ValueError) as exc:
        raise error("export member has an invalid dispatch rank") from exc
    dashboard_group_id = str(member.get("dashboard_group_id") or "")
    stable_group_id = str(member.get("stable_group_id") or "")
    stable_group_key = policy.stable_group_key(
        member.get("stable_group_key"),
        "export member stable_group_key",
    )
    representative_alert_id = str(member.get("representative_alert_id") or "")
    valid = (
        rank >= 1
        and policy.dashboard_group_id_pattern.fullmatch(dashboard_group_id)
        and policy.stable_group_id_pattern.fullmatch(stable_group_id)
        and policy.representative_alert_id_pattern.fullmatch(
            representative_alert_id
        )
    )
    if not valid:
        raise error("export member has malformed dispatch identity fields")
    return {
        "rank": rank,
        "dashboard_group_id": dashboard_group_id,
        "stable_group_id": stable_group_id,
        "stable_group_key": stable_group_key,
        "representative_alert_id": representative_alert_id,
    }


def expected_dispatch_id(
    *,
    cohort_id: str,
    frozen_plan_sha256: str,
    member: Mapping[str, Any],
    dispatch_kind: str,
    policy: DurableJobPolicy,
    error: type[RuntimeError],
) -> str:
    """Derive a dispatch identifier from the exact frozen member identity."""
    valid = (
        policy.cohort_id_pattern.fullmatch(cohort_id)
        and policy.frozen_digest_pattern.fullmatch(frozen_plan_sha256)
        and dispatch_kind in {"analyze", "escalate", "reanalyze"}
    )
    if not valid:
        raise error("export cannot derive an exact dispatch identity")
    identity = _dispatch_identity_fields(member, policy, error)
    return policy.hash_value(
        {
            "schema": policy.dispatch_id_schema,
            "cohort_id": cohort_id,
            "frozen_plan_sha256": frozen_plan_sha256,
            **identity,
            "dispatch_kind": dispatch_kind,
        }
    )


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, dict) else {}


def _validate_provenance(
    *,
    sources: tuple[tuple[str, Mapping[str, Any]], ...],
    expected: Mapping[str, str],
    stable_group_id: str,
    representative_alert_id: str,
    label: str,
    error: type[RuntimeError],
) -> None:
    for source_label, source in sources:
        for field, value in expected.items():
            if str(source.get(field) or "") != value:
                raise error(f"{label} {source_label} {field} does not match")
        if source.get("reviewer_required") is not True:
            raise error(f"{label} {source_label} reviewer_required does not match")
        stable_matches = str(source.get("stable_group_id") or "") == stable_group_id
        representative_matches = (
            str(source.get("representative_alert_id") or "")
            == representative_alert_id
        )
        if not stable_matches or not representative_matches:
            raise error(
                f"{label} {source_label} stable/representative identity "
                "does not match"
            )


def _validated_job_id(
    readback: Mapping[str, Any],
    job: Mapping[str, Any],
    label: str,
    error: type[RuntimeError],
) -> tuple[int, int]:
    try:
        return int(readback.get("job_id")), int(job.get("id"))
    except (TypeError, ValueError, OverflowError) as exc:
        raise error(f"{label} durable job ID is invalid") from exc


def _job_proof_valid(
    *,
    readback: Mapping[str, Any],
    job: Mapping[str, Any],
    expected_job_type: str,
    stable_group_id: str,
    policy: DurableJobPolicy,
    label: str,
    error: type[RuntimeError],
) -> bool:
    readback_job_id, terminal_job_id = _validated_job_id(
        readback, job, label, error
    )
    payload_sha256 = str(job.get("payload_sha256") or "")
    checks = (
        readback_job_id >= 1,
        terminal_job_id == readback_job_id,
        policy.payload_digest_pattern.fullmatch(payload_sha256) is not None,
        str(readback.get("job_payload_sha256") or "") == payload_sha256,
        str(job.get("status") or "") == "completed",
        str(job.get("job_type") or "") == expected_job_type,
        str(job.get("dedupe_key") or "") == stable_group_id,
    )
    return all(checks)


def _validate_job_window(
    *,
    dispatch: Mapping[str, Any],
    job: Mapping[str, Any],
    analysis: Mapping[str, Any],
    policy: DurableJobPolicy,
    label: str,
    error: type[RuntimeError],
) -> None:
    parse = policy.parse_timestamp
    dispatch_started = parse(dispatch.get("started_at"), f"{label} dispatch started_at")
    requested_at = parse(job.get("requested_at"), f"{label} job requested_at")
    generated_at = parse(analysis.get("generated_at"), f"{label} analysis generated_at")
    completed_at = parse(job.get("completed_at"), f"{label} job completed_at")
    last_completed_at = parse(
        job.get("last_completed_at"), f"{label} job last_completed_at"
    )
    updated_at = parse(job.get("updated_at"), f"{label} job updated_at")
    invalid = (
        requested_at < dispatch_started
        or generated_at < dispatch_started
        or generated_at < requested_at
        or generated_at > completed_at
        or generated_at > last_completed_at
        or completed_at > last_completed_at
        or last_completed_at > updated_at
    )
    if invalid:
        raise error(f"{label} analysis is outside its exact durable job window")


def _expected_provenance(
    contract: Mapping[str, Any],
    dispatch_id: str,
    cohort_id: str,
    stable_group_key: str,
) -> dict[str, str]:
    return {
        "dispatch_id": dispatch_id,
        "cohort_id": cohort_id,
        "stable_group_key": stable_group_key,
        "release_id": str(contract.get("expected_release_id") or ""),
        "expected_assigned_route": str(contract.get("expected_assigned_route") or ""),
        "expected_reviewer_route": str(contract.get("expected_reviewer_route") or ""),
    }


def _durable_job_context(
    *,
    member: Mapping[str, Any],
    result: Mapping[str, Any],
    contract: Mapping[str, Any],
    cohort_id: str,
    frozen_plan_sha256: str,
    label: str,
    policy: DurableJobPolicy,
    error: type[RuntimeError],
) -> _DurableJobContext:
    dispatch = _mapping(member.get("dispatch"))
    accepted = _mapping(dispatch.get("accepted"))
    readback = _mapping(dispatch.get("readback"))
    job = _mapping(result.get("job"))
    dispatch_kind = str(dispatch.get("kind") or "")
    dispatch_id = expected_dispatch_id(
        cohort_id=cohort_id,
        frozen_plan_sha256=frozen_plan_sha256,
        member=member,
        dispatch_kind=dispatch_kind,
        policy=policy,
        error=error,
    )
    if str(dispatch.get("dispatch_id") or "") != dispatch_id:
        raise error(f"{label} dispatch identity does not match")
    stable_group_id = str(member.get("stable_group_id") or "")
    stable_group_key = policy.stable_group_key(
        member.get("stable_group_key"), f"{label} stable_group_key"
    )
    return _DurableJobContext(
        dispatch=dispatch,
        readback=readback,
        job=job,
        sources=(
            ("accepted response", accepted),
            ("durable readback", readback),
            ("terminal durable job", job),
        ),
        expected=_expected_provenance(
            contract, dispatch_id, cohort_id, stable_group_key
        ),
        stable_group_id=stable_group_id,
        representative_alert_id=str(member.get("representative_alert_id") or ""),
        expected_job_type=(
            "ai_analysis"
            if dispatch_kind == "analyze"
            else "incident_response_analysis"
        ),
    )


def validate_durable_job_proof(
    *,
    member: Mapping[str, Any],
    result: Mapping[str, Any],
    analysis: Mapping[str, Any],
    contract: Mapping[str, Any],
    cohort_id: str,
    frozen_plan_sha256: str,
    label: str,
    policy: DurableJobPolicy,
    error: type[RuntimeError],
) -> dict[str, Any]:
    """Validate accepted, read-back, and completed durable-job provenance."""
    context = _durable_job_context(
        member=member,
        result=result,
        contract=contract,
        cohort_id=cohort_id,
        frozen_plan_sha256=frozen_plan_sha256,
        label=label,
        policy=policy,
        error=error,
    )
    _validate_provenance(
        sources=context.sources,
        expected=context.expected,
        stable_group_id=context.stable_group_id,
        representative_alert_id=context.representative_alert_id,
        label=label,
        error=error,
    )
    if not _job_proof_valid(
        readback=context.readback,
        job=context.job,
        expected_job_type=context.expected_job_type,
        stable_group_id=context.stable_group_id,
        policy=policy,
        label=label,
        error=error,
    ):
        raise error(f"{label} exact completed durable job proof is invalid")
    _validate_job_window(
        dispatch=context.dispatch,
        job=context.job,
        analysis=analysis,
        policy=policy,
        label=label,
        error=error,
    )
    return dict(context.job)
