#!/usr/bin/env python3
"""Normalize one execution-gated member from an offline cohort export."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping, Pattern, Sequence


@dataclass(frozen=True)
class ResultMemberPolicy:
    stable_group_id_pattern: Pattern[str]
    verdict_fields: Sequence[str]
    stable_group_key: Callable[[Any, str], str]
    hash_value: Callable[[Any], str]
    validate_execution_proof: Callable[..., Mapping[str, Any]]
    observed_labels: Callable[[Mapping[str, Any]], Mapping[str, Any]]
    query_audit_summary: Callable[[Mapping[str, Any]], Mapping[str, Any]]


@dataclass(frozen=True)
class NormalizedExportMember:
    rank: int
    stable_group_id: str
    identity: dict[str, Any]
    detection_projection: dict[str, Any]
    normalized: dict[str, Any]


def _rank(
    member: Mapping[str, Any],
    expected_count: int,
    ranks: set[int],
    label: str,
    error: type[RuntimeError],
) -> int:
    try:
        rank = int(member.get("rank"))
    except (TypeError, ValueError) as exc:
        raise error(f"{label} contains an invalid member rank") from exc
    if rank < 1 or rank > expected_count or rank in ranks:
        raise error(f"{label} contains an invalid or duplicate member rank")
    return rank


def _analysis_mapping(
    value: Any,
    rank: int,
    label: str,
    error: type[RuntimeError],
) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, dict):
        return dict(value)
    raise error(f"{label} member {rank} analysis is invalid")


def _result_analysis(
    member: Mapping[str, Any],
    role: str,
    rank: int,
    label: str,
    error: type[RuntimeError],
) -> tuple[Mapping[str, Any], dict[str, Any], str, str | None]:
    result = member.get("result")
    if not isinstance(result, dict):
        raise error(f"{label} member {rank} has no result object")
    state = str(result.get("state") or "").strip().lower()
    analysis = _analysis_mapping(result.get("analysis"), rank, label, error)
    observed_role = str(analysis.get("agent_role") or "").strip().lower()
    role_valid = observed_role in {"", role}
    if not role_valid:
        raise error(f"{label} member {rank} was executed by {observed_role!r}")
    analysis_id = str(analysis.get("analysis_id") or "").strip() or None
    analysis_id_valid = state != "completed" or analysis_id is not None
    if not analysis_id_valid:
        raise error(f"{label} member {rank} completed without an analysis ID")
    return result, analysis, state, analysis_id


def _bound_detection(
    member: Mapping[str, Any],
    rank: int,
    label: str,
    policy: ResultMemberPolicy,
    error: type[RuntimeError],
) -> tuple[str, Mapping[str, Any], str]:
    stable_key = policy.stable_group_key(
        member.get("stable_group_key"), f"{label} member {rank} stable_group_key"
    )
    detection = member.get("detection")
    if not isinstance(detection, dict):
        raise error(f"{label} member {rank} detection is invalid")
    detection_key = policy.stable_group_key(
        detection.get("stable_group_key"),
        f"{label} member {rank} detection stable_group_key",
    )
    if detection_key != stable_key:
        raise error(f"{label} member {rank} stable_group_key binding changed")
    return stable_key, detection, policy.hash_value(detection)


def _second_opinion(result: Mapping[str, Any]) -> dict[str, Any] | None:
    value = result.get("second_opinion")
    if not isinstance(value, dict):
        return None
    return {
        "status": str(value.get("status") or "")[:40],
        "material_disagreement": bool(value.get("material_disagreement")),
    }


def _provider(analysis: Mapping[str, Any]) -> str | None:
    result = analysis.get("result")
    result = result if isinstance(result, dict) else {}
    return str(result.get("_analysis_provider") or "").strip()[:80] or None


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, dict) else {}


def _stable_id(
    member: Mapping[str, Any],
    known: set[str],
    label: str,
    policy: ResultMemberPolicy,
    error: type[RuntimeError],
) -> str:
    stable_id = str(member.get("stable_group_id") or "").lower()
    valid = (
        policy.stable_group_id_pattern.fullmatch(stable_id) is not None
        and stable_id not in known
    )
    if not valid:
        raise error(f"{label} contains an invalid or duplicate stable group")
    return stable_id


def _identity(
    member: Mapping[str, Any],
    rank: int,
    stable_id: str,
    stable_key: str,
) -> dict[str, Any]:
    return {
        "rank": rank,
        "dashboard_group_id": str(member.get("dashboard_group_id") or ""),
        "stable_group_id": stable_id,
        "stable_group_key": stable_key,
        "representative_alert_id": str(member.get("representative_alert_id") or ""),
    }


def _normalized_record(
    *,
    rank: int,
    stable_id: str,
    analysis_id: str | None,
    state: str,
    analysis: Mapping[str, Any],
    result: Mapping[str, Any],
    dispatch: Mapping[str, Any],
    detection_sha256: str,
    policy: ResultMemberPolicy,
) -> dict[str, Any]:
    labels = policy.observed_labels(analysis) if analysis else {
        field: None for field in policy.verdict_fields
    }
    return {
        "rank": rank,
        "stable_group_id": stable_id,
        "analysis_id": analysis_id,
        "state": state,
        "completed": state == "completed",
        "labels": labels,
        "confidence": str(analysis.get("confidence") or "").strip().lower() or None,
        "model": str(analysis.get("model") or "").strip()[:200] or None,
        "provider": _provider(analysis),
        "query_audit": policy.query_audit_summary(analysis),
        "detection_sha256": detection_sha256,
        "response_sha256": str(analysis.get("response_sha256") or "")[:64] or None,
        "second_opinion": _second_opinion(result),
        "dispatch_started_at": str(dispatch.get("started_at") or ""),
    }


def normalize_export_member(
    *,
    member: Mapping[str, Any],
    role: str,
    contract: Mapping[str, Any],
    cohort_id: str,
    frozen_plan_sha256: str,
    expected_count: int,
    ranks: set[int],
    known_stable_ids: set[str],
    label: str,
    policy: ResultMemberPolicy,
    error: type[RuntimeError],
) -> NormalizedExportMember:
    """Validate, execution-gate, and normalize one member without I/O."""
    stable_id = _stable_id(member, known_stable_ids, label, policy, error)
    rank = _rank(member, expected_count, ranks, label, error)
    result, analysis, state, analysis_id = _result_analysis(
        member, role, rank, label, error
    )
    stable_key, detection, detection_sha256 = _bound_detection(
        member, rank, label, policy, error
    )
    policy.validate_execution_proof(
        member=member,
        role=role,
        contract=contract,
        cohort_id=cohort_id,
        frozen_plan_sha256=frozen_plan_sha256,
        label=f"{label} member {rank}",
    )
    identity = _identity(member, rank, stable_id, stable_key)
    normalized = _normalized_record(
        rank=rank,
        stable_id=stable_id,
        analysis_id=analysis_id,
        state=state,
        analysis=analysis,
        result=result,
        dispatch=_mapping(member.get("dispatch")),
        detection_sha256=detection_sha256,
        policy=policy,
    )
    return NormalizedExportMember(
        rank=rank,
        stable_group_id=stable_id,
        identity=identity,
        detection_projection={**identity, "detection_sha256": detection_sha256},
        normalized=normalized,
    )
