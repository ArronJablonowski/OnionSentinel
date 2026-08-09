#!/usr/bin/env python3
"""Validate and normalize a sealed offline cohort result export."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping, Pattern

from cohort_evaluation_result_member import (
    ResultMemberPolicy,
    normalize_export_member,
)


@dataclass(frozen=True)
class ResultExportPolicy:
    result_schema: str
    manifest_schema: str
    digest_pattern: Pattern[str]
    hash_value: Callable[[Any], str]
    validate_embedded_digest: Callable[[Mapping[str, Any], str], None]
    safe_content_policy: Callable[[Mapping[str, Any], str], None]
    execution_contract: Callable[[Any, str], Mapping[str, Any]]
    member_policy: ResultMemberPolicy


@dataclass(frozen=True)
class _ExportHeader:
    top_role: str
    cohort_id: str
    frozen_plan_sha256: str
    contract: Mapping[str, Any]
    selection: Mapping[str, Any]
    execution_gate: Mapping[str, Any]
    members: list[Mapping[str, Any]]
    source_sha256: str
    ordered_identity_sha256: str


@dataclass(frozen=True)
class _NormalizedMembers:
    normalized: dict[str, dict[str, Any]]
    ordered_identities: list[dict[str, Any]]
    ordered_detection_projection: list[dict[str, Any]]
    ranks: set[int]


def _selection_valid(
    selection: Mapping[str, Any],
    expected_count: int,
    source_sha256: str,
    ordered_identity_sha256: str,
    policy: ResultExportPolicy,
) -> bool:
    checks = (
        selection.get("mode") == "imported_rows",
        selection.get("order_preserved") is True,
        int(selection.get("source_count") or 0) == expected_count,
        policy.digest_pattern.fullmatch(source_sha256) is not None,
        policy.digest_pattern.fullmatch(ordered_identity_sha256) is not None,
    )
    return all(checks)


def _execution_gate_valid(
    gate: Any,
    expected_count: int,
    contract: Mapping[str, Any],
    policy: ResultExportPolicy,
) -> bool:
    if not isinstance(gate, dict):
        return False
    checks = (
        gate.get("status") == "passed",
        int(gate.get("expected_count") or 0) == expected_count,
        int(gate.get("passed_count") or 0) == expected_count,
        str(gate.get("contract_sha256") or "") == policy.hash_value(contract),
    )
    return all(checks)


def _document_identity(
    document: Mapping[str, Any],
    role: str,
    expected_count: int,
    label: str,
    policy: ResultExportPolicy,
    error: type[RuntimeError],
) -> tuple[str, Mapping[str, Any]]:
    if document.get("schema") != policy.result_schema:
        raise error(f"{label} has an unsupported schema")
    policy.validate_embedded_digest(document, "export_sha256")
    policy.safe_content_policy(document, label)
    if int(document.get("count") or 0) != expected_count:
        raise error(f"{label} count does not match expected count")
    top_role = str(document.get("agent_role") or "").strip().lower()
    if top_role != role:
        raise error(f"{label} declares agent role {top_role!r}, expected {role!r}")
    return top_role, policy.execution_contract(
        document.get("execution_contract"), label
    )


def _admit_selection(
    document: Mapping[str, Any],
    expected_count: int,
    label: str,
    policy: ResultExportPolicy,
    error: type[RuntimeError],
) -> tuple[Mapping[str, Any], str, str]:
    selection = document.get("selection")
    if not isinstance(selection, dict):
        raise error(f"{label} has no frozen selection proof")
    source_sha256 = str(selection.get("source_sha256") or "")
    ordered_sha256 = str(selection.get("ordered_identity_sha256") or "")
    if not _selection_valid(
        selection, expected_count, source_sha256, ordered_sha256, policy
    ):
        raise error(f"{label} is not bound to an exact imported source cohort")
    return selection, source_sha256, ordered_sha256


def _admit_header(
    *,
    document: Mapping[str, Any],
    role: str,
    expected_count: int,
    label: str,
    policy: ResultExportPolicy,
    error: type[RuntimeError],
) -> _ExportHeader:
    top_role, contract = _document_identity(
        document, role, expected_count, label, policy, error
    )
    selection, source_sha256, ordered_sha256 = _admit_selection(
        document, expected_count, label, policy, error
    )
    gate = document.get("execution_gate")
    if not _execution_gate_valid(gate, expected_count, contract, policy):
        raise error(f"{label} has not passed its machine execution gate")
    members = document.get("members")
    if not isinstance(members, list) or len(members) != expected_count:
        raise error(f"{label} must contain exactly {expected_count} members")
    return _ExportHeader(
        top_role=top_role,
        cohort_id=str(document.get("cohort_id") or ""),
        frozen_plan_sha256=str(document.get("frozen_plan_sha256") or ""),
        contract=contract,
        selection=selection,
        execution_gate=gate,
        members=members,
        source_sha256=source_sha256,
        ordered_identity_sha256=ordered_sha256,
    )


def _normalize_members(
    *,
    header: _ExportHeader,
    role: str,
    expected_count: int,
    label: str,
    policy: ResultExportPolicy,
    error: type[RuntimeError],
) -> _NormalizedMembers:
    normalized: dict[str, dict[str, Any]] = {}
    identities: list[dict[str, Any]] = []
    detections: list[dict[str, Any]] = []
    ranks: set[int] = set()
    for index, member in enumerate(header.members):
        if not isinstance(member, dict):
            raise error(f"{label} member {index} is invalid")
        projected = normalize_export_member(
            member=member,
            role=role,
            contract=header.contract,
            cohort_id=header.cohort_id,
            frozen_plan_sha256=header.frozen_plan_sha256,
            expected_count=expected_count,
            ranks=ranks,
            known_stable_ids=set(normalized),
            label=label,
            policy=policy.member_policy,
            error=error,
        )
        ranks.add(projected.rank)
        identities.append(projected.identity)
        detections.append(projected.detection_projection)
        normalized[projected.stable_group_id] = projected.normalized
    identities.sort(key=lambda item: int(item["rank"]))
    detections.sort(key=lambda item: int(item["rank"]))
    return _NormalizedMembers(normalized, identities, detections, ranks)


def _validate_ordered_identity(
    members: _NormalizedMembers,
    header: _ExportHeader,
    expected_count: int,
    label: str,
    policy: ResultExportPolicy,
    error: type[RuntimeError],
) -> None:
    checks = (
        policy.hash_value(members.ordered_identities)
        == header.ordered_identity_sha256,
        str(header.execution_gate.get("ordered_identity_sha256") or "")
        == header.ordered_identity_sha256,
        members.ranks == set(range(1, expected_count + 1)),
    )
    if not all(checks):
        raise error(f"{label} ordered cohort identity proof does not match")


def _frozen_member(
    identity: Mapping[str, Any],
    member: Mapping[str, Any],
    policy: ResultExportPolicy,
) -> dict[str, Any]:
    pre_state = member.get("pre_state")
    detection = member.get("detection")
    dispatch = member.get("dispatch")
    dispatch = dispatch if isinstance(dispatch, dict) else {}
    return {
        **identity,
        "pre_state_sha256": policy.hash_value(
            pre_state if isinstance(pre_state, dict) else {}
        ),
        "detection_sha256": policy.hash_value(
            detection if isinstance(detection, dict) else {}
        ),
        "dispatch_kind": str(dispatch.get("kind") or ""),
    }


def _validate_frozen_plan(
    *,
    document: Mapping[str, Any],
    header: _ExportHeader,
    members: _NormalizedMembers,
    expected_count: int,
    label: str,
    policy: ResultExportPolicy,
    error: type[RuntimeError],
) -> None:
    sorted_members = sorted(header.members, key=lambda item: int(item.get("rank") or 0))
    if len(sorted_members) != len(members.ordered_identities):
        raise error(f"{label} frozen member projection is incomplete")
    frozen_plan = {
        "schema": policy.manifest_schema,
        "cohort_id": document.get("cohort_id"),
        "agent_role": header.top_role,
        "count": expected_count,
        "created_at": document.get("frozen_at"),
        "selection": header.selection,
        "execution_contract": header.contract,
        "members": [
            _frozen_member(identity, member, policy)
            for identity, member in zip(members.ordered_identities, sorted_members)
        ],
    }
    valid = (
        policy.digest_pattern.fullmatch(header.frozen_plan_sha256) is not None
        and header.frozen_plan_sha256 == policy.hash_value(frozen_plan)
    )
    if not valid:
        raise error(f"{label} frozen plan digest does not match")


def _public_projection(
    document: Mapping[str, Any],
    role: str,
    header: _ExportHeader,
    members: _NormalizedMembers,
    policy: ResultExportPolicy,
) -> dict[str, Any]:
    return {
        "role": role,
        "cohort_id": header.cohort_id,
        "export_sha256": str(document.get("export_sha256") or ""),
        "source_rows_sha256": header.source_sha256,
        "ordered_identity_sha256": header.ordered_identity_sha256,
        "ordered_identities": members.ordered_identities,
        "ordered_detection_projection": members.ordered_detection_projection,
        "ordered_detection_sha256": policy.hash_value(
            members.ordered_detection_projection
        ),
        "frozen_plan_sha256": header.frozen_plan_sha256,
        "execution_contract": header.contract,
        "members": members.normalized,
    }


def normalize_result_export(
    *,
    document: Mapping[str, Any],
    role: str,
    expected_count: int,
    label: str,
    policy: ResultExportPolicy,
    error: type[RuntimeError],
) -> dict[str, Any]:
    """Validate a sealed export and return its bounded grading projection."""
    header = _admit_header(
        document=document,
        role=role,
        expected_count=expected_count,
        label=label,
        policy=policy,
        error=error,
    )
    members = _normalize_members(
        header=header,
        role=role,
        expected_count=expected_count,
        label=label,
        policy=policy,
        error=error,
    )
    _validate_ordered_identity(
        members, header, expected_count, label, policy, error
    )
    _validate_frozen_plan(
        document=document,
        header=header,
        members=members,
        expected_count=expected_count,
        label=label,
        policy=policy,
        error=error,
    )
    return _public_projection(document, role, header, members, policy)
