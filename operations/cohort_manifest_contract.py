#!/usr/bin/env python3
"""Pure identity, execution, and frozen-plan contracts for cohort manifests."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping, Pattern


@dataclass(frozen=True)
class ManifestContractPolicy:
    error: type[RuntimeError]
    schema: str
    cohort_id_pattern: Pattern[str]
    safe_route_pattern: Pattern[str]
    controlled_route_pattern: Pattern[str]
    release_id_pattern: Pattern[str]
    sha256_pattern: Pattern[str]
    agent_roles: frozenset[str]
    maximum_stable_group_key_bytes: int
    controlled_evaluation_profile: str
    profile_assigned_route: str
    profile_reviewer_route: str
    sha256_value: Callable[[Any], str]
    constant_time_equal: Callable[[str, str], bool]


def validate_cohort_identity(
    cohort_id: str,
    reason: str,
    policy: ManifestContractPolicy,
) -> tuple[str, str]:
    normalized_id = str(cohort_id or "").strip()
    normalized_reason = " ".join(str(reason or "").split())
    if not policy.cohort_id_pattern.fullmatch(normalized_id):
        raise policy.error(
            "cohort ID must be 3-64 characters using letters, digits, '.', '_', or '-'"
        )
    if len(normalized_reason) < 10 or len(normalized_reason) > 1000:
        raise policy.error("cohort reason must contain 10-1000 characters")
    return normalized_id, normalized_reason


def validate_agent_role(value: str, policy: ManifestContractPolicy) -> str:
    role = str(value or "incident-responder").strip().lower()
    if role not in policy.agent_roles:
        raise policy.error("agent role must be incident-responder or soc-analyst")
    return role


def validate_model_route(
    value: str,
    label: str,
    policy: ManifestContractPolicy,
    *,
    allow_empty: bool = False,
) -> str:
    route = str(value or "").strip()
    if not route and allow_empty:
        return ""
    if not policy.safe_route_pattern.fullmatch(route):
        raise policy.error(f"{label} is missing or malformed")
    return route


def validate_release_id(
    value: Any,
    policy: ManifestContractPolicy,
    label: str = "expected release ID",
) -> str:
    release_id = str(value or "").strip()
    if not policy.release_id_pattern.fullmatch(release_id):
        raise policy.error(
            f"{label} must be exactly 40 lowercase hexadecimal characters"
        )
    return release_id


def validate_stable_group_key(
    value: Any,
    label: str,
    policy: ManifestContractPolicy,
) -> str:
    """Validate an opaque stable-group key without changing its identity."""
    if not isinstance(value, str) or not value:
        raise policy.error(f"{label} is missing or malformed")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise policy.error(f"{label} is not valid UTF-8") from exc
    if len(encoded) > policy.maximum_stable_group_key_bytes or "\x00" in value:
        raise policy.error(
            f"{label} exceeds the bounded stable-group-key contract"
        )
    return value


def member_stable_group_key(
    member: Mapping[str, Any],
    policy: ManifestContractPolicy,
) -> str:
    stable_group_key = validate_stable_group_key(
        member.get("stable_group_key"),
        "frozen member stable_group_key",
        policy,
    )
    detection = member.get("detection")
    if not isinstance(detection, dict):
        raise policy.error("frozen member detection is missing or malformed")
    detection_group_key = validate_stable_group_key(
        detection.get("stable_group_key"),
        "frozen detection stable_group_key",
        policy,
    )
    if detection_group_key != stable_group_key:
        raise policy.error(
            "frozen member stable_group_key does not match detection evidence"
        )
    return stable_group_key


def execution_contract(
    *,
    expected_release_id: str,
    expected_assigned_route: str,
    expected_reviewer_route: str,
    evaluation_profile: str,
    policy: ManifestContractPolicy,
) -> dict[str, Any]:
    """Return the immutable controls required for a gradeable harness run."""
    assigned_route = validate_model_route(
        expected_assigned_route, "expected assigned route", policy
    )
    reviewer_route = validate_model_route(
        expected_reviewer_route, "expected reviewer route", policy
    )
    if not _controlled_routes_are_distinct(assigned_route, reviewer_route, policy):
        raise policy.error(
            "controlled evaluation requires distinct non-empty canonical Codex "
            "primary and reviewer routes"
        )
    profile = str(evaluation_profile or "").strip()
    if profile and not _profile_matches_routes(
        profile, assigned_route, reviewer_route, policy
    ):
        raise policy.error(
            "controlled evaluation profile does not match its exact routes"
        )
    return {
        "harness_required": True,
        "harness_mode": "shadow",
        "memory_frozen": True,
        "expected_release_id": validate_release_id(expected_release_id, policy),
        "expected_assigned_route": assigned_route,
        "expected_reviewer_route": reviewer_route,
        "reviewer_required": True,
        "evaluation_profile": profile,
    }


def _controlled_routes_are_distinct(
    assigned_route: str,
    reviewer_route: str,
    policy: ManifestContractPolicy,
) -> bool:
    return bool(
        policy.controlled_route_pattern.fullmatch(assigned_route)
        and policy.controlled_route_pattern.fullmatch(reviewer_route)
        and assigned_route.rsplit(":", 1)[0] != reviewer_route.rsplit(":", 1)[0]
    )


def _profile_matches_routes(
    profile: str,
    assigned_route: str,
    reviewer_route: str,
    policy: ManifestContractPolicy,
) -> bool:
    return bool(
        profile == policy.controlled_evaluation_profile
        and assigned_route == policy.profile_assigned_route
        and reviewer_route == policy.profile_reviewer_route
    )


def ordered_identity_projection(
    members: Iterable[Mapping[str, Any]],
    policy: ManifestContractPolicy,
) -> list[dict[str, Any]]:
    return [
        {
            "rank": int(member["rank"]),
            "dashboard_group_id": str(member["dashboard_group_id"]),
            "stable_group_id": str(member["stable_group_id"]),
            "stable_group_key": member_stable_group_key(member, policy),
            "representative_alert_id": str(member["representative_alert_id"]),
        }
        for member in members
    ]


def _member_detection_digest(
    member: Mapping[str, Any],
    policy: ManifestContractPolicy,
) -> str:
    detection = member.get("detection")
    if not isinstance(detection, dict):
        raise policy.error("frozen plan member detection is missing or malformed")
    return policy.sha256_value(detection)


def frozen_plan_digest(
    manifest: Mapping[str, Any],
    policy: ManifestContractPolicy,
) -> str:
    selection = manifest.get("selection")
    members = manifest.get("members") if isinstance(manifest.get("members"), list) else []
    identities = ordered_identity_projection(members, policy)
    if len(identities) != len(members):
        raise policy.error("frozen plan member projection is incomplete")
    return policy.sha256_value(
        {
            "schema": manifest.get("schema"),
            "cohort_id": manifest.get("cohort_id"),
            "agent_role": manifest.get("agent_role"),
            "count": manifest.get("count"),
            "created_at": manifest.get("created_at"),
            "selection": selection if isinstance(selection, dict) else {},
            "execution_contract": manifest.get("execution_contract"),
            "members": _frozen_member_projections(identities, members, policy),
        }
    )


def _frozen_member_projections(
    identities: list[dict[str, Any]],
    members: list[Mapping[str, Any]],
    policy: ManifestContractPolicy,
) -> list[dict[str, Any]]:
    return [
        {
            **identity,
            "pre_state_sha256": policy.sha256_value(
                member.get("pre_state")
                if isinstance(member.get("pre_state"), dict)
                else {}
            ),
            "detection_sha256": _member_detection_digest(member, policy),
            "dispatch_kind": str((member.get("dispatch") or {}).get("kind") or ""),
        }
        for identity, member in zip(identities, members)
    ]


def validate_manifest_document(
    document: Mapping[str, Any],
    policy: ManifestContractPolicy,
) -> None:
    if document.get("schema") != policy.schema:
        raise policy.error("unsupported cohort manifest schema")
    _validate_document_digest(document, "manifest_sha256", policy)
    validate_cohort_identity(
        str(document.get("cohort_id") or ""),
        str(document.get("reason") or ""),
        policy,
    )
    validate_agent_role(str(document.get("agent_role") or "incident-responder"), policy)
    members = document.get("members")
    if not isinstance(members, list) or not members:
        raise policy.error("cohort manifest has no members")
    _validate_execution_contract(document, policy)
    expected = str(document.get("frozen_plan_sha256") or "")
    if not policy.sha256_pattern.fullmatch(expected) or not policy.constant_time_equal(
        expected, frozen_plan_digest(document, policy)
    ):
        raise policy.error("frozen plan digest does not match the manifest")


def _validate_document_digest(
    document: Mapping[str, Any],
    field: str,
    policy: ManifestContractPolicy,
) -> None:
    expected = str(document.get(field) or "")
    unsigned = dict(document)
    unsigned.pop(field, None)
    if not policy.sha256_pattern.fullmatch(expected):
        raise policy.error(f"{field} is missing or malformed")
    if not policy.constant_time_equal(expected, policy.sha256_value(unsigned)):
        raise policy.error(f"{field} does not match the document")


def _validate_execution_contract(
    document: Mapping[str, Any],
    policy: ManifestContractPolicy,
) -> None:
    contract = document.get("execution_contract")
    if not isinstance(contract, dict):
        raise policy.error("cohort execution contract is missing or malformed")
    expected = execution_contract(
        expected_release_id=str(contract.get("expected_release_id") or ""),
        expected_assigned_route=str(contract.get("expected_assigned_route") or ""),
        expected_reviewer_route=str(contract.get("expected_reviewer_route") or ""),
        evaluation_profile=str(contract.get("evaluation_profile") or ""),
        policy=policy,
    )
    if contract != expected:
        raise policy.error("cohort execution contract is missing or malformed")
