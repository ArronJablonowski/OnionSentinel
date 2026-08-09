"""Fixed manifest, private-input, and dispatch-identity cohort adapters."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable, Mapping

from cohort_dispatch_identity import (
    DispatchIdentityPolicy,
    deterministic_dispatch_id as derive_dispatch_id,
)
from cohort_manifest_contract import (
    ManifestContractPolicy,
    execution_contract as build_execution_contract,
    frozen_plan_digest as calculate_frozen_plan_digest,
    member_stable_group_key as resolve_member_stable_group_key,
    ordered_identity_projection as project_ordered_identity,
    validate_agent_role as validate_manifest_agent_role,
    validate_cohort_identity as validate_manifest_identity,
    validate_manifest_document,
    validate_model_route as validate_manifest_model_route,
    validate_release_id as validate_manifest_release_id,
    validate_stable_group_key as validate_manifest_stable_group_key,
)
from cohort_private_input import (
    CohortPrivateInputPolicy,
    load_private_manifest as read_private_manifest,
    load_private_source_rows as read_private_source_rows,
)
from cohort_runner_contracts import (
    AGENT_ROLES,
    COHORT_ID_RE,
    CONTROLLED_EVALUATION_PROFILE,
    CONTROLLED_ROUTE_RE,
    DASHBOARD_GROUP_ID_RE,
    DISPATCH_ID_SCHEMA,
    MAX_COHORT_SIZE,
    MAX_MANIFEST_BYTES,
    MAX_SOURCE_ROWS_BYTES,
    MAX_STABLE_GROUP_KEY_BYTES,
    PROFILE_ASSIGNED_ROUTE,
    PROFILE_REVIEWER_ROUTE,
    RELEASE_ID_RE,
    REPRESENTATIVE_ALERT_ID_RE,
    SAFE_ROUTE_RE,
    SCHEMA,
    SHA256_RE,
    STABLE_GROUP_ID_RE,
    CohortError,
    constant_time_equal,
    sha256_value,
)


def manifest_contract_policy() -> ManifestContractPolicy:
    return ManifestContractPolicy(
        error=CohortError,
        schema=SCHEMA,
        cohort_id_pattern=COHORT_ID_RE,
        safe_route_pattern=SAFE_ROUTE_RE,
        controlled_route_pattern=CONTROLLED_ROUTE_RE,
        release_id_pattern=RELEASE_ID_RE,
        sha256_pattern=SHA256_RE,
        agent_roles=frozenset(AGENT_ROLES),
        maximum_stable_group_key_bytes=MAX_STABLE_GROUP_KEY_BYTES,
        controlled_evaluation_profile=CONTROLLED_EVALUATION_PROFILE,
        profile_assigned_route=PROFILE_ASSIGNED_ROUTE,
        profile_reviewer_route=PROFILE_REVIEWER_ROUTE,
        sha256_value=sha256_value,
        constant_time_equal=constant_time_equal,
    )


def private_input_policy() -> CohortPrivateInputPolicy:
    policy = manifest_contract_policy()
    return CohortPrivateInputPolicy(
        error=CohortError,
        maximum_manifest_bytes=MAX_MANIFEST_BYTES,
        maximum_source_rows_bytes=MAX_SOURCE_ROWS_BYTES,
        maximum_cohort_size=MAX_COHORT_SIZE,
        validate_manifest_document=lambda document: validate_manifest_document(
            document,
            policy,
        ),
    )


def load_private_manifest(path: Path) -> dict[str, Any]:
    return read_private_manifest(path, private_input_policy())


def load_private_source_rows(path: Path) -> tuple[list[dict[str, Any]], str]:
    return read_private_source_rows(path, private_input_policy())


def validate_cohort_identity(cohort_id: str, reason: str) -> tuple[str, str]:
    return validate_manifest_identity(cohort_id, reason, manifest_contract_policy())


def validate_agent_role(value: str) -> str:
    return validate_manifest_agent_role(value, manifest_contract_policy())


def validate_model_route(
    value: str,
    label: str,
    *,
    allow_empty: bool = False,
) -> str:
    return validate_manifest_model_route(
        value,
        label,
        manifest_contract_policy(),
        allow_empty=allow_empty,
    )


def validate_release_id(
    value: Any,
    label: str = "expected release ID",
) -> str:
    return validate_manifest_release_id(value, manifest_contract_policy(), label)


def validate_stable_group_key(value: Any, label: str) -> str:
    return validate_manifest_stable_group_key(
        value,
        label,
        manifest_contract_policy(),
    )


def member_stable_group_key(member: Mapping[str, Any]) -> str:
    return resolve_member_stable_group_key(member, manifest_contract_policy())


def execution_contract(
    *,
    expected_release_id: str,
    expected_assigned_route: str,
    expected_reviewer_route: str = "codex-cli:gpt-5.6-sol:xhigh",
    evaluation_profile: str = "",
) -> dict[str, Any]:
    return build_execution_contract(
        expected_release_id=expected_release_id,
        expected_assigned_route=expected_assigned_route,
        expected_reviewer_route=expected_reviewer_route,
        evaluation_profile=evaluation_profile,
        policy=manifest_contract_policy(),
    )


def ordered_identity_projection(
    members: Iterable[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    return project_ordered_identity(members, manifest_contract_policy())


def frozen_plan_digest(manifest: Mapping[str, Any]) -> str:
    return calculate_frozen_plan_digest(manifest, manifest_contract_policy())


def dispatch_identity_policy() -> DispatchIdentityPolicy:
    return DispatchIdentityPolicy(
        error=CohortError,
        cohort_id_pattern=COHORT_ID_RE,
        sha256_pattern=SHA256_RE,
        dashboard_group_id_pattern=DASHBOARD_GROUP_ID_RE,
        stable_group_id_pattern=STABLE_GROUP_ID_RE,
        representative_alert_id_pattern=REPRESENTATIVE_ALERT_ID_RE,
        dispatch_id_schema=DISPATCH_ID_SCHEMA,
        member_stable_group_key=member_stable_group_key,
        sha256_value=sha256_value,
        constant_time_equal=constant_time_equal,
    )


def deterministic_dispatch_id(
    manifest: Mapping[str, Any],
    member: Mapping[str, Any],
) -> str:
    return derive_dispatch_id(manifest, member, dispatch_identity_policy())
