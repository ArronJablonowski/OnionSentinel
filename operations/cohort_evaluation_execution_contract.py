#!/usr/bin/env python3
"""Validate the exact shadow/frozen cohort execution contract."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Pattern


@dataclass(frozen=True)
class ExecutionContractPolicy:
    controlled_route_pattern: Pattern[str]
    release_id_pattern: Pattern[str]
    controlled_profile: str
    profile_assigned_route: str
    profile_reviewer_route: str
    error: type[RuntimeError]


def validate_execution_contract(
    value: Any,
    label: str,
    policy: ExecutionContractPolicy,
) -> dict[str, Any]:
    """Require one exact, distinct-route, optionally profiled contract."""
    if not isinstance(value, dict):
        raise policy.error(f"{label} has no execution contract")
    expected = _project_contract(value)
    if value != expected or not policy.controlled_route_pattern.fullmatch(
        expected["expected_assigned_route"]
    ):
        raise policy.error(
            f"{label} execution contract is not the required shadow/frozen contract"
        )
    _validate_release(expected, label, policy)
    _validate_reviewer(expected, label, policy)
    _validate_profile(expected, label, policy)
    return expected


def _project_contract(value: dict[str, Any]) -> dict[str, Any]:
    return {
        "harness_required": True,
        "harness_mode": "shadow",
        "memory_frozen": True,
        "expected_release_id": str(value.get("expected_release_id") or "").strip(),
        "expected_assigned_route": str(
            value.get("expected_assigned_route") or ""
        ).strip(),
        "expected_reviewer_route": str(
            value.get("expected_reviewer_route") or ""
        ).strip(),
        "reviewer_required": value.get("reviewer_required"),
        "evaluation_profile": str(value.get("evaluation_profile") or "").strip(),
    }


def _validate_release(
    contract: dict[str, Any], label: str, policy: ExecutionContractPolicy
) -> None:
    if policy.release_id_pattern.fullmatch(contract["expected_release_id"]) is None:
        raise policy.error(f"{label} expected release ID is malformed")


def _validate_reviewer(
    contract: dict[str, Any], label: str, policy: ExecutionContractPolicy
) -> None:
    reviewer_route = contract["expected_reviewer_route"]
    reviewer_model = reviewer_route.rsplit(":", 1)[0]
    assigned_model = contract["expected_assigned_route"].rsplit(":", 1)[0]
    if (
        contract["reviewer_required"] is not True
        or policy.controlled_route_pattern.fullmatch(reviewer_route) is None
        or reviewer_model == assigned_model
    ):
        raise policy.error(f"{label} expected reviewer route contract is malformed")


def _validate_profile(
    contract: dict[str, Any], label: str, policy: ExecutionContractPolicy
) -> None:
    profile = contract["evaluation_profile"]
    if profile and (
        profile != policy.controlled_profile
        or contract["expected_assigned_route"] != policy.profile_assigned_route
        or contract["expected_reviewer_route"] != policy.profile_reviewer_route
    ):
        raise policy.error(f"{label} controlled evaluation profile does not match")
