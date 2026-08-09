#!/usr/bin/env python3
"""Derive and verify replay-stable cohort dispatch identities."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping, Pattern


@dataclass(frozen=True)
class DispatchIdentityPolicy:
    error: type[RuntimeError]
    cohort_id_pattern: Pattern[str]
    sha256_pattern: Pattern[str]
    dashboard_group_id_pattern: Pattern[str]
    stable_group_id_pattern: Pattern[str]
    representative_alert_id_pattern: Pattern[str]
    dispatch_id_schema: str
    member_stable_group_key: Callable[[Mapping[str, Any]], str]
    sha256_value: Callable[[Any], str]
    constant_time_equal: Callable[[str, str], bool]


def _validated_member_identity(
    member: Mapping[str, Any],
    policy: DispatchIdentityPolicy,
) -> tuple[str, str, str, str, str, int]:
    dashboard_id = str(member.get("dashboard_group_id") or "")
    stable_id = str(member.get("stable_group_id") or "")
    representative_alert_id = str(member.get("representative_alert_id") or "")
    stable_group_key = policy.member_stable_group_key(member)
    dispatch_kind = str((member.get("dispatch") or {}).get("kind") or "")
    if not policy.dashboard_group_id_pattern.fullmatch(dashboard_id):
        raise policy.error("cohort dispatch has an invalid dashboard group ID")
    if not policy.stable_group_id_pattern.fullmatch(stable_id):
        raise policy.error("cohort dispatch has an invalid stable group ID")
    if not policy.representative_alert_id_pattern.fullmatch(representative_alert_id):
        raise policy.error(
            "cohort dispatch has an invalid frozen representative alert ID"
        )
    if dispatch_kind not in {"analyze", "escalate", "reanalyze"}:
        raise policy.error(
            f"cohort dispatch has unsupported kind: {dispatch_kind!r}"
        )
    rank = _validated_rank(member, policy)
    return (
        dashboard_id,
        stable_id,
        representative_alert_id,
        stable_group_key,
        dispatch_kind,
        rank,
    )


def _validated_rank(
    member: Mapping[str, Any],
    policy: DispatchIdentityPolicy,
) -> int:
    try:
        rank = int(member["rank"])
    except (KeyError, TypeError, ValueError) as exc:
        raise policy.error("cohort dispatch has an invalid member rank") from exc
    if rank < 1:
        raise policy.error("cohort dispatch has an invalid member rank")
    return rank


def deterministic_dispatch_id(
    manifest: Mapping[str, Any],
    member: Mapping[str, Any],
    policy: DispatchIdentityPolicy,
) -> str:
    """Derive one replay-stable dispatch identity from the frozen plan."""
    cohort_id = str(manifest.get("cohort_id") or "")
    if not policy.cohort_id_pattern.fullmatch(cohort_id):
        raise policy.error("cohort dispatch has an invalid cohort ID")
    frozen_plan_sha256 = str(manifest.get("frozen_plan_sha256") or "")
    if not policy.sha256_pattern.fullmatch(frozen_plan_sha256):
        raise policy.error("cohort dispatch has an invalid frozen plan digest")
    (
        dashboard_id,
        stable_id,
        representative_alert_id,
        stable_group_key,
        dispatch_kind,
        rank,
    ) = _validated_member_identity(member, policy)
    dispatch_id = policy.sha256_value(
        {
            "schema": policy.dispatch_id_schema,
            "cohort_id": cohort_id,
            "frozen_plan_sha256": frozen_plan_sha256,
            "rank": rank,
            "dashboard_group_id": dashboard_id,
            "stable_group_id": stable_id,
            "stable_group_key": stable_group_key,
            "representative_alert_id": representative_alert_id,
            "dispatch_kind": dispatch_kind,
        }
    )
    existing = str((member.get("dispatch") or {}).get("dispatch_id") or "")
    if existing and (
        not policy.sha256_pattern.fullmatch(existing)
        or not policy.constant_time_equal(existing, dispatch_id)
    ):
        raise policy.error(f"dispatch ID does not match frozen member rank {rank}")
    return dispatch_id
