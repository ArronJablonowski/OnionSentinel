#!/usr/bin/env python3
"""Validate and bind pre-dispatch independent cohort evidence seals."""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Callable, Mapping, Pattern, Sequence


TOP_LEVEL_KEYS = frozenset(
    {
        "schema", "experiment_id", "expected_count", "independent_review",
        "reviewer_count", "sealed_at", "methodology_sha256",
        "source_rows_sha256", "ordered_identity_sha256",
        "ordered_detection_sha256", "role_plans", "cases", "seal_sha256",
    }
)
CASE_KEYS = frozenset({"rank", "stable_group_id", "ground_truth"})
ROLE_PLAN_KEYS = frozenset({"cohort_id", "frozen_plan_sha256"})


@dataclass(frozen=True)
class EvidenceSealPolicy:
    error: type[RuntimeError]
    schema: str
    roles: tuple[str, ...]
    cohort_id_pattern: Pattern[str]
    stable_group_id_pattern: Pattern[str]
    sha256_pattern: Pattern[str]
    parse_timestamp: Callable[[Any, str], Any]
    hash_value: Callable[[Any], str]
    validate_embedded_digest: Callable[[Mapping[str, Any], str], None]
    normalize_ground_truth: Callable[[Any, str], Mapping[str, Any]]


def _exact_keys(
    value: Mapping[str, Any],
    allowed: frozenset[str],
    label: str,
    policy: EvidenceSealPolicy,
) -> None:
    unexpected = set(value) - allowed
    missing = allowed - set(value)
    if unexpected or missing:
        details = []
        if missing:
            details.append("missing=" + ",".join(sorted(missing)))
        if unexpected:
            details.append("unexpected=" + ",".join(sorted(unexpected)))
        raise policy.error(f"{label} fields are invalid ({'; '.join(details)})")


def _count(value: Any, label: str, policy: EvidenceSealPolicy) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise policy.error(f"{label} must be an integer")
    return value


def _digest(value: Any, label: str, policy: EvidenceSealPolicy) -> str:
    digest = str(value or "")
    if policy.sha256_pattern.fullmatch(digest) is None:
        raise policy.error(f"{label} is missing or invalid")
    return digest


def _metadata(
    document: Mapping[str, Any],
    expected_count: int,
    policy: EvidenceSealPolicy,
) -> dict[str, Any]:
    _exact_keys(document, TOP_LEVEL_KEYS, "evidence seal", policy)
    if document.get("schema") != policy.schema:
        raise policy.error("unsupported independent evidence seal schema")
    policy.validate_embedded_digest(document, "seal_sha256")
    experiment = str(document.get("experiment_id") or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{2,99}", experiment):
        raise policy.error("evidence seal experiment_id is invalid")
    if document.get("independent_review") is not True:
        raise policy.error("evidence seal must affirm independent_review=true")
    count = _count(document.get("expected_count"), "expected_count", policy)
    if count != expected_count:
        raise policy.error("evidence seal expected_count does not match")
    reviewers = _count(document.get("reviewer_count"), "reviewer_count", policy)
    if reviewers < 1 or reviewers > 20:
        raise policy.error("evidence seal reviewer_count must be between 1 and 20")
    sealed_at = str(document.get("sealed_at") or "").strip()
    policy.parse_timestamp(sealed_at, "evidence seal sealed_at")
    return {
        "experiment_id": experiment,
        "reviewer_count": reviewers,
        "sealed_at": sealed_at,
    }


def _case(
    value: Any,
    expected_rank: int,
    seen: set[str],
    policy: EvidenceSealPolicy,
) -> dict[str, Any]:
    label = f"evidence seal case {expected_rank}"
    if not isinstance(value, dict):
        raise policy.error(f"{label} must be an object")
    _exact_keys(value, CASE_KEYS, label, policy)
    rank = _count(value.get("rank"), f"{label} rank", policy)
    if rank != expected_rank:
        raise policy.error(f"{label} rank/order binding is invalid")
    stable_id = str(value.get("stable_group_id") or "").strip().lower()
    if (
        policy.stable_group_id_pattern.fullmatch(stable_id) is None
        or stable_id in seen
    ):
        raise policy.error(f"{label} stable_group_id is invalid or duplicated")
    seen.add(stable_id)
    return {
        "rank": rank,
        "stable_group_id": stable_id,
        "ground_truth": dict(
            policy.normalize_ground_truth(value.get("ground_truth"), label)
        ),
    }


def _role_plans(value: Any, policy: EvidenceSealPolicy) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != set(policy.roles):
        raise policy.error("evidence seal role_plans must bind every role")
    output: dict[str, Any] = {}
    for role in policy.roles:
        plan = value.get(role)
        if not isinstance(plan, dict):
            raise policy.error(f"evidence seal role plan is invalid for {role}")
        _exact_keys(plan, ROLE_PLAN_KEYS, f"evidence seal {role} role plan", policy)
        cohort_id = str(plan.get("cohort_id") or "").strip()
        if policy.cohort_id_pattern.fullmatch(cohort_id) is None:
            raise policy.error(f"evidence seal cohort_id is invalid for {role}")
        output[role] = {
            "cohort_id": cohort_id,
            "frozen_plan_sha256": _digest(
                plan.get("frozen_plan_sha256"),
                f"{role} frozen_plan_sha256",
                policy,
            ),
        }
    return output


def validate_evidence_seal(
    document: Mapping[str, Any],
    *,
    expected_count: int,
    policy: EvidenceSealPolicy,
) -> dict[str, Any]:
    """Normalize one canonical, embedded-digest independent evidence seal."""
    metadata = _metadata(document, expected_count, policy)
    cases = document.get("cases")
    if not isinstance(cases, list) or len(cases) != expected_count:
        raise policy.error(
            f"evidence seal must contain exactly {expected_count} cases"
        )
    seen: set[str] = set()
    normalized = [
        _case(value, rank, seen, policy)
        for rank, value in enumerate(cases, start=1)
    ]
    return {
        "schema": policy.schema,
        **metadata,
        "expected_count": expected_count,
        "independent_review": True,
        "methodology_sha256": _digest(
            document.get("methodology_sha256"), "methodology_sha256", policy
        ),
        "source_rows_sha256": _digest(
            document.get("source_rows_sha256"), "source_rows_sha256", policy
        ),
        "ordered_identity_sha256": _digest(
            document.get("ordered_identity_sha256"),
            "ordered_identity_sha256",
            policy,
        ),
        "ordered_detection_sha256": _digest(
            document.get("ordered_detection_sha256"),
            "ordered_detection_sha256",
            policy,
        ),
        "role_plans": _role_plans(document.get("role_plans"), policy),
        "cases": normalized,
        "seal_sha256": str(document["seal_sha256"]),
    }


def _cohort_binding_valid(
    seal: Mapping[str, Any],
    result: Mapping[str, Any],
) -> bool:
    checks = (
        seal["source_rows_sha256"] == result["source_rows_sha256"],
        seal["ordered_identity_sha256"] == result["ordered_identity_sha256"],
        seal["ordered_detection_sha256"] == result["ordered_detection_sha256"],
    )
    return all(checks)


def _bind_role_cases(
    seal: Mapping[str, Any],
    result: Mapping[str, Any],
    role: str,
    expected: Mapping[str, Mapping[str, Any]],
    sealed_at: Any,
    policy: EvidenceSealPolicy,
) -> int:
    role_plan = seal["role_plans"][role]
    plan_matches = (
        role_plan["cohort_id"] == result["cohort_id"],
        role_plan["frozen_plan_sha256"] == result["frozen_plan_sha256"],
    )
    if not all(plan_matches):
        raise policy.error(f"evidence seal {role} role plan does not match")
    if not _cohort_binding_valid(seal, result):
        raise policy.error(f"evidence seal does not match {role} cohort")
    count = 0
    for stable_id, member in result["members"].items():
        case = expected.get(stable_id)
        exact = case is not None and all(
            (
                case["rank"] == member["rank"],
                case["ground_truth"]["detection_sha256"]
                == member["detection_sha256"],
            )
        )
        if not exact:
            raise policy.error(f"evidence seal case binding changed for {role}")
        dispatch = policy.parse_timestamp(
            member["dispatch_started_at"], f"{role} dispatch started_at"
        )
        if sealed_at >= dispatch:
            raise policy.error(
                f"evidence seal was not created before {role} dispatch"
            )
        count += 1
    return count


def bind_evidence_seal(
    seal: Mapping[str, Any],
    loaded: Mapping[str, Mapping[str, Any]],
    roles: Sequence[str],
    policy: EvidenceSealPolicy,
) -> dict[str, Any]:
    """Bind a seal to exact paired results and prove it predates dispatch."""
    anchor = loaded[roles[0]]
    if not _cohort_binding_valid(seal, anchor):
        raise policy.error("evidence seal does not match the frozen cohort")
    sealed_at = policy.parse_timestamp(seal["sealed_at"], "evidence seal sealed_at")
    expected = {item["stable_group_id"]: item for item in seal["cases"]}
    sealed_before = sum(
        _bind_role_cases(
            seal, loaded[role], role, expected, sealed_at, policy
        )
        for role in roles
    )
    return {
        "seal_sha256": seal["seal_sha256"],
        "sealed_at": seal["sealed_at"],
        "methodology_sha256": seal["methodology_sha256"],
        "role_plans": dict(seal["role_plans"]),
        "reviewer_count": seal["reviewer_count"],
        "sealed_before_dispatch_count": sealed_before,
        "expected_dispatch_count": len(roles) * int(seal["expected_count"]),
        "binding_status": "passed",
    }


def bind_adjudication_ground_truth(
    adjudication: Mapping[str, Any],
    seal: Mapping[str, Any],
    policy: EvidenceSealPolicy,
) -> None:
    """Reject post-seal changes to methodology or any ground-truth claim."""
    metadata = (
        adjudication["experiment_id"] == seal["experiment_id"],
        adjudication["reviewer_count"] == seal["reviewer_count"],
        adjudication["methodology_sha256"] == seal["methodology_sha256"],
    )
    if not all(metadata):
        raise policy.error("adjudication metadata differs from evidence seal")
    sealed = {item["stable_group_id"]: item for item in seal["cases"]}
    for item in adjudication["cases"]:
        expected = sealed.get(item["stable_group_id"])
        if expected is None or item["ground_truth"] != expected["ground_truth"]:
            raise policy.error("adjudication ground truth differs from evidence seal")
