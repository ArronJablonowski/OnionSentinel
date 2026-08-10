"""Post-analysis memory promotion decision policy."""
from __future__ import annotations

from typing import Any, Mapping

from harness_contracts import bounded_metadata
from harness_policy import HarnessPolicy, PolicyDecision


def memory_promotion_decision(
    policy: HarnessPolicy,
    response: Mapping[str, Any],
    *,
    role: str,
    has_shared_candidates: bool,
    human_approved: bool = False,
) -> PolicyDecision:
    """Gate durable model memory against review, evidence, and poisoning risks."""
    controls = (
        response.get("_automation_controls")
        if isinstance(response.get("_automation_controls"), dict)
        else {}
    )
    if controls.get("memory_writeback_blocked"):
        return PolicyDecision(
            False,
            "memory.promote",
            str(controls.get("reason") or "automation guardrail blocked memory"),
        )
    validation = (
        response.get("_evidence_reference_validation")
        if isinstance(response.get("_evidence_reference_validation"), dict)
        else {}
    )
    source_classes = {
        str(item)
        for item in validation.get("corroborating_source_classes", [])
        if str(item)
    } if isinstance(validation.get("corroborating_source_classes"), list) else set()
    invalid_refs = (
        validation.get("invalid_refs")
        if isinstance(validation.get("invalid_refs"), list)
        else []
    )
    if invalid_refs:
        return PolicyDecision(
            False,
            "memory.promote",
            "memory candidate depends on unresolved evidence references",
        )
    if len(source_classes) < 2:
        return PolicyDecision(
            False,
            "memory.promote",
            "fewer than two corroborating evidence source classes",
        )
    try:
        confidence_score = float(response.get("confidence_score"))
    except (TypeError, ValueError, OverflowError):
        confidence_score = 0.0
    if (
        str(response.get("confidence") or "").lower() != "high"
        or confidence_score < 0.8
    ):
        return PolicyDecision(
            False,
            "memory.promote",
            "analysis confidence is below the memory promotion threshold",
        )
    if policy.memory_require_independent_agreement:
        review = (
            response.get("_second_opinion")
            if isinstance(response.get("_second_opinion"), dict)
            else {}
        )
        comparison = (
            review.get("comparison")
            if isinstance(review.get("comparison"), dict)
            else {}
        )
        if (
            review.get("status") != "completed"
            or comparison.get("agreement") != "agreement"
            or comparison.get("material_disagreement") is True
        ):
            return PolicyDecision(
                False,
                "memory.promote",
                "independent reviewer did not fully corroborate the analysis",
            )
    if (
        has_shared_candidates
        and policy.shared_memory_requires_human_approval
        and not human_approved
    ):
        return PolicyDecision(
            False,
            "memory.promote",
            "shared memory requires explicit human approval",
            requires_approval=True,
        )
    return policy.authorize(
        role,
        "memory.promote",
        approved=human_approved,
    )
