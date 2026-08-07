"""Deterministic memory-promotion policy after analysis and review."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


@dataclass(frozen=True)
class MemoryGuardPolicy:
    evaluation_frozen: bool
    controlled_identity: dict[str, Any] | None


@dataclass(frozen=True)
class MemoryGuardPorts:
    promotion_decision: Callable[[dict[str, Any], bool], Any] | None
    decision_is_effective: Callable[[Any], bool]
    record_audit: Callable[[dict[str, Any]], None]
    apply_freeze: Callable[[bool, str, bool], tuple[bool, str]]
    plan: Callable[[list[Any], bool, str], dict[str, Any]]
    reviewer_eligibility: Callable[[Any], tuple[bool, str]]
    controlled_claim_digest: Callable[[dict[str, Any]], str]


@dataclass(frozen=True)
class MemoryGuardResult:
    primary_candidates: list[Any]
    primary_allowed: bool
    primary_reason: str
    reviewer_candidates: list[Any]
    reviewer_allowed: bool
    reviewer_reason: str


def apply_memory_guards(
    response: dict[str, Any],
    *,
    policy: MemoryGuardPolicy,
    ports: MemoryGuardPorts,
) -> MemoryGuardResult:
    primary = _candidates(response.get("memory_candidates"))
    second_opinion = response.get("_second_opinion")
    reviewer = _reviewer_candidates(second_opinion)
    all_candidates = [*primary, *reviewer]
    blocked_reason = ""

    if ports.promotion_decision is not None:
        audit, blocked_reason = _harness_policy(
            response, primary, reviewer, all_candidates, ports
        )
        ports.record_audit(audit)

    primary_allowed, primary_reason = _primary_lane(
        response, primary, policy, ports
    )

    reviewer_allowed, reviewer_reason = ports.reviewer_eligibility(second_opinion)
    if blocked_reason:
        reviewer_allowed, reviewer_reason = False, blocked_reason
    reviewer_allowed, reviewer_reason = ports.apply_freeze(
        reviewer_allowed, reviewer_reason, policy.evaluation_frozen
    )
    if isinstance(second_opinion, dict):
        second_opinion["memory_writeback"] = ports.plan(
            reviewer, reviewer_allowed, reviewer_reason
        )

    response["_analysis_evaluation_memory_frozen"] = policy.evaluation_frozen
    if policy.controlled_identity is not None:
        response["_analysis_controlled_claim_sha256"] = (
            ports.controlled_claim_digest(policy.controlled_identity)
        )
    return MemoryGuardResult(
        primary, primary_allowed, primary_reason,
        reviewer, reviewer_allowed, reviewer_reason,
    )


def _primary_lane(
    response: dict[str, Any],
    candidates: list[Any],
    policy: MemoryGuardPolicy,
    ports: MemoryGuardPorts,
) -> tuple[bool, str]:
    controls = response.get("_automation_controls")
    controls = controls if isinstance(controls, dict) else {}
    allowed = not bool(controls.get("memory_writeback_blocked"))
    reason = (
        str(
            controls.get("reason")
            or "memory writeback blocked by analysis guardrail"
        )[:500]
        if not allowed
        else "eligible after authoritative analysis commit"
    )
    allowed, reason = ports.apply_freeze(
        allowed, reason, policy.evaluation_frozen
    )
    response["_memory_writeback"] = ports.plan(candidates, allowed, reason)
    return allowed, reason


def _candidates(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _reviewer_candidates(second_opinion: Any) -> list[Any]:
    if not isinstance(second_opinion, dict):
        return []
    response = second_opinion.get("response")
    if not isinstance(response, dict):
        return []
    return _candidates(response.get("memory_candidates"))


def _harness_policy(
    response: dict[str, Any],
    primary: list[Any],
    reviewer: list[Any],
    all_candidates: list[Any],
    ports: MemoryGuardPorts,
) -> tuple[dict[str, Any], str]:
    if not all_candidates:
        return {
            "allowed": False,
            "requires_approval": False,
            "reason": "no memory candidates",
            "candidate_count": 0,
            "primary_candidate_count": 0,
            "reviewer_candidate_count": 0,
        }, ""
    has_shared = any(
        isinstance(item, dict)
        and str(item.get("scope") or "").strip().lower() == "shared"
        for item in all_candidates
    )
    assert ports.promotion_decision is not None
    decision = ports.promotion_decision(response, has_shared)
    audit = {
        "allowed": decision.allowed,
        "requires_approval": decision.requires_approval,
        "reason": decision.reason,
        "candidate_count": len(all_candidates),
        "primary_candidate_count": len(primary),
        "reviewer_candidate_count": len(reviewer),
    }
    if ports.decision_is_effective(decision):
        return audit, ""
    blocked_reason = str(decision.reason)[:500]
    controls = response.get("_automation_controls")
    controls = dict(controls) if isinstance(controls, dict) else {}
    controls.update({
        "memory_writeback_blocked": True,
        "requires_human_review": (
            controls.get("requires_human_review") or decision.requires_approval
        ),
        "reason": blocked_reason,
    })
    response["_automation_controls"] = controls
    return audit, blocked_reason
