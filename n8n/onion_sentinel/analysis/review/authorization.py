"""Authorization policy derived from a completed independent review."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


@dataclass(frozen=True)
class Dependencies:
    confidence_high_threshold: float
    control_tuning_values: frozenset[str]
    consequential_conclusion: Callable[[dict[str, Any]], bool]


def memory_eligibility(second_opinion: Any) -> tuple[bool, str]:
    """Prevent uncertain or disputed reviewer output from becoming memory."""
    if not isinstance(second_opinion, dict) or second_opinion.get("status") != "completed":
        return False, "reviewer did not complete"
    response = second_opinion.get("response")
    comparison = second_opinion.get("comparison")
    if not isinstance(response, dict) or not isinstance(comparison, dict):
        return False, "reviewer result is incomplete"
    if str(response.get("confidence") or "").lower() != "high":
        return False, "reviewer confidence is not high"
    if comparison.get("agreement") != "agreement" or comparison.get("material_disagreement"):
        return False, "primary and reviewer did not fully agree"
    return True, "high-confidence independent agreement"


def _reviewer_confidence(
    reviewer_response: dict[str, Any], threshold: float
) -> tuple[str, float, bool]:
    label = str(reviewer_response.get("confidence") or "").strip().lower()
    try:
        score = float(reviewer_response.get("confidence_score") or 0.0)
    except (TypeError, ValueError):
        score = 0.0
    return label, score, label == "high" and score >= threshold


def _control_tuning_requested(
    primary_response: dict[str, Any], control_values: frozenset[str]
) -> bool:
    guard = primary_response.get("_tuning_coherence_guard")
    guard = guard if isinstance(guard, dict) else {}
    return any(
        str(value or "").strip().lower() in control_values
        for value in (
            primary_response.get("tuning_recommendation"),
            guard.get("requested_tuning"),
        )
    )


def _reason(material_disagreement: bool, high_confidence: bool) -> tuple[str, str]:
    if material_disagreement:
        return (
            "material_disagreement",
            "Primary and reviewer materially disagree; human adjudication is required.",
        )
    if not high_confidence:
        return (
            "reviewer_confidence_below_automation_threshold",
            "The review completed validly but did not reach the grounded "
            "high-confidence threshold required for automation.",
        )
    return (
        "high_confidence_nonmaterial_agreement",
        "The high-confidence reviewer did not materially disagree with the primary disposition.",
    )


def automation_authorization(
    primary_response: dict[str, Any],
    reviewer_response: dict[str, Any],
    comparison: dict[str, Any],
    deps: Dependencies,
) -> dict[str, Any]:
    """Separate a valid review decision from authorization to automate it."""
    confidence, score, high = _reviewer_confidence(
        reviewer_response, deps.confidence_high_threshold
    )
    material = bool(comparison.get("material_disagreement"))
    authorized = high and not material
    tuning_requested = _control_tuning_requested(
        primary_response, deps.control_tuning_values
    )
    full_agreement = comparison.get("agreement") == "agreement"
    reason_code, reason = _reason(material, high)
    return {
        "schema": "onion-sentinel-reviewer-automation-authorization-v1",
        "authorized": authorized,
        "reason_code": reason_code,
        "reason": reason,
        "reviewer_confidence": confidence,
        "reviewer_confidence_score": round(score, 3),
        "required_confidence": "high",
        "required_confidence_score": deps.confidence_high_threshold,
        "agreement": str(comparison.get("agreement") or ""),
        "material_disagreement": material,
        "consequential_automation_requested": deps.consequential_conclusion(primary_response),
        "automatic_closure_authorized": authorized,
        "containment_authorized": authorized,
        "tuning_authorized": bool(authorized and not tuning_requested),
        "control_tuning_requested": tuning_requested,
        "memory_writeback_authorized": bool(authorized and full_agreement),
    }
