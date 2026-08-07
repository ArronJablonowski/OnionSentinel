"""Fail-closed automation gates for independent-review outcomes."""

from __future__ import annotations

from typing import Any


def _block_controls(response: dict[str, Any], reason: str) -> None:
    controls = response.get("_automation_controls")
    controls = dict(controls) if isinstance(controls, dict) else {}
    controls.update({
        "automatic_closure_blocked": True, "containment_blocked": True,
        "tuning_blocked": True, "memory_writeback_blocked": True,
        "requires_human_review": True, "reason": reason[:500],
    })
    response["_automation_controls"] = controls


def _block_actions(response: dict[str, Any], reason: str, prefix: str) -> None:
    if str(response.get("handling") or "").strip().lower() == "contain":
        response["handling"] = "investigate"
    response["tuning_recommendation"] = "needs_more_data"
    response["tuning_reason"] = f"{prefix}: {reason[:500]}"
    response["recommended_tuning_actions"] = []
    response["memory_candidates"] = []
    _block_controls(response, reason)


def _low_confidence(response: dict[str, Any], status: str) -> None:
    try:
        score = float(response.get("confidence_score"))
    except (TypeError, ValueError):
        score = 0.3
    response["confidence_score"] = round(min(max(score, 0.0), 0.39), 3)
    response["confidence"] = "low"
    calibration = response.get("_confidence_calibration")
    calibration = dict(calibration) if isinstance(calibration, dict) else {}
    limiters = list(calibration.get("limiters")) if isinstance(calibration.get("limiters"), list) else []
    limiter = f"required_reviewer_unavailable:{status}"
    if limiter not in limiters:
        limiters.append(limiter)
    calibration.update({
        "calibrated_confidence": "low",
        "calibrated_confidence_score": response["confidence_score"],
        "maximum_confidence_score": min(
            float(calibration.get("maximum_confidence_score", 1.0) or 1.0), 0.39
        ),
        "limiters": limiters,
    })
    response["_confidence_calibration"] = calibration


def required(response: dict[str, Any], *, status: str, reason: str) -> dict[str, Any]:
    """Block automation and cap confidence when required review is unavailable."""
    response["final_disposition_status"] = status
    _low_confidence(response, status)
    _block_actions(
        response, reason,
        "Automatic tuning is blocked because the required independent review did not validate",
    )
    return response


def completed(response: dict[str, Any], *, reason: str) -> dict[str, Any]:
    """Block controls without mislabeling a valid uncertain review as failed."""
    response["final_disposition_status"] = "review_completed_not_authorized"
    _block_actions(
        response, reason,
        "Automatic tuning is blocked because the completed independent review did not authorize automation",
    )
    return response
