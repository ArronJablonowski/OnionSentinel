"""Conservative publication policy for material reviewer disagreement."""

from __future__ import annotations

from typing import Any


VERDICT_FIELDS = frozenset({
    "detection_outcome", "event_status", "detection_validity",
    "activity_disposition", "handling", "duplicate_of", "escalation_needed",
})


def _disputed_fields(comparison: dict[str, Any]) -> tuple[list[Any], set[str]]:
    fields = comparison.get("disputed_fields")
    fields = fields if isinstance(fields, list) else []
    material = {
        str(item.get("field") or "")
        for item in fields
        if isinstance(item, dict) and item.get("material") is True
    }
    return fields, material


def _prefix(response: dict[str, Any], notice: str, marker: str) -> None:
    for field in ("bluf", "summary"):
        value = str(response.get(field) or "").strip()
        if not value.startswith(marker):
            response[field] = f"{notice} {value}".strip()


def _append_list(container: dict[str, Any], field: str, value: str) -> None:
    items = list(container.get(field)) if isinstance(container.get(field), list) else []
    if value not in items:
        items.append(value)
    container[field] = items


def _report_notice(response: dict[str, Any], notice: str, *, disputed: bool) -> None:
    report = response.get("incident_response_report")
    if not isinstance(report, dict):
        return
    if disputed:
        for field in ("executive_bluf", "conclusion"):
            value = str(report.get(field) or "").strip()
            if not value.startswith("DISPUTED"):
                report[field] = f"{notice} {value}".strip()
    _append_list(report, "constraints", notice)


def _calibration(response: dict[str, Any]) -> dict[str, Any]:
    current = response.get("_confidence_calibration")
    return dict(current) if isinstance(current, dict) else {}


def _add_limiter(calibration: dict[str, Any], limiter: str) -> None:
    limiters = list(calibration.get("limiters")) if isinstance(calibration.get("limiters"), list) else []
    if limiter not in limiters:
        limiters.append(limiter)
    calibration["limiters"] = limiters


def _control_only(
    response: dict[str, Any], comparison: dict[str, Any], fields: list[Any]
) -> dict[str, Any]:
    notice = (
        "DISPUTED TUNING — the primary and independent reviewer agree on the "
        "case disposition but materially disagree on a detection control; "
        "human adjudication is required before tuning."
    )
    _prefix(response, notice, "DISPUTED TUNING")
    _append_list(response, "evidence_gaps", notice)
    _report_notice(response, notice, disputed=False)
    calibration = _calibration(response)
    _add_limiter(calibration, "material_second_opinion_tuning_disagreement")
    response["_confidence_calibration"] = calibration
    response["_material_disagreement_gate"] = {
        "version": 2, "applied": True, "scope": "control_only",
        "agreement": comparison.get("agreement"), "disputed_fields": fields,
        "guarded_handling": response.get("handling"), "verdict_preserved": True,
    }
    return response


def _guarded_handling(primary: dict[str, Any], reviewer: dict[str, Any]) -> str:
    values = {
        str(primary.get("handling") or "").strip().lower(),
        str(reviewer.get("handling") or "").strip().lower(),
    }
    return "investigate" if values.intersection({"contain", "escalate", "investigate"}) else "monitor"


def _guarded_steps(handling: str) -> list[str]:
    if handling == "investigate":
        first = "Preserve the current evidence and continue a bounded human investigation."
        second = "Resolve the material primary/reviewer disagreements with the specific additional evidence listed in the adjudication record."
    else:
        first = "Continue monitoring while a human reviewer resolves the material primary/reviewer disagreements."
        second = "Collect only the bounded additional evidence listed in the adjudication record if the activity recurs."
    return [
        first, second,
        "Do not close, contain, tune, or write durable memory until a human reviewer records the adjudicated disposition.",
    ]


def _case_disposition(
    response: dict[str, Any], reviewer: dict[str, Any],
    comparison: dict[str, Any], fields: list[Any],
) -> dict[str, Any]:
    handling = _guarded_handling(response, reviewer)
    response.update({
        "detection_outcome": "inconclusive", "activity_disposition": "unknown",
        "handling": handling, "duplicate_of": None, "escalation_needed": True,
        "confidence": "low",
    })
    try:
        score = float(response.get("confidence_score") or 0.39)
    except (TypeError, ValueError, OverflowError):
        score = 0.39
    response["confidence_score"] = round(min(max(score, 0.0), 0.39), 3)
    notice = (
        "DISPUTED — the primary and independent reviewer materially disagree; "
        "human adjudication is required before closure, containment, or tuning."
    )
    _prefix(response, notice, "DISPUTED")
    _append_list(response, "evidence_gaps", notice)
    response["recommended_next_steps"] = _guarded_steps(handling)
    _report_notice(response, notice, disputed=True)
    _apply_case_calibration(response)
    response["_material_disagreement_gate"] = {
        "version": 2, "applied": True, "scope": "case_disposition",
        "agreement": comparison.get("agreement"), "disputed_fields": fields,
        "guarded_handling": handling, "verdict_preserved": False,
    }
    return response


def _apply_case_calibration(response: dict[str, Any]) -> None:
    calibration = _calibration(response)
    _add_limiter(calibration, "material_second_opinion_disagreement")
    calibration.update({
        "calibrated_confidence": "low",
        "calibrated_confidence_score": response["confidence_score"],
        "maximum_confidence_score": min(
            float(calibration.get("maximum_confidence_score", 1.0) or 1.0), 0.39
        ),
    })
    response["_confidence_calibration"] = calibration


def apply(
    primary_response: dict[str, Any], reviewer_response: dict[str, Any],
    comparison: dict[str, Any],
) -> dict[str, Any]:
    """Publish a conservative state while preserving immutable review artifacts."""
    fields, material = _disputed_fields(comparison)
    if not material.intersection(VERDICT_FIELDS):
        return _control_only(primary_response, comparison, fields)
    return _case_disposition(primary_response, reviewer_response, comparison, fields)
