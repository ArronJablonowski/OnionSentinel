"""Analyst-facing projection of validated shadow adjudication decisions."""

from __future__ import annotations

from typing import Any


ANALYTICAL_FIELDS = (
    "event_status", "detection_validity", "activity_disposition", "handling",
    "duplicate_of", "detection_outcome", "escalation_needed",
)


def _completed_shadow_result(adjudication: Any) -> dict[str, Any] | None:
    if not isinstance(adjudication, dict):
        return None
    result = adjudication.get("response")
    if (
        adjudication.get("status") != "completed"
        or adjudication.get("mode") != "shadow"
        or adjudication.get("automation_authorized") is not False
        or not isinstance(result, dict)
    ):
        return None
    return result


def _validated_decision(adjudication: Any) -> tuple[str, dict[str, Any]] | None:
    result = _completed_shadow_result(adjudication)
    if result is None:
        return None
    validation = result.get("_adjudication_contract_validation")
    decision = str(result.get("decision") or "").strip().lower()
    remaining = {
        str(item or "").strip()
        for item in result.get("remaining_disagreements", [])
        if str(item or "").strip()
    } if isinstance(result.get("remaining_disagreements"), list) else set()
    if (
        not isinstance(validation, dict) or validation.get("valid") is not True
        or validation.get("automation_authorized") is not False
        or decision not in {"primary_supported", "reviewer_supported"}
        or remaining
    ):
        return None
    return decision, result


def apply(
    primary_response: dict[str, Any], reviewer_response: dict[str, Any],
    adjudication: Any,
) -> bool:
    """Project one supported position without granting operational authority."""
    validated = _validated_decision(adjudication)
    if validated is None:
        return False
    decision, result = validated
    chosen = primary_response if decision == "primary_supported" else reviewer_response
    before = {key: primary_response.get(key) for key in ANALYTICAL_FIELDS}
    for key in ANALYTICAL_FIELDS:
        primary_response[key] = chosen.get(key)
    if isinstance(chosen.get("scope_dispositions"), dict):
        primary_response["scope_dispositions"] = dict(chosen["scope_dispositions"])
    primary_response["_analytical_adjudication_projection"] = {
        "schema": "onion-sentinel-analytical-adjudication-projection-v1",
        "applied": True, "selected_position": decision,
        "resolved_fields": list(result.get("resolved_fields") or [])[:16],
        "remaining_disagreements": [], "before": before,
        "after": {key: primary_response.get(key) for key in ANALYTICAL_FIELDS},
        "automation_authorized": False, "human_adjudication_required": True,
    }
    return True
