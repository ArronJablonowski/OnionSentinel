"""Pure second-opinion trigger and independent-result comparison policy."""
from __future__ import annotations

import re
from typing import Any, Callable, Collection, Mapping


def _token(value: Any) -> Any:
    if isinstance(value, bool):
        return value
    return re.sub(r"[^a-z0-9]+", "_", str(value or "").lower()).strip("_")


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _nested(payload: Mapping[str, Any], dotted_key: str) -> Any:
    value: Any = payload
    for key in dotted_key.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def _manual_ir_reanalysis(prompt: Mapping[str, Any] | None) -> bool:
    return bool(
        isinstance(prompt, dict)
        and prompt.get("manual_reanalysis") is True
        and str(prompt.get("agent_role") or "").strip() == "incident-responder"
    )


def _requested_reason(response: Mapping[str, Any], prompt: Mapping[str, Any] | None) -> str:
    explicit = str(response.get("second_opinion_reason") or "").strip()[:1000]
    requested = bool(response.get("second_opinion_recommended")) or bool(
        response.get("hosted_second_opinion_recommended")
    )
    if requested:
        return explicit or "The primary model explicitly requested another opinion."
    if _manual_ir_reanalysis(prompt):
        return "Manual Incident Responder reanalysis requires an independent second opinion."
    return ""


def _verdict_reason(response: Mapping[str, Any]) -> str:
    verdict = _dict(response.get("_verdict_validation"))
    if verdict.get("material_contradiction"):
        return "Runtime verdict checks found a material contradiction."
    guard = _dict(verdict.get("deterministic_evidence_guard"))
    intent = guard.get("rule_intent_match")
    if intent == "mismatch" and guard.get("override_applied"):
        return "Deterministic rule-intent validation overrode the model verdict."
    if intent == "unknown" and guard.get("confidence_cap") is not None:
        return "Deterministic evidence could not establish rule intent for a consequential conclusion."
    return ""


def _confidence_reason(response: Mapping[str, Any]) -> str:
    if str(response.get("confidence") or "").strip().lower() == "low":
        return "The primary model reported low confidence."
    if _token(response.get("detection_outcome")) == "inconclusive":
        return "The primary model classified the detection as inconclusive."
    limiters = _dict(response.get("_confidence_calibration")).get("limiters")
    limiters = limiters if isinstance(limiters, list) else []
    prefixes = ("critical_schema_repair", "invalid_", "material_verdict_contradiction")
    if any(str(item).startswith(prefixes) for item in limiters):
        return "Runtime evidence checks capped confidence because decisive output was invalid or incomplete."
    return ""


def _action_reason(response: Mapping[str, Any], tuning_values: Collection[str]) -> str:
    handling = str(response.get("handling") or "").strip().lower()
    if handling in {"contain", "escalate"} or bool(response.get("escalation_needed")):
        return "The primary model recommended a consequential response action."
    if str(response.get("tuning_recommendation") or "").strip().lower() in tuning_values:
        return "The primary model recommended suppressing or dropping detection signal."
    return ""


def _severity_reason(
    response: Mapping[str, Any],
    prompt: Mapping[str, Any] | None,
    outcomes: Collection[str],
) -> str:
    alert = _dict(prompt.get("alert")) if isinstance(prompt, dict) else {}
    triage = str(alert.get("triage_level") or "").strip().lower()
    if triage in {"critical", "high"} and _token(response.get("detection_outcome")) in outcomes:
        return "A high-severity detection received a consequential closure disposition."
    return ""


def trigger(
    response: Mapping[str, Any],
    prompt_package: Mapping[str, Any] | None,
    *,
    control_tuning_values: Collection[str],
    consequential_outcomes: Collection[str],
) -> str:
    """Return the highest-priority deterministic reason review is required."""
    reasons = (
        _requested_reason(response, prompt_package),
        _verdict_reason(response),
        _confidence_reason(response),
        _action_reason(response, control_tuning_values),
        _severity_reason(response, prompt_package, consequential_outcomes),
    )
    return next((reason for reason in reasons if reason), "")


def _handling_is_material(
    primary: Mapping[str, Any],
    reviewer: Mapping[str, Any],
    *,
    non_escalatory_values: Collection[str],
    boolean_setting: Callable[[Any], bool],
) -> bool:
    handling_pair = {_token(primary.get("handling")), _token(reviewer.get("handling"))}
    dispositions = {
        _token(primary.get("activity_disposition")),
        _token(reviewer.get("activity_disposition")),
    }
    escalations = {
        boolean_setting(primary.get("escalation_needed")),
        boolean_setting(reviewer.get("escalation_needed")),
    }
    advisory = (
        handling_pair.issubset(non_escalatory_values)
        and True not in escalations
        and not dispositions.intersection({"malicious", "suspicious"})
    )
    return not advisory


def _snapshot(response: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: response.get(key)
        for key in (
            "detection_outcome", "event_status", "detection_validity",
            "activity_disposition", "handling", "duplicate_of", "confidence",
            "confidence_score", "escalation_needed",
        )
    }


def _comparison_checks(tuning_material: bool) -> tuple[tuple[str, bool], ...]:
    return (
        ("detection_outcome", True), ("event_status", True),
        ("detection_validity", True), ("activity_disposition", True),
        ("handling", True), ("duplicate_of", True),
        ("escalation_needed", True),
        ("correlation_assessment.correlation_found", False),
        ("confidence", False), ("confidence_score", False),
        ("tuning_recommendation", tuning_material),
    )


def _disputes(
    primary: Mapping[str, Any],
    reviewer: Mapping[str, Any],
    checks: Collection[tuple[str, bool]],
    *,
    non_escalatory_values: Collection[str],
    boolean_setting: Callable[[Any], bool],
) -> list[dict[str, Any]]:
    disputes: list[dict[str, Any]] = []
    for field, default_material in checks:
        primary_value, reviewer_value = _nested(primary, field), _nested(reviewer, field)
        if _token(primary_value) == _token(reviewer_value):
            continue
        material = default_material
        if field == "handling":
            material = _handling_is_material(
                primary, reviewer, non_escalatory_values=non_escalatory_values,
                boolean_setting=boolean_setting,
            )
        disputes.append({
            "field": field, "primary": primary_value,
            "reviewer": reviewer_value, "material": material,
        })
    return disputes


def _agreement(disputes: list[dict[str, Any]]) -> tuple[str, bool, str]:
    material = any(item["material"] for item in disputes)
    if not disputes:
        return (
            "agreement", False,
            "Primary and reviewer agree on all compared disposition fields.",
        )
    if material:
        return (
            "material_disagreement", True,
            "Primary and reviewer disagree on an analyst-handling decision.",
        )
    return (
        "partial_disagreement", False,
        "Primary and reviewer agree on disposition but differ on advisory context.",
    )


def compare(
    primary: Mapping[str, Any],
    reviewer: Mapping[str, Any],
    *,
    control_tuning_values: Collection[str],
    non_escalatory_values: Collection[str],
    boolean_setting: Callable[[Any], bool],
) -> dict[str, Any]:
    """Compare independent positions without letting either model arbitrate."""
    tuning_material = any(
        str(item.get("tuning_recommendation") or "").strip().lower() in control_tuning_values
        for item in (primary, reviewer)
    )
    disputes = _disputes(
        primary, reviewer, _comparison_checks(tuning_material),
        non_escalatory_values=non_escalatory_values,
        boolean_setting=boolean_setting,
    )
    agreement, material_disagreement, summary = _agreement(disputes)
    return {
        "agreement": agreement, "material_disagreement": material_disagreement,
        "disputed_fields": disputes, "summary": summary,
        "primary": _snapshot(primary), "reviewer": _snapshot(reviewer),
    }
