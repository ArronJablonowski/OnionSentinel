"""Collector-owned rule-intent reconciliation for model conclusions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


@dataclass(frozen=True)
class Dependencies:
    bounded_text: Callable[[Any, int], str]
    bounded_text_list: Callable[..., list[str]]
    normalized_outcome: Callable[[Any], str]
    has_trusted_endpoint_evidence: Callable[[dict[str, Any]], bool]
    derive_legacy_outcome: Callable[[dict[str, Any]], str]
    control_tuning_values: frozenset[str]
    factored_verdict_keys: frozenset[str]


VERDICT_FIELDS = (
    "detection_outcome", "event_status", "detection_validity",
    "activity_disposition", "handling", "duplicate_of", "escalation_needed",
    "tuning_recommendation", "recommended_tuning_actions",
)


def consequential(response: dict[str, Any], deps: Dependencies) -> bool:
    outcome = deps.normalized_outcome(response.get("detection_outcome"))
    handling = str(response.get("handling") or "").strip().lower()
    tuning = str(response.get("tuning_recommendation") or "").strip().lower()
    return (
        outcome != "inconclusive"
        or handling in {"contain", "escalate"}
        or bool(response.get("escalation_needed"))
        or tuning in deps.control_tuning_values
    )


def _intent_and_event(validation: dict[str, Any]) -> tuple[str, str]:
    raw_intent = str(validation.get("rule_intent_match") or "unknown").strip().lower()
    intent = raw_intent if raw_intent in {"match", "mismatch", "unknown"} else "unknown"
    raw_event = str(validation.get("event_status") or "").strip().lower()
    if raw_event in {"observed", "unknown"}:
        event = raw_event
    elif validation.get("event_observed") is True:
        event = "observed"
    else:
        event = "unknown"
    return intent, event


def _snapshot(response: dict[str, Any]) -> dict[str, Any]:
    snapshot = {key: response.get(key) for key in VERDICT_FIELDS}
    actions = response.get("recommended_tuning_actions")
    snapshot["recommended_tuning_actions"] = list(actions) if isinstance(actions, list) else []
    return snapshot


def _audit(
    validation: dict[str, Any],
    intent: str,
    event: str,
    original: dict[str, Any],
    deps: Dependencies,
) -> dict[str, Any]:
    rule = validation.get("rule") if isinstance(validation.get("rule"), dict) else {}
    return {
        "schema": str(validation.get("schema") or "")[:200],
        "rule_intent_match": intent,
        "event_status": event,
        "rule": {
            "sid": deps.bounded_text(rule.get("sid"), 100),
            "revision": rule.get("revision"),
            "rule_sha256": deps.bounded_text(rule.get("rule_sha256"), 128),
        },
        "confidence_limiters": deps.bounded_text_list(
            validation.get("confidence_limiters"), limit=20, item_limit=1000
        ),
        "model_verdict_before_guard": original,
        "override_applied": False,
        "blocked_controls": [],
        "confidence_cap": None,
        "confidence_cap_reasons": [],
    }


def _validation_lists(response: dict[str, Any]) -> tuple[dict[str, Any], list[Any], list[Any]]:
    validation = dict(response.get("_verdict_validation")) if isinstance(
        response.get("_verdict_validation"), dict
    ) else {}
    warnings = list(validation.get("warnings")) if isinstance(
        validation.get("warnings"), list
    ) else []
    contradictions = list(validation.get("contradictions")) if isinstance(
        validation.get("contradictions"), list
    ) else []
    return validation, warnings, contradictions


def _block_controls(
    response: dict[str, Any],
    original: dict[str, Any],
    audit: dict[str, Any],
    deps: Dependencies,
) -> tuple[str, str]:
    handling = str(original.get("handling") or "").strip().lower()
    tuning = str(original.get("tuning_recommendation") or "").strip().lower()
    if handling == "contain":
        response["handling"] = "investigate"
        response["escalation_needed"] = False
        audit["blocked_controls"].append("contain")
    if tuning in deps.control_tuning_values:
        response["tuning_recommendation"] = "needs_more_data"
        response["tuning_reason"] = (
            "Automatic suppress/drop tuning is blocked because deterministic "
            "rule-intent validation found a mismatch. Review the rule predicates "
            "and supporting evidence before changing signal collection."
        )
        response["recommended_tuning_actions"] = []
        audit["blocked_controls"].append(tuning)
    return handling, tuning


def _unsupported_malicious(
    original: dict[str, Any], prompt_package: dict[str, Any], deps: Dependencies
) -> bool:
    disposition = str(original.get("activity_disposition") or "").strip().lower()
    outcome = deps.normalized_outcome(original.get("detection_outcome"))
    claimed = disposition == "malicious" or outcome in {
        "true_positive_malicious", "false_negative",
    }
    return claimed and not deps.has_trusted_endpoint_evidence(prompt_package)


def _apply_mismatch(
    response: dict[str, Any],
    prompt_package: dict[str, Any],
    event: str,
    original: dict[str, Any],
    audit: dict[str, Any],
    warnings: list[Any],
    contradictions: list[Any],
    deps: Dependencies,
) -> None:
    response["event_status"] = event
    response["detection_validity"] = "logic_error"
    if str(response.get("activity_disposition") or "").lower() in {"malicious", "suspicious"}:
        response["activity_disposition"] = "unknown"
    response["duplicate_of"] = None
    response["detection_outcome"] = "false_positive_logic_rule"
    audit["confidence_cap"] = 0.79
    audit["confidence_cap_reasons"].append("deterministic_rule_intent_mismatch")
    handling, tuning = _block_controls(response, original, audit, deps)
    if _unsupported_malicious(original, prompt_package, deps):
        audit["confidence_cap"] = 0.39
        audit["confidence_cap_reasons"].append(
            "malicious_attribution_without_trusted_endpoint_evidence"
        )
        contradiction = (
            "model malicious attribution conflicts with deterministic "
            "rule-intent mismatch and lacks trusted endpoint evidence"
        )
        if contradiction not in contradictions:
            contradictions.append(contradiction)
    warning = (
        "collector-owned detection validation overrode the model verdict "
        "because required rule-intent predicates mismatched"
    )
    if warning not in warnings:
        warnings.append(warning)
    _automation_controls(response, audit, handling, tuning, deps)
    guarded = {key: response.get(key) for key in VERDICT_FIELDS}
    audit["guarded_verdict"] = guarded
    audit["override_applied"] = guarded != original


def _automation_controls(
    response: dict[str, Any], audit: dict[str, Any], handling: str, tuning: str,
    deps: Dependencies,
) -> None:
    controls = dict(response.get("_automation_controls")) if isinstance(
        response.get("_automation_controls"), dict
    ) else {}
    if audit["blocked_controls"]:
        controls["requires_human_review"] = True
        controls["reason"] = "deterministic rule-intent mismatch"
    if tuning in deps.control_tuning_values:
        controls["tuning_blocked"] = True
    if handling == "contain":
        controls["containment_blocked"] = True
    if controls:
        response["_automation_controls"] = controls


def apply(
    response: dict[str, Any],
    prompt_package: dict[str, Any] | None,
    deps: Dependencies,
) -> dict[str, Any]:
    """Reconcile a model verdict with collector-owned rule-intent evidence."""
    if not isinstance(prompt_package, dict):
        return response
    detection = prompt_package.get("detection_validation")
    if not isinstance(detection, dict):
        return response
    intent, event = _intent_and_event(detection)
    original = _snapshot(response)
    audit = _audit(detection, intent, event, original, deps)
    validation, warnings, contradictions = _validation_lists(response)
    if intent == "mismatch":
        _apply_mismatch(
            response, prompt_package, event, original, audit, warnings,
            contradictions, deps,
        )
    elif intent == "unknown" and consequential(response, deps):
        audit["confidence_cap"] = 0.79
        audit["confidence_cap_reasons"].append(
            "deterministic_rule_intent_unknown_for_consequential_conclusion"
        )
    validation["warnings"] = warnings
    validation["contradictions"] = contradictions
    validation["material_contradiction"] = bool(
        validation.get("material_contradiction") or contradictions
    )
    validation["deterministic_evidence_guard"] = audit
    validation["canonical_legacy_outcome"] = response.get("detection_outcome")
    validation["derived_legacy_outcome"] = deps.derive_legacy_outcome(
        {key: response.get(key) for key in deps.factored_verdict_keys}
    )
    response["_verdict_validation"] = validation
    return response
