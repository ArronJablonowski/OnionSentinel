"""Conclusion-safe public detection validation projection."""
from __future__ import annotations

from typing import Any, Callable

from detection_validation_rule import VALIDATION_SCHEMA


StunValidator = Callable[[dict[str, Any], dict[str, Any]], bool]


def _interpretation(intent_match: str) -> str:
    if intent_match == "mismatch":
        return "The observed packets violate one or more required threat-behavior predicates."
    if intent_match == "match":
        return "The required threat-behavior predicates matched the supplied packet evidence."
    return "The supplied evidence cannot deterministically establish the detection intent."


def _rule_projection(
    rule_context: dict[str, Any],
    parsed_rule: object,
    identity_conflict: bool,
) -> dict[str, Any]:
    conflicts = rule_context.get("identity_conflicts")
    return {
        "sid": rule_context.get("sid"),
        "revision": rule_context.get("revision"),
        "name": rule_context.get("name"),
        "ruleset": rule_context.get("ruleset"),
        "rule_sha256": (
            parsed_rule.get("rule_sha256") if isinstance(parsed_rule, dict) else ""
        ),
        "identity_status": "conflict" if identity_conflict else "consistent",
        "identity_conflicts": conflicts if identity_conflict else {},
    }


def _playbook_projection(playbook: object) -> dict[str, Any] | None:
    if not isinstance(playbook, dict):
        return None
    return {
        "id": playbook.get("id"),
        "version": playbook.get("version"),
        "status": playbook.get("status"),
        "intent": playbook.get("intent"),
        "known_false_positive_risk": playbook.get("known_false_positive_risk"),
        "references": playbook.get("references") or [],
    }


def _confidence_limiters(playbook: object) -> list[Any]:
    if isinstance(playbook, dict) and isinstance(playbook.get("confidence_limiters"), list):
        return list(playbook.get("confidence_limiters") or [])
    return []


def project_detection_validation(
    rule_context: dict[str, Any],
    parsed_rule: object,
    packet_features: dict[str, Any],
    playbook: object,
    predicate_results: list[dict[str, Any]],
    intent_match: str,
    identity_conflict: bool,
    missing_constraints: list[str],
    validate_stun: StunValidator,
) -> dict[str, Any]:
    """Return the stable validation schema without asserting maliciousness."""
    event_status = "observed" if packet_features.get("packets_parsed") else "unknown"
    return {
        "schema": VALIDATION_SCHEMA,
        "event_status": event_status,
        "event_observed": True if event_status == "observed" else None,
        "rule_intent_match": intent_match,
        "rule_intent_basis": (
            "validated_rfc5389_stun_semantics"
            if validate_stun(rule_context, packet_features)
            else "deployed_rule_predicates"
        ),
        "rule": _rule_projection(rule_context, parsed_rule, identity_conflict),
        "playbook": _playbook_projection(playbook),
        "predicate_results": predicate_results,
        "rule_drift": {
            "detected": bool(missing_constraints),
            "missing_installed_constraints": missing_constraints,
        },
        "packet_features": packet_features,
        "confidence_limiters": _confidence_limiters(playbook),
        "interpretation": _interpretation(intent_match),
    }
