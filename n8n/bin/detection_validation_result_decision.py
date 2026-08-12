"""Fail-closed intent and rule-drift decisions."""
from __future__ import annotations

from typing import Any, Callable


StunValidator = Callable[[dict[str, Any], dict[str, Any]], bool]


def has_identity_conflict(rule_context: dict[str, Any]) -> bool:
    """Return true for any SID or revision identity conflict."""
    conflicts = rule_context.get("identity_conflicts")
    return bool(
        isinstance(conflicts, dict)
        and any(conflicts.get(key) for key in ("sid", "revision"))
    )


def decide_intent_match(
    predicate_results: list[dict[str, Any]],
    rule_context: dict[str, Any],
    packet_features: dict[str, Any],
    identity_conflict: bool,
    validate_stun: StunValidator,
) -> str:
    """Choose mismatch, match, or unknown with exact fail-closed precedence."""
    required = _required_predicates(predicate_results)
    if identity_conflict:
        return "unknown"
    if _has_mismatch(required):
        return "mismatch"
    if required and (
        _all_matched(required)
        or _validated_stun_match(
            required,
            rule_context,
            packet_features,
            validate_stun,
        )
    ):
        return "match"
    return "unknown"


def _required_predicates(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [item for item in results if item.get("required")]


def _has_mismatch(required: list[dict[str, Any]]) -> bool:
    return any(item.get("status") == "mismatched" for item in required)


def _all_matched(required: list[dict[str, Any]]) -> bool:
    return all(item.get("status") == "matched" for item in required)


def _stun_compatible(required: list[dict[str, Any]]) -> bool:
    return all(
        item.get("status") == "matched"
        or str(item.get("field") or "") == "udp.payload_marker"
        for item in required
    )


def _validated_stun_match(
    required: list[dict[str, Any]],
    rule_context: dict[str, Any],
    packet_features: dict[str, Any],
    validate_stun: StunValidator,
) -> bool:
    return validate_stun(rule_context, packet_features) and _stun_compatible(required)


def missing_installed_constraints(
    predicate_results: list[dict[str, Any]],
) -> list[str]:
    """Return required playbook fields absent from installed-rule evidence."""
    installed_fields = {
        str(item.get("field"))
        for item in predicate_results
        if item.get("source") == "deployed_rule"
    }
    playbook_required_fields = {
        str(item.get("field"))
        for item in predicate_results
        if item.get("required") and item.get("source") == "playbook"
    }
    return sorted(playbook_required_fields.difference(installed_fields))
