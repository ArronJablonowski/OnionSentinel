"""Numeric, state, and unsupported detection predicate projection."""
from __future__ import annotations

from typing import Any, Callable


PredicateEvaluator = Callable[..., dict[str, Any]]
StateInferer = Callable[[dict[str, Any], dict[str, Any], dict[str, Any]], bool]


def _state_result(
    index: int,
    item: dict[str, Any],
    inferred_stun_state: bool,
) -> dict[str, Any]:
    operation = str(item.get("operation") or "").strip().lower()
    return {
        "id": f"deployed-state-{index}",
        "field": f"{str(item.get('kind') or 'state')}.state",
        "operator": operation,
        "expected": "required state is intentionally not disclosed",
        "observed": (
            {"state": "inferred_satisfied", "engine_trace_observed": False}
            if inferred_stun_state
            else None
        ),
        "status": "matched" if inferred_stun_state else "unknown",
        "required": True,
        "source": "deployed_rule",
        "reason": (
            "STUN-specific inference from the exact stored Suricata SID 2016150 "
            "alert and a validated RFC 5389 Binding-success packet; the xbits "
            "engine state was not independently observed in a rule-engine trace"
            if inferred_stun_state
            else "stateful rule precondition requires a trusted Suricata rule-engine trace"
        ),
        "provenance": (
            {
                "kind": "inference",
                "basis": [
                    "exact_suricata_alert",
                    "validated_stun_binding_success_packet",
                ],
                "engine_trace_observed": False,
                "scope": "suricata_sid_2016150_only",
            }
            if inferred_stun_state
            else {"kind": "unobserved", "engine_trace_observed": False}
        ),
    }


def append_deployed_predicates(
    parsed_rule: object,
    rule_context: dict[str, Any],
    packet_features: dict[str, Any],
    results: list[dict[str, Any]],
    evaluate_numeric: PredicateEvaluator,
    infer_stun_state: StateInferer,
) -> None:
    """Append deployed numeric predicates and supported state operations."""
    if not isinstance(parsed_rule, dict):
        return
    predicates = parsed_rule.get("predicates")
    for item in predicates if isinstance(predicates, list) else []:
        if isinstance(item, dict):
            results.append(evaluate_numeric(item, packet_features, source="deployed_rule"))
    operations = parsed_rule.get("state_operations")
    for index, item in enumerate(operations if isinstance(operations, list) else [], 1):
        if not isinstance(item, dict):
            continue
        operation = str(item.get("operation") or "").strip().lower()
        if operation not in {"isset", "isnotset"}:
            continue
        inferred = infer_stun_state(rule_context, packet_features, item)
        results.append(_state_result(index, item, inferred))


def _applies(item: dict[str, Any], rule_context: dict[str, Any]) -> bool:
    applies_to = item.get("applies_to_sids")
    applies = {str(value) for value in applies_to} if isinstance(applies_to, list) else set()
    return not applies or str(rule_context.get("sid") or "") in applies


def _append_playbook_group(
    predicates: object,
    rule_context: dict[str, Any],
    packet_features: dict[str, Any],
    results: list[dict[str, Any]],
    evaluate_numeric: PredicateEvaluator,
    *,
    required: bool,
) -> None:
    for item in predicates if isinstance(predicates, list) else []:
        if not isinstance(item, dict) or not _applies(item, rule_context):
            continue
        selected = {**item, "required": True} if required else item
        results.append(evaluate_numeric(selected, packet_features, source="playbook"))


def append_playbook_numeric_predicates(
    playbook: object,
    rule_context: dict[str, Any],
    packet_features: dict[str, Any],
    results: list[dict[str, Any]],
    evaluate_numeric: PredicateEvaluator,
) -> None:
    """Append applicable required then supporting playbook predicates."""
    if not isinstance(playbook, dict):
        return
    _append_playbook_group(
        playbook.get("required_predicates"),
        rule_context,
        packet_features,
        results,
        evaluate_numeric,
        required=True,
    )
    _append_playbook_group(
        playbook.get("supporting_predicates"),
        rule_context,
        packet_features,
        results,
        evaluate_numeric,
        required=False,
    )


def append_unsupported_predicates(
    parsed_rule: object,
    results: list[dict[str, Any]],
) -> None:
    """Represent each unsupported installed constraint as required unknown."""
    if not isinstance(parsed_rule, dict):
        return
    options = parsed_rule.get("unsupported_match_options")
    for index, item in enumerate(options if isinstance(options, list) else [], 1):
        if not isinstance(item, dict):
            continue
        results.append(
            {
                "id": f"deployed-unsupported-{index}",
                "field": f"suricata.{str(item.get('option') or 'unknown')}",
                "operator": "unsupported",
                "expected": {"value_sha256": item.get("value_sha256")},
                "observed": None,
                "status": "unknown",
                "required": True,
                "source": "deployed_rule",
                "reason": "installed rule constraint is outside the deterministic validator's supported subset",
            }
        )
