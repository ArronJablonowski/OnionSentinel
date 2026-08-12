"""Orchestrate deterministic conclusion-safe detection validation."""
from __future__ import annotations

from typing import Any, Callable

from detection_validation_result_content import (
    append_deployed_content_predicates,
    append_playbook_marker_predicates,
    marker_lookup,
)
from detection_validation_result_decision import (
    decide_intent_match,
    has_identity_conflict,
    missing_installed_constraints,
)
from detection_validation_result_predicates import (
    append_deployed_predicates,
    append_playbook_numeric_predicates,
    append_unsupported_predicates,
)
from detection_validation_result_projection import project_detection_validation


def _compose_predicate_results(
    rule_context: dict[str, Any],
    packet_features: dict[str, Any],
    playbook: dict[str, Any] | None,
    evaluate_numeric: Callable[..., dict[str, Any]],
    infer_stun_state: Callable[[dict[str, Any], dict[str, Any], dict[str, Any]], bool],
) -> tuple[object, list[dict[str, Any]]]:
    predicate_results: list[dict[str, Any]] = []
    parsed_rule = rule_context.get("parsed_rule")
    append_deployed_predicates(
        parsed_rule,
        rule_context,
        packet_features,
        predicate_results,
        evaluate_numeric,
        infer_stun_state,
    )
    append_playbook_numeric_predicates(
        playbook,
        rule_context,
        packet_features,
        predicate_results,
        evaluate_numeric,
    )
    observations = marker_lookup(packet_features)
    append_deployed_content_predicates(
        parsed_rule,
        packet_features,
        observations,
        predicate_results,
    )
    append_playbook_marker_predicates(
        playbook,
        rule_context,
        packet_features,
        observations,
        predicate_results,
    )
    append_unsupported_predicates(parsed_rule, predicate_results)
    return parsed_rule, predicate_results


def build_detection_validation(
    rule_context: dict[str, Any],
    packet_features: dict[str, Any],
    playbook: dict[str, Any] | None,
    evaluate_numeric: Callable[..., dict[str, Any]],
    infer_stun_state: Callable[[dict[str, Any], dict[str, Any], dict[str, Any]], bool],
    validate_stun: Callable[[dict[str, Any], dict[str, Any]], bool],
) -> dict[str, Any]:
    """Build ordered predicates, decisions, and the stable public projection."""
    parsed_rule, predicate_results = _compose_predicate_results(
        rule_context,
        packet_features,
        playbook,
        evaluate_numeric,
        infer_stun_state,
    )
    identity_conflict = has_identity_conflict(rule_context)
    intent_match = decide_intent_match(
        predicate_results,
        rule_context,
        packet_features,
        identity_conflict,
        validate_stun,
    )
    missing_constraints = missing_installed_constraints(predicate_results)
    return project_detection_validation(
        rule_context,
        parsed_rule,
        packet_features,
        playbook,
        predicate_results,
        intent_match,
        identity_conflict,
        missing_constraints,
        validate_stun,
    )
