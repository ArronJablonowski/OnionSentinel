"""Conclusion-safe detection validation result composition."""
from __future__ import annotations

from detection_validation_rule import *  # noqa: F401,F403
from detection_validation_packet import *  # noqa: F401,F403
from detection_validation_features import *  # noqa: F401,F403
from detection_validation_policy import *  # noqa: F401,F403
from detection_validation_policy import (  # noqa: F401
    _evaluate_numeric_predicate,
    _infer_stun_response_xbits_state,
    _validated_stun_rule_semantics,
)
def build_detection_validation(
    rule_context: dict[str, Any],
    packet_features: dict[str, Any],
    playbook: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a deterministic rule-intent assessment; never infer maliciousness."""
    predicate_results: list[dict[str, Any]] = []
    parsed_rule = rule_context.get("parsed_rule")
    if isinstance(parsed_rule, dict):
        for item in parsed_rule.get("predicates", []) if isinstance(parsed_rule.get("predicates"), list) else []:
            if isinstance(item, dict):
                predicate_results.append(_evaluate_numeric_predicate(item, packet_features, source="deployed_rule"))
        for index, item in enumerate(
            parsed_rule.get("state_operations", [])
            if isinstance(parsed_rule.get("state_operations"), list)
            else [],
            1,
        ):
            if not isinstance(item, dict):
                continue
            operation = str(item.get("operation") or "").strip().lower()
            if operation not in {"isset", "isnotset"}:
                continue
            inferred_stun_state = _infer_stun_response_xbits_state(
                rule_context,
                packet_features,
                item,
            )
            predicate_results.append(
                {
                    "id": f"deployed-state-{index}",
                    "field": f"{str(item.get('kind') or 'state')}.state",
                    "operator": operation,
                    "expected": "required state is intentionally not disclosed",
                    "observed": (
                        {
                            "state": "inferred_satisfied",
                            "engine_trace_observed": False,
                        }
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
                        else {
                            "kind": "unobserved",
                            "engine_trace_observed": False,
                        }
                    ),
                }
            )
    if isinstance(playbook, dict):
        predicates = playbook.get("required_predicates")
        for item in predicates if isinstance(predicates, list) else []:
            if not isinstance(item, dict):
                continue
            applies = {str(value) for value in item.get("applies_to_sids", [])} if isinstance(item.get("applies_to_sids"), list) else set()
            if applies and str(rule_context.get("sid") or "") not in applies:
                continue
            item = {**item, "required": True}
            predicate_results.append(_evaluate_numeric_predicate(item, packet_features, source="playbook"))
        predicates = playbook.get("supporting_predicates")
        for item in predicates if isinstance(predicates, list) else []:
            if not isinstance(item, dict):
                continue
            applies = {str(value) for value in item.get("applies_to_sids", [])} if isinstance(item.get("applies_to_sids"), list) else set()
            if applies and str(rule_context.get("sid") or "") not in applies:
                continue
            predicate_results.append(_evaluate_numeric_predicate(item, packet_features, source="playbook"))

    marker_lookup = {
        str(item.get("id")): item
        for item in packet_features.get("markers", [])
        if isinstance(item, dict)
    }
    if isinstance(parsed_rule, dict):
        contents = (
            parsed_rule.get("contents")
            if isinstance(parsed_rule.get("contents"), list)
            else []
        )
        for item in contents:
            if not isinstance(item, dict):
                continue
            marker_id = str(item.get("id") or "")
            observation = marker_lookup.get(marker_id, {})
            modifiers = item.get("modifiers") if isinstance(item.get("modifiers"), dict) else {}
            buffer_name = str(item.get("buffer") or "").strip().lower()
            expected_offset_raw = modifiers.get("offset")
            try:
                expected_offset = (
                    int(expected_offset_raw)
                    if expected_offset_raw not in (None, "")
                    else None
                )
            except (TypeError, ValueError):
                expected_offset = None
            observed_count = int(observation.get("observations") or 0)
            expected_count = observation.get("expected_offset_observations")
            constraint_supported = observation.get("constraint_supported") is True
            evaluated = int(observation.get("packets_evaluated_for_constraint") or 0)
            satisfied = int(observation.get("packets_satisfying_constraint") or 0)
            violated = int(observation.get("packets_violating_constraint") or 0)
            content_packets = int(
                packet_features.get("content_packets_parsed")
                or packet_features.get("icmp_packets_parsed")
                or 0
            )
            complete = (
                int(packet_features.get("candidate_packets") or 0) > 0
                and int(packet_features.get("candidate_packets") or 0)
                == content_packets
                and not int(packet_features.get("parse_errors") or 0)
                and packet_features.get("truncated") is not True
            )
            if not content_packets or not constraint_supported:
                status = "unknown"
            elif violated:
                status = "mismatched"
            elif complete and evaluated == content_packets and satisfied == evaluated:
                status = "matched"
            else:
                status = "unknown"
            if buffer_name:
                predicate_field = buffer_name
            elif parsed_rule.get("protocol") == "icmp":
                predicate_field = "icmp.payload_marker"
            elif parsed_rule.get("protocol") == "udp":
                predicate_field = "udp.payload_marker"
            else:
                predicate_field = "packet.payload_marker"
            predicate_results.append(
                {
                    "id": marker_id,
                    "field": predicate_field,
                    "operator": "not_contains" if item.get("negated") else "contains",
                    "expected": {
                        "sha256": observation.get("sha256") or item.get("sha256"),
                        "length": observation.get("length") or item.get("length"),
                        "search_offset": expected_offset,
                        "depth": modifiers.get("depth"),
                        "buffer": buffer_name or None,
                        "dotprefix": bool(modifiers.get("dotprefix")),
                        "bsize": modifiers.get("bsize"),
                        "negated": bool(item.get("negated")),
                    },
                    "observed": {
                        "packets_with_marker": int(observation.get("packets_with_marker") or 0),
                        "observations": observed_count,
                        "offsets": observation.get("offsets") or [],
                        "packets_evaluated_for_constraint": evaluated,
                        "packets_satisfying_constraint": satisfied,
                        "packets_violating_constraint": violated,
                    },
                    "status": status,
                    "required": True,
                    "source": "deployed_rule",
                    "reason": (
                        "unsupported sticky-buffer, transform, or buffer-size "
                        "evaluation requires a trusted Suricata rule-engine trace"
                        if not constraint_supported
                        else (
                            "supported application sticky-buffer evidence was "
                            "not present in the supplied alert projection"
                            if buffer_name and not evaluated
                            else "deployed rule content predicate"
                        )
                    ),
                }
            )
    if isinstance(playbook, dict):
        predicates = playbook.get("marker_predicates")
        for item in predicates if isinstance(predicates, list) else []:
            if not isinstance(item, dict):
                continue
            applies = {str(value) for value in item.get("applies_to_sids", [])} if isinstance(item.get("applies_to_sids"), list) else set()
            if applies and str(rule_context.get("sid") or "") not in applies:
                continue
            marker_id = str(item.get("id") or "")
            observation = marker_lookup.get(marker_id, {})
            expected_offset = item.get("expected_offset")
            observed_count = int(observation.get("observations") or 0)
            expected_count = observation.get("expected_offset_observations")
            if not packet_features.get("icmp_packets_parsed"):
                status = "unknown"
            elif expected_offset is not None:
                if int(expected_count or 0) > 0:
                    status = "matched"
                elif int(packet_features.get("parse_errors") or 0) or packet_features.get("truncated") is True:
                    status = "unknown"
                else:
                    status = "mismatched"
            else:
                if observed_count > 0:
                    status = "matched"
                elif int(packet_features.get("parse_errors") or 0) or packet_features.get("truncated") is True:
                    status = "unknown"
                else:
                    status = "mismatched"
            predicate_results.append({
                "id": marker_id,
                "field": "icmp.payload_marker",
                "operator": "at_offset" if expected_offset is not None else "contains",
                "expected": {
                    "sha256": observation.get("sha256"),
                    "length": observation.get("length"),
                    "offset": expected_offset,
                },
                "observed": {
                    "packets_with_marker": int(observation.get("packets_with_marker") or 0),
                    "observations": observed_count,
                    "expected_offset_observations": expected_count,
                    "offsets": observation.get("offsets") or [],
                },
                "status": status,
                "required": bool(item.get("required")),
                "source": "playbook",
                "reason": str(item.get("reason") or "")[:1000],
            })

    if isinstance(parsed_rule, dict):
        for index, item in enumerate(
            parsed_rule.get("unsupported_match_options", [])
            if isinstance(parsed_rule.get("unsupported_match_options"), list)
            else [],
            1,
        ):
            if not isinstance(item, dict):
                continue
            predicate_results.append(
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

    required = [item for item in predicate_results if item.get("required")]
    identity_conflicts = rule_context.get("identity_conflicts")
    identity_conflict = bool(
        isinstance(identity_conflicts, dict)
        and any(identity_conflicts.get(key) for key in ("sid", "revision"))
    )
    if identity_conflict:
        intent_match = "unknown"
    elif any(item.get("status") == "mismatched" for item in required):
        intent_match = "mismatch"
    elif required and (
        all(item.get("status") == "matched" for item in required)
        or (
            _validated_stun_rule_semantics(
                rule_context,
                packet_features,
            )
            and all(
                item.get("status") == "matched"
                or str(item.get("field") or "") == "udp.payload_marker"
                for item in required
            )
        )
    ):
        intent_match = "match"
    else:
        intent_match = "unknown"
    installed_fields = {
        str(item.get("field")) for item in predicate_results
        if item.get("source") == "deployed_rule"
    }
    playbook_required_fields = {
        str(item.get("field")) for item in required if item.get("source") == "playbook"
    }
    missing_installed_constraints = sorted(playbook_required_fields.difference(installed_fields))
    event_status = "observed" if packet_features.get("packets_parsed") else "unknown"
    return {
        "schema": VALIDATION_SCHEMA,
        "event_status": event_status,
        "event_observed": True if event_status == "observed" else None,
        "rule_intent_match": intent_match,
        "rule_intent_basis": (
            "validated_rfc5389_stun_semantics"
            if _validated_stun_rule_semantics(
                rule_context,
                packet_features,
            )
            else "deployed_rule_predicates"
        ),
        "rule": {
            "sid": rule_context.get("sid"),
            "revision": rule_context.get("revision"),
            "name": rule_context.get("name"),
            "ruleset": rule_context.get("ruleset"),
            "rule_sha256": (
                parsed_rule.get("rule_sha256")
                if isinstance(parsed_rule, dict)
                else ""
            ),
            "identity_status": "conflict" if identity_conflict else "consistent",
            "identity_conflicts": identity_conflicts if identity_conflict else {},
        },
        "playbook": {
            "id": playbook.get("id"),
            "version": playbook.get("version"),
            "status": playbook.get("status"),
            "intent": playbook.get("intent"),
            "known_false_positive_risk": playbook.get("known_false_positive_risk"),
            "references": playbook.get("references") or [],
        } if isinstance(playbook, dict) else None,
        "predicate_results": predicate_results,
        "rule_drift": {
            "detected": bool(missing_installed_constraints),
            "missing_installed_constraints": missing_installed_constraints,
        },
        "packet_features": packet_features,
        "confidence_limiters": (
            list(playbook.get("confidence_limiters") or [])
            if isinstance(playbook, dict) and isinstance(playbook.get("confidence_limiters"), list)
            else []
        ),
        "interpretation": (
            "The observed packets violate one or more required threat-behavior predicates."
            if intent_match == "mismatch"
            else "The required threat-behavior predicates matched the supplied packet evidence."
            if intent_match == "match"
            else "The supplied evidence cannot deterministically establish the detection intent."
        ),
    }
