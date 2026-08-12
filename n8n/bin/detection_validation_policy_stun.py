"""Fail-closed STUN rule and state-operation policy."""

from __future__ import annotations

from typing import Any


_STUN_RESPONSE_NAME = (
    "ET INFO Session Traversal Utilities for NAT (STUN Binding Response)"
)
_STUN_RULES = {
    ("2016149", 4): "binding_request",
    ("2016150", 4): "binding_success_response",
    ("2033078", 5): "binding_request",
}


def _identity_conflicts(rule_context: dict[str, Any]) -> bool:
    conflicts = rule_context.get("identity_conflicts")
    return isinstance(conflicts, dict) and any(
        conflicts.get(key) for key in ("sid", "revision")
    )


def _message_types(stun: dict[str, Any]) -> dict[str, int]:
    return {
        str(item.get("value") or ""): int(item.get("count") or 0)
        for item in stun.get("message_types", [])
        if isinstance(item, dict)
    }


def _stun_message_context(
    packet_features: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, int]] | None:
    stun = packet_features.get("stun")
    if not isinstance(stun, dict):
        return None
    return stun, _message_types(stun)


def _exact_response_rule(rule_context: dict[str, Any]) -> bool:
    if (
        str(rule_context.get("sid") or "") != "2016150"
        or rule_context.get("revision") != 4
        or str(rule_context.get("name") or "") != _STUN_RESPONSE_NAME
    ):
        return False
    parsed_rule = rule_context.get("parsed_rule")
    return isinstance(parsed_rule, dict) and parsed_rule.get("protocol") == "udp"


def _exact_xbits_operation(state_operation: dict[str, Any]) -> bool:
    return bool(
        str(state_operation.get("kind") or "").strip().casefold() == "xbits"
        and str(state_operation.get("operation") or "").strip().casefold()
        == "isset"
        and str(state_operation.get("name") or "").strip().casefold() == "et.stun"
        and str(state_operation.get("track") or "").strip().casefold()
        == "track ip_dst"
    )


def _infer_stun_response_xbits_state(
    rule_context: dict[str, Any],
    packet_features: dict[str, Any],
    state_operation: dict[str, Any],
) -> bool:
    """Infer only the deployed STUN-response xbit from exact validated alert packets."""
    if (
        not _exact_response_rule(rule_context)
        or _identity_conflicts(rule_context)
        or not _exact_xbits_operation(state_operation)
    ):
        return False
    candidate_packets = int(packet_features.get("candidate_packets") or 0)
    content_packets = int(packet_features.get("content_packets_parsed") or 0)
    context = _stun_message_context(packet_features)
    if context is None:
        return False
    stun, message_types = context
    return bool(
        candidate_packets > 0
        and candidate_packets == content_packets
        and int(stun.get("packets_parsed") or 0) == candidate_packets
        and message_types.get("binding_success_response") == candidate_packets
        and not int(packet_features.get("parse_errors") or 0)
        and packet_features.get("truncated") is not True
        and packet_features.get("source")
        == "stored-security-onion-alert-packet-copies"
    )


def _validated_stun_rule_semantics(
    rule_context: dict[str, Any],
    packet_features: dict[str, Any],
) -> bool:
    """Validate the bounded STUN SID family with the RFC 5389 parser."""
    expected = _STUN_RULES.get(
        (str(rule_context.get("sid") or ""), rule_context.get("revision"))
    )
    if not expected or _identity_conflicts(rule_context):
        return False
    candidate_packets = int(packet_features.get("candidate_packets") or 0)
    context = _stun_message_context(packet_features)
    if context is None:
        return False
    stun, message_types = context
    return bool(
        candidate_packets > 0
        and int(stun.get("packets_parsed") or 0) == candidate_packets
        and message_types.get(expected) == candidate_packets
        and not int(packet_features.get("parse_errors") or 0)
        and packet_features.get("truncated") is not True
    )
