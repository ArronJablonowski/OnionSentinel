"""Deployed and playbook marker predicate result composition."""
from __future__ import annotations

from typing import Any


def marker_lookup(packet_features: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Index bounded marker observations by stable marker identity."""
    return {
        str(item.get("id")): item
        for item in packet_features.get("markers", [])
        if isinstance(item, dict)
    }


def _integer_or_none(value: object) -> int | None:
    try:
        return int(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


def _count(value: dict[str, Any], key: str) -> int:
    return int(value.get(key) or 0)


def _preferred(primary: object, fallback: object) -> object:
    return primary or fallback


def _content_packet_count(packet_features: dict[str, Any]) -> int:
    return int(
        packet_features.get("content_packets_parsed")
        or packet_features.get("icmp_packets_parsed")
        or 0
    )


def _complete_content_evidence(
    packet_features: dict[str, Any],
    content_packets: int,
) -> bool:
    return (
        int(packet_features.get("candidate_packets") or 0) > 0
        and int(packet_features.get("candidate_packets") or 0) == content_packets
        and not int(packet_features.get("parse_errors") or 0)
        and packet_features.get("truncated") is not True
    )


def _content_status(
    observation: dict[str, Any],
    packet_features: dict[str, Any],
) -> str:
    content_packets = _content_packet_count(packet_features)
    supported = observation.get("constraint_supported") is True
    evaluated = _count(observation, "packets_evaluated_for_constraint")
    satisfied = _count(observation, "packets_satisfying_constraint")
    violated = _count(observation, "packets_violating_constraint")
    if not content_packets or not supported:
        return "unknown"
    if violated:
        return "mismatched"
    if (
        _complete_content_evidence(packet_features, content_packets)
        and evaluated == content_packets
        and satisfied == evaluated
    ):
        return "matched"
    return "unknown"


def _content_field(parsed_rule: dict[str, Any], buffer_name: str) -> str:
    if buffer_name:
        return buffer_name
    if parsed_rule.get("protocol") == "icmp":
        return "icmp.payload_marker"
    if parsed_rule.get("protocol") == "udp":
        return "udp.payload_marker"
    return "packet.payload_marker"


def _content_reason(
    observation: dict[str, Any],
    buffer_name: str,
) -> str:
    if observation.get("constraint_supported") is not True:
        return (
            "unsupported sticky-buffer, transform, or buffer-size "
            "evaluation requires a trusted Suricata rule-engine trace"
        )
    if buffer_name and not int(observation.get("packets_evaluated_for_constraint") or 0):
        return (
            "supported application sticky-buffer evidence was "
            "not present in the supplied alert projection"
        )
    return "deployed rule content predicate"


def _deployed_content_result(
    parsed_rule: dict[str, Any],
    item: dict[str, Any],
    observation: dict[str, Any],
    packet_features: dict[str, Any],
) -> dict[str, Any]:
    modifiers = item.get("modifiers") if isinstance(item.get("modifiers"), dict) else {}
    buffer_name = str(item.get("buffer") or "").strip().lower()
    expected_offset = _integer_or_none(modifiers.get("offset"))
    evaluated = _count(observation, "packets_evaluated_for_constraint")
    satisfied = _count(observation, "packets_satisfying_constraint")
    violated = _count(observation, "packets_violating_constraint")
    return {
        "id": str(item.get("id") or ""),
        "field": _content_field(parsed_rule, buffer_name),
        "operator": "not_contains" if item.get("negated") else "contains",
        "expected": {
            "sha256": _preferred(observation.get("sha256"), item.get("sha256")),
            "length": _preferred(observation.get("length"), item.get("length")),
            "search_offset": expected_offset,
            "depth": modifiers.get("depth"),
            "buffer": buffer_name or None,
            "dotprefix": bool(modifiers.get("dotprefix")),
            "bsize": modifiers.get("bsize"),
            "negated": bool(item.get("negated")),
        },
        "observed": {
            "packets_with_marker": _count(observation, "packets_with_marker"),
            "observations": _count(observation, "observations"),
            "offsets": observation.get("offsets") or [],
            "packets_evaluated_for_constraint": evaluated,
            "packets_satisfying_constraint": satisfied,
            "packets_violating_constraint": violated,
        },
        "status": _content_status(observation, packet_features),
        "required": True,
        "source": "deployed_rule",
        "reason": _content_reason(observation, buffer_name),
    }


def append_deployed_content_predicates(
    parsed_rule: object,
    packet_features: dict[str, Any],
    observations: dict[str, dict[str, Any]],
    results: list[dict[str, Any]],
) -> None:
    """Append installed content predicates in their rule order."""
    if not isinstance(parsed_rule, dict):
        return
    contents = parsed_rule.get("contents")
    for item in contents if isinstance(contents, list) else []:
        if not isinstance(item, dict):
            continue
        observation = observations.get(str(item.get("id") or ""), {})
        results.append(_deployed_content_result(parsed_rule, item, observation, packet_features))


def _playbook_status(
    item: dict[str, Any],
    observation: dict[str, Any],
    packet_features: dict[str, Any],
) -> str:
    if not packet_features.get("icmp_packets_parsed"):
        return "unknown"
    expected_offset = item.get("expected_offset")
    observed_count = _count(observation, "observations")
    incomplete = _incomplete_packet_evidence(packet_features)
    if expected_offset is not None:
        if _count(observation, "expected_offset_observations") > 0:
            return "matched"
        return "unknown" if incomplete else "mismatched"
    if observed_count > 0:
        return "matched"
    return "unknown" if incomplete else "mismatched"


def _incomplete_packet_evidence(packet_features: dict[str, Any]) -> bool:
    return bool(
        int(packet_features.get("parse_errors") or 0)
        or packet_features.get("truncated") is True
    )


def _playbook_marker_result(
    item: dict[str, Any],
    observation: dict[str, Any],
    packet_features: dict[str, Any],
) -> dict[str, Any]:
    expected_offset = item.get("expected_offset")
    return {
        "id": str(item.get("id") or ""),
        "field": "icmp.payload_marker",
        "operator": "at_offset" if expected_offset is not None else "contains",
        "expected": {
            "sha256": observation.get("sha256"),
            "length": observation.get("length"),
            "offset": expected_offset,
        },
        "observed": {
            "packets_with_marker": _count(observation, "packets_with_marker"),
            "observations": _count(observation, "observations"),
            "expected_offset_observations": observation.get("expected_offset_observations"),
            "offsets": observation.get("offsets") or [],
        },
        "status": _playbook_status(item, observation, packet_features),
        "required": bool(item.get("required")),
        "source": "playbook",
        "reason": str(item.get("reason") or "")[:1000],
    }


def append_playbook_marker_predicates(
    playbook: object,
    rule_context: dict[str, Any],
    packet_features: dict[str, Any],
    observations: dict[str, dict[str, Any]],
    results: list[dict[str, Any]],
) -> None:
    """Append applicable playbook marker predicates in registry order."""
    if not isinstance(playbook, dict):
        return
    predicates = playbook.get("marker_predicates")
    for item in predicates if isinstance(predicates, list) else []:
        if not _playbook_item_applies(item, rule_context):
            continue
        observation = observations.get(str(item.get("id") or ""), {})
        results.append(_playbook_marker_result(item, observation, packet_features))


def _playbook_item_applies(item: object, rule_context: dict[str, Any]) -> bool:
    if not isinstance(item, dict):
        return False
    applies_to = item.get("applies_to_sids")
    applies = {str(value) for value in applies_to} if isinstance(applies_to, list) else set()
    return not applies or str(rule_context.get("sid") or "") in applies
