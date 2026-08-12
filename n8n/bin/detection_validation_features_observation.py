"""Decode stored packet copies and update bounded feature state."""
from __future__ import annotations

import base64
from typing import Any

from detection_validation_rule import _icmp_from_packet, _json_object, _nested, _row_value
from detection_validation_packet import (
    MAX_PACKET_BASE64_CHARS,
    _bounded_application_buffers,
    _entropy,
    _network_packet_envelope,
    _stun_binding_semantics,
    _udp_from_packet,
)
from detection_validation_features_markers import observe_content, select_markers
from detection_validation_features_state import FeatureState


def _row_sources(row: object) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    raw = _json_object(_row_value(row, "raw_event_json"))
    alert = _json_object(_row_value(row, "alert_json"))
    if not raw:
        raw = _json_object(_nested(alert, "security_onion.raw_event"))
    return raw, alert, _json_object(raw.get("message"))


def _decode_packet(
    message: dict[str, Any],
    state: FeatureState,
) -> tuple[bytes, int, dict[str, Any]] | None:
    packet_text = str(message.get("packet") or "").strip()
    if not packet_text:
        return None
    state.candidate_count += 1
    if len(packet_text) > MAX_PACKET_BASE64_CHARS:
        state.parse_errors += 1
        return None
    try:
        packet = base64.b64decode(packet_text, validate=True)
    except (ValueError, TypeError):
        state.parse_errors += 1
        return None
    try:
        linktype = int(_nested(message, "packet_info.linktype") or 1)
    except (TypeError, ValueError):
        linktype = 1
    envelope = _network_packet_envelope(packet, linktype)
    if not envelope:
        state.parse_errors += 1
        return None
    return packet, linktype, envelope


def _protocol_name(protocol_number: int) -> str:
    return {
        1: "icmp",
        6: "tcp",
        17: "udp",
        58: "icmpv6",
    }.get(protocol_number, f"ip_protocol_{protocol_number}")


def _observe_application_buffers(
    buffers: dict[str, bytes],
    marker_values: list[tuple[dict[str, Any], bytes]],
    state: FeatureState,
) -> bool:
    row_has_content = False
    for buffer_name, payload in buffers.items():
        selected = select_markers(marker_values, buffer_name)
        row_has_content = (
            observe_content(payload, selected, state, application_buffer=buffer_name)
            or row_has_content
        )
    return row_has_content


def _observe_icmp(
    packet: bytes,
    linktype: int,
    state: FeatureState,
) -> bytes | None:
    parsed = _icmp_from_packet(packet, linktype)
    if not parsed:
        state.parse_errors += 1
        return None
    state.parsed_packet_count += 1
    state.icmp_packet_count += 1
    payload = parsed.pop("_payload")
    state.type_counts[parsed["type"]] += 1
    state.code_counts[parsed["code"]] += 1
    state.identifiers[parsed["identifier"]] += 1
    state.sequences[parsed["sequence"]] += 1
    state.payload_lengths[len(payload)] += 1
    state.frame_lengths[parsed["frame_bytes"]] += 1
    state.entropies.append(_entropy(payload))
    return payload


def _observe_udp(
    packet: bytes,
    envelope: dict[str, Any],
    state: FeatureState,
) -> bytes | None:
    parsed = _udp_from_packet(packet, envelope)
    if not parsed:
        state.parse_errors += 1
        return None
    state.parsed_packet_count += 1
    state.udp_packet_count += 1
    payload = parsed.pop("_payload")
    state.udp_payload_lengths[len(payload)] += 1
    stun = _stun_binding_semantics(payload)
    if stun:
        state.stun_kinds[str(stun["kind"])] += 1
        state.stun_body_lengths[int(stun["declared_body_bytes"])] += 1
    return payload


def _observe_transport(
    packet: bytes,
    linktype: int,
    envelope: dict[str, Any],
    state: FeatureState,
) -> bytes | None:
    protocol_number = int(envelope.get("protocol_number", -1))
    if protocol_number in {1, 58}:
        return _observe_icmp(packet, linktype, state)
    if protocol_number == 17:
        return _observe_udp(packet, envelope, state)
    state.parsed_packet_count += 1
    state.unsupported_protocol_packets += 1
    return None


def observe_row(
    row: object,
    marker_values: list[tuple[dict[str, Any], bytes]],
    state: FeatureState,
) -> None:
    """Observe one stored alert row without retaining its packet bytes."""
    raw, alert, message = _row_sources(row)
    application_buffers = _bounded_application_buffers(raw, message, alert, marker_values)
    decoded = _decode_packet(message, state)
    if decoded is None:
        return
    packet, linktype, envelope = decoded
    protocol_number = int(envelope.get("protocol_number", -1))
    state.protocol_counts[_protocol_name(protocol_number)] += 1
    row_has_content = _observe_application_buffers(application_buffers, marker_values, state)
    payload = _observe_transport(packet, linktype, envelope, state)
    if protocol_number not in {1, 17, 58}:
        if row_has_content:
            state.content_packet_count += 1
        return
    if payload is None:
        return
    raw_markers = select_markers(marker_values, "", "pkt_data")
    row_has_content = observe_content(payload, raw_markers, state) or row_has_content
    if row_has_content:
        state.content_packet_count += 1
