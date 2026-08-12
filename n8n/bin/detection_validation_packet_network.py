"""Bounded network and STUN metadata decoding for detection validation."""

from __future__ import annotations

import struct
from typing import Any

from detection_validation_rule import MAX_PACKET_BYTES


def _ethernet_protocol(packet: bytes, linktype: int) -> tuple[int, int] | None:
    if linktype == 1:
        if len(packet) < 14:
            return None
        ethertype = struct.unpack("!H", packet[12:14])[0]
        offset = 14
        while ethertype in {0x8100, 0x88A8, 0x9100}:
            if len(packet) < offset + 4:
                return None
            ethertype = struct.unpack("!H", packet[offset + 2 : offset + 4])[0]
            offset += 4
        return ethertype, offset
    if packet[0] >> 4 == 4:
        return 0x0800, 0
    if packet[0] >> 4 == 6:
        return 0x86DD, 0
    return 0, 0


def _ipv4_envelope(packet: bytes, offset: int) -> dict[str, Any] | None:
    if len(packet) < offset + 20 or packet[offset] >> 4 != 4:
        return None
    ihl = (packet[offset] & 0x0F) * 4
    if ihl < 20 or len(packet) < offset + ihl:
        return None
    total_length = struct.unpack("!H", packet[offset + 2 : offset + 4])[0]
    if total_length < ihl:
        return None
    return {
        "family": "ipv4",
        "protocol_number": int(packet[offset + 9]),
        "transport_offset": offset + ihl,
        "end": min(len(packet), offset + total_length),
    }


def _ipv6_envelope(packet: bytes, offset: int) -> dict[str, Any] | None:
    if len(packet) < offset + 40 or packet[offset] >> 4 != 6:
        return None
    payload_length = struct.unpack("!H", packet[offset + 4 : offset + 6])[0]
    return {
        "family": "ipv6",
        "protocol_number": int(packet[offset + 6]),
        "transport_offset": offset + 40,
        "end": min(len(packet), offset + 40 + payload_length),
    }


def _network_packet_envelope(
    packet: bytes,
    linktype: int = 1,
) -> dict[str, Any] | None:
    """Return bounded IP transport metadata without exposing packet contents."""
    if not packet or len(packet) > MAX_PACKET_BYTES:
        return None
    protocol = _ethernet_protocol(packet, linktype)
    if protocol is None:
        return None
    ethertype, offset = protocol
    if ethertype == 0x0800:
        return _ipv4_envelope(packet, offset)
    if ethertype == 0x86DD:
        return _ipv6_envelope(packet, offset)
    return None


def _udp_from_packet(
    packet: bytes,
    envelope: dict[str, Any],
) -> dict[str, Any] | None:
    if int(envelope.get("protocol_number", -1)) != 17:
        return None
    offset = int(envelope.get("transport_offset") or 0)
    end = int(envelope.get("end") or 0)
    if offset < 0 or end < offset + 8 or len(packet) < offset + 8:
        return None
    source_port, destination_port, udp_length = struct.unpack(
        "!HHH", packet[offset : offset + 6]
    )
    if udp_length < 8 or offset + udp_length > end:
        return None
    return {
        "source_port": source_port,
        "destination_port": destination_port,
        "payload_length": udp_length - 8,
        "_payload": packet[offset + 8 : offset + udp_length],
    }


def _stun_binding_semantics(payload: bytes) -> dict[str, Any] | None:
    """Recognize a complete RFC 5389 STUN message without retaining identifiers."""
    if len(payload) < 20:
        return None
    message_type, message_length, magic_cookie = struct.unpack("!HHI", payload[:8])
    if message_type & 0xC000 or magic_cookie != 0x2112A442:
        return None
    if message_length % 4 or 20 + message_length > len(payload):
        return None
    method = (
        (message_type & 0x000F)
        | ((message_type & 0x00E0) >> 1)
        | ((message_type & 0x3E00) >> 2)
    )
    message_class = ((message_type & 0x0010) >> 4) | (
        (message_type & 0x0100) >> 7
    )
    if method != 0x001:
        return None
    kind = {
        0: "binding_request",
        1: "binding_indication",
        2: "binding_success_response",
        3: "binding_error_response",
    }.get(message_class)
    if kind is None:
        return None
    return {"kind": kind, "declared_body_bytes": message_length}
