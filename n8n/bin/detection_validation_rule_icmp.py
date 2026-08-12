"""Bounded Ethernet, VLAN, IPv4, IPv6, and ICMP metadata decoding."""

from __future__ import annotations

from typing import Any

from detection_validation_rule_contract import (
    MAX_PACKET_BYTES,
    ipaddress,
    struct,
)


def _link_layer(packet: bytes, linktype: int) -> tuple[int, int] | None:
    offset = 0
    ethertype = 0
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
    elif packet[0] >> 4 == 4:
        ethertype = 0x0800
    elif packet[0] >> 4 == 6:
        ethertype = 0x86DD
    return ethertype, offset


def _ipv4_context(packet: bytes, offset: int) -> tuple[int, str, str, int] | None:
    if len(packet) < offset + 20:
        return None
    ihl = (packet[offset] & 0x0F) * 4
    if ihl < 20 or len(packet) < offset + ihl + 8 or packet[offset + 9] != 1:
        return None
    total_length = struct.unpack("!H", packet[offset + 2 : offset + 4])[0]
    end = min(len(packet), offset + max(total_length, ihl + 8))
    source = str(ipaddress.ip_address(packet[offset + 12 : offset + 16]))
    destination = str(ipaddress.ip_address(packet[offset + 16 : offset + 20]))
    return end, source, destination, offset + ihl


def _ipv6_context(packet: bytes, offset: int) -> tuple[int, str, str, int] | None:
    if len(packet) < offset + 48 or packet[offset + 6] != 58:
        return None
    payload_length = struct.unpack("!H", packet[offset + 4 : offset + 6])[0]
    end = min(len(packet), offset + 40 + payload_length)
    source = str(ipaddress.ip_address(packet[offset + 8 : offset + 24]))
    destination = str(ipaddress.ip_address(packet[offset + 24 : offset + 40]))
    return end, source, destination, offset + 40


def _network_context(
    packet: bytes,
    ethertype: int,
    offset: int,
) -> tuple[int, str, str, int] | None:
    if ethertype == 0x0800:
        return _ipv4_context(packet, offset)
    if ethertype == 0x86DD:
        return _ipv6_context(packet, offset)
    return None


def _icmp_from_packet(packet: bytes, linktype: int = 1) -> dict[str, Any] | None:
    if not packet or len(packet) > MAX_PACKET_BYTES:
        return None
    link_layer = _link_layer(packet, linktype)
    if link_layer is None:
        return None
    ethertype, offset = link_layer
    network = _network_context(packet, ethertype, offset)
    if network is None:
        return None
    end, source, destination, icmp_offset = network
    if end < icmp_offset + 8:
        return None
    icmp_type, code = packet[icmp_offset], packet[icmp_offset + 1]
    identifier, sequence = struct.unpack(
        "!HH", packet[icmp_offset + 4 : icmp_offset + 8]
    )
    return {
        "family": "icmpv6" if ethertype == 0x86DD else "icmp",
        "type": icmp_type,
        "code": code,
        "identifier": identifier,
        "sequence": sequence,
        "source_ip": source,
        "destination_ip": destination,
        "frame_bytes": len(packet),
        "_payload": packet[icmp_offset + 8 : end],
    }
