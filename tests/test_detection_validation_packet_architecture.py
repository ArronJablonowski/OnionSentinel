"""Characterize detection packet semantics before owner extraction."""

from __future__ import annotations

import importlib
import inspect
import json
import struct
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
sys.path.insert(0, str(BIN))
PACKET = importlib.import_module("detection_validation_packet")


def stun_ipv4_packet(*, ethernet: bool = True, vlan: bool = False) -> bytes:
    stun = struct.pack("!HHI", 0x0001, 0, 0x2112A442) + b"0" * 12
    udp = struct.pack("!HHHH", 12345, 3478, 8 + len(stun), 0) + stun
    ip = (
        bytes([0x45, 0])
        + struct.pack("!H", 20 + len(udp))
        + b"\x00\x00\x00\x00"
        + bytes([64, 17])
        + b"\x00\x00"
        + b"\x0a\x00\x00\x01"
        + b"\x0a\x00\x00\x02"
        + udp
    )
    if not ethernet:
        return ip
    if vlan:
        return (
            b"\x00" * 12
            + struct.pack("!H", 0x8100)
            + b"\x00\x01"
            + struct.pack("!H", 0x0800)
            + ip
        )
    return b"\x00" * 12 + struct.pack("!H", 0x0800) + ip


class DetectionValidationPacketCharacterizationTests(unittest.TestCase):
    def test_legacy_namespace_and_local_signatures_are_frozen(self):
        self.assertEqual(
            sorted(name for name in vars(PACKET) if not name.startswith("__")),
            [
                "APPLICATION_STICKY_BUFFERS",
                "Any",
                "Iterable",
                "MAX_COUNTER_VALUES",
                "MAX_GROUP_PACKETS",
                "MAX_MARKERS",
                "MAX_MARKER_MATCHES_PER_PACKET",
                "MAX_PACKET_BASE64_CHARS",
                "MAX_PACKET_BYTES",
                "MAX_PLAYBOOK_BYTES",
                "PLAYBOOK_SCHEMA",
                "Path",
                "REV_RE",
                "SID_RE",
                "VALIDATION_SCHEMA",
                "_bounded_application_buffers",
                "_bounded_counter",
                "_bounded_text_counter",
                "_content_constraint",
                "_content_evaluation_supported",
                "_content_match_positions",
                "_entropy",
                "_nested",
                "_network_packet_envelope",
                "_nonnegative_modifier",
                "_ordered_deployed_content_constraints",
                "_stun_binding_semantics",
                "_udp_from_packet",
                "annotations",
                "base64",
                "collections",
                "extract_rule_context",
                "hashlib",
                "ipaddress",
                "json",
                "marker_specs",
                "math",
                "parse_suricata_rule",
                "re",
                "struct",
            ],
        )
        expected = {
            "_bounded_application_buffers": "(raw: 'dict[str, Any]', message: 'dict[str, Any]', alert: 'dict[str, Any]', marker_values: 'list[tuple[dict[str, Any], bytes]] | None' = None) -> 'dict[str, bytes]'",
            "_bounded_counter": "(counter: 'collections.Counter[int]') -> 'list[dict[str, int]]'",
            "_bounded_text_counter": "(counter: 'collections.Counter[str]') -> 'list[dict[str, Any]]'",
            "_content_constraint": "(payload: 'bytes', marker: 'bytes', spec: 'dict[str, Any]') -> 'bool | None'",
            "_content_evaluation_supported": "(spec: 'dict[str, Any]', *, application_buffer: 'str | None' = None) -> 'bool'",
            "_content_match_positions": "(payload: 'bytes', marker: 'bytes', spec: 'dict[str, Any]', *, previous_match_end: 'int | None' = None, application_buffer: 'str | None' = None) -> 'list[int] | None'",
            "_entropy": "(payload: 'bytes') -> 'float'",
            "_network_packet_envelope": "(packet: 'bytes', linktype: 'int' = 1) -> 'dict[str, Any] | None'",
            "_nonnegative_modifier": "(value: 'object') -> 'int | None'",
            "_ordered_deployed_content_constraints": "(payload: 'bytes', marker_values: 'list[tuple[dict[str, Any], bytes]]', *, application_buffer: 'str | None' = None) -> 'dict[str, bool | None]'",
            "_stun_binding_semantics": "(payload: 'bytes') -> 'dict[str, Any] | None'",
            "_udp_from_packet": "(packet: 'bytes', envelope: 'dict[str, Any]') -> 'dict[str, Any] | None'",
            "marker_specs": "(rule_context: 'dict[str, Any]', playbook: 'dict[str, Any] | None') -> 'list[dict[str, Any]]'",
        }
        self.assertEqual(
            {name: str(inspect.signature(getattr(PACKET, name))) for name in expected},
            expected,
        )

    def test_network_udp_and_stun_metadata_are_frozen(self):
        cases = (
            (stun_ipv4_packet(ethernet=False), 101, 20, 48),
            (stun_ipv4_packet(), 1, 34, 62),
            (stun_ipv4_packet(vlan=True), 1, 38, 66),
        )
        for packet, linktype, transport_offset, end in cases:
            with self.subTest(linktype=linktype, transport_offset=transport_offset):
                envelope = PACKET._network_packet_envelope(packet, linktype)
                self.assertEqual(
                    envelope,
                    {
                        "family": "ipv4",
                        "protocol_number": 17,
                        "transport_offset": transport_offset,
                        "end": end,
                    },
                )
                udp = PACKET._udp_from_packet(packet, envelope)
                self.assertEqual(
                    {key: value for key, value in udp.items() if key != "_payload"},
                    {
                        "source_port": 12345,
                        "destination_port": 3478,
                        "payload_length": 20,
                    },
                )
                self.assertEqual(
                    PACKET._stun_binding_semantics(udp["_payload"]),
                    {"kind": "binding_request", "declared_body_bytes": 0},
                )
        self.assertIsNone(PACKET._network_packet_envelope(b"bad"))
        self.assertIsNone(PACKET._stun_binding_semantics(b"bad"))

    def test_marker_and_content_cursor_semantics_are_frozen(self):
        context = {
            "sid": "1",
            "parsed_rule": {
                "contents": [
                    {"id": "one", "hex": "4142", "modifiers": {}, "buffer": "pkt_data"},
                    {"id": "one", "hex": "4142", "modifiers": {}, "buffer": "pkt_data"},
                    {"id": "neg", "hex": "43", "negated": True},
                ]
            },
        }
        playbook = {
            "marker_predicates": [
                {"id": "pb", "hex": "44", "applies_to_sids": ["1"]},
                {"id": "skip", "hex": "45", "applies_to_sids": ["2"]},
            ]
        }
        self.assertEqual(
            json.loads(json.dumps(PACKET.marker_specs(context, playbook))),
            [
                {"id": "one", "hex": "4142", "modifiers": {}, "buffer": "pkt_data", "negated": False, "source": "deployed_rule"},
                {"id": "neg", "hex": "43", "modifiers": {}, "buffer": "", "negated": True, "source": "deployed_rule"},
                {"id": "pb", "hex": "44", "expected_offset": None, "modifiers": {}, "negated": False, "source": "playbook"},
            ],
        )
        payload = b"xxABCyDEFzz"
        specs = [
            {"id": "a", "source": "deployed_rule", "buffer": "pkt_data", "modifiers": {}},
            {"id": "b", "source": "deployed_rule", "buffer": "pkt_data", "modifiers": {"distance": "1", "within": "4"}},
            {"id": "c", "source": "deployed_rule", "buffer": "pkt_data", "modifiers": {"offset": "1", "depth": "4", "nocase": True}},
            {"id": "neg", "source": "deployed_rule", "buffer": "pkt_data", "modifiers": {}, "negated": True},
        ]
        markers = [b"ABC", b"DEF", b"Xab", b"NO"]
        self.assertEqual(PACKET._content_match_positions(payload, markers[0], specs[0]), [2])
        self.assertIsNone(PACKET._content_constraint(payload, markers[1], specs[1]))
        self.assertEqual(PACKET._content_match_positions(payload, markers[2], specs[2]), [1])
        self.assertTrue(PACKET._content_constraint(payload, markers[3], specs[3]))
        self.assertEqual(
            PACKET._ordered_deployed_content_constraints(payload, list(zip(specs, markers))),
            {"a": True, "b": True, "c": True, "neg": True},
        )

    def test_application_buffer_projection_is_frozen_and_bounded(self):
        raw = {
            "network": {"data": {"decoded": "GET /a HTTP/1.1\r\nHost: Example.COM\r\nUser-Agent: Unit\r\nServer: Test\r\n"}},
            "dns": {"query": {"name": "dns.example."}},
            "tls": {"server": {"name": "tls.example."}},
        }
        self.assertEqual(
            PACKET._bounded_application_buffers(raw, {}, {}),
            {
                "http.method": b"GET",
                "http.uri": b"/a",
                "http.host": b"Example.COM",
                "http.user_agent": b"Unit",
                "http.server": b"Test",
                "dns.query": b"dns.example",
                "tls.sni": b"tls.example",
            },
        )
        oversized = "x" * (PACKET.MAX_PACKET_BYTES + 1)
        self.assertEqual(
            PACKET._bounded_application_buffers(
                {"network": {"data": {"decoded": oversized}}}, {}, {}
            ),
            {},
        )


if __name__ == "__main__":
    unittest.main()
