"""Characterize detection packet-feature aggregation before owner extraction."""

from __future__ import annotations

import base64
import ast
import importlib
import inspect
import json
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
sys.path.insert(0, str(BIN))
FEATURES = importlib.import_module("detection_validation_features")
OWNER_FILES = (
    "detection_validation_features_state.py",
    "detection_validation_features_markers.py",
    "detection_validation_features_observation.py",
    "detection_validation_features_projection.py",
    "detection_validation_features_workflow.py",
    "detection_validation_features.py",
)


def row(packet: bytes, *, linktype: object = 1) -> dict[str, str]:
    message = {
        "packet": base64.b64encode(packet).decode("ascii"),
        "packet_info": {"linktype": linktype},
    }
    return {"raw_event_json": json.dumps({"message": json.dumps(message)})}


def ipv4_packet(protocol: int, transport: bytes) -> bytes:
    header = bytearray(20)
    header[0] = 0x45
    header[2:4] = struct.pack("!H", len(header) + len(transport))
    header[8] = 64
    header[9] = protocol
    header[12:16] = bytes((192, 0, 2, 1))
    header[16:20] = bytes((198, 51, 100, 2))
    return bytes(12) + b"\x08\x00" + bytes(header) + transport


def icmp_frame(payload: bytes) -> bytes:
    return ipv4_packet(
        1,
        bytes((8, 0, 0, 0)) + struct.pack("!HH", 0x1234, 7) + payload,
    )


def stun_frame() -> bytes:
    stun = (
        struct.pack("!HHI", 0x0001, 0, 0x2112A442)
        + bytes.fromhex("00112233445566778899aabb")
    )
    udp = struct.pack("!HHHH", 12345, 3478, 8 + len(stun), 0) + stun
    return ipv4_packet(17, udp)


class DetectionValidationFeaturesCharacterizationTests(unittest.TestCase):
    def test_legacy_namespace_and_signature_are_frozen(self):
        self.assertEqual(
            sorted(name for name in vars(FEATURES) if not name.startswith("__")),
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
                "_entropy",
                "_icmp_from_packet",
                "_json_object",
                "_nested",
                "_network_packet_envelope",
                "_ordered_deployed_content_constraints",
                "_row_value",
                "_stun_binding_semantics",
                "_udp_from_packet",
                "annotations",
                "base64",
                "collections",
                "extract_group_packet_features",
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
        self.assertEqual(
            str(inspect.signature(FEATURES.extract_group_packet_features)),
            "(grouped_rows: 'Iterable[object]', markers: 'list[dict[str, Any]] | None' = None) -> 'dict[str, Any]'",
        )

    def test_empty_projection_is_frozen(self):
        self.assertEqual(
            FEATURES.extract_group_packet_features([], []),
            {
                "source": "stored-security-onion-alert-packet-copies",
                "application_evidence_source": "stored-security-onion-suricata-application-projection",
                "raw_payloads_included": False,
                "candidate_packets": 0,
                "packets_parsed": 0,
                "content_packets_parsed": 0,
                "packet_protocols": [],
                "unsupported_protocol_packets": 0,
                "icmp_packets_parsed": 0,
                "udp_packets_parsed": 0,
                "udp_payload_lengths": [],
                "stun": {
                    "packets_parsed": 0,
                    "message_types": [],
                    "declared_body_lengths": [],
                    "magic_cookie_valid_packets": 0,
                    "transaction_ids_included": False,
                    "raw_payloads_included": False,
                },
                "parse_errors": 0,
                "truncated": False,
                "icmp_types": [],
                "icmp_codes": [],
                "icmp_identifiers": [],
                "icmp_sequences": [],
                "payload_lengths": [],
                "frame_lengths": [],
                "payload_entropy": {"minimum": None, "maximum": None, "average": None},
                "markers": [],
            },
        )

    def test_mixed_protocol_marker_and_error_projection_is_frozen(self):
        payload = b"AbC--abc"
        tcp = struct.pack("!HHIIHHHH", 1111, 80, 1, 1, 0x5010, 8192, 0, 0)
        malformed = {"raw_event_json": json.dumps({"message": json.dumps({"packet": "%%%"})})}
        markers = [
            {"id": "needle", "hex": "616263", "source": "playbook", "modifiers": {"nocase": True}},
            {"id": "invalid", "hex": "not-hex", "source": "playbook"},
            {"id": "empty", "hex": "", "source": "playbook"},
        ]

        result = FEATURES.extract_group_packet_features(
            [row(icmp_frame(payload)), row(stun_frame()), row(ipv4_packet(6, tcp)), malformed],
            markers,
        )

        self.assertEqual(result["candidate_packets"], 4)
        self.assertEqual(result["packets_parsed"], 3)
        self.assertEqual(result["parse_errors"], 1)
        self.assertEqual(result["icmp_packets_parsed"], 1)
        self.assertEqual(result["udp_packets_parsed"], 1)
        self.assertEqual(result["unsupported_protocol_packets"], 1)
        self.assertEqual(
            result["packet_protocols"],
            [
                {"value": "icmp", "count": 1},
                {"value": "udp", "count": 1},
                {"value": "tcp", "count": 1},
            ],
        )
        self.assertEqual(result["stun"]["message_types"], [{"value": "binding_request", "count": 1}])
        self.assertEqual(
            result["markers"],
            [
                {
                    "id": "needle",
                    "source": "playbook",
                    "sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                    "length": 3,
                    "packets_with_marker": 1,
                    "observations": 2,
                    "expected_offset": None,
                    "expected_offset_observations": None,
                    "offsets": [{"value": 0, "count": 1}, {"value": 5, "count": 1}],
                    "constraint_supported": True,
                    "packets_evaluated_for_constraint": 2,
                    "packets_satisfying_constraint": 1,
                    "packets_violating_constraint": 1,
                }
            ],
        )
        serialized = json.dumps(result)
        self.assertNotIn(base64.b64encode(icmp_frame(payload)).decode("ascii"), serialized)
        self.assertNotIn("00112233445566778899aabb", serialized)

    def test_candidate_limit_and_bad_linktype_fallback_are_frozen(self):
        rows = [row(icmp_frame(b"x"), linktype="bad") for _ in range(FEATURES.MAX_GROUP_PACKETS + 1)]
        result = FEATURES.extract_group_packet_features(rows, [])
        self.assertEqual(result["candidate_packets"], FEATURES.MAX_GROUP_PACKETS)
        self.assertEqual(result["packets_parsed"], FEATURES.MAX_GROUP_PACKETS)
        self.assertTrue(result["truncated"])


class DetectionValidationFeaturesArchitectureTests(unittest.TestCase):
    def test_facade_and_owners_obey_size_and_dependency_boundaries(self):
        expected_imports = {
            "detection_validation_features_state.py": set(),
            "detection_validation_features_markers.py": {
                "detection_validation_packet",
                "detection_validation_features_state",
            },
            "detection_validation_features_observation.py": {
                "detection_validation_rule",
                "detection_validation_packet",
                "detection_validation_features_markers",
                "detection_validation_features_state",
            },
            "detection_validation_features_projection.py": {
                "detection_validation_packet",
                "detection_validation_features_markers",
                "detection_validation_features_state",
            },
            "detection_validation_features_workflow.py": {
                "detection_validation_packet",
                "detection_validation_features_markers",
                "detection_validation_features_observation",
                "detection_validation_features_projection",
                "detection_validation_features_state",
            },
            "detection_validation_features.py": {
                "detection_validation_rule",
                "detection_validation_packet",
                "detection_validation_features_workflow",
            },
        }
        for name in OWNER_FILES:
            with self.subTest(name=name):
                source = (BIN / name).read_text(encoding="utf-8")
                limit = 250 if name == "detection_validation_features.py" else 800
                self.assertLessEqual(len(source.splitlines()), limit)
                imports = {
                    node.module
                    for node in ast.walk(ast.parse(source))
                    if isinstance(node, ast.ImportFrom)
                    and node.module
                    and node.module.startswith("detection_validation")
                }
                self.assertEqual(imports, expected_imports[name])

    def test_feature_facade_imports_from_an_isolated_flat_dependency_unit(self):
        sources = (
            "detection_validation_rule_contract.py",
            "detection_validation_rule_parser.py",
            "detection_validation_rule_context.py",
            "detection_validation_rule_icmp.py",
            "detection_validation_rule.py",
            "detection_validation_packet_network.py",
            "detection_validation_packet_markers.py",
            "detection_validation_packet_content.py",
            "detection_validation_packet_buffers.py",
            "detection_validation_packet.py",
            *OWNER_FILES,
        )
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            for name in sources:
                (target / name).write_bytes((BIN / name).read_bytes())
            completed = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    "-c",
                    (
                        "import sys; sys.path.insert(0, sys.argv[1]); "
                        "import detection_validation_features as f; "
                        "assert f.extract_group_packet_features([], [])['packets_parsed'] == 0"
                    ),
                    directory,
                ],
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_mac_installer_copies_the_complete_feature_dependency_unit(self):
        installer = (BIN / "install-macstudio-stack.zsh").read_text(encoding="utf-8")
        for name in OWNER_FILES:
            with self.subTest(name=name):
                self.assertIn(f"n8n/bin/{name}", installer)


if __name__ == "__main__":
    unittest.main()
