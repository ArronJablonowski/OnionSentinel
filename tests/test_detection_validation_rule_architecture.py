"""Characterize detection-validation rule semantics before owner extraction."""

from __future__ import annotations

import ast
import importlib
import inspect
import struct
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
sys.path.insert(0, str(BIN))
RULE = importlib.import_module("detection_validation_rule")
OWNER_FILES = (
    "detection_validation_rule_contract.py",
    "detection_validation_rule_parser.py",
    "detection_validation_rule_context.py",
    "detection_validation_rule_icmp.py",
    "detection_validation_rule.py",
)


def ipv4_icmp_frame(*, vlan: bool = False, payload: bytes = b"payload") -> bytes:
    icmp = bytes((8, 0, 0, 0)) + struct.pack("!HH", 0x1234, 7) + payload
    ip = bytearray(20)
    ip[0] = 0x45
    ip[2:4] = struct.pack("!H", len(ip) + len(icmp))
    ip[9] = 1
    ip[12:16] = bytes((192, 0, 2, 1))
    ip[16:20] = bytes((198, 51, 100, 2))
    ethernet = bytes(12) + (b"\x81\x00" if vlan else b"\x08\x00")
    tag = b"\x00\x01\x08\x00" if vlan else b""
    return ethernet + tag + bytes(ip) + icmp


def ipv6_icmp_packet(payload: bytes = b"v6") -> bytes:
    icmp = bytes((128, 0, 0, 0)) + struct.pack("!HH", 0xBEEF, 9) + payload
    header = bytearray(40)
    header[0] = 0x60
    header[4:6] = struct.pack("!H", len(icmp))
    header[6] = 58
    header[8:24] = bytes.fromhex("20010db8000000000000000000000001")
    header[24:40] = bytes.fromhex("20010db8000000000000000000000002")
    return bytes(header) + icmp


class DetectionValidationRuleCharacterizationTests(unittest.TestCase):
    def test_legacy_namespace_and_signatures_are_frozen(self):
        self.assertEqual(
            sorted(name for name in vars(RULE) if not name.startswith("__")),
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
                "_decode_suricata_content",
                "_icmp_from_packet",
                "_json_object",
                "_nested",
                "_row_value",
                "_safe_ascii",
                "_split_rule_options",
                "annotations",
                "base64",
                "collections",
                "extract_rule_context",
                "hashlib",
                "ipaddress",
                "json",
                "math",
                "parse_suricata_rule",
                "re",
                "struct",
            ],
        )
        expected = {
            "_decode_suricata_content": "(value: 'str') -> 'bytes'",
            "_icmp_from_packet": "(packet: 'bytes', linktype: 'int' = 1) -> 'dict[str, Any] | None'",
            "_json_object": "(value: 'object') -> 'dict[str, Any]'",
            "_nested": "(value: 'object', dotted_path: 'str') -> 'object'",
            "_row_value": "(row: 'object', key: 'str') -> 'object'",
            "_safe_ascii": "(value: 'bytes') -> 'str'",
            "_split_rule_options": "(text: 'str') -> 'list[str]'",
            "extract_rule_context": "(alert_payload: 'object', raw_event_payload: 'object' = None, database_rule_id: 'object' = None) -> 'dict[str, Any]'",
            "parse_suricata_rule": "(rule_text: 'object') -> 'dict[str, Any]'",
        }
        self.assertEqual(
            {name: str(inspect.signature(getattr(RULE, name))) for name in expected},
            expected,
        )

    def test_rule_option_content_and_state_projection_are_frozen(self):
        rule = (
            'alert udp any any -> any any (msg:"unit; rule"; '
            'dns_query; dotprefix; content:!"|01|abc"; nocase; distance:2; '
            'fast_pattern; within:8; pkt_data; content:"ok"; startswith; '
            'itype:8; icode:<4; xbits:isset, ET.STUN, track ip_dst; '
            'threshold:type both, track by_src, count 2, seconds 60; '
            'unknown_match:value; sid:2016150; rev:4;)'
        )
        parsed = RULE.parse_suricata_rule(rule)
        self.assertTrue(parsed["available"])
        self.assertEqual((parsed["protocol"], parsed["sid"], parsed["revision"]), ("udp", "2016150", 4))
        self.assertEqual(
            parsed["predicates"],
            [
                {
                    "field": "icmp.type",
                    "operator": "equals",
                    "expected": 8,
                    "required": True,
                    "source": "deployed_rule",
                },
                {
                    "field": "icmp.code",
                    "operator": "unsupported_expression",
                    "expected": "<4",
                    "required": True,
                    "source": "deployed_rule",
                },
            ],
        )
        self.assertEqual(
            [
                (item["hex"], item["negated"], item["buffer"], item["modifiers"])
                for item in parsed["contents"]
            ],
            [
                (
                    "01616263",
                    True,
                    "dns.query",
                    {"dotprefix": True, "nocase": True, "distance": "2", "within": "8"},
                ),
                ("6f6b", False, "", {"startswith": True}),
            ],
        )
        self.assertEqual(
            parsed["state_operations"],
            [{"kind": "xbits", "operation": "isset", "name": "ET.STUN", "track": "track ip_dst"}],
        )
        self.assertEqual(
            [item["option"] for item in parsed["unsupported_match_options"]],
            ["unknown_match"],
        )

    def test_unavailable_rule_and_context_identity_precedence_are_frozen(self):
        unavailable = RULE.parse_suricata_rule("not a rule")
        self.assertEqual(
            {key: unavailable[key] for key in ("available", "predicates", "contents", "state_operations")},
            {"available": False, "predicates": [], "contents": [], "state_operations": []},
        )
        raw = {
            "message": {
                "alert": {
                    "signature_id": "2016150",
                    "rev": "4",
                    "signature": "raw name",
                    "category": "raw category",
                    "rule": "alert icmp any any -> any any (itype:8; sid:2016149; rev:5;)",
                }
            },
            "rule": {"id": "ec7d130a-a537-4c61-8325-69f0fe7d24e8", "ruleset": "ET INFO"},
        }
        context = RULE.extract_rule_context(
            {"rule_id": "999999", "rule_name": "stored name"},
            raw,
            "999998",
        )
        self.assertEqual(context["sid"], "2016150")
        self.assertEqual(context["record_rule_id"], "999998")
        self.assertEqual(context["revision"], 4)
        self.assertEqual(context["name"], "stored name")
        self.assertEqual(context["ruleset"], "ET INFO")
        self.assertEqual(
            context["identity_conflicts"],
            {"sid": ["2016149", "2016150", "999998", "999999"], "revision": [4, 5]},
        )

    def test_icmp_linktype_vlan_and_ip_family_boundaries_are_frozen(self):
        expected_v4 = {
            "family": "icmp",
            "type": 8,
            "code": 0,
            "identifier": 0x1234,
            "sequence": 7,
            "source_ip": "192.0.2.1",
            "destination_ip": "198.51.100.2",
            "frame_bytes": 49,
            "_payload": b"payload",
        }
        self.assertEqual(RULE._icmp_from_packet(ipv4_icmp_frame()), expected_v4)
        self.assertEqual(
            RULE._icmp_from_packet(ipv4_icmp_frame(vlan=True)),
            {**expected_v4, "frame_bytes": 53},
        )
        self.assertEqual(
            RULE._icmp_from_packet(ipv6_icmp_packet(), linktype=101),
            {
                "family": "icmpv6",
                "type": 128,
                "code": 0,
                "identifier": 0xBEEF,
                "sequence": 9,
                "source_ip": "2001:db8::1",
                "destination_ip": "2001:db8::2",
                "frame_bytes": 50,
                "_payload": b"v6",
            },
        )
        for packet, linktype in ((b"", 1), (b"short", 1), (bytes(20), 101)):
            with self.subTest(length=len(packet), linktype=linktype):
                self.assertIsNone(RULE._icmp_from_packet(packet, linktype))


class DetectionValidationRuleArchitectureTests(unittest.TestCase):
    def test_facade_and_owners_obey_size_and_dependency_boundaries(self):
        expected_imports = {
            "detection_validation_rule_contract.py": set(),
            "detection_validation_rule_parser.py": {"detection_validation_rule_contract"},
            "detection_validation_rule_context.py": {
                "detection_validation_rule_contract",
                "detection_validation_rule_parser",
            },
            "detection_validation_rule_icmp.py": {"detection_validation_rule_contract"},
            "detection_validation_rule.py": {
                "detection_validation_rule_contract",
                "detection_validation_rule_parser",
                "detection_validation_rule_context",
                "detection_validation_rule_icmp",
            },
        }
        for name in OWNER_FILES:
            with self.subTest(name=name):
                source = (BIN / name).read_text(encoding="utf-8")
                limit = 250 if name == "detection_validation_rule.py" else 800
                self.assertLessEqual(len(source.splitlines()), limit)
                imports = {
                    node.module
                    for node in ast.walk(ast.parse(source))
                    if isinstance(node, ast.ImportFrom)
                    and node.module
                    and node.module.startswith("detection_validation")
                }
                self.assertEqual(imports, expected_imports[name])

    def test_rule_facade_imports_from_an_isolated_flat_dependency_unit(self):
        with __import__("tempfile").TemporaryDirectory() as directory:
            target = Path(directory)
            for name in OWNER_FILES:
                (target / name).write_bytes((BIN / name).read_bytes())
            completed = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    "-c",
                    (
                        "import sys; sys.path.insert(0, sys.argv[1]); "
                        "import detection_validation_rule as r; "
                        "assert r.parse_suricata_rule('alert icmp any any -> any any "
                        "(itype:8; sid:1; rev:1;)')['sid'] == '1'"
                    ),
                    directory,
                ],
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_mac_installer_copies_the_complete_rule_dependency_unit(self):
        installer = (BIN / "install-macstudio-stack.zsh").read_text(encoding="utf-8")
        for name in OWNER_FILES:
            with self.subTest(name=name):
                self.assertIn(f"n8n/bin/{name}", installer)


if __name__ == "__main__":
    unittest.main()
