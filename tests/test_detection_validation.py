#!/usr/bin/env python3
"""Deterministic rule-intent and stored-packet validation regressions."""
from __future__ import annotations

import base64
import importlib.util
import json
import socket
import struct
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
BIN_DIR = REPO_ROOT / "n8n" / "bin"
MODULE_PATH = BIN_DIR / "detection_validation.py"


def load_module():
    spec = importlib.util.spec_from_file_location("detection_validation_test", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


validation = load_module()


def icmp_frame(
    *,
    icmp_type: int = 0,
    code: int = 0,
    identifier: int = 36425,
    sequence: int = 2,
    payload: bytes,
) -> bytes:
    destination_mac = bytes.fromhex("969eaec0fe6b")
    source_mac = bytes.fromhex("90ec77890954")
    ethernet = destination_mac + source_mac + struct.pack("!H", 0x0800)
    total_length = 20 + 8 + len(payload)
    ipv4 = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        1,
        0,
        64,
        1,
        0,
        socket.inet_aton("192.0.2.41"),
        socket.inet_aton("192.0.2.42"),
    )
    icmp = struct.pack("!BBHHH", icmp_type, code, 0, identifier, sequence)
    return ethernet + ipv4 + icmp + payload


def alert_row(packet: bytes) -> dict[str, str]:
    raw_rule = (
        'alert icmp $HOME_NET any -> any any '
        '(msg:"ET MALWARE BPFDoor ICMP Echo Reply, Heartbeat (Outbound)"; '
        "xbits:isset,ET.bpfdoor,track ip_src; itype:0; sid:2069174; rev:5;)"
    )
    message = {
        "timestamp": "2026-07-23  20:53:28.042-06:00",
        "src_ip": "192.0.2.41",
        "dest_ip": "192.0.2.42",
        "proto": "ICMP",
        "alert": {
            "signature_id": 2069174,
            "rev": 5,
            "signature": "ET MALWARE BPFDoor ICMP Echo Reply, Heartbeat (Outbound)",
            "rule": raw_rule,
        },
        "packet": base64.b64encode(packet).decode("ascii"),
        "packet_info": {"linktype": 1},
    }
    raw = {
        "message": json.dumps(message),
        "rule": {"rule": raw_rule, "rev": 5, "ruleset": "Emerging Threats"},
    }
    alert = {
        "rule_id": "2069174",
        "rule_name": message["alert"]["signature"],
        "rule_ruleset": "Emerging Threats",
        "security_onion": {"raw_event": raw},
    }
    return {
        "rule_id": "2069174",
        "raw_event_json": json.dumps(raw),
        "alert_json": json.dumps(alert),
    }


class DetectionValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = validation.load_detection_playbooks(
            REPO_ROOT / "n8n" / "config" / "detection_playbooks.json"
        )

    def test_rule_parser_extracts_state_and_packet_predicates(self) -> None:
        rule = (
            'alert icmp $HOME_NET any -> any any (msg:"fixture"; '
            'content:"X:"; offset:16; depth:2; xbits:set,ET.fixture,track ip_src; '
            "itype:8; icode:0; sid:999001; rev:3;)"
        )

        parsed = validation.parse_suricata_rule(rule)

        self.assertTrue(parsed["available"])
        self.assertEqual(parsed["sid"], "999001")
        self.assertEqual(parsed["revision"], 3)
        self.assertEqual(
            {(item["field"], item["expected"]) for item in parsed["predicates"]},
            {("icmp.type", 8), ("icmp.code", 0)},
        )
        self.assertEqual(parsed["contents"][0]["printable"], "X:")
        self.assertEqual(parsed["contents"][0]["modifiers"]["offset"], "16")
        self.assertEqual(parsed["state_operations"][0]["operation"], "set")

    def test_bpfdoor_false_positive_pattern_is_a_deterministic_intent_mismatch(self) -> None:
        rows = []
        for sequence, marker_offset in ((2, 5), (3, None), (4, None)):
            payload = bytearray(b"A" * 320)
            if marker_offset is not None:
                payload[marker_offset:marker_offset + 2] = b"X:"
            rows.append(alert_row(icmp_frame(sequence=sequence, code=0, payload=bytes(payload))))
        context = validation.extract_rule_context(
            json.loads(rows[0]["alert_json"]),
            json.loads(rows[0]["raw_event_json"]),
            "2069174",
        )
        playbook = validation.resolve_detection_playbook(self.registry, context)
        markers = validation.marker_specs(context, playbook)

        features = validation.extract_group_packet_features(rows, markers)
        result = validation.build_detection_validation(context, features, playbook)

        self.assertEqual(features["icmp_packets_parsed"], 3)
        self.assertEqual(features["icmp_codes"], [{"value": 0, "count": 3}])
        self.assertEqual(
            {item["value"] for item in features["icmp_sequences"]},
            {2, 3, 4},
        )
        self.assertEqual(features["markers"], [])
        self.assertEqual(result["event_status"], "observed")
        self.assertEqual(result["rule_intent_match"], "mismatch")
        self.assertTrue(result["rule_drift"]["detected"])
        self.assertIn("icmp.code", result["rule_drift"]["missing_installed_constraints"])
        self.assertFalse(features["raw_payloads_included"])
        serialized = json.dumps(result)
        raw_message = json.loads(json.loads(rows[0]["raw_event_json"])["message"])
        self.assertNotIn(raw_message["packet"], serialized)
        self.assertNotIn(bytes(payload).hex(), serialized)

    def test_security_onion_rule_uuid_is_not_treated_as_a_suricata_sid(self) -> None:
        row = alert_row(icmp_frame(code=0, sequence=2, payload=b"A" * 320))
        rule_uuid = "93fcfa6f-e11d-4c24-9f55-0c83593fd3b5"
        alert = json.loads(row["alert_json"])
        alert["rule_id"] = rule_uuid
        raw = json.loads(row["raw_event_json"])
        raw["rule"]["id"] = rule_uuid

        context = validation.extract_rule_context(alert, raw, rule_uuid)

        self.assertEqual(context["record_rule_id"], rule_uuid)
        self.assertEqual(context["sid"], "2069174")
        self.assertEqual(context["identity_conflicts"]["sid"], [])
        playbook = validation.resolve_detection_playbook(self.registry, context)
        self.assertIsNotNone(playbook)
        self.assertEqual(playbook["id"], "emerging-threats-bpfdoor-icmp-v1")

    def test_matching_packet_predicates_remain_unknown_without_xbit_trace(self) -> None:
        payload = bytearray(b"B" * 64)
        payload[16:18] = b"X:"
        row = alert_row(icmp_frame(code=1, sequence=1234, payload=bytes(payload)))
        context = validation.extract_rule_context(
            json.loads(row["alert_json"]),
            json.loads(row["raw_event_json"]),
            "2069174",
        )
        playbook = validation.resolve_detection_playbook(self.registry, context)
        features = validation.extract_group_packet_features(
            [row],
            validation.marker_specs(context, playbook),
        )

        result = validation.build_detection_validation(context, features, playbook)

        self.assertEqual(result["event_status"], "observed")
        self.assertEqual(result["rule_intent_match"], "unknown")
        self.assertEqual(
            next(item for item in result["predicate_results"] if item["id"] == "bpfdoor-heartbeat-invalid-code")["status"],
            "matched",
        )
        self.assertNotIn(
            "bpfdoor-command-marker",
            {item["id"] for item in result["predicate_results"]},
        )
        state = next(
            item
            for item in result["predicate_results"]
            if item["field"] == "xbits.state"
        )
        self.assertTrue(state["required"])
        self.assertEqual(state["status"], "unknown")

    def test_deployed_rule_content_is_required_without_a_playbook(self) -> None:
        payload = bytearray(b"C" * 64)
        payload[7:9] = b"X:"
        row = alert_row(icmp_frame(code=0, sequence=8, payload=bytes(payload)))
        raw = json.loads(row["raw_event_json"])
        raw["message"] = json.dumps(
            {
                **json.loads(raw["message"]),
                "alert": {
                    "signature_id": 999999,
                    "rev": 1,
                    "signature": "fixture",
                    "rule": (
                        'alert icmp any any -> any any '
                        '(msg:"fixture"; itype:0; content:"X:"; offset:16; sid:999999; rev:1;)'
                    ),
                },
            }
        )
        raw["rule"] = {
            "rule": (
                'alert icmp any any -> any any '
                '(msg:"fixture"; itype:0; content:"X:"; offset:16; sid:999999; rev:1;)'
            ),
            "rev": 1,
            "ruleset": "fixture",
        }
        context = validation.extract_rule_context(
            {},
            raw,
            "999999",
        )
        features = validation.extract_group_packet_features(
            [row],
            validation.marker_specs(context, None),
        )
        result = validation.build_detection_validation(context, features, None)

        self.assertEqual(result["rule_intent_match"], "mismatch")
        content = next(
            item
            for item in result["predicate_results"]
            if item["id"] == "deployed-content-1"
        )
        self.assertTrue(content["required"])
        self.assertEqual(content["status"], "mismatched")

    def test_deployed_offset_is_search_start_not_exact_position(self) -> None:
        payload = bytearray(b"C" * 64)
        payload[20:22] = b"X:"
        row = alert_row(icmp_frame(code=0, sequence=8, payload=bytes(payload)))
        raw = json.loads(row["raw_event_json"])
        message = json.loads(raw["message"])
        rule = (
            'alert icmp any any -> any any '
            '(msg:"fixture"; itype:0; content:"X:"; offset:16; sid:999999; rev:1;)'
        )
        message["alert"] = {
            "signature_id": 999999,
            "rev": 1,
            "signature": "fixture",
            "rule": rule,
        }
        raw["message"] = json.dumps(message)
        raw["rule"] = {"rule": rule, "rev": 1, "ruleset": "fixture"}
        context = validation.extract_rule_context({}, raw, "999999")
        features = validation.extract_group_packet_features(
            [row | {"raw_event_json": json.dumps(raw)}],
            validation.marker_specs(context, None),
        )

        result = validation.build_detection_validation(context, features, None)

        self.assertEqual(result["rule_intent_match"], "match")
        content = next(
            item for item in result["predicate_results"]
            if item["id"] == "deployed-content-1"
        )
        self.assertEqual(content["status"], "matched")
        self.assertEqual(content["expected"]["search_offset"], 16)

    def test_negated_content_and_numeric_comparator_fail_closed(self) -> None:
        rule = (
            'alert icmp any any -> any any (msg:"fixture"; itype:<8; '
            'content:!"|20 21 22 23|"; sid:999998; rev:1;)'
        )
        parsed = validation.parse_suricata_rule(rule)
        self.assertEqual(parsed["predicates"][0]["operator"], "unsupported_expression")
        self.assertTrue(parsed["contents"][0]["negated"])
        self.assertEqual(parsed["contents"][0]["hex"], "20212223")
        context = {
            "sid": "999998",
            "revision": 1,
            "name": "fixture",
            "ruleset": "fixture",
            "parsed_rule": parsed,
            "identity_conflicts": {"sid": [], "revision": []},
        }
        row = alert_row(icmp_frame(code=0, sequence=8, payload=b"safe payload"))
        features = validation.extract_group_packet_features(
            [row],
            validation.marker_specs(context, None),
        )
        result = validation.build_detection_validation(context, features, None)
        self.assertEqual(result["rule_intent_match"], "unknown")
        negated = next(
            item for item in result["predicate_results"]
            if item["id"] == "deployed-content-1"
        )
        self.assertEqual(negated["status"], "matched")

    def test_ruleset_matching_is_exact(self) -> None:
        context = {
            "sid": "2069174",
            "revision": 5,
            "ruleset": "Not Emerging Threats experimental",
            "parsed_rule": {"rule_sha256": "0" * 64},
            "identity_conflicts": {"sid": [], "revision": []},
        }
        self.assertIsNone(validation.resolve_detection_playbook(self.registry, context))

    def test_playbook_registry_rejects_bad_version_and_marker_hex(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "playbooks.json"
            path.write_text(
                json.dumps(
                    {
                        "schema": validation.PLAYBOOK_SCHEMA,
                        "version": 2,
                        "playbooks": [],
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "version"):
                validation.load_detection_playbooks(path)
            payload = json.loads(
                (REPO_ROOT / "n8n" / "config" / "detection_playbooks.json").read_text()
            )
            payload["playbooks"][0]["marker_predicates"][0]["hex"] = "not-hex"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "hex"):
                validation.load_detection_playbooks(path)

    def test_oversized_packet_copy_is_rejected_before_decode(self) -> None:
        row = alert_row(icmp_frame(code=0, sequence=1, payload=b"safe"))
        raw = json.loads(row["raw_event_json"])
        message = json.loads(raw["message"])
        message["packet"] = "A" * (validation.MAX_PACKET_BASE64_CHARS + 4)
        raw["message"] = json.dumps(message)
        row["raw_event_json"] = json.dumps(raw)
        features = validation.extract_group_packet_features([row], [])
        self.assertEqual(features["candidate_packets"], 1)
        self.assertEqual(features["icmp_packets_parsed"], 0)
        self.assertEqual(features["parse_errors"], 1)


if __name__ == "__main__":
    unittest.main()
