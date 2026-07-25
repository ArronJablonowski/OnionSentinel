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


def udp_frame(
    payload: bytes,
    *,
    source_port: int = 61933,
    destination_port: int = 3478,
    vlan: bool = True,
) -> bytes:
    destination_mac = bytes.fromhex("969eaec0fe6b")
    source_mac = bytes.fromhex("90ec77890954")
    if vlan:
        ethernet = (
            destination_mac
            + source_mac
            + struct.pack("!HHH", 0x8100, 100, 0x0800)
        )
    else:
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
        17,
        0,
        socket.inet_aton("192.0.2.41"),
        socket.inet_aton("192.0.2.42"),
    )
    udp = struct.pack(
        "!HHHH",
        source_port,
        destination_port,
        8 + len(payload),
        0,
    )
    return ethernet + ipv4 + udp + payload


def stun_message(message_type: int, *, body: bytes = b"") -> bytes:
    if len(body) % 4:
        raise ValueError("STUN fixture body must use 32-bit alignment")
    transaction_id = bytes.fromhex("00112233445566778899aabb")
    return (
        struct.pack("!HHI", message_type, len(body), 0x2112A442)
        + transaction_id
        + body
    )


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


def stun_alert_row(packet: bytes, *, response: bool = False) -> dict[str, str]:
    if response:
        sid = 2016150
        name = "ET INFO Session Traversal Utilities for NAT (STUN Binding Response)"
        raw_rule = (
            'alert udp $EXTERNAL_NET 3478 -> $HOME_NET any '
            f'(msg:"{name}"; xbits:isset,ET.STUN,track ip_dst; '
            'content:"|01 01|"; depth:2; content:"|21 12 a4 42|"; '
            f"distance:2; within:4; sid:{sid}; rev:4;)"
        )
    else:
        sid = 2016149
        name = "ET INFO Session Traversal Utilities for NAT (STUN Binding Request)"
        raw_rule = (
            'alert udp $HOME_NET any -> $EXTERNAL_NET 3478 '
            f'(msg:"{name}"; xbits:set,ET.STUN,track ip_src; '
            'content:"|00 01|"; depth:2; content:"|21 12 a4 42|"; '
            f"distance:2; within:4; sid:{sid}; rev:4;)"
        )
    message = {
        "timestamp": "2026-07-24  14:31:58.631-06:00",
        "src_ip": "192.0.2.41",
        "src_port": 61933,
        "dest_ip": "192.0.2.42",
        "dest_port": 3478,
        "proto": "UDP",
        "alert": {
            "signature_id": sid,
            "rev": 4,
            "signature": name,
            "rule": raw_rule,
        },
        "packet": base64.b64encode(packet).decode("ascii"),
        "packet_info": {"linktype": 1},
    }
    raw = {
        "message": json.dumps(message),
        "rule": {"rule": raw_rule, "rev": 4, "ruleset": "Emerging Threats"},
    }
    alert = {
        "rule_id": str(sid),
        "rule_name": name,
        "rule_ruleset": "Emerging Threats",
        "security_onion": {"raw_event": raw},
    }
    return {
        "rule_id": str(sid),
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

    def test_bpfdoor_code_zero_remains_unknown_without_xbit_trace(self) -> None:
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
        self.assertEqual(result["rule_intent_match"], "unknown")
        self.assertFalse(result["rule_drift"]["detected"])
        heartbeat = next(
            item
            for item in result["predicate_results"]
            if item["id"] == "bpfdoor-heartbeat-invalid-code"
        )
        self.assertFalse(heartbeat["required"])
        self.assertEqual(heartbeat["status"], "mismatched")
        state = next(
            item
            for item in result["predicate_results"]
            if item["field"] == "xbits.state"
        )
        self.assertTrue(state["required"])
        self.assertEqual(state["status"], "unknown")
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
        self.assertEqual(content["field"], "icmp.payload_marker")

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

    def test_vlan_udp_stun_binding_request_is_bounded_and_observed(self) -> None:
        payload = stun_message(0x0001, body=b"\x00\x06\x00\x04safe")
        row = stun_alert_row(udp_frame(payload))
        context = validation.extract_rule_context(
            json.loads(row["alert_json"]),
            json.loads(row["raw_event_json"]),
            row["rule_id"],
        )

        features = validation.extract_group_packet_features(
            [row],
            validation.marker_specs(context, None),
        )
        result = validation.build_detection_validation(context, features, None)

        self.assertEqual(features["candidate_packets"], 1)
        self.assertEqual(features["packets_parsed"], 1)
        self.assertEqual(features["icmp_packets_parsed"], 0)
        self.assertEqual(features["udp_packets_parsed"], 1)
        self.assertEqual(features["parse_errors"], 0)
        self.assertEqual(
            features["packet_protocols"],
            [{"value": "udp", "count": 1}],
        )
        self.assertEqual(features["stun"]["packets_parsed"], 1)
        self.assertEqual(
            features["stun"]["message_types"],
            [{"value": "binding_request", "count": 1}],
        )
        self.assertEqual(features["stun"]["magic_cookie_valid_packets"], 1)
        self.assertFalse(features["stun"]["transaction_ids_included"])
        self.assertFalse(features["stun"]["raw_payloads_included"])
        self.assertEqual(result["event_status"], "observed")
        self.assertEqual(result["rule_intent_match"], "match")
        deployed_contents = [
            item
            for item in result["predicate_results"]
            if item["id"].startswith("deployed-content-")
        ]
        self.assertEqual(
            [item["status"] for item in deployed_contents],
            ["matched", "matched"],
        )
        self.assertEqual(
            {item["field"] for item in deployed_contents},
            {"udp.payload_marker"},
        )
        serialized = json.dumps(result)
        self.assertNotIn(base64.b64encode(udp_frame(payload)).decode("ascii"), serialized)
        self.assertNotIn("00112233445566778899aabb", serialized)
        self.assertNotIn(payload.hex(), serialized)

    def test_stun_request_and_success_response_are_counted_without_identifiers(self) -> None:
        request = stun_alert_row(udp_frame(stun_message(0x0001)))
        response = stun_alert_row(
            udp_frame(
                stun_message(0x0101, body=b"\x00\x20\x00\x08\x00\x01\x00\x00"),
                source_port=3478,
                destination_port=61933,
            ),
            response=True,
        )

        features = validation.extract_group_packet_features([request, response], [])

        self.assertEqual(features["packets_parsed"], 2)
        self.assertEqual(features["udp_packets_parsed"], 2)
        self.assertEqual(features["parse_errors"], 0)
        self.assertEqual(
            features["stun"]["message_types"],
            [
                {"value": "binding_request", "count": 1},
                {"value": "binding_success_response", "count": 1},
            ],
        )
        self.assertEqual(features["stun"]["magic_cookie_valid_packets"], 2)
        self.assertNotIn("transaction", json.dumps(features["stun"]["message_types"]))

        response_context = validation.extract_rule_context(
            json.loads(response["alert_json"]),
            json.loads(response["raw_event_json"]),
            response["rule_id"],
        )
        response_features = validation.extract_group_packet_features(
            [response],
            validation.marker_specs(response_context, None),
        )
        response_result = validation.build_detection_validation(
            response_context,
            response_features,
            None,
        )
        self.assertEqual(response_result["rule_intent_match"], "match")
        state = next(
            item
            for item in response_result["predicate_results"]
            if item["id"] == "deployed-state-1"
        )
        self.assertEqual(state["status"], "matched")
        self.assertEqual(state["provenance"]["kind"], "inference")
        self.assertEqual(
            state["provenance"]["scope"],
            "suricata_sid_2016150_only",
        )
        self.assertFalse(state["provenance"]["engine_trace_observed"])
        self.assertIn("not independently observed", state["reason"])

    def test_stun_response_state_inference_does_not_generalize_to_other_xbits(self) -> None:
        response = stun_alert_row(
            udp_frame(
                stun_message(0x0101, body=b"\x00\x20\x00\x08\x00\x01\x00\x00"),
                source_port=3478,
                destination_port=61933,
            ),
            response=True,
        )
        raw = json.loads(response["raw_event_json"])
        raw["rule"]["rule"] = raw["rule"]["rule"].replace("ET.STUN", "ET.OTHER")
        response["raw_event_json"] = json.dumps(raw)
        context = validation.extract_rule_context(
            json.loads(response["alert_json"]),
            raw,
            response["rule_id"],
        )
        features = validation.extract_group_packet_features(
            [response],
            validation.marker_specs(context, None),
        )

        result = validation.build_detection_validation(context, features, None)

        self.assertEqual(result["rule_intent_match"], "unknown")
        state = next(
            item
            for item in result["predicate_results"]
            if item["id"] == "deployed-state-1"
        )
        self.assertEqual(state["status"], "unknown")
        self.assertEqual(state["provenance"]["kind"], "unobserved")
        self.assertFalse(state["provenance"]["engine_trace_observed"])

    def test_valid_non_stun_udp_is_not_an_icmp_parse_error(self) -> None:
        row = stun_alert_row(udp_frame(b"ordinary udp payload"))

        features = validation.extract_group_packet_features([row], [])

        self.assertEqual(features["packets_parsed"], 1)
        self.assertEqual(features["icmp_packets_parsed"], 0)
        self.assertEqual(features["udp_packets_parsed"], 1)
        self.assertEqual(features["stun"]["packets_parsed"], 0)
        self.assertEqual(features["parse_errors"], 0)


if __name__ == "__main__":
    unittest.main()
