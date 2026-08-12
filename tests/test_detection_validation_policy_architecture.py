"""Characterize detection-validation policy before owner extraction."""

from __future__ import annotations

import importlib
import inspect
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
sys.path.insert(0, str(BIN))
POLICY = importlib.import_module("detection_validation_policy")


def valid_playbook() -> dict:
    return {
        "id": "unit.stun",
        "version": 1,
        "match": {
            "sids": ["2016150"],
            "revisions": [4],
            "ruleset": "ET INFO",
            "rule_sha256": "a" * 64,
        },
        "required_predicates": [
            {
                "id": "icmp-type",
                "field": "icmp.type",
                "operator": "equals",
                "expected": [8],
                "applies_to_sids": ["2016150"],
            }
        ],
        "supporting_predicates": [],
        "marker_predicates": [
            {
                "id": "marker",
                "hex": "2112A442",
                "expected_offset": 4,
                "applies_to_sids": ["2016150"],
            }
        ],
    }


class DetectionValidationPolicyCharacterizationTests(unittest.TestCase):
    def test_legacy_namespace_and_local_signatures_are_frozen(self):
        self.assertEqual(
            sorted(name for name in vars(POLICY) if not name.startswith("__")),
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
                "_evaluate_numeric_predicate",
                "_infer_stun_response_xbits_state",
                "_observed_values",
                "_validated_stun_rule_semantics",
                "annotations",
                "base64",
                "collections",
                "extract_group_packet_features",
                "extract_rule_context",
                "hashlib",
                "ipaddress",
                "json",
                "load_detection_playbooks",
                "marker_specs",
                "math",
                "parse_suricata_rule",
                "re",
                "resolve_detection_playbook",
                "struct",
            ],
        )
        expected = {
            "_evaluate_numeric_predicate": "(predicate: 'dict[str, Any]', features: 'dict[str, Any]', *, source: 'str') -> 'dict[str, Any]'",
            "_infer_stun_response_xbits_state": "(rule_context: 'dict[str, Any]', packet_features: 'dict[str, Any]', state_operation: 'dict[str, Any]') -> 'bool'",
            "_observed_values": "(features: 'dict[str, Any]', field: 'str') -> 'list[int]'",
            "_validated_stun_rule_semantics": "(rule_context: 'dict[str, Any]', packet_features: 'dict[str, Any]') -> 'bool'",
            "load_detection_playbooks": "(path: 'Path') -> 'dict[str, Any]'",
            "resolve_detection_playbook": "(registry: 'dict[str, Any]', rule_context: 'dict[str, Any]') -> 'dict[str, Any] | None'",
        }
        self.assertEqual(
            {name: str(inspect.signature(getattr(POLICY, name))) for name in expected},
            expected,
        )

    def test_registry_normalization_and_failure_order_are_frozen(self):
        payload = {
            "schema": POLICY.PLAYBOOK_SCHEMA,
            "version": 1,
            "generated_at": "2026-08-12T00:00:00Z",
            "playbooks": [valid_playbook()],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "playbooks.json"
            self.assertEqual(
                POLICY.load_detection_playbooks(path),
                {"schema": POLICY.PLAYBOOK_SCHEMA, "version": 0, "playbooks": []},
            )
            path.write_text(json.dumps(payload), encoding="utf-8")
            self.assertEqual(
                POLICY.load_detection_playbooks(path),
                {**payload, "playbooks": [valid_playbook()]},
            )
            failures = (
                ({**payload, "schema": "wrong"}, "unsupported detection playbook registry"),
                ({**payload, "version": 2}, "unsupported detection playbook registry version"),
                ({**payload, "playbooks": {}}, "detection playbooks must be a list"),
                ({**payload, "playbooks": [valid_playbook(), valid_playbook()]}, "duplicate detection playbook id: unit.stun"),
            )
            for value, message in failures:
                with self.subTest(message=message):
                    path.write_text(json.dumps(value), encoding="utf-8")
                    with self.assertRaisesRegex(ValueError, f"^{__import__('re').escape(message)}$"):
                        POLICY.load_detection_playbooks(path)

    def test_resolution_and_numeric_predicate_projection_are_frozen(self):
        playbook = valid_playbook()
        registry = {"playbooks": [playbook]}
        context = {
            "sid": "2016150",
            "revision": 4,
            "ruleset": "et info",
            "identity_conflicts": {},
            "parsed_rule": {"rule_sha256": "a" * 64},
        }
        self.assertIs(POLICY.resolve_detection_playbook(registry, context), playbook)
        self.assertIsNone(
            POLICY.resolve_detection_playbook(
                registry, {**context, "identity_conflicts": {"sid": True}}
            )
        )
        features = {"icmp_types": [{"value": 8, "count": 3}]}
        self.assertEqual(
            POLICY._evaluate_numeric_predicate(
                {
                    "id": "type",
                    "field": "icmp.type",
                    "operator": "equals",
                    "expected": [8],
                    "required": True,
                    "reason": " exact ",
                },
                features,
                source="deployed_rule",
            ),
            {
                "id": "type",
                "field": "icmp.type",
                "operator": "equals",
                "expected": [8],
                "observed": [8],
                "status": "matched",
                "required": True,
                "source": "deployed_rule",
                "reason": " exact ",
            },
        )

    def test_stun_identity_and_complete_evidence_guards_are_frozen(self):
        context = {
            "sid": "2016150",
            "revision": 4,
            "name": "ET INFO Session Traversal Utilities for NAT (STUN Binding Response)",
            "identity_conflicts": {},
            "parsed_rule": {"protocol": "udp"},
        }
        features = {
            "candidate_packets": 2,
            "content_packets_parsed": 2,
            "parse_errors": 0,
            "truncated": False,
            "source": "stored-security-onion-alert-packet-copies",
            "stun": {
                "packets_parsed": 2,
                "message_types": [
                    {"value": "binding_success_response", "count": 2}
                ],
            },
        }
        operation = {
            "kind": "xbits",
            "operation": "isset",
            "name": "et.stun",
            "track": "track ip_dst",
        }
        self.assertTrue(
            POLICY._infer_stun_response_xbits_state(context, features, operation)
        )
        self.assertTrue(POLICY._validated_stun_rule_semantics(context, features))
        self.assertFalse(
            POLICY._infer_stun_response_xbits_state(
                context, {**features, "truncated": True}, operation
            )
        )
        self.assertFalse(
            POLICY._validated_stun_rule_semantics(
                {**context, "revision": 5}, features
            )
        )


if __name__ == "__main__":
    unittest.main()
