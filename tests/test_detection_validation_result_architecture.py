"""Characterize conclusion-safe detection results before owner extraction."""

from __future__ import annotations

import importlib
import inspect
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
sys.path.insert(0, str(BIN))
RESULT = importlib.import_module("detection_validation_result")


def rule_context(*, conflicts: bool = False) -> dict[str, object]:
    return {
        "sid": "7",
        "revision": 1,
        "name": "unit",
        "ruleset": "test",
        "identity_conflicts": {"sid": ["7", "8"]} if conflicts else {},
        "parsed_rule": {
            "available": True,
            "protocol": "icmp",
            "rule_sha256": "abc",
            "predicates": [
                {
                    "id": "type",
                    "field": "icmp.type",
                    "operator": "equals",
                    "expected": 8,
                    "required": True,
                }
            ],
            "state_operations": [],
            "contents": [
                {
                    "id": "content",
                    "sha256": "content-sha",
                    "length": 3,
                    "buffer": "pkt_data",
                    "modifiers": {"offset": "2", "depth": "5"},
                    "negated": False,
                }
            ],
            "unsupported_match_options": [
                {"option": "flags", "value_sha256": "unsupported-sha"}
            ],
        },
    }


def packet_features(*, icmp_type: int = 8) -> dict[str, object]:
    return {
        "packets_parsed": 1,
        "icmp_packets_parsed": 1,
        "candidate_packets": 1,
        "content_packets_parsed": 1,
        "parse_errors": 0,
        "truncated": False,
        "icmp_types": [{"value": icmp_type, "count": 1}],
        "markers": [
            {
                "id": "content",
                "sha256": "content-sha",
                "length": 3,
                "observations": 1,
                "packets_with_marker": 1,
                "offsets": [{"value": 2, "count": 1}],
                "constraint_supported": True,
                "packets_evaluated_for_constraint": 1,
                "packets_satisfying_constraint": 1,
                "packets_violating_constraint": 0,
            },
            {
                "id": "playbook-marker",
                "sha256": "playbook-sha",
                "length": 2,
                "observations": 0,
                "packets_with_marker": 0,
                "expected_offset_observations": 0,
                "offsets": [],
            },
        ],
    }


def playbook() -> dict[str, object]:
    return {
        "id": "playbook",
        "version": 2,
        "status": "active",
        "intent": "unit intent",
        "known_false_positive_risk": "low",
        "references": ["reference"],
        "required_predicates": [],
        "supporting_predicates": [],
        "marker_predicates": [
            {
                "id": "playbook-marker",
                "applies_to_sids": ["7"],
                "expected_offset": 4,
                "required": False,
                "reason": "supporting marker",
            }
        ],
        "confidence_limiters": ["bounded evidence"],
    }


class DetectionValidationResultCharacterizationTests(unittest.TestCase):
    def test_legacy_namespace_and_signature_are_frozen(self):
        self.assertEqual(
            sorted(name for name in vars(RESULT) if not name.startswith("__")),
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
                "_validated_stun_rule_semantics",
                "annotations",
                "base64",
                "build_detection_validation",
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
        self.assertEqual(
            str(inspect.signature(RESULT.build_detection_validation)),
            "(rule_context: 'dict[str, Any]', packet_features: 'dict[str, Any]', playbook: 'dict[str, Any] | None' = None) -> 'dict[str, Any]'",
        )

    def test_empty_conclusion_projection_is_frozen(self):
        self.assertEqual(
            RESULT.build_detection_validation({}, {}),
            {
                "schema": "onion-sentinel-detection-validation-v1",
                "event_status": "unknown",
                "event_observed": None,
                "rule_intent_match": "unknown",
                "rule_intent_basis": "deployed_rule_predicates",
                "rule": {
                    "sid": None,
                    "revision": None,
                    "name": None,
                    "ruleset": None,
                    "rule_sha256": "",
                    "identity_status": "consistent",
                    "identity_conflicts": {},
                },
                "playbook": None,
                "predicate_results": [],
                "rule_drift": {
                    "detected": False,
                    "missing_installed_constraints": [],
                },
                "packet_features": {},
                "confidence_limiters": [],
                "interpretation": "The supplied evidence cannot deterministically establish the detection intent.",
            },
        )

    def test_predicate_order_identity_fail_closed_and_projection_are_frozen(self):
        features = packet_features()
        result = RESULT.build_detection_validation(
            rule_context(conflicts=True),
            features,
            playbook(),
        )

        self.assertEqual(
            [(item["id"], item["status"], item["required"]) for item in result["predicate_results"]],
            [
                ("type", "matched", True),
                ("content", "matched", True),
                ("playbook-marker", "mismatched", False),
                ("deployed-unsupported-1", "unknown", True),
            ],
        )
        self.assertEqual(result["rule_intent_match"], "unknown")
        self.assertEqual(result["rule"]["identity_status"], "conflict")
        self.assertEqual(result["rule"]["identity_conflicts"], {"sid": ["7", "8"]})
        self.assertEqual(result["confidence_limiters"], ["bounded evidence"])
        self.assertIs(result["packet_features"], features)
        self.assertEqual(
            result["interpretation"],
            "The supplied evidence cannot deterministically establish the detection intent.",
        )

    def test_match_and_mismatch_interpretations_are_frozen(self):
        context = rule_context()
        context["parsed_rule"]["unsupported_match_options"] = []
        matched = RESULT.build_detection_validation(context, packet_features())
        mismatched = RESULT.build_detection_validation(context, packet_features(icmp_type=3))
        self.assertEqual(matched["rule_intent_match"], "match")
        self.assertEqual(
            matched["interpretation"],
            "The required threat-behavior predicates matched the supplied packet evidence.",
        )
        self.assertEqual(mismatched["rule_intent_match"], "mismatch")
        self.assertEqual(
            mismatched["interpretation"],
            "The observed packets violate one or more required threat-behavior predicates.",
        )


if __name__ == "__main__":
    unittest.main()
