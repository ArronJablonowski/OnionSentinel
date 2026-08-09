#!/usr/bin/env python3
"""Direct contracts for bounded model-facing alert projection."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))

from prompt_alert_projection import (  # noqa: E402
    AlertProjectionSources,
    MAX_SAFE_MESSAGE_CHARS,
    project_compact_alert,
)


def alert_record(message="Safe alert summary") -> dict:
    alert = {
        "message": message,
        "triage": {"reasons": ["fixture reason"]},
        "source": {"ip": "192.0.2.10"},
        "destination": {"ip": "198.51.100.20"},
        "network": {"transport": "tcp"},
        "event": {"dataset": "suricata.eve"},
        "observer": {"name": "sensor"},
        "rule_category": "Fixture",
        "rule_ruleset": "fixture.rules",
        "signature_id": 900001,
        "packet": "must-not-project",
    }
    return {
        "alert_id": "alert-1",
        "timestamp": "2026-08-08T12:00:00Z",
        "first_seen": "2026-08-08T11:59:00Z",
        "last_seen": "2026-08-08T12:00:00Z",
        "seen_count": 2,
        "rule_name": "Fixture rule",
        "event_dataset": "suricata.eve",
        "severity": 2,
        "severity_label": "high",
        "source_ip": "192.0.2.10",
        "destination_ip": "198.51.100.20",
        "traffic_direction": "outbound",
        "triage_score": 80,
        "triage_level": "high",
        "routing": "analyze",
        "filter_status": "accepted",
        "filter_reason": "eligible",
        "suppression_key": "fixture-key",
        "rule_id": "900001",
        "alert_json": json.dumps(alert),
        "raw_event_json": json.dumps({"event": "fixture"}),
    }


def rule_context() -> dict:
    return {
        "sid": "900001",
        "record_rule_id": "900001",
        "revision": 3,
        "name": "Fixture rule",
        "ruleset": "fixture.rules",
        "category": "Fixture",
        "parsed_rule": {
            "rule_sha256": "a" * 64,
            "protocol": "tcp",
            "predicates": [{"kind": "destination_port", "value": "443"}],
            "contents": [
                {
                    "id": "content-1",
                    "sha256": "b" * 64,
                    "length": 8,
                    "negated": False,
                    "value": "must-not-project",
                    "modifiers": {
                        "offset": "12",
                        "within": 24,
                        "nocase": True,
                        "depth": "not-numeric",
                        "unknown": "drop",
                    },
                },
                "invalid-content",
            ],
            "state_operations": [
                {"kind": "flowbit", "operation": "isset", "name": "secret"},
                {"kind": "flowbit", "operation": "ISNOTSET"},
                {"kind": "flowbit", "operation": "set"},
            ],
            "unsupported_match_options": ["one", "two"],
        },
    }


def sources(extractor=None) -> AlertProjectionSources:
    return AlertProjectionSources(
        row_value=lambda row, key: row.get(key),
        parse_alert_json=lambda raw: json.loads(raw),
        parse_json_object=lambda raw: json.loads(raw),
        extract_rule_context=extractor or mock.Mock(return_value=rule_context()),
    )


class PromptAlertProjectionTests(unittest.TestCase):
    def test_projection_keeps_safe_rule_semantics_without_content_values(self):
        projected = project_compact_alert(sources(), alert_record())
        deployed = projected["rule_context"]["deployed_rule"]
        serialized = json.dumps(projected)

        self.assertEqual(projected["triage_reasons"], ["fixture reason"])
        self.assertEqual(projected["raw_alert_subset"]["message"], "Safe alert summary")
        self.assertNotIn("must-not-project", serialized)
        self.assertEqual(
            deployed["content_predicates"][0]["modifiers"],
            {"offset": "12", "within": 24, "nocase": True},
        )
        self.assertEqual(
            deployed["state_preconditions"],
            [
                {"kind": "flowbit", "operation": "isset"},
                {"kind": "flowbit", "operation": "ISNOTSET"},
            ],
        )
        self.assertEqual(deployed["unsupported_constraint_count"], 2)

    def test_packet_bearing_and_oversized_messages_are_suppressed(self):
        packet = project_compact_alert(
            sources(), alert_record('{"packet":"sensitive"}')
        )
        oversized = project_compact_alert(
            sources(), alert_record("x" * (MAX_SAFE_MESSAGE_CHARS + 1))
        )

        self.assertIsNone(packet["raw_alert_subset"]["message"])
        self.assertIsNone(oversized["raw_alert_subset"]["message"])

    def test_optional_row_fields_default_to_none(self):
        projected = project_compact_alert(sources(), alert_record())

        for key in (
            "total_seen_count",
            "source_port",
            "destination_port",
            "transport_protocol",
            "network_protocol",
        ):
            self.assertIsNone(projected[key])

    def test_rule_extractor_receives_parsed_alert_event_and_record_rule_id(self):
        extractor = mock.Mock(return_value={"parsed_rule": {}})
        record = alert_record()
        projected = project_compact_alert(sources(extractor), record)

        alert, raw_event, rule_id = extractor.call_args.args
        self.assertEqual(alert["signature_id"], 900001)
        self.assertEqual(raw_event, {"event": "fixture"})
        self.assertEqual(rule_id, "900001")
        self.assertEqual(projected["rule_context"]["deployed_rule"]["content_predicates"], [])


if __name__ == "__main__":
    unittest.main()
