#!/usr/bin/env python3
"""Direct contracts for prompt detection and asset-context preparation."""
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

from prompt_detection_context import (  # noqa: E402
    DetectionContextRequest,
    DetectionContextSources,
    VALIDATION_EXTRA_COLUMNS,
    extract_asset_observables_and_events,
    prepare_detection_context,
    select_exact_detection_group_rows,
)


def request(**changes) -> DetectionContextRequest:
    values = {
        "connection": "connection",
        "selected": {
            "alert_json": '{"alert": true}',
            "raw_event_json": '{"event": true}',
            "rule_id": "rule-1",
            "event_dataset": "suricata.alert",
            "transport_protocol": "tcp",
            "network_protocol": "tls",
            "destination_port": 443,
            "rule_name": "Fixture rule",
            "timestamp": "2026-08-08T12:00:00Z",
            "last_seen": "2026-08-08T12:05:00Z",
        },
        "include_tests": False,
        "agent_role": "incident-responder",
        "investigation_skills_path": Path("/fixture/skills.json"),
        "detection_playbooks_path": Path("/fixture/playbooks.json"),
        "asset_inventory_path": Path("/fixture/assets.json"),
        "maximum_group_rows": 25,
    }
    values.update(changes)
    return DetectionContextRequest(**values)


def sources(**changes) -> DetectionContextSources:
    values = {
        "row_value": lambda row, key: row.get(key),
        "alert_group_rows": mock.Mock(return_value=[{"candidate": 1}]),
        "parse_alert_json": mock.Mock(return_value={"parsed_alert": 1}),
        "parse_json_object": mock.Mock(return_value={"parsed_event": 1}),
        "extract_rule_context": mock.Mock(return_value={"sid": "rule-1"}),
        "load_investigation_skills": mock.Mock(return_value={"skills": 1}),
        "resolve_investigation_skills": mock.Mock(return_value={"selected": ["tls"]}),
        "load_detection_playbooks": mock.Mock(return_value={"playbooks": 1}),
        "resolve_detection_playbook": mock.Mock(return_value={"playbook": 1}),
        "marker_specs": mock.Mock(return_value=[{"marker": 1}]),
        "extract_group_packet_features": mock.Mock(return_value={"packets": 1}),
        "build_detection_validation": mock.Mock(return_value={"intent": "match"}),
        "load_asset_inventory": mock.Mock(return_value={"assets": 1}),
        "resolve_asset_context": mock.Mock(return_value={"matched": ["asset-1"]}),
    }
    values.update(changes)
    return DetectionContextSources(**values)


class PromptDetectionContextTests(unittest.TestCase):
    def test_prepares_exact_detection_skill_and_asset_context(self):
        dependencies = sources()
        prepared = prepare_detection_context(dependencies, request())

        dependencies.alert_group_rows.assert_called_once_with(
            "connection",
            request().selected,
            include_tests=False,
            extra_columns=VALIDATION_EXTRA_COLUMNS,
            row_limit=26,
        )
        self.assertEqual(dependencies.extract_rule_context.call_count, 2)
        self.assertEqual(
            dependencies.extract_rule_context.call_args_list[0],
            mock.call(
            {"parsed_alert": 1},
            {"parsed_event": 1},
            "rule-1",
            ),
        )
        dependencies.resolve_investigation_skills.assert_called_once_with(
            {"skills": 1},
            {
                "event_dataset": "suricata.alert",
                "transport_protocol": "tcp",
                "network_protocol": "tls",
                "destination_port": 443,
                "rule_name": "Fixture rule",
                "evidence_sources": [],
            },
            "incident-responder",
        )
        packet_features = dependencies.build_detection_validation.call_args.args[1]
        self.assertEqual(packet_features["group_scope"]["exact_rule_rows"], 1)
        self.assertIs(packet_features["group_scope"]["input_truncated"], False)
        self.assertNotIn("truncated", packet_features)
        dependencies.resolve_asset_context.assert_called_once_with(
            {"assets": 1},
            [],
            "2026-08-08T12:00:00Z",
            [
                {
                    "source_ip": None,
                    "destination_ip": None,
                    "destination_port": None,
                    "protocol": None,
                }
            ],
        )
        self.assertEqual(prepared.exact_validation_rows, [{"candidate": 1}])
        self.assertEqual(prepared.investigation_skills, {"selected": ["tls"]})
        self.assertEqual(prepared.detection_validation, {"intent": "match"})
        self.assertEqual(prepared.asset_context, {"matched": ["asset-1"]})

    def test_asset_resolution_falls_back_to_last_seen(self):
        dependencies = sources()
        selected = dict(request().selected, timestamp="")

        prepare_detection_context(dependencies, request(selected=selected))

        self.assertEqual(
            dependencies.resolve_asset_context.call_args.args[2],
            "2026-08-08T12:05:00Z",
        )

    def test_exact_group_failure_stops_playbook_and_asset_processing(self):
        exact_rows = mock.Mock(side_effect=ValueError("ambiguous detection group"))
        dependencies = sources()

        with mock.patch(
            "prompt_detection_context.select_exact_detection_group_rows",
            exact_rows,
        ):
            with self.assertRaisesRegex(ValueError, "ambiguous detection group"):
                prepare_detection_context(dependencies, request())

        dependencies.load_detection_playbooks.assert_not_called()
        dependencies.load_asset_inventory.assert_not_called()

    def test_exact_scope_requires_sid_revision_digest_and_no_identity_conflict(self):
        digest = "a" * 64
        selected_context = {
            "sid": "900001",
            "revision": 3,
            "parsed_rule": {"rule_sha256": digest},
        }

        def context_from_raw(_alert, raw, _rule_id):
            return raw["context"]

        def candidate(name, context):
            return {
                "id": name,
                "alert_json": "{}",
                "raw_event_json": json.dumps({"context": context}),
                "rule_id": "900001",
            }

        dependencies = sources(
            parse_alert_json=lambda raw: json.loads(raw),
            parse_json_object=lambda raw: json.loads(raw),
            extract_rule_context=context_from_raw,
        )
        candidates = [
            candidate("exact", selected_context),
            candidate(
                "wrong-revision",
                {**selected_context, "revision": 2},
            ),
            candidate(
                "conflicted",
                {
                    **selected_context,
                    "identity_conflicts": {"sid": ["other"]},
                },
            ),
            candidate("outside-bound", selected_context),
        ]

        exact, scope = select_exact_detection_group_rows(
            dependencies,
            candidates,
            selected_context,
            3,
        )

        self.assertEqual([item["id"] for item in exact], ["exact"])
        self.assertEqual(scope["input_rows"], 3)
        self.assertEqual(scope["exact_rule_rows"], 1)
        self.assertEqual(scope["excluded_nonmatching_rows"], 2)
        self.assertIs(scope["input_truncated"], True)
        self.assertEqual(
            scope["identity"],
            {"sid": "900001", "revision": 3, "rule_sha256": digest},
        )

    def test_asset_evidence_uses_explicit_endpoint_fields_and_respects_bound(self):
        dependencies = sources(
            parse_alert_json=lambda raw: json.loads(raw),
        )
        rows = [
            {
                "alert_json": json.dumps(
                    {
                        "client": {"ip": "192.0.2.30"},
                        "host": {"hostname": "endpoint.example"},
                        "observer": {
                            "hostname": "must-not-promote.example",
                            "ip": "203.0.113.99",
                        },
                    }
                ),
                "source_ip": "192.0.2.10",
                "destination_ip": "198.51.100.20",
                "destination_port": 443,
                "transport_protocol": "tcp",
            },
            {
                "alert_json": "{}",
                "source_ip": "outside-bound",
            },
        ]

        observables, events = extract_asset_observables_and_events(
            dependencies,
            rows,
            1,
        )

        values = {(item["type"], item["value"], item["role"]) for item in observables}
        self.assertIn(("ip", "192.0.2.10", "source"), values)
        self.assertIn(("ip", "192.0.2.30", "client"), values)
        self.assertIn(("hostname", "endpoint.example", "host"), values)
        self.assertNotIn(("hostname", "must-not-promote.example", "observer"), values)
        self.assertNotIn(("ip", "203.0.113.99", "observer"), values)
        self.assertEqual(
            events,
            [
                {
                    "source_ip": "192.0.2.10",
                    "destination_ip": "198.51.100.20",
                    "destination_port": 443,
                    "protocol": "tcp",
                }
            ],
        )


if __name__ == "__main__":
    unittest.main()
