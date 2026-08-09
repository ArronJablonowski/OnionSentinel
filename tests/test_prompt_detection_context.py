#!/usr/bin/env python3
"""Direct contracts for prompt detection and asset-context preparation."""
from __future__ import annotations

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
    prepare_detection_context,
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
        "exact_detection_group_rows": mock.Mock(
            return_value=([{"exact": 1}], {"input_truncated": True})
        ),
        "load_detection_playbooks": mock.Mock(return_value={"playbooks": 1}),
        "resolve_detection_playbook": mock.Mock(return_value={"playbook": 1}),
        "marker_specs": mock.Mock(return_value=[{"marker": 1}]),
        "extract_group_packet_features": mock.Mock(return_value={"packets": 1}),
        "build_detection_validation": mock.Mock(return_value={"intent": "match"}),
        "load_asset_inventory": mock.Mock(return_value={"assets": 1}),
        "asset_observables_and_events": mock.Mock(
            return_value=([{"type": "ip"}], [{"flow": 1}])
        ),
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
        dependencies.extract_rule_context.assert_called_once_with(
            {"parsed_alert": 1},
            {"parsed_event": 1},
            "rule-1",
        )
        dependencies.resolve_investigation_skills.assert_called_once_with(
            {"skills": 1},
            {
                "event_dataset": "suricata.alert",
                "transport_protocol": "tcp",
                "network_protocol": "tls",
                "destination_port": 443,
                "rule_name": "Fixture rule",
            },
            "incident-responder",
        )
        packet_features = dependencies.build_detection_validation.call_args.args[1]
        self.assertEqual(packet_features["group_scope"], {"input_truncated": True})
        self.assertIs(packet_features["truncated"], True)
        dependencies.resolve_asset_context.assert_called_once_with(
            {"assets": 1},
            [{"type": "ip"}],
            "2026-08-08T12:00:00Z",
            [{"flow": 1}],
        )
        self.assertEqual(prepared.exact_validation_rows, [{"exact": 1}])
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
        dependencies = sources(exact_detection_group_rows=exact_rows)

        with self.assertRaisesRegex(ValueError, "ambiguous detection group"):
            prepare_detection_context(dependencies, request())

        dependencies.load_detection_playbooks.assert_not_called()
        dependencies.load_asset_inventory.assert_not_called()


if __name__ == "__main__":
    unittest.main()
