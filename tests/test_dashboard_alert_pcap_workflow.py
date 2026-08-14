#!/usr/bin/env python3
"""Contracts for extracted dashboard PCAP workflow resolution."""
from __future__ import annotations

import hashlib
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "onion-sentinel-dashboard" / "scripts"
MODULE_PATH = SCRIPTS / "dashboard_alert_pcap_workflow.py"
BUILDER_PATH = SCRIPTS / "build_soc_alerts_dashboard.py"
INSTALLER_PATH = ROOT / "n8n" / "bin" / "install-macstudio-stack.zsh"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def empty_index() -> dict[str, object]:
    return {
        "group_ids": set(), "alert_ids": set(),
        "records_by_group_id": {}, "records_by_alert_id": {},
        "records_by_request_id": {}, "requests_by_group_id": {},
        "requests_by_alert_id": {}, "requests_by_request_id": {},
    }


class DashboardAlertPcapWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = load_module("dashboard_alert_pcap_workflow", MODULE_PATH)
        cls.builder = load_module("alert_pcap_workflow_test_builder", BUILDER_PATH)

    def config(self):
        return self.workflow.PcapWorkflowConfig(Path("alerts.sqlite3"), Path("pcap"))

    def test_materialized_group_key_produces_stable_short_id(self) -> None:
        row = {"alert_id": "a1", "alert_group_key": "stable-group"}
        expected = hashlib.sha1(b"stable-group").hexdigest()[:12]
        self.assertEqual(self.workflow.grouped_alert_id(row), expected)

    def test_parsed_evidence_takes_precedence_over_broker_state(self) -> None:
        row = {"alert_id": "a1", "alert_group_key": "group"}
        index = empty_index()
        index["alert_ids"] = {"a1"}
        index["requests_by_alert_id"] = {"a1": {"status": "failed", "error": "failure"}}

        status = self.workflow.pcap_status_for_row(row, self.config(), index)

        self.assertEqual(status[:2], ("analyzed", "Analyzed"))

    def test_broker_states_map_to_queued_parsing_and_actionable_failures(self) -> None:
        row = {"alert_id": "a1", "alert_group_key": "group"}
        cases = (
            ({"status": "pending"}, ("queued", "Queued")),
            ({"status": "fulfilled"}, ("queued", "Parsing")),
            (
                {
                    "status": "rejected", "outcome": "policy_skipped",
                    "error": "Automatic PCAP analysis skipped below configured high threshold",
                },
                ("not-queued", "Skipped"),
            ),
            (
                {"status": "failed", "error": "no matching packets", "used_capture_file": False},
                ("error", "Retry"),
            ),
            (
                {"status": "failed", "error": "no matching packets", "used_capture_file": True},
                ("no-packets", "No Packets"),
            ),
            ({"status": "failed", "error": "relay unavailable"}, ("error", "Failed")),
        )
        for request, expected in cases:
            with self.subTest(request=request):
                index = empty_index()
                index["requests_by_alert_id"] = {"a1": {"request_id": "r1", **request}}
                self.assertEqual(
                    self.workflow.pcap_status_for_row(row, self.config(), index)[:2],
                    expected,
                )

    def test_analysis_lookup_prefers_group_then_alert_then_request(self) -> None:
        row = {"alert_id": "a1", "alert_group_key": "group"}
        group_id = self.workflow.grouped_alert_id(row)
        index = empty_index()
        index["records_by_group_id"] = {group_id: {"source": "group"}}
        index["records_by_alert_id"] = {"a1": {"source": "alert"}}
        self.assertEqual(
            self.workflow.pcap_analysis_for_row(row, self.config(), index),
            {"source": "group"},
        )

        index["records_by_group_id"] = {}
        self.assertEqual(
            self.workflow.pcap_analysis_for_row(row, self.config(), index),
            {"source": "alert"},
        )

        index["records_by_alert_id"] = {}
        index["requests_by_alert_id"] = {"a1": {"request_id": "r1", "status": "fulfilled"}}
        index["records_by_request_id"] = {"r1": {"source": "request"}}
        self.assertEqual(
            self.workflow.pcap_analysis_for_row(row, self.config(), index),
            {"source": "request"},
        )

    def test_builder_wrappers_preserve_the_configured_workflow_behavior(self) -> None:
        row = {"alert_id": "a1", "alert_group_key": "group"}
        index = empty_index()
        index["requests_by_alert_id"] = {"a1": {"status": "claimed"}}
        self.assertEqual(
            self.builder.pcap_status_for_row(row, index),
            self.workflow.pcap_status_for_row(
                row,
                self.workflow.PcapWorkflowConfig(self.builder.DB_PATH, self.builder.PCAP_ANALYSIS_DIR),
                index,
            ),
        )

    def test_empty_analysis_directory_produces_a_reusable_index(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            index = self.workflow.pcap_analysis_index(
                self.workflow.PcapWorkflowConfig(Path("alerts.sqlite3"), Path(directory))
            )
        self.assertEqual(index["group_ids"], set())
        self.assertEqual(index["alert_ids"], set())

    def test_module_is_bounded_and_deployed_once(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertLessEqual(len(source.splitlines()), 180)
        for forbidden in ("import sqlite3", "subprocess", "urllib", "write_text(", "open("):
            self.assertNotIn(forbidden, source)
        installer = INSTALLER_PATH.read_text(encoding="utf-8")
        self.assertEqual(installer.count("dashboard_alert_pcap_workflow.py"), 2)


if __name__ == "__main__":
    unittest.main()
