#!/usr/bin/env python3
"""Contracts for the extracted SOC alert report factory."""
from __future__ import annotations

import importlib.util
import sys
import tempfile
import types
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "onion-sentinel-dashboard" / "scripts"
FACTORY_PATH = SCRIPTS / "dashboard_alert_report_factory.py"
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


def report_row() -> dict[str, object]:
    return {
        "alert_id": "alert-1",
        "alert_group_key": "stable-group",
        "alert_json": '{"source":{"ip":"10.0.0.7","port":51515},'
                      '"destination":{"ip":"203.0.113.8","port":443},'
                      '"rule_id":"rule-7"}',
        "raw_alert_count": 2,
        "total_seen_count": 5,
        "seen_count": 3,
        "first_seen": "2026-08-01T01:00:00Z",
        "last_seen": "2026-08-01T01:05:00Z",
        "timestamp": "2026-08-01T01:04:00Z",
        "rule_name": "Example Rule",
        "event_dataset": "suricata.alert",
        "severity": 2,
        "severity_label": "medium",
        "triage_level": "medium",
        "source_ip": "",
        "source_port": None,
        "destination_ip": "",
        "destination_port": None,
        "filter_status": "accepted",
        "filter_reason": "eligible",
        "enrichment_json": "{}",
        "member_timeline": [],
    }


class DashboardAlertReportFactoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.factory = load_module("dashboard_alert_report_factory", FACTORY_PATH)
        cls.builder = load_module("alert_report_factory_test_builder", BUILDER_PATH)

    def services(self):
        return self.factory.AlertReportFactoryServices(
            finalize_detail_report_html=lambda rendered, timeline, issues: (
                f'<article data-issues="{len(issues)}">{timeline}{rendered}</article>'
            ),
        )

    def test_factory_builds_complete_model_from_normalized_row(self) -> None:
        row = report_row()
        config = self.factory.AlertReportFactoryConfig(Path("alerts.sqlite3"), (), Path("pcap"))
        analyses = {
            "alert-1": {
                "response": {
                    "bluf": "Evidence-backed result.",
                    "_analysis_model": "gpt-test",
                    "tuning_recommendation": "review",
                    "tuning_reason": "Repeated activity",
                    "recommended_tuning_actions": [" Validate scope ", ""],
                }
            }
        }

        report = self.factory.build_alert_report(
            row, {}, analyses, {}, set(), {"empty": True}, "medium", config, self.services(),
        )

        self.assertEqual(report.title, "[MEDIUM] Example Rule")
        self.assertEqual(report.rel_source, "SQLite alert-store")
        self.assertEqual(report.repeat_count, 5)
        self.assertEqual(report.source_endpoint, "10.0.0.7:51515")
        self.assertEqual(report.destination_endpoint, "203.0.113.8:443")
        self.assertEqual(report.rule_id, "rule-7")
        self.assertEqual(report.ai_status_key, "analyzed")
        self.assertEqual(report.tuning_recommendation, "review")
        self.assertEqual(report.recommended_tuning_actions, ["Validate scope"])
        self.assertIn("Evidence-backed result.", report.rendered_html)

    def test_attached_markdown_uses_relative_source_and_stat_size(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source_root = Path(directory)
            source = source_root / "nested" / "alert.md"
            attachment = (source, "## Analyst Notes\n\nAttached evidence.", types.SimpleNamespace(st_size=321))
            config = self.factory.AlertReportFactoryConfig(Path("alerts.sqlite3"), (source_root,), Path("pcap"))

            report = self.factory.build_alert_report(
                report_row(), {"alert-1": attachment}, {}, {}, set(), {"empty": True},
                "medium", config, self.services(),
            )

        self.assertEqual(report.source, source)
        self.assertEqual(report.rel_source, "nested/alert.md")
        self.assertEqual(report.size, 321)
        self.assertIn("Attached evidence.", report.rendered_html)

    def test_missing_rule_name_retains_the_legacy_report_identity(self) -> None:
        row = report_row()
        row["rule_name"] = ""
        config = self.factory.AlertReportFactoryConfig(Path("alerts.sqlite3"), (), Path("pcap"))

        report = self.factory.build_alert_report(
            row, {}, {}, {}, set(), {"empty": True}, "medium", config, self.services(),
        )

        self.assertEqual(report.title, "[MEDIUM] Security Onion Alert")
        self.assertEqual(report.rule_name, report.title)

    def test_builder_reexports_factory_and_value_helpers(self) -> None:
        self.assertIs(self.builder.build_alert_report, self.factory.build_alert_report)
        self.assertIs(self.builder.clean_endpoint_part, self.factory.clean_endpoint_part)
        self.assertIs(self.builder.endpoint_label, self.factory.endpoint_label)
        self.assertIs(self.builder.summarize_markdown, self.factory.summarize_markdown)

    def test_module_is_bounded_and_deployed_once(self) -> None:
        source = FACTORY_PATH.read_text(encoding="utf-8")
        self.assertLessEqual(len(source.splitlines()), 320)
        for forbidden in ("sqlite3", "subprocess", "urllib", "read_text(", "write_text(", "open("):
            self.assertNotIn(forbidden, source)
        installer = INSTALLER_PATH.read_text(encoding="utf-8")
        self.assertEqual(installer.count("dashboard_alert_report_factory.py"), 2)


if __name__ == "__main__":
    unittest.main()
