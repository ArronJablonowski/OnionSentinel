#!/usr/bin/env python3
"""Contracts for core identity, summary, notes, and raw-log sections."""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "onion-sentinel-dashboard" / "scripts"
BUILDER_PATH = SCRIPTS / "build_soc_alerts_dashboard.py"
SECTIONS_PATH = SCRIPTS / "dashboard_alert_detail_sections.py"
INSTALLER_PATH = ROOT / "n8n" / "bin" / "install-macstudio-stack.zsh"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class AlertDetailSectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.sections = load_module("dashboard_alert_detail_sections", SECTIONS_PATH)
        cls.builder = load_module("alert_detail_sections_test_builder", BUILDER_PATH)

    def test_builder_reexports_the_core_section_contract(self) -> None:
        for name in (
            "CRITICALITY_LABELS",
            "alert_identity_markdown",
            "alert_summary_markdown",
            "analyst_notes_markdown",
            "complete_alert_json_markdown",
            "raw_alert_markdown",
            "raw_logs_markdown",
            "severity_label_from_row",
            "triage_reasons_markdown",
        ):
            self.assertIs(getattr(self.builder, name), getattr(self.sections, name))

    def test_severity_and_identity_prefer_authoritative_triage_state(self) -> None:
        row = {
            "triage_level": "high",
            "severity": 3,
            "rule_name": "Example Rule",
            "alert_id": "alert-1",
            "filter_status": "escalated",
            "routing": "incident-response",
            "triage_score": 88,
            "traffic_direction": "outbound",
            "source_ip": "10.0.0.2",
            "source_port": 51515,
            "destination_ip": "203.0.113.8",
            "destination_port": 443,
        }
        identity = self.sections.alert_identity_markdown(
            row,
            "generated_at: 2026-07-24T18:30:00Z",
        )
        self.assertTrue(identity.startswith("# [HIGH] Example Rule"))
        self.assertIn("10.0.0.2:51515 -> 203.0.113.8:443", identity)
        self.assertIn("**Workflow status:** escalated", identity)
        self.assertNotIn("T18:", identity)
        self.assertEqual(self.sections.severity_label_from_row({"severity": 1}), "Critical")

    def test_summary_preserves_zero_counts_and_normalizes_timestamps(self) -> None:
        summary = self.sections.alert_summary_markdown({
            "rule_name": "Rule|Name",
            "seen_count": 0,
            "raw_alert_count": 0,
            "first_seen": "2026-07-24T18:30:00Z",
            "filter_status": "accepted",
        })
        self.assertIn("Rule\\|Name", summary)
        self.assertIn("| Seen count | 0 |", summary)
        self.assertIn("| Grouped alert rows | 0 |", summary)
        self.assertNotIn("T18:", summary)

    def test_triage_notes_and_raw_logs_preserve_legacy_and_ai_evidence(self) -> None:
        triage = self.sections.triage_reasons_markdown(
            {"triage": {"reasons": ["rare destination", "rare destination", "high score"]}},
            {},
        )
        self.assertEqual(triage.count("rare destination"), 1)
        existing = "## Analyst Notes\n\nconfirmed by analyst"
        self.assertEqual(self.sections.analyst_notes_markdown({"analyst notes": existing}), existing)
        raw_logs = self.sections.raw_logs_markdown(
            {"z": 1, "a": 2},
            analysis={"response": {"verdict": "review"}},
            legacy_sections=[("Old Section", "legacy evidence")],
        )
        self.assertLess(raw_logs.index("Legacy Source Content"), raw_logs.index("Complete Alert JSON"))
        self.assertIn("legacy evidence", raw_logs)
        self.assertIn("Complete AI Response JSON", raw_logs)
        self.assertLess(raw_logs.index('"a": 2'), raw_logs.index('"z": 1'))

    def test_module_is_bounded_pure_and_deployed_once(self) -> None:
        source = SECTIONS_PATH.read_text(encoding="utf-8")
        self.assertLessEqual(len(source.splitlines()), 200)
        for forbidden in ("import sqlite3", "import subprocess", "from pathlib", "Path.home", "open("):
            self.assertNotIn(forbidden, source)
        installer = INSTALLER_PATH.read_text(encoding="utf-8")
        self.assertEqual(installer.count("dashboard_alert_detail_sections.py"), 2)


if __name__ == "__main__":
    unittest.main()
