#!/usr/bin/env python3
"""Contracts for the shared dashboard alert report view model."""
from __future__ import annotations

import importlib.util
import sys
import unittest
from dataclasses import fields
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "onion-sentinel-dashboard" / "scripts"
MODEL_PATH = SCRIPTS / "dashboard_alert_report_model.py"
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


class DashboardAlertReportModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.model = load_module("dashboard_alert_report_model", MODEL_PATH)
        cls.builder = load_module("alert_report_model_test_builder", BUILDER_PATH)

    def test_builder_reexports_the_shared_model_and_order(self) -> None:
        self.assertIs(self.builder.AlertReport, self.model.AlertReport)
        self.assertIs(self.builder.CRITICALITY_ORDER, self.model.CRITICALITY_ORDER)

    def test_view_model_retains_the_complete_dashboard_contract(self) -> None:
        names = {field.name for field in fields(self.model.AlertReport)}
        self.assertEqual(len(names), 43)
        for required in (
            "alert_group_key", "rendered_html", "ai_status_key",
            "enrichment_status_key", "pcap_status_key", "recommended_tuning_actions",
        ):
            self.assertIn(required, names)
        self.assertGreater(self.model.CRITICALITY_ORDER["critical"], self.model.CRITICALITY_ORDER["high"])
        self.assertEqual(self.model.CRITICALITY_ORDER["info"], self.model.CRITICALITY_ORDER["informational"])

    def test_module_is_bounded_and_deployed_once(self) -> None:
        source = MODEL_PATH.read_text(encoding="utf-8")
        self.assertLessEqual(len(source.splitlines()), 90)
        for forbidden in ("sqlite3", "subprocess", "json", "open("):
            self.assertNotIn(forbidden, source)
        installer = INSTALLER_PATH.read_text(encoding="utf-8")
        self.assertEqual(installer.count("dashboard_alert_report_model.py"), 2)


if __name__ == "__main__":
    unittest.main()
