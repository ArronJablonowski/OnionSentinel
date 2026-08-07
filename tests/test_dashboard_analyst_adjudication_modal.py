#!/usr/bin/env python3
"""Contracts for the shared analyst-adjudication modal component."""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "onion-sentinel-dashboard" / "scripts"
BUILDER_PATH = SCRIPTS / "build_soc_alerts_dashboard.py"
COMPONENT_PATH = SCRIPTS / "dashboard_analyst_adjudication_modal.py"
INSTALLER_PATH = ROOT / "n8n" / "bin" / "install-macstudio-stack.zsh"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class AnalystAdjudicationModalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.component = load_module("dashboard_analyst_adjudication_modal", COMPONENT_PATH)
        cls.builder = load_module("adjudication_modal_test_builder", BUILDER_PATH)
        cls.page = cls.component.analyst_adjudication_modal_html()

    def test_builder_reexports_canonical_component(self) -> None:
        self.assertIs(
            self.builder.analyst_adjudication_modal_html,
            self.component.analyst_adjudication_modal_html,
        )
        self.assertEqual(self.builder.analyst_adjudication_modal_html(), self.page)

    def test_dialog_is_accessible_and_collects_bounded_human_evidence(self) -> None:
        self.assertIn('role="dialog"', self.page)
        self.assertIn('aria-modal="true"', self.page)
        self.assertIn('aria-labelledby="analyst-adjudication-title"', self.page)
        self.assertIn('role="status" aria-live="polite"', self.page)
        self.assertIn("window.setTimeout(()=>outcome.focus(),25)", self.page)
        self.assertIn("event.key==='Escape'", self.page)
        for field in (
            "analyst-outcome",
            "analyst-confidence",
            "analyst-event-status",
            "analyst-detection-validity",
            "analyst-activity-disposition",
            "analyst-handling",
            "analyst-duplicate-of",
            "analyst-rationale",
            "analyst-evidence-gap",
            "analyst-next-action",
            "analyst-reviewer",
        ):
            self.assertIn(f'id="{field}"', self.page)
        self.assertIn('maxlength="4000"', self.page)
        self.assertIn("append-only human decision", self.page)

    def test_submission_preserves_same_origin_api_contract(self) -> None:
        self.assertIn(
            "`/api/soc-incidents/${encodeURIComponent(submissionContext.caseId)}/adjudicate`",
            self.page,
        )
        self.assertIn(
            "`/api/soc-alerts/${encodeURIComponent(submissionContext.groupId)}/adjudicate`",
            self.page,
        )
        self.assertIn("method:'POST'", self.page)
        self.assertIn("credentials:'same-origin'", self.page)
        self.assertIn("'X-Onion-Sentinel-Request':'dashboard'", self.page)
        self.assertIn("body:JSON.stringify(payload)", self.page)
        self.assertIn("onion-sentinel:adjudicated", self.page)

    def test_component_is_pure_bounded_and_deployed_once(self) -> None:
        source = COMPONENT_PATH.read_text(encoding="utf-8")
        self.assertLessEqual(len(source.splitlines()), 600)
        for forbidden in ("import sqlite3", "import subprocess", "from pathlib", "Path.home"):
            self.assertNotIn(forbidden, source)
        installer = INSTALLER_PATH.read_text(encoding="utf-8")
        self.assertEqual(installer.count("dashboard_analyst_adjudication_modal.py"), 2)


if __name__ == "__main__":
    unittest.main()
