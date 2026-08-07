#!/usr/bin/env python3
"""Contracts for extracted dashboard AI workflow status policy."""
from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "onion-sentinel-dashboard" / "scripts"
MODULE_PATH = SCRIPTS / "dashboard_alert_ai_workflow.py"
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


class DashboardAlertAiWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = load_module("dashboard_alert_ai_workflow", MODULE_PATH)
        cls.builder = load_module("alert_ai_workflow_test_builder", BUILDER_PATH)

    def test_group_candidates_and_first_available_analysis_are_stable(self) -> None:
        row = {"alert_id": "new", "member_alert_ids": ["new", "old", ""]}

        self.assertEqual(
            self.workflow.candidate_alert_ids_for_row(row),
            ["new", "new", "old"],
        )
        self.assertEqual(
            self.workflow.ai_analysis_for_row(row, {"old": {"result": "older"}}),
            {"result": "older"},
        )

    def test_eligibility_applies_test_filter_and_severity_policy(self) -> None:
        eligible = {"alert_id": "real-1", "filter_status": "accepted", "triage_level": "info"}
        self.assertTrue(self.workflow.row_is_ai_backlog_eligible(eligible, "informational")[0])
        self.assertFalse(self.workflow.row_is_ai_backlog_eligible(eligible, "disabled")[0])
        self.assertFalse(self.workflow.row_is_ai_backlog_eligible(
            {**eligible, "alert_id": "phase-test"}, "informational",
        )[0])
        self.assertFalse(self.workflow.row_is_ai_backlog_eligible(
            {**eligible, "filter_status": "dropped"}, "informational",
        )[0])
        recognized, reason = self.workflow.row_is_ai_backlog_eligible(
            {**eligible, "triage_level": "mystery"}, "informational",
        )
        self.assertFalse(recognized)
        self.assertIn("Unrecognized severity mystery", reason)

    def test_running_and_completed_artifacts_take_precedence_over_threshold(self) -> None:
        row = {"alert_id": "low-1", "filter_status": "accepted", "triage_level": "low"}
        running = self.workflow.ai_workflow_status_for_row(
            row, {}, {"low-1": {"_prompt_filename": "prompt.json"}}, {"low-1"}, "high",
        )
        self.assertEqual(running, ("analyzing", "Analyzing", "prompt.json"))

        completed = self.workflow.ai_workflow_status_for_row(
            row,
            {"low-1": {"generated_at": "2026-08-01T01:00:00Z", "response": {"_analysis_model": "model-a"}}},
            {}, set(), "high",
        )
        self.assertEqual(completed[:2], ("analyzed", "Analyzed"))
        self.assertIn("model-a", completed[2])

    def test_newer_prompt_supersedes_an_older_analysis_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "analysis.json"
            artifact.write_text("{}", encoding="utf-8")
            os.utime(artifact, (10, 10))
            status = self.workflow.ai_workflow_status_for_row(
                {"alert_id": "a1", "filter_status": "accepted", "triage_level": "high"},
                {"a1": {"_analysis_path": str(artifact)}},
                {"a1": {"_prompt_mtime": 20, "_prompt_filename": "new.json"}},
                set(), "medium",
            )

        self.assertEqual(status[:2], ("queued", "Queued"))
        self.assertIn("new.json", status[2])

    def test_unanalyzed_rows_report_backlog_or_skipped_status(self) -> None:
        queued = self.workflow.ai_workflow_status_for_row(
            {"alert_id": "high-1", "filter_status": "accepted", "triage_level": "high"},
            {}, {}, set(), "medium",
        )
        skipped = self.workflow.ai_workflow_status_for_row(
            {"alert_id": "low-1", "filter_status": "accepted", "triage_level": "low"},
            {}, {}, set(), "medium",
        )
        self.assertEqual(queued[:2], ("queued", "Queued"))
        self.assertEqual(skipped[:2], ("not-queued", "Skipped"))
        self.assertIn("Medium automatic AI-analysis minimum", skipped[2])

    def test_builder_reexports_the_workflow_contract(self) -> None:
        for name in (
            "candidate_alert_ids_for_row", "severity_meets_analysis_threshold",
            "row_is_ai_backlog_eligible", "ai_analysis_for_row",
            "analysis_artifact_mtime", "ai_workflow_status_for_row",
        ):
            self.assertIs(getattr(self.builder, name), getattr(self.workflow, name))

    def test_module_is_bounded_and_deployed_once(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertLessEqual(len(source.splitlines()), 200)
        for forbidden in ("sqlite3", "subprocess", "urllib", "write_text(", "open("):
            self.assertNotIn(forbidden, source)
        installer = INSTALLER_PATH.read_text(encoding="utf-8")
        self.assertEqual(installer.count("dashboard_alert_ai_workflow.py"), 2)


if __name__ == "__main__":
    unittest.main()
