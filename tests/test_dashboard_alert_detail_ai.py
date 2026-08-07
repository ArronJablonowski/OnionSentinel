#!/usr/bin/env python3
"""Contracts for pure alert-detail AI analysis report sections."""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "onion-sentinel-dashboard" / "scripts"
BUILDER_PATH = SCRIPTS / "build_soc_alerts_dashboard.py"
AI_PATH = SCRIPTS / "dashboard_alert_detail_ai.py"
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


class AlertDetailAiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.ai = load_module("dashboard_alert_detail_ai", AI_PATH)
        cls.builder = load_module("alert_detail_ai_test_builder", BUILDER_PATH)

    def test_builder_reexports_the_ai_report_contract(self) -> None:
        for name in (
            "ai_analysis_output_markdown",
            "ai_analysis_report_markdown",
            "ai_model_used_markdown",
            "complete_ai_response_json_markdown",
            "markdown_bullets",
        ):
            self.assertIs(getattr(self.builder, name), getattr(self.ai, name))

    def test_pending_analysis_has_explicit_output_and_model_states(self) -> None:
        self.assertIn("No AI analysis artifact was found", self.ai.ai_analysis_output_markdown(None))
        model = self.ai.ai_model_used_markdown(None)
        self.assertIn("| Analysis status | Not analyzed yet |", model)
        self.assertIn("| Model | n/a |", model)
        self.assertEqual(self.ai.complete_ai_response_json_markdown(None), "")

    def test_completed_analysis_preserves_false_flags_and_related_groups(self) -> None:
        analysis = {
            "generated_at": "2026-07-24T18:30:00Z",
            "analysis_type": "frontier-cloud",
            "prompt_package": "prompt.json",
            "_analysis_filename": "result.json",
            "_analysis_path": "/tmp/result.json",
            "response": {
                "_analysis_model": "codex|gpt",
                "detection_outcome": "true_positive_suspicious",
                "bluf": "Observed behavior requires review.",
                "correlation_assessment": {
                    "correlation_found": False,
                    "related_groups": [
                        {"group_id": "group-1", "reason": "shared source"},
                        "group-2",
                    ],
                },
                "escalation_needed": False,
                "hosted_second_opinion_recommended": False,
            },
        }
        output = self.ai.ai_analysis_output_markdown(analysis)
        self.assertIn("**Detection outcome:** true_positive_suspicious", output)
        self.assertIn("- **Correlation found:** False", output)
        self.assertIn("- group-1: shared source", output)
        self.assertIn("- group-2: relationship requires analyst validation", output)
        self.assertIn("- **Escalation needed:** False", output)
        model = self.ai.ai_model_used_markdown(analysis)
        self.assertIn("| Model path | Frontier cloud CLI |", model)
        self.assertIn("| Model | codex\\|gpt |", model)

    def test_combined_report_and_raw_json_are_deterministic(self) -> None:
        analysis = {"response": {"z": 1, "a": 2}}
        report = self.ai.ai_analysis_report_markdown(analysis)
        self.assertLess(report.index("## AI Analysis Output"), report.index("## AI Model Used"))
        raw = self.ai.complete_ai_response_json_markdown(analysis)
        self.assertLess(raw.index('"a": 2'), raw.index('"z": 1'))
        self.assertTrue(raw.endswith("```"))

    def test_module_is_bounded_pure_and_deployed_once(self) -> None:
        source = AI_PATH.read_text(encoding="utf-8")
        self.assertLessEqual(len(source.splitlines()), 220)
        for forbidden in ("import sqlite3", "import subprocess", "from pathlib", "Path.home", "open("):
            self.assertNotIn(forbidden, source)
        installer = INSTALLER_PATH.read_text(encoding="utf-8")
        self.assertEqual(installer.count("dashboard_alert_detail_ai.py"), 2)


if __name__ == "__main__":
    unittest.main()
