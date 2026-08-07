#!/usr/bin/env python3
"""Contracts for model assignment and execution-provenance presentation."""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "onion-sentinel-dashboard" / "scripts"
MODULE_PATH = SCRIPTS / "dashboard_model_presentation.py"
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


class DashboardModelPresentationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.presentation = load_module("dashboard_model_presentation", MODULE_PATH)
        cls.builder = load_module("dashboard_model_presentation_test_builder", BUILDER_PATH)

    def settings(self) -> dict:
        roles = ("soc-analyst", "incident-responder", "siem-engineer", "cyber-threat-intel", "threat-hunter")
        return {
            "enabled_ollama_models": ["primary:latest", "reviewer:latest"],
            "codex_cli_models": [{
                "model": "gpt-5.6-sol", "reasoning_effort": "xhigh", "enabled": True,
            }],
            "hermes_agent_enabled": True,
            "hermes_agent_model": "gpt-5.5",
            "openclaw_enabled": True,
            "openclaw_model": "ollama/gemma4:26b-mlx",
            "openclaw_reasoning_effort": "high",
            "agent_models": {role: "ollama:primary:latest" for role in roles},
            "agent_second_opinion_models": {role: "ollama:reviewer:latest" for role in roles},
            "agent_adjudicator_models": {role: "codex-cli:gpt-5.6-sol:xhigh" for role in roles},
        }

    def test_route_labels_cover_every_provider_and_escape_selector_values(self) -> None:
        settings = self.settings()
        expected = {
            "ollama:primary:latest": "Ollama: primary:latest",
            "codex-cli:gpt-5.6-sol:xhigh": "Codex CLI: gpt-5.6-sol (xhigh)",
            "hermes-agent:gpt-5.5:medium": "Hermes Agent: gpt-5.5 (medium)",
            "openclaw:ollama/gemma4:26b-mlx:high": "OpenClaw: ollama/gemma4:26b-mlx (high)",
        }
        for route, label in expected.items():
            with self.subTest(route=route):
                self.assertEqual(self.presentation.agent_route_label(route, settings), label)
        settings["enabled_ollama_models"].append('unsafe"><script>')
        options = self.presentation.agent_model_option_rows(settings, "soc-analyst")
        self.assertNotIn("<script>", options)
        self.assertIn("&quot;&gt;&lt;script&gt;", options)

    def test_reviewer_and_adjudicator_options_exclude_same_model_identity(self) -> None:
        settings = self.settings()
        reviewer = self.presentation.agent_model_option_rows(
            settings, "soc-analyst", second_opinion=True
        )
        adjudicator = self.presentation.agent_model_option_rows(
            settings, "soc-analyst", adjudicator=True
        )
        self.assertNotIn("Ollama: primary:latest", reviewer)
        self.assertIn("Ollama: reviewer:latest", reviewer)
        self.assertNotIn("Ollama: primary:latest", adjudicator)
        self.assertNotIn("Ollama: reviewer:latest", adjudicator)
        self.assertIn("Codex CLI: gpt-5.6-sol (xhigh)", adjudicator)

    def test_assignment_projection_reports_exact_route_and_never_falls_back(self) -> None:
        settings = self.settings()
        settings["agent_models"]["soc-analyst"] = "openclaw:ollama/gemma4:26b-mlx:high"
        projection = self.presentation.assigned_model_projection(settings, "soc-analyst")
        self.assertEqual(projection["provider"], "OpenClaw")
        self.assertEqual(projection["model_detail"], "ollama/gemma4:26b-mlx (high)")
        self.assertEqual(projection["route"], "openclaw:ollama/gemma4:26b-mlx:high")
        settings["agent_models"]["soc-analyst"] = "invalid-route"
        self.assertIsNone(self.presentation.assigned_model_projection(settings, "soc-analyst"))

    def test_observed_and_unassigned_projections_preserve_truthful_provenance(self) -> None:
        observed = self.presentation.observed_model_projection({
            "response": {
                "_analysis_model": "gpt-5.6-sol",
                "_analysis_model_path": "frontier-codex-cli",
            },
        })
        self.assertEqual(observed["label"], "Codex CLI · gpt-5.6-sol")
        self.assertEqual(observed["route"], "")
        unknown = self.presentation.observed_model_projection({
            "analysis_model": "custom-model", "analysis_model_path": "custom-provider",
        })
        self.assertEqual(unknown["provider"], "Unknown provider")
        self.assertIsNone(self.presentation.observed_model_projection({"response": {}}))
        self.assertEqual(
            self.presentation.unassigned_model_projection("")["label"],
            "Unassigned · unassigned",
        )

    def test_execution_labels_distinguish_active_historical_and_idle_models(self) -> None:
        cases = (
            ({"status": "running", "active_phase": "primary_analysis", "active_model_route": "codex-cli:gpt-5.6-sol:xhigh"}, True, "Codex CLI · gpt-5.6-sol (xhigh)"),
            ({"status": "running", "active_phase": "second_opinion", "active_model_route": "ollama:reviewer:latest"}, True, "Ollama · reviewer:latest"),
            ({"status": "running", "active_phase": "post_processing", "active_model_route": "", "active_model": ""}, True, "No model running"),
            ({"status": "success", "model": "gpt-5.5", "model_path": "hermes-agent"}, False, "Hermes Agent · gpt-5.5"),
            ({"status": "failure"}, False, "No model started"),
            ({"status": "success", "model": "old"}, True, "No model running"),
        )
        for log, live, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(
                    self.presentation.llm_executed_model_label(log, live=live), expected
                )
        self.assertEqual(self.presentation.llm_agent_label({"agent_role": "soc_analyst"}), "SOC Analyst")
        self.assertEqual(self.presentation.llm_job_label({"agent_role": "incident-responder"}), "Incident response investigation")
        self.assertEqual(self.presentation.llm_phase_label({"status": "running", "active_phase": "second_opinion"}), "Second-opinion review")

    def test_builder_prefers_assignment_then_newest_valid_stamped_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            analysis_dir = Path(directory)
            older = analysis_dir / "older.json"
            newer_invalid = analysis_dir / "newer.json"
            older.write_text(json.dumps({
                "analysis_model": "observed-model", "analysis_model_path": "ollama",
            }), encoding="utf-8")
            newer_invalid.write_text("{invalid", encoding="utf-8")
            os.utime(older, (1, 1))
            os.utime(newer_invalid, (2, 2))
            settings = {"agent_models": {"soc-analyst": "invalid-route"}}
            with mock.patch.object(self.builder, "AI_ANALYSIS_DIR", analysis_dir):
                observed = self.builder.current_soc_analysis_model(settings)
            settings["agent_models"]["soc-analyst"] = "ollama:configured-model"
            configured = self.builder.current_soc_analysis_model(settings)

        self.assertEqual(observed["label"], "Ollama · observed-model")
        self.assertEqual(configured["label"], "Ollama · configured-model")

    def test_builder_reexports_presentation_contract(self) -> None:
        for name in (
            "agent_model_route_label", "agent_model_option_rows", "llm_agent_label",
            "llm_job_label", "llm_phase_label", "llm_executed_model_label",
        ):
            self.assertIs(getattr(self.builder, name), getattr(self.presentation, name))

    def test_module_is_bounded_and_deployed_after_routing_policy(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertLessEqual(len(source.splitlines()), 320)
        for forbidden in ("subprocess", "sqlite3", "urllib", "read_text(", "write_text("):
            self.assertNotIn(forbidden, source)
        installer = INSTALLER_PATH.read_text(encoding="utf-8")
        self.assertEqual(installer.count("dashboard_model_presentation.py"), 2)
        self.assertLess(
            installer.index("dashboard_model_routing.py"),
            installer.index("dashboard_model_presentation.py"),
        )


if __name__ == "__main__":
    unittest.main()
