#!/usr/bin/env python3
"""Contract tests for Cyber Security Agent model assignments on Settings."""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = REPO_ROOT / "onion-sentinel-dashboard" / "scripts"
BUILDER_PATH = SCRIPT_DIR / "build_soc_alerts_dashboard.py"


def load_builder():
    if str(SCRIPT_DIR) not in sys.path:
        sys.path.insert(0, str(SCRIPT_DIR))
    spec = importlib.util.spec_from_file_location("build_soc_alerts_dashboard", BUILDER_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class DashboardAgentModelLabelTests(unittest.TestCase):
    def setUp(self) -> None:
        self.builder = load_builder()

    def test_model_route_label_is_specific_to_each_agent(self) -> None:
        base = {
            "ollama_model": "local-test:latest",
            "enabled_ollama_models": ["local-test:latest"],
            "cloud_provider": "codex-cli",
            "cloud_model": "gpt-5.5",
            "codex_cli_model": "gpt-5.5",
            "codex_cli_reasoning_effort": "medium",
            "gpt_cli_enabled": True,
            "agent_models": {
                "soc-analyst": "ollama:local-test:latest",
                "incident-responder": "gpt-cli",
            },
        }

        self.assertEqual(
            self.builder.agent_model_route_label(base, "soc-analyst"),
            "Ollama: local-test:latest",
        )
        self.assertEqual(
            self.builder.agent_model_route_label(base, "incident-responder"),
            "Codex CLI: gpt-5.5 (medium)",
        )
        self.assertEqual(
            self.builder.agent_model_route_label(base, "threat-hunter"),
            "No analysis model assigned",
        )

    def test_every_collapsed_agent_row_shows_the_resolved_model(self) -> None:
        settings = {
            **self.builder.default_soc_ai_settings(),
            "mode": "ollama",
            "ollama_model": "local-test:latest",
            "enabled_ollama_models": ["local-test:latest"],
            "agent_models": {
                role: "ollama:local-test:latest" for role in self.builder.CYBER_SECURITY_AGENT_ROLES
            },
        }
        with (
            mock.patch.object(self.builder, "load_soc_ai_settings", return_value=settings),
            mock.patch.object(self.builder, "list_ollama_models", return_value=["local-test:latest"]),
        ):
            rendered = self.builder.settings_page_section()

        self.assertEqual(rendered.count('data-agent-model="'), 5)
        self.assertEqual(rendered.count('data-agent-second-opinion-model="'), 5)
        self.assertEqual(rendered.count("None selected"), 5)
        self.assertEqual(rendered.count("data-agent-model-select"), 5)
        self.assertEqual(rendered.count("data-agent-second-opinion-select"), 5)
        self.assertEqual(rendered.count("data-agent-model-save="), 5)
        self.assertGreaterEqual(rendered.count("Ollama: local-test:latest"), 10)

    def test_collapsed_agent_row_shows_the_resolved_second_opinion_model(self) -> None:
        settings = {
            **self.builder.default_soc_ai_settings(),
            "mode": "ollama",
            "ollama_model": "primary:latest",
            "enabled_ollama_models": ["primary:latest", "reviewer:latest"],
            "agent_models": {
                role: "ollama:primary:latest" for role in self.builder.CYBER_SECURITY_AGENT_ROLES
            },
            "agent_second_opinion_models": {
                role: "ollama:reviewer:latest" for role in self.builder.CYBER_SECURITY_AGENT_ROLES
            },
        }
        with (
            mock.patch.object(self.builder, "load_soc_ai_settings", return_value=settings),
            mock.patch.object(
                self.builder,
                "list_ollama_models",
                return_value=["primary:latest", "reviewer:latest"],
            ),
        ):
            rendered = self.builder.settings_page_section()

        self.assertEqual(rendered.count('data-agent-second-opinion-model="'), 5)
        for role in self.builder.CYBER_SECURITY_AGENT_ROLES:
            self.assertIn(
                f'data-agent-second-opinion-model="{role}">Ollama: reviewer:latest</span>',
                rendered,
            )
        self.assertNotIn("None selected", rendered)

    def test_model_selection_uses_collapsed_provider_sections_and_model_toggles(self) -> None:
        settings = {
            **self.builder.default_soc_ai_settings(),
            "enabled_ollama_models": ["primary:latest"],
            "ollama_model": "primary:latest",
        }
        with (
            mock.patch.object(self.builder, "load_soc_ai_settings", return_value=settings),
            mock.patch.object(self.builder, "list_ollama_models", return_value=["primary:latest", "fallback:latest"]),
        ):
            rendered = self.builder.settings_page_section()

        self.assertIn('id="ollama-provider-settings"', rendered)
        self.assertIn('id="gpt-cli-provider-settings"', rendered)
        self.assertIn("Codex CLI", rendered)
        self.assertIn('id="ai-codex-cli-path"', rendered)
        self.assertIn('id="ai-codex-cli-model"', rendered)
        self.assertIn('id="ai-codex-cli-reasoning-effort"', rendered)
        self.assertNotIn('id="ai-cloud-command"', rendered)
        self.assertNotIn('id="ai-analysis-mode"', rendered)
        self.assertEqual(rendered.count("data-ollama-model-toggle"), 2)
        self.assertNotIn('<details class="settings-provider-details" id="ollama-provider-settings" open', rendered)
        self.assertNotIn('<details class="settings-provider-details" id="gpt-cli-provider-settings" open', rendered)

    def test_saved_settings_refresh_role_specific_controls(self) -> None:
        script = self.builder.SETTINGS_PAGE_JS

        self.assertIn("const agentModelLabels = [...document.querySelectorAll('[data-agent-model]')]", script)
        self.assertIn(
            "const agentSecondOpinionModelLabels = [...document.querySelectorAll('[data-agent-second-opinion-model]')]",
            script,
        )
        self.assertIn("element.textContent = route ? agentModelRouteLabel(route, settings) : 'None selected';", script)
        self.assertIn("const agentSecondOpinionSelects", script)
        self.assertIn("settings.agent_second_opinion_models", script)
        self.assertIn("/api/soc-settings/agent-model", script)
        self.assertIn("body: JSON.stringify({role, model, second_opinion_model: secondOpinionModel})", script)
        self.assertIn("data-agent-model-status", script)

    def test_model_inventory_renders_workflow_compatibility_warnings(self) -> None:
        script = self.builder.SETTINGS_PAGE_JS
        css = self.builder.SETTINGS_PAGE_CSS

        self.assertIn("workflowCompatibilityReason", script)
        self.assertIn("Workflow compatibility warning:", script)
        self.assertIn("data.compatibility", script)
        self.assertIn("?refresh=1", script)
        self.assertIn(".settings-model-warning", css)


if __name__ == "__main__":
    unittest.main()
