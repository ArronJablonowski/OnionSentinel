#!/usr/bin/env python3
"""Modular ownership and deployment contracts for Settings page assets."""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = ROOT / "onion-sentinel-dashboard" / "scripts"
BUILDER_PATH = SCRIPT_DIR / "build_soc_alerts_dashboard.py"
ASSETS_PATH = SCRIPT_DIR / "dashboard_settings_assets.py"
AGENT_CARD_PATH = SCRIPT_DIR / "dashboard_settings_agent_card.py"
INSTALLER_PATH = ROOT / "n8n" / "bin" / "install-macstudio-stack.zsh"
MODULE_NAMES = (
    "dashboard_settings_assets.py",
    "dashboard_settings_agent_card.py",
    "dashboard_settings_client_shell.py",
    "dashboard_settings_client_model.py",
    "dashboard_settings_client_actions.py",
)


def load(path: Path, name: str):
    if str(SCRIPT_DIR) not in sys.path:
        sys.path.insert(0, str(SCRIPT_DIR))
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class DashboardSettingsModuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.assets = load(ASSETS_PATH, "dashboard_settings_assets")
        cls.agent_card = load(AGENT_CARD_PATH, "dashboard_settings_agent_card")
        cls.builder = load(BUILDER_PATH, "dashboard_settings_builder_test")
        cls.installer = INSTALLER_PATH.read_text(encoding="utf-8")

    def test_builder_reexports_the_assembled_assets(self) -> None:
        self.assertIs(self.builder.SETTINGS_PAGE_CSS, self.assets.SETTINGS_PAGE_CSS)
        self.assertIs(self.builder.SETTINGS_PAGE_JS, self.assets.SETTINGS_PAGE_JS)
        self.assertIs(self.builder.inject_settings_assets, self.assets.inject_settings_assets)

    def test_assembled_client_remains_one_complete_script(self) -> None:
        script = self.assets.SETTINGS_PAGE_JS
        self.assertTrue(script.startswith("\n<script>\n(() => {"))
        self.assertTrue(script.endswith("})();\n</script>\n"))
        self.assertEqual(script.count("<script>"), 1)
        self.assertEqual(script.count("</script>"), 1)
        self.assertIn("function enabledAgentRoutes(settings)", script)
        self.assertIn("async function saveAiSettings()", script)
        self.assertIn("promptConfigurations.forEach(refreshPromptEditor)", script)

    def test_injection_is_idempotent(self) -> None:
        shell = "<html><head></head><body></body></html>"
        first = self.assets.inject_settings_assets(shell)
        second = self.assets.inject_settings_assets(first)
        self.assertEqual(first, second)
        self.assertEqual(first.count(self.assets.SETTINGS_PAGE_CSS), 1)
        self.assertEqual(first.count(self.assets.SETTINGS_PAGE_JS), 1)

    def test_agent_card_renderer_escapes_data_and_preserves_owned_controls(self) -> None:
        view = self.agent_card.AgentSettingsCardViewModel(
            role="test-agent",
            role_label="Test & Agent",
            kicker="Test <agent>",
            title="Agent <title>",
            trigger="Run & inspect",
            description="Description <unsafe>",
            icon_path='assets/test".png',
            prompt_path="~/prompt&a.md",
            reviewer_prompt_path="~/review.md",
            memory_path="~/memory.md",
            shared_memory_path="~/shared.md",
            model_label="model<&>",
            reviewer_model_label="reviewer",
            adjudicator_model_label="adjudicator",
            model_control_html='<div id="model-control"></div>',
            prompt_control_html='<div id="prompt-control"></div>',
            note="Review <carefully>",
        )
        rendered = self.agent_card.render_agent_settings_card(view)
        self.assertIn("Test &amp; Agent files", rendered)
        self.assertIn("Test &lt;agent&gt;", rendered)
        self.assertIn("model&lt;&amp;&gt;", rendered)
        self.assertIn('assets/test&quot;.png', rendered)
        self.assertIn("Review &lt;carefully&gt;", rendered)
        self.assertIn('<div id="model-control"></div>', rendered)
        self.assertIn('<div id="prompt-control"></div>', rendered)

    def test_soc_agent_renderer_owns_policy_markup_and_escapes_data(self) -> None:
        view = self.agent_card.SocAgentSettingsCardViewModel(
            prompt_path="~/prompt<&>.md",
            reviewer_prompt_path="~/review.md",
            memory_path="~/memory.md",
            shared_memory_path="~/shared.md",
            model_label="primary<&>",
            reviewer_model_label="reviewer",
            adjudicator_model_label="adjudicator",
            analysis_threshold_label="Medium",
            pcap_threshold_label="High",
            incident_threshold_label="Critical",
            analysis_disabled=False,
            incident_disabled=True,
            analysis_threshold_options_html='<option selected>Medium</option>',
            pcap_threshold_options_html='<option selected>High</option>',
            incident_threshold_options_html='<option selected>Disabled</option>',
            model_control_html='<div id="soc-model-control"></div>',
            prompt_control_html='<div id="soc-prompt-control"></div>',
        )
        rendered = self.agent_card.render_soc_agent_settings_card(view)
        self.assertIn("primary&lt;&amp;&gt;", rendered)
        self.assertIn("~/prompt&lt;&amp;&gt;.md", rendered)
        self.assertIn('data-soc-policy-label="analysis">Medium and higher', rendered)
        self.assertIn('data-soc-policy-label="incident">Disabled', rendered)
        self.assertIn('id="pcap-capture-loss-threshold-percent"', rendered)
        self.assertIn('<div id="soc-model-control"></div>', rendered)
        self.assertIn('<div id="soc-prompt-control"></div>', rendered)

    def test_settings_modules_stay_within_the_maintenance_target(self) -> None:
        for name in MODULE_NAMES:
            with self.subTest(name=name):
                lines = (SCRIPT_DIR / name).read_text(encoding="utf-8").splitlines()
                self.assertLessEqual(len(lines), 600)

    def test_installer_copies_every_settings_asset_module(self) -> None:
        for name in MODULE_NAMES:
            with self.subTest(name=name):
                command = (
                    f'cp "$REPO_DIR/onion-sentinel-dashboard/scripts/{name}" '
                    f'"$DASHBOARD_RUNTIME_DIR/scripts/{name}"'
                )
                self.assertEqual(self.installer.count(command), 1)


if __name__ == "__main__":
    unittest.main()
