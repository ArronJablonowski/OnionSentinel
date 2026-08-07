#!/usr/bin/env python3
"""Contracts for persisted dashboard AI settings and legacy migration."""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "onion-sentinel-dashboard" / "scripts"
MODULE_PATH = SCRIPTS / "dashboard_ai_settings.py"
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


class DashboardAiSettingsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.settings_module = load_module("dashboard_ai_settings", MODULE_PATH)
        cls.builder = load_module("dashboard_ai_settings_test_builder", BUILDER_PATH)

    def load(self, payload: object, environ: dict[str, str] | None = None) -> dict:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ai_model_settings.json"
            if isinstance(payload, str):
                path.write_text(payload, encoding="utf-8")
            else:
                path.write_text(json.dumps(payload), encoding="utf-8")
            return self.settings_module.load_ai_settings(path, environ or {})

    def test_defaults_honor_only_explicit_environment_inputs(self) -> None:
        settings = self.settings_module.default_soc_ai_settings({
            "SOC_AI_MODEL": "local:test",
            "OLLAMA_URL": "http://ollama.test:11434",
        })
        self.assertEqual(settings["enabled_ollama_models"], ["local:test"])
        self.assertEqual(settings["ollama_url"], "http://ollama.test:11434")
        self.assertEqual(settings["pcap_capture_loss_threshold_percent"], 5.0)

    def test_malformed_and_non_object_json_fail_safe_to_defaults(self) -> None:
        for payload in ("{broken", ["not", "an", "object"]):
            with self.subTest(payload=payload):
                settings = self.load(payload)
                self.assertEqual(settings["mode"], "ollama")
                self.assertEqual(settings["enabled_ollama_models"], ["devstral:latest"])
                self.assertFalse(settings["gpt_cli_enabled"])

    def test_legacy_cloud_mode_enables_fixed_codex_catalog_entry(self) -> None:
        settings = self.load({
            "mode": "cloud",
            "cloud_model": "gpt-5.6-sol",
            "codex_cli_model": "gpt-5.6-sol",
            "codex_cli_reasoning_effort": "xhigh",
        })
        self.assertEqual(settings["mode"], "cloud")
        self.assertEqual(settings["enabled_ollama_models"], [])
        self.assertTrue(settings["gpt_cli_enabled"])
        self.assertEqual(settings["codex_cli_model"], "gpt-5.6-sol")
        self.assertEqual(settings["codex_cli_reasoning_effort"], "xhigh")
        self.assertEqual(
            settings["agent_models"]["soc-analyst"],
            "codex-cli:gpt-5.6-sol:xhigh",
        )

    def test_all_disabled_providers_restore_safe_local_fallback(self) -> None:
        settings = self.load({
            "mode": "cloud",
            "enabled_ollama_models": [],
            "codex_cli_models": [],
            "gpt_cli_enabled": False,
            "hermes_agent_enabled": False,
            "openclaw_enabled": False,
        })
        self.assertEqual(settings["mode"], "ollama")
        self.assertEqual(settings["enabled_ollama_models"], ["devstral:latest"])
        self.assertEqual(settings["agent_models"]["incident-responder"], "ollama:devstral:latest")

    def test_provider_safety_threshold_alias_and_legacy_geoip_migrate(self) -> None:
        settings = self.load({
            "enabled_ollama_models": ["primary:latest", "reviewer:latest"],
            "hermes_agent_enabled": True,
            "hermes_agent_path": "/tmp/not-hermes",
            "hermes_agent_model": "unknown-model",
            "openclaw_enabled": True,
            "openclaw_path": "unsafe-command",
            "openclaw_model": "openai/gpt-5.6-sol",
            "openclaw_reasoning_effort": "impossible",
            "soc_analyst_analysis_min_severity": "info",
            "soc_analyst_pcap_min_severity": "unknown",
            "maxmind_geoip_db_path": "/legacy/GeoLite2-City.mmdb",
            "agent_models": {"soc-analyst": "ollama:primary:latest"},
            "agent_second_opinion_models": {"soc-analyst": "ollama:reviewer:latest"},
            "agent_adjudicator_models": {"soc-analyst": "ollama:primary:latest"},
        })
        self.assertEqual(settings["hermes_agent_path"], "hermes")
        self.assertEqual(settings["hermes_agent_model"], "gpt-5.5")
        self.assertEqual(settings["openclaw_path"], "openclaw")
        self.assertEqual(settings["openclaw_model"], "ollama/gemma4:26b-mlx")
        self.assertEqual(settings["openclaw_reasoning_effort"], "medium")
        self.assertEqual(settings["soc_analyst_analysis_min_severity"], "informational")
        self.assertEqual(settings["soc_analyst_pcap_min_severity"], "informational")
        self.assertEqual(settings["maxmind_geoip_city_db_path"], "/legacy/GeoLite2-City.mmdb")
        self.assertEqual(settings["agent_second_opinion_models"]["soc-analyst"], "ollama:reviewer:latest")
        self.assertEqual(settings["agent_adjudicator_models"]["soc-analyst"], "")

    def test_builder_reexports_contract_and_uses_runtime_path_override(self) -> None:
        for name in (
            "default_soc_ai_settings",
            "_normalized_cli_path",
            "_normalized_codex_cli_models",
        ):
            self.assertIs(getattr(self.builder, name), getattr(self.settings_module, name))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "settings.json"
            path.write_text(json.dumps({"enabled_ollama_models": ["patched:latest"]}), encoding="utf-8")
            with mock.patch.object(self.builder, "SOC_AI_SETTINGS_FILE", path):
                self.assertEqual(
                    self.builder.load_soc_ai_settings()["enabled_ollama_models"],
                    ["patched:latest"],
                )

    def test_module_is_bounded_and_deployed_after_routing_dependency(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertLessEqual(len(source.splitlines()), 320)
        for forbidden in ("subprocess", "urllib", "sqlite3", "write_text("):
            self.assertNotIn(forbidden, source)
        installer = INSTALLER_PATH.read_text(encoding="utf-8")
        self.assertEqual(installer.count("dashboard_ai_settings.py"), 2)
        self.assertLess(
            installer.index("dashboard_model_routing.py"),
            installer.index("dashboard_ai_settings.py"),
        )


if __name__ == "__main__":
    unittest.main()
