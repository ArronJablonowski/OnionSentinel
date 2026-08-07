#!/usr/bin/env python3
"""Contracts for the dashboard adapter over canonical provider routing."""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "onion-sentinel-dashboard" / "scripts"
MODULE_PATH = SCRIPTS / "dashboard_model_routing.py"
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


class DashboardModelRoutingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.routing = load_module("dashboard_model_routing", MODULE_PATH)
        cls.builder = load_module("dashboard_model_routing_test_builder", BUILDER_PATH)

    def settings(self) -> dict:
        return {
            "enabled_ollama_models": ["local:latest"],
            "codex_cli_models": [
                {"model": "gpt-5.6-sol", "reasoning_effort": "xhigh", "enabled": True},
            ],
            "hermes_agent_enabled": True,
            "hermes_agent_model": "gpt-5.5",
            "openclaw_enabled": True,
            "openclaw_model": "ollama/gemma4:26b-mlx",
            "openclaw_reasoning_effort": "high",
        }

    def test_enabled_routes_reuse_canonical_order_with_dashboard_safety(self) -> None:
        self.assertEqual(
            self.routing.enabled_agent_model_routes(self.settings()),
            [
                "ollama:local:latest",
                "codex-cli:gpt-5.6-sol:xhigh",
                "hermes-agent:gpt-5.5:medium",
                "openclaw:ollama/gemma4:26b-mlx:high",
            ],
        )
        unsafe = {**self.settings(), "openclaw_model": "openai/gpt-5.6-sol"}
        self.assertIn(
            "openclaw:ollama/gemma4:26b-mlx:high",
            self.routing.enabled_agent_model_routes(unsafe),
        )

    def test_primary_reviewer_and_adjudicator_assignments_fail_closed(self) -> None:
        routes = self.routing.enabled_agent_model_routes(self.settings())
        primary = self.routing.normalize_agent_models(
            {"soc-analyst": "codex-cli:gpt-5.6-sol:medium"}, routes,
        )
        self.assertEqual(primary["soc-analyst"], "codex-cli:gpt-5.6-sol:xhigh")
        reviewers = self.routing.normalize_agent_second_opinion_models(
            {"soc-analyst": "hermes-agent:gpt-5.5:medium"}, routes, primary,
        )
        self.assertEqual(reviewers["soc-analyst"], "hermes-agent:gpt-5.5:medium")
        adjudicators = self.routing.normalize_agent_adjudicator_models(
            {"soc-analyst": "codex-cli:gpt-5.6-sol:xhigh"},
            routes, primary, reviewers,
        )
        self.assertEqual(adjudicators["soc-analyst"], "")

    def test_builder_reexports_adapter_contract(self) -> None:
        for name in (
            "enabled_agent_model_routes", "model_route_identity",
            "normalize_agent_models", "normalize_agent_second_opinion_models",
            "normalize_agent_adjudicator_models",
        ):
            self.assertIs(getattr(self.builder, name), getattr(self.routing, name))

    def test_module_is_bounded_and_both_runtime_layers_are_deployed(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertLessEqual(len(source.splitlines()), 180)
        for forbidden in ("subprocess", "json", "write_text(", "open("):
            self.assertNotIn(forbidden, source)
        installer = INSTALLER_PATH.read_text(encoding="utf-8")
        self.assertEqual(installer.count("dashboard_model_routing.py"), 2)
        package_install = installer.index('install-ai-runtime-package.py" \\\n  --source')
        adapter_install = installer.index("dashboard_model_routing.py")
        self.assertLess(package_install, adapter_install)


if __name__ == "__main__":
    unittest.main()
