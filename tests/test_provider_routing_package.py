#!/usr/bin/env python3
"""Behavior and compatibility contracts for extracted route policy."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
N8N_ROOT = ROOT / "n8n"
BIN = N8N_ROOT / "bin"
for path in (N8N_ROOT, BIN):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from onion_sentinel.analysis.providers import routing


def load_runner():
    path = BIN / "run-local-ai-analysis.py"
    spec = importlib.util.spec_from_file_location("provider_routing_legacy_runner", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class ProviderRoutingPackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.runner = load_runner()

    def settings(self):
        return {
            "enabled_ollama_models": ["local:latest"],
            "codex_cli_models": [
                {"model": "gpt-5.6-sol", "reasoning_effort": "xhigh", "enabled": True}
            ],
            "hermes_agent_enabled": True,
            "hermes_agent_model": "gpt-5.5",
            "openclaw_enabled": True,
            "openclaw_model": "ollama/gemma4:26b-mlx",
            "openclaw_reasoning_effort": "high",
            "agent_models": {"soc-analyst": "codex-cli:gpt-5.6-sol:medium"},
            "mode": "hybrid",
        }

    def test_enabled_routes_and_stale_effort_are_exact_and_ordered(self) -> None:
        routes = routing.enabled_agent_model_routes(self.settings())
        self.assertEqual(
            routes,
            [
                "ollama:local:latest",
                "codex-cli:gpt-5.6-sol:xhigh",
                "hermes-agent:gpt-5.5:medium",
                "openclaw:ollama/gemma4:26b-mlx:high",
            ],
        )
        self.assertEqual(
            routing.canonical_model_route("codex-cli:gpt-5.6-sol:medium", routes),
            "codex-cli:gpt-5.6-sol:xhigh",
        )

    def test_malformed_and_unsupported_routes_fail_closed(self) -> None:
        for route in (
            "codex-cli:",
            "codex-cli:gpt-5.6-sol:ultra",
            "codex-cli:bad model:high",
            "ollama:gpt-5.6-sol:high",
        ):
            with self.subTest(route=route):
                self.assertIsNone(routing.parse_codex_cli_route(route))
        self.assertIsNone(
            routing.parse_cli_harness_route(
                "hermes-agent:gpt-5.6-sol:xhigh",
                "hermes-agent",
            )
        )
        self.assertIsNone(
            routing.parse_cli_harness_route("openclaw:ollama/model:ultra", "openclaw")
        )

    def test_metadata_reports_configured_and_underlying_identity(self) -> None:
        settings = self.settings()
        self.assertEqual(
            routing.model_route_metadata(
                settings,
                "codex-cli:gpt-5.6-sol:medium",
            ),
            (
                "codex-cli:gpt-5.6-sol:xhigh",
                "gpt-5.6-sol",
                "frontier-codex-cli",
                "codex-cli",
            ),
        )
        self.assertEqual(
            routing.model_route_identity("hermes-agent:gpt-5.5:medium"),
            "openai-codex:gpt-5.5",
        )
        self.assertEqual(
            routing.model_route_identity("openclaw:ollama/gemma4:26b-mlx:high"),
            "ollama:gemma4:26b-mlx",
        )

    def test_legacy_symbols_delegate_with_byte_for_byte_values(self) -> None:
        settings = self.settings()
        calls = (
            ("normalized_model_roster", ([" one ", "one", "two"],)),
            ("boolean_setting", ("enabled",)),
            ("parse_codex_cli_route", ("codex-cli:gpt-5.6-sol:xhigh",)),
            (
                "parse_cli_harness_route",
                ("openclaw:ollama/gemma4:26b-mlx:high", "openclaw"),
            ),
            ("enabled_agent_model_routes", (settings,)),
            ("model_route_identity", ("codex-cli:gpt-5.6-sol:medium",)),
        )
        for name, arguments in calls:
            with self.subTest(name=name):
                expected = getattr(routing, name)(*arguments)
                actual = getattr(self.runner, name)(*arguments)
                self.assertEqual(actual, expected)

    def test_external_agent_detection_never_matches_provider_like_model_text(self) -> None:
        routes = [
            "ollama:openclaw-model:latest",
            "codex-cli:hermes-agent-compatible:medium",
        ]
        for route in routes:
            with self.subTest(route=route):
                self.assertEqual(routing.canonical_model_route(route, routes), route)
        self.assertTrue(routing.openclaw_model_uses_ollama_runtime(" OLLAMA/model "))
        self.assertFalse(routing.openclaw_model_uses_ollama_runtime("openai/model"))


if __name__ == "__main__":
    unittest.main()
