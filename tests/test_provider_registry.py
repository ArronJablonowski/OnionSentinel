#!/usr/bin/env python3
"""Direct contracts for exact provider dispatch and runtime attestation."""
from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
N8N_ROOT = ROOT / "n8n"
if str(N8N_ROOT) not in sys.path:
    sys.path.insert(0, str(N8N_ROOT))

from onion_sentinel.analysis.providers import registry


class ProviderRegistryTests(unittest.TestCase):
    def dispatch(self, route: str, enabled: list[str], events: list[object]):
        def adapter(name):
            def invoke(*_args, **kwargs):
                events.append((name, kwargs.get("model"), kwargs.get("reasoning_effort")))
                identities = {
                    "codex": ("gpt-5.6-sol", "codex-cli", "codex-cli"),
                    "hermes": ("gpt-5.6-sol", "hermes-agent", "openai-codex"),
                    "openclaw": ("ollama/local:latest", "openclaw", "ollama"),
                    "ollama": ("local:latest", "ollama", "ollama"),
                }
                model, path, provider = identities[name]
                return {
                    "_analysis_model": model,
                    "_analysis_model_path": path,
                    "_analysis_provider": provider,
                }
            return invoke

        metadata = {
            "codex-cli:gpt-5.6-sol:xhigh": (
                "gpt-5.6-sol", "codex-cli", "codex-cli"
            ),
            "hermes-agent:gpt-5.6-sol:medium": (
                "gpt-5.6-sol", "hermes-agent", "openai-codex"
            ),
            "openclaw:ollama/local:latest:high": (
                "ollama/local:latest", "openclaw", "ollama"
            ),
            "ollama:local:latest": ("local:latest", "ollama", "ollama"),
        }
        return registry.dispatch(
            route,
            {"evidence": "bounded"},
            object(),
            {},
            system_prompt_file=Path("/synthetic/prompt.md"),
            independent_review=False,
            enabled_routes=lambda _settings: enabled,
            canonicalize=lambda value, _routes: value,
            is_hosted=lambda value, _settings: not value.startswith("ollama:"),
            synchronize_hosted=lambda _prompt: events.append("synchronized"),
            parse_codex=lambda value: (
                ("gpt-5.6-sol", "xhigh") if value.startswith("codex-cli:") else None
            ),
            parse_harness=lambda value, provider: (
                ("gpt-5.6-sol", "medium")
                if provider == "hermes-agent" and value.startswith("hermes-agent:")
                else ("ollama/local:latest", "high")
                if provider == "openclaw" and value.startswith("openclaw:")
                else None
            ),
            codex_adapter=adapter("codex"),
            hermes_adapter=adapter("hermes"),
            openclaw_adapter=adapter("openclaw"),
            ollama_adapter=adapter("ollama"),
            attest=lambda settings, selected, response: registry.attest_response(
                settings,
                selected,
                response,
                route_metadata=lambda _settings, value: (value, *metadata[value]),
            ),
        )

    def test_each_route_invokes_exactly_one_adapter_and_attests_route(self) -> None:
        cases = (
            ("codex-cli:gpt-5.6-sol:xhigh", "codex", True),
            ("hermes-agent:gpt-5.6-sol:medium", "hermes", True),
            ("openclaw:ollama/local:latest:high", "openclaw", True),
            ("ollama:local:latest", "ollama", False),
        )
        for route, adapter, hosted in cases:
            events: list[object] = []
            with self.subTest(route=route):
                response = self.dispatch(route, [route], events)
            calls = [event for event in events if isinstance(event, tuple)]
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0][0], adapter)
            self.assertEqual("synchronized" in events, hosted)
            self.assertEqual(response["_analysis_model_route"], route)

    def test_disabled_route_fails_before_sync_or_adapter_execution(self) -> None:
        events: list[object] = []
        with self.assertRaisesRegex(SystemExit, "route is not enabled"):
            self.dispatch("codex-cli:gpt-5.6-sol:xhigh", [], events)
        self.assertEqual(events, [])

    def test_attestation_rejects_requested_and_observed_identity_mismatch(self) -> None:
        with self.assertRaisesRegex(SystemExit, "model, provider"):
            registry.attest_response(
                {},
                "codex-cli:gpt-5.6-sol:xhigh",
                {
                    "_analysis_model": "gpt-5.6-terra",
                    "_analysis_model_path": "codex-cli",
                    "_analysis_provider": "openai",
                },
                route_metadata=lambda _settings, route: (
                    route,
                    "gpt-5.6-sol",
                    "codex-cli",
                    "codex-cli",
                ),
            )

    def test_invalid_enabled_provider_route_never_falls_back(self) -> None:
        events: list[object] = []
        route = "unknown-provider:model"
        with self.assertRaisesRegex(SystemExit, "Unsupported or disabled"):
            self.dispatch(route, [route], events)
        self.assertEqual(events, ["synchronized"])


if __name__ == "__main__":
    unittest.main()
