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

    def test_dispatch_preserves_canonical_sync_parse_adapter_attest_order(self) -> None:
        events: list[object] = []
        prompt = {"evidence": ["bounded"]}
        args = object()
        settings = {"enabled": True}
        response = {"summary": "result"}

        def enabled(observed_settings):
            events.append(("enabled", observed_settings is settings))
            return ["codex-cli:gpt-5.6-sol:xhigh"]

        def canonicalize(route, routes):
            events.append(("canonicalize", route, tuple(routes)))
            return "codex-cli:gpt-5.6-sol:xhigh"

        def hosted(route, observed_settings):
            events.append(("hosted", route, observed_settings is settings))
            return True

        def synchronize(observed_prompt):
            events.append(("synchronize", observed_prompt is prompt))

        def parse(route):
            events.append(("parse", route))
            return "gpt-5.6-sol", "xhigh"

        def adapter(observed_prompt, observed_args, observed_settings, **kwargs):
            events.append((
                "adapter", observed_prompt is prompt, observed_args is args,
                observed_settings is settings, kwargs,
            ))
            return response

        def attest(observed_settings, route, observed_response):
            events.append((
                "attest", observed_settings is settings, route,
                observed_response is response,
            ))
            return observed_response

        result = registry.dispatch(
            "gpt-cli", prompt, args, settings,
            system_prompt_file=Path("/synthetic/system.md"),
            independent_review=True, enabled_routes=enabled,
            canonicalize=canonicalize, is_hosted=hosted,
            synchronize_hosted=synchronize, parse_codex=parse,
            parse_harness=lambda *_args: self.fail("harness parser called"),
            codex_adapter=adapter,
            hermes_adapter=lambda *_args, **_kwargs: self.fail("Hermes called"),
            openclaw_adapter=lambda *_args, **_kwargs: self.fail("OpenClaw called"),
            ollama_adapter=lambda *_args, **_kwargs: self.fail("Ollama called"),
            attest=attest,
        )

        self.assertIs(result, response)
        self.assertEqual([event[0] for event in events], [
            "enabled", "canonicalize", "hosted", "synchronize", "parse",
            "adapter", "attest",
        ])
        self.assertEqual(events[5][4], {
            "model": "gpt-5.6-sol",
            "reasoning_effort": "xhigh",
            "system_prompt_file": Path("/synthetic/system.md"),
            "independent_review": True,
        })
        self.assertEqual(events[6][2], "codex-cli:gpt-5.6-sol:xhigh")
        self.assertEqual(prompt, {"evidence": ["bounded"]})
        self.assertEqual(settings, {"enabled": True})

    def test_route_specific_validation_errors_preserve_sync_precedence(self) -> None:
        cases = (
            ("codex-cli:invalid", "Configured Codex CLI route is invalid"),
            ("hermes-agent:invalid", "Configured Hermes Agent route is invalid"),
            ("openclaw:invalid", "Configured OpenClaw route is invalid"),
            ("ollama:   ", "Configured Ollama route has an empty model name"),
        )
        for route, message in cases:
            events: list[object] = []
            with self.subTest(route=route), self.assertRaisesRegex(
                SystemExit, message
            ):
                registry.dispatch(
                    route, {}, object(), {}, system_prompt_file=None,
                    independent_review=False,
                    enabled_routes=lambda _settings: [route],
                    canonicalize=lambda value, _routes: value,
                    is_hosted=lambda *_args: True,
                    synchronize_hosted=lambda _prompt: events.append("sync"),
                    parse_codex=lambda value: events.append(("codex", value)),
                    parse_harness=lambda value, provider: events.append(
                        (provider, value)
                    ),
                    codex_adapter=lambda *_args, **_kwargs: self.fail("adapter called"),
                    hermes_adapter=lambda *_args, **_kwargs: self.fail("adapter called"),
                    openclaw_adapter=lambda *_args, **_kwargs: self.fail("adapter called"),
                    ollama_adapter=lambda *_args, **_kwargs: self.fail("adapter called"),
                    attest=lambda *_args: self.fail("attest called"),
                )
            self.assertEqual(events[0], "sync")
            if not route.startswith("ollama:"):
                self.assertEqual(len(events), 2)


if __name__ == "__main__":
    unittest.main()
