"""Characterize canonical model-route metadata attribution."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.analysis.providers import routing  # noqa: E402


class ExplodingString:
    def __str__(self) -> str:
        raise RuntimeError("configured model stringification failed")


class ProviderRouteMetadataCharacterizationTests(unittest.TestCase):
    def test_canonicalization_precedes_route_branch_and_preserves_arguments(self) -> None:
        settings = {"enabled_ollama_models": ["model-a"]}
        routes = object()
        calls: list[tuple[object, ...]] = []

        with mock.patch.object(
            routing,
            "enabled_agent_model_routes",
            side_effect=lambda value: calls.append(("enabled", value)) or routes,
        ), mock.patch.object(
            routing,
            "canonical_model_route",
            side_effect=lambda route, enabled: calls.append(
                ("canonical", route, enabled)
            )
            or "ollama:model-a",
        ), mock.patch.object(
            routing,
            "parse_codex_cli_route",
            side_effect=AssertionError("ollama must not parse as Codex"),
        ):
            self.assertEqual(
                routing.model_route_metadata(settings, "stale-route"),
                ("ollama:model-a", "model-a", "ollama", "ollama"),
            )

        self.assertEqual(calls, [
            ("enabled", settings),
            ("canonical", "stale-route", routes),
        ])

    def test_ollama_empty_model_falls_through_to_parser_order(self) -> None:
        calls: list[tuple[object, ...]] = []

        def parse_codex(route: str) -> None:
            calls.append(("codex", route))
            return None

        def parse_harness(route: str, provider: str) -> None:
            calls.append((provider, route))
            return None

        with mock.patch.object(
            routing, "enabled_agent_model_routes", return_value=[]
        ), mock.patch.object(
            routing, "canonical_model_route", return_value="ollama:   "
        ), mock.patch.object(
            routing, "parse_codex_cli_route", side_effect=parse_codex
        ), mock.patch.object(
            routing, "parse_cli_harness_route", side_effect=parse_harness
        ):
            result = routing.model_route_metadata({}, "route")

        self.assertEqual(result, ("ollama:   ", "", "unknown", "unknown"))
        self.assertEqual(calls, [
            ("codex", "ollama:   "),
            ("hermes-agent", "ollama:   "),
            ("openclaw", "ollama:   "),
        ])

    def test_codex_hermes_and_openclaw_metadata_stop_at_first_parser_match(self) -> None:
        cases = (
            (
                "codex-cli:gpt:high",
                ("gpt", "high"),
                None,
                ("codex-cli:gpt:high", "gpt", "frontier-codex-cli", "codex-cli"),
                ["codex"],
            ),
            (
                "hermes-agent:gpt:medium",
                None,
                ("gpt", "medium"),
                ("hermes-agent:gpt:medium", "gpt", "hermes-agent", "openai-codex"),
                ["codex", "hermes-agent"],
            ),
            (
                "openclaw:ollama/model:high",
                None,
                ("ollama/model", "high"),
                ("openclaw:ollama/model:high", "ollama/model", "openclaw", "ollama"),
                ["codex", "hermes-agent", "openclaw"],
            ),
            (
                "openclaw:model:high",
                None,
                ("model", "high"),
                ("openclaw:model:high", "model", "openclaw", "openclaw"),
                ["codex", "hermes-agent", "openclaw"],
            ),
        )
        for canonical, codex_value, harness_value, expected, expected_calls in cases:
            calls: list[str] = []

            def codex(_route: str) -> object:
                calls.append("codex")
                return codex_value

            def harness(_route: str, provider: str) -> object:
                calls.append(provider)
                if provider == "hermes-agent" and canonical.startswith("hermes"):
                    return harness_value
                if provider == "openclaw" and canonical.startswith("openclaw"):
                    return harness_value
                return None

            with self.subTest(canonical=canonical), mock.patch.object(
                routing, "enabled_agent_model_routes", return_value=[]
            ), mock.patch.object(
                routing, "canonical_model_route", return_value=canonical
            ), mock.patch.object(
                routing, "parse_codex_cli_route", side_effect=codex
            ), mock.patch.object(
                routing, "parse_cli_harness_route", side_effect=harness
            ):
                self.assertEqual(routing.model_route_metadata({}, "route"), expected)
                self.assertEqual(calls, expected_calls)

    def test_provider_only_codex_fallback_and_unknowns_are_exact(self) -> None:
        cases = (
            ({"codex_cli_model": " model-a ", "cloud_model": "cloud"}, "model-a"),
            ({"codex_cli_model": "", "cloud_model": " cloud-b "}, "cloud-b"),
            ({"codex_cli_model": 0, "cloud_model": None}, ""),
        )
        for settings, expected_model in cases:
            before = deepcopy(settings)
            with self.subTest(settings=settings), mock.patch.object(
                routing, "enabled_agent_model_routes", return_value=[]
            ), mock.patch.object(
                routing, "canonical_model_route", return_value="codex-cli"
            ):
                expected = (
                    ("codex-cli", expected_model, "frontier-codex-cli", "codex-cli")
                    if expected_model
                    else ("codex-cli", "", "unknown", "unknown")
                )
                self.assertEqual(
                    routing.model_route_metadata(settings, "route"), expected
                )
                self.assertEqual(settings, before)

        with mock.patch.object(
            routing, "enabled_agent_model_routes", return_value=[]
        ), mock.patch.object(
            routing, "canonical_model_route", return_value="unknown-route"
        ):
            self.assertEqual(
                routing.model_route_metadata({}, "route"),
                ("unknown-route", "", "unknown", "unknown"),
            )

    def test_configured_fallback_stringification_exceptions_propagate(self) -> None:
        with mock.patch.object(
            routing, "enabled_agent_model_routes", return_value=[]
        ), mock.patch.object(
            routing, "canonical_model_route", return_value="codex-cli"
        ):
            with self.assertRaisesRegex(RuntimeError, "stringification failed"):
                routing.model_route_metadata(
                    {"codex_cli_model": ExplodingString()}, "route"
                )


if __name__ == "__main__":
    unittest.main()
