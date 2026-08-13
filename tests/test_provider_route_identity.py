"""Characterize reasoning-effort-independent model route identity."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.analysis.providers import routing  # noqa: E402


class RouteValue:
    def __init__(self, text: str, calls: list[str]) -> None:
        self.text = text
        self.calls = calls

    def __bool__(self) -> bool:
        self.calls.append("route.bool")
        return True

    def __str__(self) -> str:
        self.calls.append("route.str")
        return self.text


class ExplodingModel:
    def __str__(self) -> str:
        raise RuntimeError("configured identity stringification failed")


class ProviderRouteIdentityCharacterizationTests(unittest.TestCase):
    def test_route_normalization_and_codex_prefix_parser_gate_are_exact(self) -> None:
        calls: list[str] = []
        route = RouteValue("  CoDeX-ClI:GPT-5.6-SOL:HIGH  ", calls)
        parser_calls: list[str] = []

        with mock.patch.object(
            routing,
            "parse_codex_cli_route",
            side_effect=lambda value: parser_calls.append(value)
            or ("GPT-5.6-SOL", "high"),
        ), mock.patch.object(
            routing,
            "parse_cli_harness_route",
            side_effect=AssertionError("Codex match must stop harness parsing"),
        ):
            self.assertEqual(
                routing.model_route_identity(route),
                "openai-codex:gpt-5.6-sol",
            )

        self.assertEqual(calls, ["route.bool", "route.str"])
        self.assertEqual(parser_calls, ["codex-cli:gpt-5.6-sol:high"])

        with mock.patch.object(routing, "parse_codex_cli_route") as parser:
            self.assertEqual(
                routing.model_route_identity("ollama:model"), "ollama:model"
            )
        parser.assert_not_called()

    def test_provider_only_codex_identity_uses_exact_configured_fallback(self) -> None:
        cases = (
            ({"codex_cli_model": " GPT-5.6-SOL "}, "openai-codex:gpt-5.6-sol"),
            ({"codex_cli_model": ""}, "openai-codex:configured-default"),
            (None, "openai-codex:configured-default"),
        )
        for settings, expected in cases:
            before = deepcopy(settings)
            with self.subTest(settings=settings), mock.patch.object(
                routing, "parse_codex_cli_route", return_value=None
            ), mock.patch.object(
                routing, "parse_cli_harness_route"
            ) as harness:
                self.assertEqual(
                    routing.model_route_identity("GPT-CLI", settings), expected
                )
                self.assertEqual(settings, before)
                harness.assert_not_called()

    def test_harness_parser_order_and_identity_projection_are_exact(self) -> None:
        cases = (
            (
                "hermes-agent:gpt:medium",
                ("gPt-5.6-Sol", "medium"),
                None,
                "openai-codex:gpt-5.6-sol",
                ["hermes-agent"],
            ),
            (
                "openclaw:ollama/model:high",
                None,
                ("OlLaMa/Model", "high"),
                "ollama:model",
                ["hermes-agent", "openclaw"],
            ),
            (
                "openclaw:provider/name/extra:high",
                None,
                ("Provider/Name/Extra", "high"),
                "provider:name/extra",
                ["hermes-agent", "openclaw"],
            ),
            (
                "openclaw:model:high",
                None,
                ("MoDeL", "high"),
                "openclaw:model",
                ["hermes-agent", "openclaw"],
            ),
        )
        for route, hermes, openclaw, expected, expected_calls in cases:
            calls: list[str] = []

            def parse(_route: str, provider: str) -> object:
                calls.append(provider)
                return hermes if provider == "hermes-agent" else openclaw

            with self.subTest(route=route), mock.patch.object(
                routing, "parse_codex_cli_route", return_value=None
            ), mock.patch.object(
                routing, "parse_cli_harness_route", side_effect=parse
            ):
                self.assertEqual(routing.model_route_identity(route), expected)
                self.assertEqual(calls, expected_calls)

    def test_unknown_and_falsey_routes_return_normalized_identity(self) -> None:
        for route, expected in (
            (None, ""),
            (0, ""),
            ("  Unknown.Route  ", "unknown.route"),
            ("OLLAMA:Model-A", "ollama:model-a"),
        ):
            with self.subTest(route=route):
                self.assertEqual(routing.model_route_identity(route), expected)

    def test_parser_and_configured_model_exceptions_propagate(self) -> None:
        with mock.patch.object(
            routing,
            "parse_codex_cli_route",
            side_effect=RuntimeError("codex parser failed"),
        ):
            with self.assertRaisesRegex(RuntimeError, "codex parser failed"):
                routing.model_route_identity("codex-cli:model:high")

        with mock.patch.object(
            routing, "parse_codex_cli_route", return_value=None
        ):
            with self.assertRaisesRegex(RuntimeError, "stringification failed"):
                routing.model_route_identity(
                    "codex-cli", {"codex_cli_model": ExplodingModel()}
                )


if __name__ == "__main__":
    unittest.main()
