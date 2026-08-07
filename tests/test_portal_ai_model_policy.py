"""Direct contracts for AI model roster and assignment policy."""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

import portal_ai_model_policy as policy  # noqa: E402
import report_portal as portal  # noqa: E402


class AiModelPolicyTests(unittest.TestCase):
    def test_portal_reexports_shared_policy_symbols(self) -> None:
        for name in (
            "default_soc_ai_settings",
            "_canonical_agent_route",
            "_model_route_identity",
            "_normalize_agent_models",
            "_normalize_agent_second_opinion_models",
            "_normalize_agent_adjudicator_models",
        ):
            self.assertIs(getattr(portal, name), getattr(policy, name))

    def test_defaults_honor_environment_without_sharing_assignment_dicts(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"SOC_AI_MODEL": "environment:model", "OLLAMA_URL": "http://localhost:11434"},
        ):
            first = policy.default_soc_ai_settings()
            second = policy.default_soc_ai_settings()

        self.assertEqual(first["ollama_model"], "environment:model")
        self.assertEqual(first["ollama_url"], "http://localhost:11434")
        self.assertEqual(
            set(first["agent_models"]), set(policy.CYBER_SECURITY_AGENT_ROLES)
        )
        first["agent_models"]["soc-analyst"] = "changed"
        self.assertNotEqual(first["agent_models"], second["agent_models"])

    def test_model_and_boolean_normalization_is_bounded_and_literal(self) -> None:
        models = ["one", "two", "one", "bad\nmodel"] + [f"model-{i}" for i in range(40)]

        normalized = policy._normalized_model_list(models)

        self.assertEqual(normalized[:2], ["one", "two"])
        self.assertEqual(len(normalized), 30)
        self.assertNotIn("bad\nmodel", normalized)
        for value in (True, 1, "yes", "enabled"):
            self.assertTrue(policy._boolean_setting(value))
        for value in (False, 0, "false", "disabled"):
            self.assertFalse(policy._boolean_setting(value, True))

    def test_provider_paths_and_models_reject_shell_or_hosted_routes(self) -> None:
        self.assertTrue(policy._valid_cli_executable_path("codex", "codex"))
        self.assertTrue(
            policy._valid_cli_executable_path("/opt/homebrew/bin/codex", "codex")
        )
        for unsafe in ("codex --unsafe", "/tmp/not-codex", "/tmp/$(id)/codex"):
            self.assertFalse(policy._valid_cli_executable_path(unsafe, "codex"))
        self.assertTrue(policy._valid_openclaw_model("ollama/gemma4:26b-mlx"))
        self.assertFalse(policy._valid_openclaw_model("openai/gpt-5.6-sol"))
        self.assertFalse(policy._valid_openclaw_model("ollama/model;command"))

    def test_codex_catalog_is_complete_ordered_and_rejects_duplicates(self) -> None:
        valid, roster = policy._normalize_codex_cli_models(
            [{"model": "gpt-5.6-sol", "reasoning_effort": "xhigh", "enabled": "yes"}],
            legacy_model="gpt-5.5",
            legacy_effort="medium",
            legacy_enabled=False,
        )

        self.assertTrue(valid)
        self.assertEqual(
            [entry["model"] for entry in roster], list(policy.CODEX_CLI_MODEL_CATALOG)
        )
        self.assertEqual(
            [entry for entry in roster if entry["enabled"]],
            [{"model": "gpt-5.6-sol", "reasoning_effort": "xhigh", "enabled": True}],
        )
        duplicate = [
            {"model": "gpt-5.6-sol", "reasoning_effort": "high", "enabled": True},
            {"model": "gpt-5.6-sol", "reasoning_effort": "low", "enabled": False},
        ]
        self.assertEqual(
            policy._normalize_codex_cli_models(
                duplicate,
                legacy_model="gpt-5.5",
                legacy_effort="medium",
                legacy_enabled=False,
            ),
            (False, []),
        )

    def test_routes_include_only_enabled_providers_and_migrate_stale_effort(self) -> None:
        roster = [
            {"model": "gpt-5.6-sol", "reasoning_effort": "high", "enabled": True},
            {"model": "gpt-5.6-terra", "reasoning_effort": "low", "enabled": False},
        ]
        routes = policy._enabled_agent_model_routes(
            ["local:latest"],
            roster,
            hermes_agent_enabled=True,
            hermes_agent_model="gpt-5.6-terra",
            openclaw_enabled=True,
            openclaw_model="ollama/gemma4:31b",
            openclaw_reasoning_effort="xhigh",
        )

        self.assertEqual(
            routes,
            [
                "ollama:local:latest",
                "codex-cli:gpt-5.6-sol:high",
                "hermes-agent:gpt-5.6-terra:medium",
                "openclaw:ollama/gemma4:31b:xhigh",
            ],
        )
        self.assertEqual(
            policy._canonical_agent_route("gpt-cli", routes),
            "codex-cli:gpt-5.6-sol:high",
        )
        self.assertEqual(
            policy._canonical_agent_route("codex-cli:gpt-5.6-sol:medium", routes),
            "codex-cli:gpt-5.6-sol:high",
        )

    def test_route_identity_prevents_cross_harness_model_collisions(self) -> None:
        settings = {"codex_cli_model": "gpt-5.6-sol"}
        identities = {
            policy._model_route_identity("codex-cli:gpt-5.6-sol:high", settings),
            policy._model_route_identity("hermes-agent:gpt-5.6-sol:medium", settings),
            policy._model_route_identity("gpt-cli", settings),
        }
        self.assertEqual(identities, {"openai-codex:gpt-5.6-sol"})
        self.assertEqual(
            policy._model_route_identity("openclaw:ollama/gemma4:31b:xhigh"),
            "ollama:gemma4:31b",
        )

    def test_primary_reviewer_and_adjudicator_require_distinct_identities(self) -> None:
        routes = [
            "ollama:local:latest",
            "codex-cli:gpt-5.6-sol:high",
            "hermes-agent:gpt-5.6-sol:medium",
            "openclaw:ollama/reviewer:latest:xhigh",
        ]
        primary = policy._normalize_agent_models(
            {"soc-analyst": "codex-cli:gpt-5.6-sol:high"}, routes
        )
        reviewer = policy._normalize_agent_second_opinion_models(
            {
                "soc-analyst": "hermes-agent:gpt-5.6-sol:medium",
                "incident-responder": "openclaw:ollama/reviewer:latest:xhigh",
            },
            routes,
            primary,
        )
        adjudicator = policy._normalize_agent_adjudicator_models(
            {
                "soc-analyst": "openclaw:ollama/reviewer:latest:xhigh",
                "incident-responder": "openclaw:ollama/reviewer:latest:xhigh",
            },
            routes,
            primary,
            reviewer,
        )

        self.assertEqual(reviewer["soc-analyst"], "")
        self.assertEqual(
            reviewer["incident-responder"],
            "openclaw:ollama/reviewer:latest:xhigh",
        )
        self.assertEqual(
            adjudicator["soc-analyst"],
            "openclaw:ollama/reviewer:latest:xhigh",
        )
        self.assertEqual(adjudicator["incident-responder"], "")


if __name__ == "__main__":
    unittest.main()
