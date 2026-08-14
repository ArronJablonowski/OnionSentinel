"""Direct contracts for model-roster and CLI harness settings normalization."""
from __future__ import annotations

from pathlib import Path
import re
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.analysis.providers import routing, runtime_adapter, settings  # noqa: E402


class SettingsError(ValueError):
    pass


CATALOG = ("gpt-5.5", "gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna")
POLICY = settings.Policy(
    codex_catalog=CATALOG,
    reasoning_efforts=frozenset({"low", "medium", "high", "xhigh"}),
    harness_model_pattern=re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,239}$"),
    openclaw_ollama_prefix="ollama/",
    hermes_effort="medium",
    fallback_ollama_model="gemma4:31b",
)


def dependencies() -> settings.Dependencies:
    return settings.Dependencies(
        boolean_setting=routing.boolean_setting,
        normalized_model_roster=routing.normalized_model_roster,
        openclaw_uses_ollama=routing.openclaw_model_uses_ollama_runtime,
        enabled_routes=routing.enabled_agent_model_routes,
        normalize_primary=lambda _value, routes: {"soc-analyst": routes[0] if routes else ""},
        normalize_reviewer=lambda _value, _routes, _primary, _settings: {
            "soc-analyst": ""
        },
        normalize_adjudicator=lambda _value, _routes, _primary, _reviewer, _settings: {
            "soc-analyst": ""
        },
        error_type=SettingsError,
    )


def base_settings() -> dict:
    return {
        "mode": "ollama", "ollama_model": "gemma4:31b",
        "codex_cli_path": "codex", "codex_cli_model": "gpt-5.5",
        "codex_cli_reasoning_effort": "medium",
        "hermes_agent_path": "hermes", "hermes_agent_model": "gpt-5.5",
        "hermes_agent_reasoning_effort": "medium",
        "openclaw_path": "openclaw", "openclaw_model": "ollama/gemma4:26b-mlx",
        "openclaw_reasoning_effort": "medium",
    }


class ProviderSettingsPackageTests(unittest.TestCase):
    def test_codex_catalog_is_fixed_order_complete_and_boolean_safe(self) -> None:
        roster = settings.codex_models(
            [{"model": "gpt-5.6-sol", "reasoning_effort": "HIGH", "enabled": "true"}],
            legacy_model="gpt-5.5", legacy_effort="medium", legacy_enabled=False,
            policy=POLICY, dependencies=dependencies(),
        )
        self.assertEqual([item["model"] for item in roster], list(CATALOG))
        self.assertEqual(roster[1]["reasoning_effort"], "high")
        self.assertTrue(roster[1]["enabled"])
        self.assertFalse(roster[0]["enabled"])

    def test_codex_catalog_rejects_unknown_duplicate_and_overlarge_rosters(self) -> None:
        cases = (
            [{"model": "foreign", "enabled": True}],
            [{"model": "gpt-5.5"}, {"model": "gpt-5.5"}],
            [{"model": "gpt-5.5"}] * 5,
        )
        for roster in cases:
            with self.subTest(roster=roster), self.assertRaises(SettingsError):
                settings.codex_models(
                    roster, legacy_model="gpt-5.5", legacy_effort="medium",
                    legacy_enabled=False, policy=POLICY, dependencies=dependencies(),
                )

    def test_codex_normalization_selects_first_enabled_and_clears_command(self) -> None:
        target = base_settings()
        settings.normalize_codex(target, {
            "codex_cli_path": "/opt/homebrew/bin/codex",
            "codex_cli_models": [
                {"model": "gpt-5.6-terra", "reasoning_effort": "xhigh", "enabled": True},
            ],
            "cloud_command": "unsafe --flag",
        }, policy=POLICY, dependencies=dependencies())
        self.assertEqual(target["codex_cli_model"], "gpt-5.6-terra")
        self.assertEqual(target["codex_cli_reasoning_effort"], "xhigh")
        self.assertEqual(target["cloud_command"], "")

    def test_executable_paths_reject_shell_text_and_wrong_basename(self) -> None:
        for value in ("codex --flag", "/tmp/not-codex", "/tmp/codex;whoami"):
            with self.subTest(value=value), self.assertRaises(SettingsError):
                settings.normalize_harness_executable(
                    value, "codex", "Codex CLI", SettingsError,
                )

    def test_harnesses_admit_only_fixed_hermes_and_local_openclaw_routes(self) -> None:
        target = base_settings()
        settings.normalize_harnesses(target, {
            "hermes_agent_enabled": "yes", "hermes_agent_model": "gpt-5.6-sol",
            "openclaw_enabled": 1, "openclaw_model": "ollama/qwen3:30b",
            "openclaw_reasoning_effort": "high",
        }, policy=POLICY, dependencies=dependencies())
        self.assertTrue(target["hermes_agent_enabled"])
        self.assertTrue(target["openclaw_enabled"])
        self.assertEqual(target["openclaw_model"], "ollama/qwen3:30b")

        for raw in (
            {"hermes_agent_reasoning_effort": "high"},
            {"openclaw_model": "openai/gpt-5.6-sol"},
            {"openclaw_model": "ollama/"},
        ):
            with self.subTest(raw=raw), self.assertRaises(SettingsError):
                settings.normalize_harnesses(
                    base_settings(), raw, policy=POLICY, dependencies=dependencies(),
                )

    def test_roster_derives_local_cloud_and_hybrid_compatibility_modes(self) -> None:
        local = base_settings() | {
            "codex_cli_models": [], "hermes_agent_enabled": False,
            "openclaw_enabled": False,
        }
        settings.apply_roster(local, {"enabled_ollama_models": ["gemma4:31b"]},
                              policy=POLICY, dependencies=dependencies())
        self.assertEqual(local["mode"], "ollama")

        cloud = base_settings() | {
            "codex_cli_models": [{"model": "gpt-5.5", "reasoning_effort": "high", "enabled": True}],
            "hermes_agent_enabled": False, "openclaw_enabled": False,
        }
        settings.apply_roster(cloud, {"enabled_ollama_models": []},
                              policy=POLICY, dependencies=dependencies())
        self.assertEqual(cloud["mode"], "cloud")

        hybrid = dict(cloud)
        settings.apply_roster(hybrid, {"enabled_ollama_models": ["gemma4:31b"]},
                              policy=POLICY, dependencies=dependencies())
        self.assertEqual(hybrid["mode"], "hybrid")

    def test_roster_rejects_configuration_with_no_enabled_route(self) -> None:
        target = base_settings() | {
            "codex_cli_models": [], "hermes_agent_enabled": False,
            "openclaw_enabled": False,
        }
        with self.assertRaisesRegex(SettingsError, "at least one"):
            settings.apply_roster(
                target, {"enabled_ollama_models": []},
                policy=POLICY, dependencies=dependencies(),
            )

    def test_roster_gives_reviewer_normalizer_the_current_settings_identity(self) -> None:
        target = base_settings() | {
            "codex_cli_models": [
                {
                    "model": "gpt-5.6-sol",
                    "reasoning_effort": "high",
                    "enabled": True,
                }
            ],
            "hermes_agent_enabled": True,
            "hermes_agent_model": "gpt-5.6-sol",
            "openclaw_enabled": False,
        }
        observed = []

        def normalize_reviewer(value, routes, primary, current):
            observed.append(current)
            requested = routing.canonical_model_route(
                (value or {}).get("soc-analyst"), routes
            )
            same_identity = routing.model_route_identity(
                requested, current
            ) == routing.model_route_identity(primary["soc-analyst"], current)
            return {"soc-analyst": "" if same_identity else requested}

        configured = dependencies()
        configured = settings.Dependencies(
            **{
                **configured.__dict__,
                "normalize_primary": lambda _value, routes: {
                    "soc-analyst": next(
                        route for route in routes if route.startswith("codex-cli:")
                    )
                },
                "normalize_reviewer": normalize_reviewer,
            }
        )

        settings.apply_roster(
            target,
            {
                "enabled_ollama_models": [],
                "agent_second_opinion_models": {
                    "soc-analyst": "hermes-agent:gpt-5.6-sol:medium"
                },
            },
            policy=POLICY,
            dependencies=configured,
        )

        self.assertEqual(observed, [target])
        self.assertEqual(target["agent_second_opinion_models"]["soc-analyst"], "")

    def test_worker_reviewer_policy_matches_cross_harness_model_identity(self) -> None:
        routes = [
            "codex-cli:gpt-5.6-sol:high",
            "hermes-agent:gpt-5.6-sol:medium",
        ]
        current = {"codex_cli_model": "gpt-5.6-sol"}
        bindings = {
            "CYBER_SECURITY_AGENT_ROLES": ("soc-analyst",),
            "canonical_model_route": routing.canonical_model_route,
            "model_route_identity": routing.model_route_identity,
        }

        normalized = runtime_adapter.normalize_agent_second_opinion_models(
            bindings,
            {"soc-analyst": "hermes-agent:gpt-5.6-sol:medium"},
            routes,
            {"soc-analyst": "codex-cli:gpt-5.6-sol:high"},
            current,
        )

        self.assertEqual(normalized, {"soc-analyst": ""})

    def test_merge_protects_structured_fields_and_runs_normalizers_in_order(self) -> None:
        target = {
            "mode": "ollama", "enabled_ollama_models": ["existing"],
            "ollama_model": "existing", "ollama_url": "http://existing",
            "hybrid_policy": "invalid", "known_text": "before",
        }
        calls = []

        def stage(name):
            return lambda settings_value, raw: calls.append(
                (name, settings_value, raw)
            ) or settings_value

        result = settings.merge(
            target,
            {"enabled_ollama_models": ["untrusted-direct-copy"], "known_text": " trimmed "},
            policy=settings.MergePolicy(
                protected_keys=frozenset({"enabled_ollama_models"}),
                hybrid_policies=frozenset({"approved"}),
                default_hybrid_policy="approved",
                fallback_ollama_model="fallback",
                default_ollama_url="http://default",
            ),
            dependencies=settings.MergeDependencies(
                normalize_codex=stage("codex"),
                normalize_harnesses=stage("harness"),
                apply_roster=stage("roster"),
            ),
        )
        self.assertIs(result, target)
        self.assertEqual(target["enabled_ollama_models"], ["existing"])
        self.assertEqual(target["known_text"], "trimmed")
        self.assertEqual(target["hybrid_policy"], "approved")
        self.assertEqual([item[0] for item in calls], ["codex", "harness", "roster"])

    def test_package_has_no_io_or_execution_primitives(self) -> None:
        source = (ROOT / "n8n/onion_sentinel/analysis/providers/settings.py").read_text()
        for primitive in ("subprocess", "urlopen(", "import requests", "open("):
            self.assertNotIn(primitive, source)


if __name__ == "__main__":
    unittest.main()
