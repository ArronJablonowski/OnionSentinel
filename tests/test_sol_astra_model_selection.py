"""New model routes preserve three distinct analysis/review identities."""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))
import portal_ai_model_policy as policy


class SolAstraModelSelectionTests(unittest.TestCase):
    def test_roster_retains_three_independent_roles(self):
        valid, roster = policy._normalize_codex_cli_models([
            {"model": model, "reasoning_effort": effort, "enabled": True}
            for model, effort in (
                ("gpt-6.1-sol", "medium"),
                ("gpt-5.6-terra", "medium"),
                ("gpt-6-astra", "high"),
            )
        ], legacy_model="gpt-5.5", legacy_effort="medium", legacy_enabled=False)
        self.assertTrue(valid)
        routes = policy._enabled_agent_model_routes([], roster)
        assignments = [
            {role: route for role in policy.CYBER_SECURITY_AGENT_ROLES}
            for route in (
                "codex-cli:gpt-6.1-sol:medium",
                "codex-cli:gpt-5.6-terra:medium",
                "codex-cli:gpt-6-astra:high",
            )
        ]
        primary, reviewer, adjudicator = assignments
        self.assertEqual(policy._normalize_agent_models(primary, routes), primary)
        self.assertEqual(policy._normalize_agent_second_opinion_models(reviewer, routes, primary), reviewer)
        self.assertEqual(policy._normalize_agent_adjudicator_models(adjudicator, routes, primary, reviewer), adjudicator)
        self.assertEqual(set(policy._normalize_agent_adjudicator_models(primary, routes, primary, reviewer).values()), {""})

    def test_all_runtime_catalogs_accept_targets(self):
        for name in (
            "n8n/bin/local_ai_runtime_contract.py",
            "n8n/bin/scheduler_facade.py",
            "onion-sentinel-dashboard/scripts/dashboard_ai_settings.py",
            "onion-sentinel-dashboard/scripts/dashboard_settings_client_shell.py",
        ):
            source = (ROOT / name).read_text()
            with self.subTest(module=name):
                self.assertIn("gpt-6.1-sol", source)
                self.assertIn("gpt-6-astra", source)
