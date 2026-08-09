#!/usr/bin/env python3
"""Direct contracts for immutable role-specific prompt objectives."""
from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))

from prompt_role_task import DEFAULT_TASK, build_agent_task  # noqa: E402


class PromptRoleTaskTests(unittest.TestCase):
    def test_incident_responder_uses_prior_analysis_during_normal_run(self):
        task = build_agent_task("incident-responder")

        self.assertIn("prior SOC analyses", task)
        self.assertNotIn("human analyst adjudications", task)
        self.assertIn("fact-grounded timeline", task)
        self.assertIn("Never claim", task)

    def test_blind_incident_reanalysis_excludes_prior_model_context(self):
        task = build_agent_task("incident-responder", blind_reanalysis=True)

        self.assertIn("human analyst adjudications", task)
        self.assertNotIn("prior SOC analyses", task)

    def test_each_specialist_has_a_distinct_bounded_objective(self):
        expected = {
            "siem-engineer": "detection-engineering assessment",
            "cyber-threat-intel": "threat-intelligence assessment",
            "threat-hunter": "threat-hunting assessment",
        }

        tasks = {role: build_agent_task(role) for role in expected}

        self.assertEqual(len(set(tasks.values())), len(tasks))
        for role, phrase in expected.items():
            with self.subTest(role=role):
                self.assertIn(phrase, tasks[role])
                self.assertIn("never claim", tasks[role].lower())

    def test_unknown_and_soc_analyst_roles_use_the_stable_default(self):
        self.assertEqual(build_agent_task("soc-analyst"), DEFAULT_TASK)
        self.assertEqual(build_agent_task("unknown-role"), DEFAULT_TASK)


if __name__ == "__main__":
    unittest.main()
