#!/usr/bin/env python3
"""Compatibility contracts for configured prompt detection/query adapters."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))

import prompt_builder_policy as policy  # noqa: E402
import prompt_detection_facade as facade  # noqa: E402


def load_builder():
    path = BIN / "build-ai-investigation-prompt.py"
    spec = importlib.util.spec_from_file_location("prompt_detection_facade_test", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load prompt builder")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PromptDetectionFacadeTests(unittest.TestCase):
    def test_legacy_builder_reexports_detection_entry_points(self):
        builder = load_builder()
        names = (
            "agent_task",
            "asset_observables_and_events",
            "exact_detection_group_rows",
            "investigation_query_context",
            "investigation_query_context_policy",
            "investigation_query_context_sources",
            "model_policy",
        )

        for name in names:
            with self.subTest(name=name):
                self.assertIs(getattr(builder, name), getattr(facade, name))

    def test_query_policy_binds_authoritative_limits_and_contract(self):
        configured = facade.investigation_query_context_policy()

        self.assertEqual(configured.query_contract, policy.INVESTIGATION_QUERY_CONTRACT)
        self.assertEqual(configured.query_packs, policy.INVESTIGATION_QUERY_PACKS)
        self.assertEqual(configured.max_rounds, policy.INVESTIGATION_QUERY_MAX_ROUNDS)
        self.assertEqual(
            configured.max_queries_per_round,
            policy.INVESTIGATION_QUERY_MAX_PER_ROUND,
        )
        self.assertEqual(
            configured.allowed_actor_roles,
            frozenset(policy.INVESTIGATION_CONTRACT.ALLOWED_ACTOR_ROLES),
        )

    def test_detection_sources_bind_evidence_and_registry_ports(self):
        configured = facade._detection_context_sources()

        self.assertIs(configured.alert_group_rows, facade.alert_group_rows)
        self.assertIs(configured.parse_alert_json, facade.parse_alert_json)
        self.assertIs(configured.load_asset_inventory, facade.load_asset_inventory)
        self.assertIs(
            configured.resolve_investigation_skills,
            facade.resolve_investigation_skills,
        )


if __name__ == "__main__":
    unittest.main()
