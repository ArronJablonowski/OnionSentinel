#!/usr/bin/env python3
"""Direct invariants for prompt-builder runtime and query policy."""
from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))

import investigation_query_contract as query_contract  # noqa: E402
import prompt_builder_policy as policy  # noqa: E402


class PromptBuilderPolicyTests(unittest.TestCase):
    def test_runtime_defaults_share_the_expected_stack_root(self):
        stack_root = Path.home() / "n8n-local"

        self.assertTrue(policy.DEFAULT_DB.is_relative_to(stack_root))
        self.assertTrue(policy.DEFAULT_OUT.is_relative_to(stack_root))
        self.assertTrue(
            policy.DEFAULT_SYSTEM_PROMPT_FILE.is_relative_to(stack_root)
        )
        self.assertEqual(
            policy.DEFAULT_SOC_ANALYST_MEMORY_FILE.parent,
            policy.DEFAULT_AGENT_MEMORY_DIR,
        )

    def test_environment_limits_keep_hard_minimums(self):
        self.assertGreaterEqual(policy.DEFAULT_MAX_PACKAGE_BYTES, 256 * 1024)
        self.assertGreaterEqual(policy.MAX_ARTIFACT_JSON_BYTES, 64 * 1024)
        self.assertGreaterEqual(policy.MAX_SYSTEM_PROMPT_BYTES, 8 * 1024)
        self.assertGreaterEqual(policy.LEGACY_ARTIFACT_SCAN_LIMIT, 10)
        self.assertGreater(policy.MAX_INCIDENT_EVIDENCE_BYTES, 0)

    def test_query_policy_tracks_the_authoritative_contract(self):
        self.assertIs(policy.INVESTIGATION_CONTRACT, query_contract)
        self.assertEqual(
            policy.INVESTIGATION_QUERY_CONTRACT,
            query_contract.INVESTIGATION_QUERY_CONTRACT,
        )
        self.assertEqual(policy.INVESTIGATION_CONTRACT_PACKS, query_contract.PACKS)
        self.assertTrue(
            set(policy.INVESTIGATION_QUERY_PACKS)
            <= set(policy.INVESTIGATION_QUERY_PACK_DESCRIPTIONS)
        )
        self.assertLessEqual(
            policy.INVESTIGATION_QUERY_MAX_PER_ROUND,
            policy.INVESTIGATION_QUERY_MAX_TOTAL,
        )

    def test_derived_filters_are_allowlisted_by_operation(self):
        self.assertIn("connections", policy.INVESTIGATION_DERIVED_OPERATIONS)
        self.assertIn("source_ip", policy.INVESTIGATION_DERIVED_FILTERS["common_flow"])
        self.assertIn("icmp_type", policy.INVESTIGATION_DERIVED_FILTERS["icmp_facts"])
        self.assertNotIn("command", policy.INVESTIGATION_DERIVED_FILTERS["common_flow"])

    def test_identity_patterns_accept_expected_values_and_reject_unsafe_input(self):
        self.assertIsNotNone(
            policy.ALERT_INDEX_RE.fullmatch("logs-suricata.alerts-so")
        )
        self.assertIsNotNone(policy.SAFE_ELASTIC_ID_RE.fullmatch("event:@id-1"))
        self.assertIsNotNone(policy.SAFE_PIVOT_ATOM_RE.fullmatch("192.0.2.10"))
        self.assertIsNotNone(policy.SAFE_PIVOT_DOMAIN_RE.fullmatch("example.test"))
        self.assertIsNone(policy.SAFE_ELASTIC_ID_RE.fullmatch("unsafe value"))
        self.assertIsNone(policy.SAFE_PIVOT_DOMAIN_RE.fullmatch("not a domain"))


if __name__ == "__main__":
    unittest.main()
