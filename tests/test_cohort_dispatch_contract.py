#!/usr/bin/env python3
"""Boundary tests for extracted cohort dispatch contracts."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
OPERATIONS = ROOT / "operations"
if str(OPERATIONS) not in sys.path:
    sys.path.insert(0, str(OPERATIONS))

import cohort_dispatch_contract  # noqa: E402


def load_legacy_cohort():
    path = OPERATIONS / "cohort_runner_service.py"
    spec = importlib.util.spec_from_file_location("cohort_dispatch_test", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load cohort runner")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CohortDispatchContractBoundaryTests(unittest.TestCase):
    def test_legacy_runner_binds_dispatch_contract_authorities(self):
        legacy = load_legacy_cohort()
        policy = legacy._cohort_dispatch_contract()

        self.assertIsInstance(
            policy,
            cohort_dispatch_contract.CohortDispatchContract,
        )
        self.assertIs(policy.cohort_error, legacy.CohortError)
        self.assertIs(
            policy.ambiguous_dispatch_error,
            legacy.AmbiguousDispatchError,
        )
        self.assertIs(
            policy.deterministic_dispatch_id,
            legacy.deterministic_dispatch_id,
        )

    def test_unknown_dispatch_kind_fails_closed(self):
        legacy = load_legacy_cohort()
        manifest = {
            "cohort_id": "cohort-one",
            "reason": "boundary test",
            "execution_contract": {
                "expected_release_id": "a" * 40,
                "expected_assigned_route": "codex-cli:gpt-5.5:high",
                "expected_reviewer_route": "codex-cli:gpt-5.6-sol:xhigh",
                "reviewer_required": True,
            },
        }
        member = {
            "dispatch": {"kind": "unsupported"},
            "stable_group_id": "1" * 20,
            "stable_group_key": "v2|one",
            "representative_alert_id": "alert-one",
        }

        with self.assertRaisesRegex(legacy.CohortError, "unsupported dispatch kind"):
            legacy._request_for_member("http://127.0.0.1:8766", manifest, member)


if __name__ == "__main__":
    unittest.main()
