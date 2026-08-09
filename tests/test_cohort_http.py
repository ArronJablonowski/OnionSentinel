#!/usr/bin/env python3
"""Boundary tests for the extracted cohort HTTP adapter."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
OPERATIONS = ROOT / "operations"
if str(OPERATIONS) not in sys.path:
    sys.path.insert(0, str(OPERATIONS))

import cohort_http  # noqa: E402


def load_legacy_cohort():
    path = OPERATIONS / "cohort_runner_service.py"
    spec = importlib.util.spec_from_file_location("cohort_http_test", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load cohort runner")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CohortHttpBoundaryTests(unittest.TestCase):
    def test_legacy_runner_reexports_http_result_contract(self):
        legacy = load_legacy_cohort()

        self.assertIs(legacy.HttpResult, cohort_http.HttpResult)
        policy = legacy._cohort_http_policy()
        self.assertIsInstance(policy, cohort_http.CohortHttpPolicy)
        self.assertIs(policy.cohort_error, legacy.CohortError)
        self.assertIs(
            policy.ambiguous_dispatch_error,
            legacy.AmbiguousDispatchError,
        )

    def test_loopback_policy_preserves_canonical_origin(self):
        legacy = load_legacy_cohort()

        self.assertEqual(
            legacy.validate_loopback_base_url("http://[::1]:8766/"),
            "http://[::1]:8766",
        )
        with self.assertRaises(legacy.CohortError):
            legacy.validate_loopback_base_url("https://127.0.0.1:8766")


if __name__ == "__main__":
    unittest.main()
