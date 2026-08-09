#!/usr/bin/env python3
"""Boundary tests for the extracted cohort-freezing workflow."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
OPERATIONS = ROOT / "operations"
if str(OPERATIONS) not in sys.path:
    sys.path.insert(0, str(OPERATIONS))

import cohort_freezing  # noqa: E402


def load_legacy_cohort():
    path = OPERATIONS / "run-incident-harness-cohort.py"
    spec = importlib.util.spec_from_file_location("cohort_freezing_test", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load cohort runner")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CohortFreezingBoundaryTests(unittest.TestCase):
    def test_legacy_freeze_delegates_with_bound_policy_and_sources(self):
        legacy = load_legacy_cohort()
        expected = {"state": "frozen"}
        legacy.run_freeze_cohort = mock.Mock(return_value=expected)

        result = legacy.freeze_cohort(
            Path("alerts.sqlite3"),
            Path("cohort.json"),
            cohort_id="cohort-one",
            reason="characterization",
            count=2,
            expected_release_id="a" * 40,
            dry_run=True,
        )

        self.assertIs(result, expected)
        policy, sources = legacy.run_freeze_cohort.call_args.args[:2]
        self.assertIsInstance(policy, cohort_freezing.CohortFreezePolicy)
        self.assertIsInstance(sources, cohort_freezing.CohortFreezeSources)
        self.assertIs(sources.error_type, legacy.CohortError)
        self.assertIs(sources.connect_read_only, legacy.connect_read_only)

    def test_new_member_preserves_role_specific_dispatch_kind(self):
        incident = cohort_freezing._new_member(
            1, "incident-responder", "a" * 12, "1" * 20, "stable-key",
            "alert-1", {}, {"incident_case": {"case_id": "ir-one"}},
        )
        analyst = cohort_freezing._new_member(
            2, "soc-analyst", "b" * 12, "2" * 20, "stable-key-two",
            "alert-2", {}, {"incident_case": None},
        )

        self.assertEqual(incident["dispatch"]["kind"], "reanalyze")
        self.assertEqual(analyst["dispatch"]["kind"], "analyze")
        self.assertEqual(incident["monitor"], {"state": "not_started"})


if __name__ == "__main__":
    unittest.main()
