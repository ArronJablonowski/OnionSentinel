#!/usr/bin/env python3
"""Boundary tests for extracted cohort monitor temporal contracts."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
OPERATIONS = ROOT / "operations"
if str(OPERATIONS) not in sys.path:
    sys.path.insert(0, str(OPERATIONS))

import cohort_monitor_contract  # noqa: E402


def load_legacy_cohort():
    path = OPERATIONS / "run-incident-harness-cohort.py"
    spec = importlib.util.spec_from_file_location("cohort_contract_test", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load cohort runner")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CohortMonitorContractBoundaryTests(unittest.TestCase):
    def test_legacy_runner_binds_temporal_contract_sources(self):
        legacy = load_legacy_cohort()
        contract = legacy._cohort_monitor_contract()

        self.assertIsInstance(
            contract,
            cohort_monitor_contract.CohortMonitorContract,
        )
        self.assertIs(contract.cohort_error, legacy.CohortError)
        self.assertIs(contract.parse_timestamp, legacy._parse_timestamp)


if __name__ == "__main__":
    unittest.main()
