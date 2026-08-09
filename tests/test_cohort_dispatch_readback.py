#!/usr/bin/env python3
"""Boundary tests for extracted cohort dispatch readback proofs."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
OPERATIONS = ROOT / "operations"
if str(OPERATIONS) not in sys.path:
    sys.path.insert(0, str(OPERATIONS))

import cohort_dispatch_readback  # noqa: E402


def load_legacy_cohort():
    path = OPERATIONS / "cohort_runner_service.py"
    spec = importlib.util.spec_from_file_location("cohort_readback_test", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load cohort runner")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CohortDispatchReadbackBoundaryTests(unittest.TestCase):
    def test_legacy_runner_binds_read_only_readback_sources(self):
        legacy = load_legacy_cohort()
        sources = legacy._cohort_dispatch_readback_sources()

        self.assertIsInstance(
            sources,
            cohort_dispatch_readback.CohortDispatchReadbackSources,
        )
        self.assertIs(sources.connect_read_only, legacy.connect_read_only)
        self.assertIs(
            sources.validate_dispatch_job_payload,
            legacy._validate_dispatch_job_payload,
        )
        self.assertEqual(
            sources.active_job_states,
            frozenset(legacy.ACTIVE_JOB_STATES),
        )


if __name__ == "__main__":
    unittest.main()
