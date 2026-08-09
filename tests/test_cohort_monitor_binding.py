#!/usr/bin/env python3
"""Boundary tests for extracted monitor-time dispatch rebinding."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
OPERATIONS = ROOT / "operations"
if str(OPERATIONS) not in sys.path:
    sys.path.insert(0, str(OPERATIONS))

import cohort_monitor_binding  # noqa: E402


def load_legacy_cohort():
    path = OPERATIONS / "run-incident-harness-cohort.py"
    spec = importlib.util.spec_from_file_location("cohort_binding_test", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load cohort runner")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CohortMonitorBindingBoundaryTests(unittest.TestCase):
    def test_legacy_runner_binds_monitor_proof_sources(self):
        legacy = load_legacy_cohort()
        sources = legacy._cohort_monitor_binding_sources()

        self.assertIsInstance(
            sources,
            cohort_monitor_binding.CohortMonitorBindingSources,
        )
        self.assertIs(
            sources.validate_representative_binding,
            legacy._validate_representative_binding,
        )
        self.assertIs(
            sources.validate_dispatch_job_payload,
            legacy._validate_dispatch_job_payload,
        )
        self.assertIs(
            sources.current_summary_identity,
            legacy._current_summary_identity,
        )


if __name__ == "__main__":
    unittest.main()
