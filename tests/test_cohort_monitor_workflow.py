#!/usr/bin/env python3
"""Boundary tests for extracted cohort terminal-monitor workflow."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
OPERATIONS = ROOT / "operations"
if str(OPERATIONS) not in sys.path:
    sys.path.insert(0, str(OPERATIONS))

import cohort_monitor_workflow  # noqa: E402


def load_legacy_cohort():
    path = OPERATIONS / "run-incident-harness-cohort.py"
    spec = importlib.util.spec_from_file_location("cohort_workflow_test", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load cohort runner")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CohortMonitorWorkflowBoundaryTests(unittest.TestCase):
    def test_legacy_runner_binds_monitor_workflow_sources(self):
        legacy = load_legacy_cohort()
        sources = legacy._cohort_monitor_sources()

        self.assertIsInstance(
            sources,
            cohort_monitor_workflow.CohortMonitorSources,
        )
        self.assertIs(
            sources.monitor_dispatch_job_binding,
            legacy._monitor_dispatch_job_binding,
        )
        self.assertIs(
            sources.durable_job_monitor_state,
            legacy._durable_job_monitor_state,
        )
        self.assertIs(sources.reanalysis_run_case, legacy._reanalysis_monitor_case)


if __name__ == "__main__":
    unittest.main()
