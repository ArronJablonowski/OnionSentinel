#!/usr/bin/env python3
"""Boundary tests for the extracted cohort dispatch state machine."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
OPERATIONS = ROOT / "operations"
if str(OPERATIONS) not in sys.path:
    sys.path.insert(0, str(OPERATIONS))

import cohort_dispatch_workflow  # noqa: E402


def load_legacy_cohort():
    path = OPERATIONS / "cohort_runner_service.py"
    spec = importlib.util.spec_from_file_location("cohort_workflow_test", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load cohort runner")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CohortDispatchWorkflowBoundaryTests(unittest.TestCase):
    def test_legacy_runner_binds_queue_state_machine_ports(self):
        legacy = load_legacy_cohort()
        sources = legacy._cohort_dispatch_sources()

        self.assertIsInstance(
            sources,
            cohort_dispatch_workflow.CohortDispatchSources,
        )
        self.assertIs(sources.connect_read_only, legacy.connect_read_only)
        self.assertIs(
            sources.verify_dispatch_readback,
            legacy._verify_dispatch_readback,
        )
        self.assertIs(
            sources.dashboard_post_json,
            legacy.dashboard_post_json,
        )


if __name__ == "__main__":
    unittest.main()
