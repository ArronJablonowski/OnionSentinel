#!/usr/bin/env python3
"""Boundary tests for extracted cohort adjudication normalization."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
OPERATIONS = ROOT / "operations"
if str(OPERATIONS) not in sys.path:
    sys.path.insert(0, str(OPERATIONS))

import cohort_adjudication  # noqa: E402


def load_evaluator():
    path = OPERATIONS / "evaluate-investigation-cohort.py"
    spec = importlib.util.spec_from_file_location("adjudication_boundary", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load cohort evaluator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CohortAdjudicationBoundaryTests(unittest.TestCase):
    def test_evaluator_binds_canonical_adjudication_contract(self):
        evaluator = load_evaluator()
        policy = evaluator._adjudication_policy()

        self.assertIsInstance(policy, cohort_adjudication.AdjudicationPolicy)
        self.assertIs(
            evaluator.normalize_adjudication,
            cohort_adjudication.validate_adjudication,
        )
        self.assertIs(
            evaluator.TOP_LEVEL_ADJUDICATION_KEYS,
            cohort_adjudication.TOP_LEVEL_ADJUDICATION_KEYS,
        )
        self.assertIs(policy.error, evaluator.CohortEvaluationError)


if __name__ == "__main__":
    unittest.main()
