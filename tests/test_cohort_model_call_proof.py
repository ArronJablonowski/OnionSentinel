#!/usr/bin/env python3
"""Boundary tests for canonical offline cohort model-call proof validation."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
OPERATIONS = ROOT / "operations"
if str(OPERATIONS) not in sys.path:
    sys.path.insert(0, str(OPERATIONS))

import cohort_model_call_proof  # noqa: E402


def load_evaluator():
    path = OPERATIONS / "evaluate-investigation-cohort.py"
    spec = importlib.util.spec_from_file_location("cohort_evaluator_boundary", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load cohort evaluator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CohortModelCallProofBoundaryTests(unittest.TestCase):
    def test_evaluator_uses_canonical_model_call_validator(self):
        evaluator = load_evaluator()

        self.assertIs(
            evaluator.validate_bounded_model_call_proof,
            cohort_model_call_proof.bounded_model_call_proof_valid,
        )
        self.assertIs(
            evaluator.MODEL_CALL_FACT_KEYS,
            cohort_model_call_proof.MODEL_CALL_FACT_KEYS,
        )
        self.assertEqual(
            evaluator.MAX_RUNTIME_MODEL_CALLS,
            cohort_model_call_proof.MAX_RUNTIME_MODEL_CALLS,
        )


if __name__ == "__main__":
    unittest.main()
