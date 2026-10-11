"""Tests for the offline SOC/IR cohort accuracy evaluator."""


from __future__ import annotations


import contextlib


import importlib.util


import io


import json


import os


import stat


import tempfile


import unittest


from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


MODULE_PATH = ROOT / "operations" / "evaluate-investigation-cohort.py"


SPEC = importlib.util.spec_from_file_location(
    "evaluate_investigation_cohort",
    MODULE_PATH,
)


assert SPEC and SPEC.loader


evaluator = importlib.util.module_from_spec(SPEC)


SPEC.loader.exec_module(evaluator)


import cohort_evaluation_query_audit  # noqa: E402


import cohort_evaluation_execution_contract  # noqa: E402


import cohort_evaluation_execution_proof  # noqa: E402


import cohort_evaluation_contracts  # noqa: E402


import cohort_evaluation_private_input  # noqa: E402


import cohort_evaluation_result_loader  # noqa: E402


import cohort_evaluation_api  # noqa: E402


import cohort_evaluation_service  # noqa: E402


import cohort_evaluation_result_policy  # noqa: E402


import cohort_execution_result  # noqa: E402


