"""Tests for the safe Incident Responder harness cohort orchestrator."""


from __future__ import annotations


import importlib.util


import hashlib


import json


import os


import sqlite3


import stat


import tempfile


import unittest


from pathlib import Path


from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


MODULE_PATH = ROOT / "operations" / "cohort_runner_service.py"


SPEC = importlib.util.spec_from_file_location(
    "run_incident_harness_cohort",
    MODULE_PATH,
)


assert SPEC and SPEC.loader


cohort = importlib.util.module_from_spec(SPEC)


SPEC.loader.exec_module(cohort)


EVALUATOR_PATH = ROOT / "operations" / "evaluate-investigation-cohort.py"


EVALUATOR_SPEC = importlib.util.spec_from_file_location(
    "evaluate_investigation_cohort_for_export_test",
    EVALUATOR_PATH,
)


assert EVALUATOR_SPEC and EVALUATOR_SPEC.loader


cohort_evaluator = importlib.util.module_from_spec(EVALUATOR_SPEC)


EVALUATOR_SPEC.loader.exec_module(cohort_evaluator)


import cohort_evaluation_query_audit  # noqa: E402


import cohort_query_audit_projection  # noqa: E402


import cohort_execution_proof_service  # noqa: E402


import cohort_analysis_metadata  # noqa: E402


import cohort_preflight  # noqa: E402


import cohort_dispatch_identity  # noqa: E402


import cohort_manifest_contract  # noqa: E402


import cohort_private_input  # noqa: E402


import cohort_artifact_io  # noqa: E402


import cohort_storage_core  # noqa: E402


import cohort_storage_state  # noqa: E402


import cohort_source_rows  # noqa: E402


import cohort_representative_state  # noqa: E402


import cohort_second_opinion_state  # noqa: E402


import cohort_runner_contracts  # noqa: E402


import cohort_dispatch_adapters  # noqa: E402


import cohort_monitor_adapters  # noqa: E402


import cohort_artifact_adapters  # noqa: E402


import cohort_manifest_adapters  # noqa: E402


import cohort_freeze_state_composition  # noqa: E402


import cohort_runtime_composition  # noqa: E402
