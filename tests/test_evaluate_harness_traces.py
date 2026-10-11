"""Discover focused contract suites; preserve historical test identities."""
from __future__ import annotations

import unittest
import sys
from pathlib import Path

_test_directory = str(Path(__file__).resolve().parent)
if _test_directory not in sys.path:
    sys.path.insert(0, _test_directory)

from evaluate_harness_traces_fixtures import (
    EVALUATOR_PATH,
    HARNESS_PATH,
    HARNESS_SPEC,
    INSTALLER_PATH,
    Path,
    ROOT,
    SPEC,
    canonical_json,
    collections,
    contextlib,
    create_terminal_harness_database,
    create_trace_database,
    digest_json,
    evaluator,
    harness,
    hashlib,
    importlib,
    io,
    json,
    os,
    replace_terminal_manifest,
    sqlite3,
    sys,
    tempfile,
    trace_evaluation_api,
    trace_evaluation_contract,
    trace_evaluation_events,
    trace_evaluation_integrity,
    trace_evaluation_model_completion,
    trace_evaluation_model_contract,
    trace_evaluation_model_routes,
    trace_evaluation_output,
    trace_evaluation_reviewer,
    trace_evaluation_run,
    trace_evaluation_skills,
    trace_evaluation_storage,
    trace_evaluation_summary,
    unittest,
    v2_skill_selection,
)

from evaluate_harness_traces_fixtures_harnesstraceevaluatortests import HarnessTraceEvaluatorTestsFixtures
from cases_evaluate_harness_traces_harnesstraceevaluatortests_evaluator_uses_extracted_skill_attestation_service import HarnessTraceEvaluatorTestsEvaluatorUsesExtractedSkillAttestationServiceCases
from cases_evaluate_harness_traces_harnesstraceevaluatortests_model_purpose_completion_rejects_malformed_retry_patterns import HarnessTraceEvaluatorTestsModelPurposeCompletionRejectsMalformedRetryPatternsCases
from cases_evaluate_harness_traces_harnesstraceevaluatortests_projects_hash_bound_terminal_execution_controls import HarnessTraceEvaluatorTestsProjectsHashBoundTerminalExecutionControlsCases


class HarnessTraceEvaluatorTests(
    HarnessTraceEvaluatorTestsEvaluatorUsesExtractedSkillAttestationServiceCases,
    HarnessTraceEvaluatorTestsModelPurposeCompletionRejectsMalformedRetryPatternsCases,
    HarnessTraceEvaluatorTestsProjectsHashBoundTerminalExecutionControlsCases,
    HarnessTraceEvaluatorTestsFixtures,
):
    """Compose independently maintained behavior contracts with shared fixtures."""


if __name__ == "__main__":
    unittest.main()
