"""Discover focused contract suites; preserve historical test identities."""
from __future__ import annotations

import unittest
import sys
from pathlib import Path

_test_directory = str(Path(__file__).resolve().parent)
if _test_directory not in sys.path:
    sys.path.insert(0, _test_directory)

from analysis_replay_evaluation_fixtures import (
    DetectionModuleRecorder,
    EVALUATOR_PATH,
    EvaluationRunnerRecorder,
    FIXTURE_PATH,
    FakeRunner,
    Path,
    ROOT,
    SPEC,
    copy,
    evaluator,
    importlib,
    json,
    mock,
    os,
    tempfile,
    unittest,
)

from analysis_replay_evaluation_fixtures_analysisreplayevaluationtests import AnalysisReplayEvaluationTestsFixtures
from cases_analysis_replay_evaluation_analysisreplayevaluationtests_load_suite_preserves_identity_precedence_and_copy_isolation import AnalysisReplayEvaluationTestsLoadSuitePreservesIdentityPrecedenceAndCopyIsolationCases
from cases_analysis_replay_evaluation_analysisreplayevaluationtests_summarize_preserves_schema_calls_identity_and_reviewer_metrics import AnalysisReplayEvaluationTestsSummarizePreservesSchemaCallsIdentityAndReviewerMetricsCases


class AnalysisReplayEvaluationTests(
    AnalysisReplayEvaluationTestsLoadSuitePreservesIdentityPrecedenceAndCopyIsolationCases,
    AnalysisReplayEvaluationTestsSummarizePreservesSchemaCallsIdentityAndReviewerMetricsCases,
    AnalysisReplayEvaluationTestsFixtures,
):
    """Compose independently maintained behavior contracts with shared fixtures."""


if __name__ == "__main__":
    unittest.main()
