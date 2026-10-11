"""Discover focused contract suites; preserve historical test identities."""
from __future__ import annotations

import unittest
import sys
from pathlib import Path

_test_directory = str(Path(__file__).resolve().parent)
if _test_directory not in sys.path:
    sys.path.insert(0, _test_directory)

from investigation_cohort_evaluation_fixtures import (
    MODULE_PATH,
    Path,
    ROOT,
    SPEC,
    cohort_evaluation_api,
    cohort_evaluation_contracts,
    cohort_evaluation_execution_contract,
    cohort_evaluation_execution_proof,
    cohort_evaluation_private_input,
    cohort_evaluation_query_audit,
    cohort_evaluation_result_loader,
    cohort_evaluation_result_policy,
    cohort_evaluation_service,
    cohort_execution_result,
    contextlib,
    evaluator,
    importlib,
    io,
    json,
    os,
    stat,
    tempfile,
    unittest,
)

from investigation_cohort_evaluation_fixtures_investigationcohortevaluationtests import InvestigationCohortEvaluationTestsFixtures
from cases_investigation_cohort_evaluation_investigationcohortevaluationtests_evaluator_uses_extracted_query_audit_services import InvestigationCohortEvaluationTestsEvaluatorUsesExtractedQueryAuditServicesCases
from cases_investigation_cohort_evaluation_investigationcohortevaluationtests_project_timestamp_double_space_remains_gradeable import InvestigationCohortEvaluationTestsProjectTimestampDoubleSpaceRemainsGradeableCases


class InvestigationCohortEvaluationTests(
    InvestigationCohortEvaluationTestsEvaluatorUsesExtractedQueryAuditServicesCases,
    InvestigationCohortEvaluationTestsProjectTimestampDoubleSpaceRemainsGradeableCases,
    InvestigationCohortEvaluationTestsFixtures,
):
    """Compose independently maintained behavior contracts with shared fixtures."""


if __name__ == "__main__":
    unittest.main()
