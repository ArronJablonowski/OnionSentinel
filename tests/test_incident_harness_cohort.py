"""Discover focused contract suites; preserve historical test identities."""
from __future__ import annotations

import unittest
import sys
from pathlib import Path

_test_directory = str(Path(__file__).resolve().parent)
if _test_directory not in sys.path:
    sys.path.insert(0, _test_directory)

from incident_harness_cohort_fixtures import (
    EVALUATOR_PATH,
    EVALUATOR_SPEC,
    MODULE_PATH,
    Path,
    ROOT,
    SPEC,
    cohort,
    cohort_analysis_metadata,
    cohort_artifact_adapters,
    cohort_artifact_io,
    cohort_dispatch_adapters,
    cohort_dispatch_identity,
    cohort_evaluation_query_audit,
    cohort_evaluator,
    cohort_execution_proof_service,
    cohort_freeze_state_composition,
    cohort_manifest_adapters,
    cohort_manifest_contract,
    cohort_monitor_adapters,
    cohort_preflight,
    cohort_private_input,
    cohort_query_audit_projection,
    cohort_representative_state,
    cohort_runner_contracts,
    cohort_runtime_composition,
    cohort_second_opinion_state,
    cohort_source_rows,
    cohort_storage_core,
    cohort_storage_state,
    hashlib,
    importlib,
    json,
    mock,
    os,
    sqlite3,
    stat,
    tempfile,
    unittest,
)

from incident_harness_cohort_fixtures_incidentharnesscohorttests import IncidentHarnessCohortTestsFixtures
from cases_incident_harness_cohort_incidentharnesscohorttests_runner_uses_canonical_query_audit_services import IncidentHarnessCohortTestsRunnerUsesCanonicalQueryAuditServicesCases
from cases_incident_harness_cohort_incidentharnesscohorttests_case_and_run_identity_grammars_match_runtime_bounds import IncidentHarnessCohortTestsCaseAndRunIdentityGrammarsMatchRuntimeBoundsCases
from cases_incident_harness_cohort_incidentharnesscohorttests_dispatch_readback_requires_exact_agent_role import IncidentHarnessCohortTestsDispatchReadbackRequiresExactAgentRoleCases
from cases_incident_harness_cohort_incidentharnesscohorttests_soc_role_uses_analyze_and_monitors_exact_new_analysis_id import IncidentHarnessCohortTestsSocRoleUsesAnalyzeAndMonitorsExactNewAnalysisIdCases
from cases_incident_harness_cohort_incidentharnesscohorttests_execution_proof_accepts_timestamp_normalization_and_distinct_submissio import IncidentHarnessCohortTestsExecutionProofAcceptsTimestampNormalizationAndDistinctSubmissioCases


class IncidentHarnessCohortTests(
    IncidentHarnessCohortTestsRunnerUsesCanonicalQueryAuditServicesCases,
    IncidentHarnessCohortTestsCaseAndRunIdentityGrammarsMatchRuntimeBoundsCases,
    IncidentHarnessCohortTestsDispatchReadbackRequiresExactAgentRoleCases,
    IncidentHarnessCohortTestsSocRoleUsesAnalyzeAndMonitorsExactNewAnalysisIdCases,
    IncidentHarnessCohortTestsExecutionProofAcceptsTimestampNormalizationAndDistinctSubmissioCases,
    IncidentHarnessCohortTestsFixtures,
):
    """Compose independently maintained behavior contracts with shared fixtures."""


if __name__ == "__main__":
    unittest.main()
