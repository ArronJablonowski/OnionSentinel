"""Discover focused contract suites; preserve historical test identities."""
from __future__ import annotations

import unittest
import sys
from pathlib import Path

_test_directory = str(Path(__file__).resolve().parent)
if _test_directory not in sys.path:
    sys.path.insert(0, _test_directory)

from controlled_evaluation_runtime_fixtures import (
    ALERT_STORE,
    ALERT_STORE_DIR,
    BIN_DIR,
    BaseHTTPRequestHandler,
    CONTROLLED_CREDENTIAL_KEYS,
    CONTROLLED_ROUTE_FIELDS,
    DASHBOARD_SERVER,
    EVALUATION_TOKEN,
    INSTALLER_PATH,
    PIPELINE_ADAPTER_PATH,
    PRIMARY_ROUTE,
    Path,
    RELEASE_ID,
    REPLACEMENT_RELEASE_ID,
    REVIEWER_ROUTE,
    ROOT,
    RUNNER_PATH,
    SCHEDULER_PATH,
    SCORING_RULES,
    SimpleNamespace,
    ThreadingHTTPServer,
    available_port,
    closing,
    dt,
    hashlib,
    importlib,
    io,
    json,
    load_python_module,
    mock,
    os,
    process_output,
    raw_request_status,
    request_json,
    request_json_bytes,
    request_status,
    sanitized_environment,
    shutil,
    socket,
    sqlite3,
    startup_failure_diagnostic,
    stop_process,
    subprocess,
    sys,
    tempfile,
    threading,
    time,
    unittest,
    urllib,
    write_controlled_route_fixture,
)

from controlled_evaluation_runtime_fixtures_controlledalertstoretests import ControlledAlertStoreTestsFixtures
from cases_controlled_evaluation_runtime_controlledalertstoretests_startup_requires_every_explicit_runtime_field import ControlledAlertStoreTestsStartupRequiresEveryExplicitRuntimeFieldCases
from cases_controlled_evaluation_runtime_controlledalertstoretests_controlled_retirement_supports_same_release_recovery import ControlledAlertStoreTestsControlledRetirementSupportsSameReleaseRecoveryCases
from cases_controlled_evaluation_runtime_controlledalertstoretests_controlled_soc_dispatch_persists_role_and_renews_lease import ControlledAlertStoreTestsControlledSocDispatchPersistsRoleAndRenewsLeaseCases
from cases_controlled_evaluation_runtime_controlledalertstoretests_restart_blocks_a_second_global_processing_claim import ControlledAlertStoreTestsRestartBlocksASecondGlobalProcessingClaimCases
from cases_controlled_evaluation_runtime_controlledalertstoretests_utf16_truncation_conflict_uses_full_terminal_db_proof import ControlledAlertStoreTestsUtf16TruncationConflictUsesFullTerminalDbProofCases


class ControlledAlertStoreTests(
    ControlledAlertStoreTestsStartupRequiresEveryExplicitRuntimeFieldCases,
    ControlledAlertStoreTestsControlledRetirementSupportsSameReleaseRecoveryCases,
    ControlledAlertStoreTestsControlledSocDispatchPersistsRoleAndRenewsLeaseCases,
    ControlledAlertStoreTestsRestartBlocksASecondGlobalProcessingClaimCases,
    ControlledAlertStoreTestsUtf16TruncationConflictUsesFullTerminalDbProofCases,
    ControlledAlertStoreTestsFixtures,
):
    """Compose independently maintained behavior contracts with shared fixtures."""


from controlled_evaluation_runtime_fixtures_controlleddashboardtests import ControlledDashboardTestsFixtures
from cases_controlled_evaluation_runtime_controlleddashboardtests_health_identifies_exact_runtime_and_all_other_reads_are_blocked import ControlledDashboardTestsHealthIdentifiesExactRuntimeAndAllOtherReadsAreBlockedCases


class ControlledDashboardTests(
    ControlledDashboardTestsHealthIdentifiesExactRuntimeAndAllOtherReadsAreBlockedCases,
    ControlledDashboardTestsFixtures,
):
    """Compose independently maintained behavior contracts with shared fixtures."""


from controlled_evaluation_runtime_fixtures_controlledworkerisolationtests import ControlledWorkerIsolationTestsFixtures
from cases_controlled_evaluation_runtime_controlledworkerisolationtests_installer_copies_controlled_evaluation_runtime_dependency import ControlledWorkerIsolationTestsInstallerCopiesControlledEvaluationRuntimeDependencyCases
from cases_controlled_evaluation_runtime_controlledworkerisolationtests_scheduler_retries_an_indeterminate_exact_claim_boundedly import ControlledWorkerIsolationTestsSchedulerRetriesAnIndeterminateExactClaimBoundedlyCases
from cases_controlled_evaluation_runtime_controlledworkerisolationtests_controlled_enrichment_never_reads_production_env_file import ControlledWorkerIsolationTestsControlledEnrichmentNeverReadsProductionEnvFileCases


class ControlledWorkerIsolationTests(
    ControlledWorkerIsolationTestsInstallerCopiesControlledEvaluationRuntimeDependencyCases,
    ControlledWorkerIsolationTestsSchedulerRetriesAnIndeterminateExactClaimBoundedlyCases,
    ControlledWorkerIsolationTestsControlledEnrichmentNeverReadsProductionEnvFileCases,
    ControlledWorkerIsolationTestsFixtures,
):
    """Compose independently maintained behavior contracts with shared fixtures."""


if __name__ == "__main__":
    unittest.main()
