"""Discover focused contract suites; preserve historical test identities."""
from __future__ import annotations

import unittest
import sys
from pathlib import Path

_test_directory = str(Path(__file__).resolve().parent)
if _test_directory not in sys.path:
    sys.path.insert(0, _test_directory)

from incident_reanalysis_lineage_fixtures import (
    ALERT_STORE,
    ALERT_STORE_DIR,
    COHORT_MODULE_PATH,
    COHORT_SPEC,
    CONTROLLED_ROUTE_FIELDS,
    DEPLOYED_RELEASE,
    PRIMARY_ROUTE,
    Path,
    REPO_ROOT,
    REVIEWER_ROUTE,
    SCORING_RULES,
    available_port,
    closing,
    cohort,
    dt,
    hashlib,
    importlib,
    json,
    os,
    request_json,
    socket,
    sqlite3,
    subprocess,
    tempfile,
    time,
    unittest,
    urllib,
)

from incident_reanalysis_lineage_fixtures_incidentreanalysislineagetests import IncidentReanalysisLineageTestsFixtures
from cases_incident_reanalysis_lineage_incidentreanalysislineagetests_initial_escalation_is_not_claimed_as_case_bound_reanalysis import IncidentReanalysisLineageTestsInitialEscalationIsNotClaimedAsCaseBoundReanalysisCases
from cases_incident_reanalysis_lineage_incidentreanalysislineagetests_preclaim_overlap_returns_replacement_identity_with_lease import IncidentReanalysisLineageTestsPreclaimOverlapReturnsReplacementIdentityWithLeaseCases
from cases_incident_reanalysis_lineage_incidentreanalysislineagetests_processing_identity_drift_allows_old_result_non_authoritatively import IncidentReanalysisLineageTestsProcessingIdentityDriftAllowsOldResultNonAuthoritativelyCases


class IncidentReanalysisLineageTests(
    IncidentReanalysisLineageTestsInitialEscalationIsNotClaimedAsCaseBoundReanalysisCases,
    IncidentReanalysisLineageTestsPreclaimOverlapReturnsReplacementIdentityWithLeaseCases,
    IncidentReanalysisLineageTestsProcessingIdentityDriftAllowsOldResultNonAuthoritativelyCases,
    IncidentReanalysisLineageTestsFixtures,
):
    """Compose independently maintained behavior contracts with shared fixtures."""


if __name__ == "__main__":
    unittest.main()
