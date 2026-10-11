"""Discover focused contract suites; preserve historical test identities."""
from __future__ import annotations

import unittest
import sys
from pathlib import Path

_test_directory = str(Path(__file__).resolve().parent)
if _test_directory not in sys.path:
    sys.path.insert(0, _test_directory)

from investigation_query_pivots_fixtures import (
    ALERT_INDEX_SCOPE,
    BIN_DIR,
    BROKER_PATH,
    COLLECTOR_PATH,
    COMPAT_V1_COLLECTOR_PATH,
    EVENT_TUPLE_FIELDS,
    EVENT_TUPLE_PATHS,
    INVESTIGATION_QUERY_CONTRACT,
    InvestigationQueryContractError,
    OBSERVABLE_FIELDS,
    PACKS,
    Path,
    QUERY_AUTHORIZATION,
    QUERY_RESPONSE,
    RELAY_APP_DIR,
    REPO_ROOT,
    WRAPPER_PATH,
    authorize_investigation_query_request,
    build_query_dsl,
    canonical_digest,
    context,
    contextlib,
    controls_for,
    copy,
    hashlib,
    importlib,
    inspect,
    io,
    json,
    kql_equivalent,
    load_source_module,
    mock,
    oql_equivalent,
    proposal,
    query_endpoint,
    result_coverage,
    role_aware_context,
    role_aware_proposal,
    search_result_for,
    subprocess,
    sys,
    tempfile,
    unittest,
    valid_response,
    validate_investigation_query_response,
)

from investigation_query_pivots_fixtures_investigationquerycontracttests import InvestigationQueryContractTestsFixtures
from cases_investigation_query_pivots_investigationquerycontracttests_authorization_compatibility_surface_and_signatures_are_stable import InvestigationQueryContractTestsAuthorizationCompatibilitySurfaceAndSignaturesAreStableCases


class InvestigationQueryContractTests(
    InvestigationQueryContractTestsAuthorizationCompatibilitySurfaceAndSignaturesAreStableCases,
    InvestigationQueryContractTestsFixtures,
):
    """Compose independently maintained behavior contracts with shared fixtures."""


from investigation_query_pivots_fixtures_securityonioninvestigationpivottests import SecurityOnionInvestigationPivotTestsFixtures
from cases_investigation_query_pivots_securityonioninvestigationpivottests_wrapper_pack_and_observable_contract_matches_client import SecurityOnionInvestigationPivotTestsWrapperPackAndObservableContractMatchesClientCases


class SecurityOnionInvestigationPivotTests(
    SecurityOnionInvestigationPivotTestsWrapperPackAndObservableContractMatchesClientCases,
    SecurityOnionInvestigationPivotTestsFixtures,
):
    """Compose independently maintained behavior contracts with shared fixtures."""


from investigation_query_pivots_fixtures_investigationpivotcollectortests import InvestigationPivotCollectorTestsFixtures
from cases_investigation_query_pivots_investigationpivotcollectortests_collector_compatibility_surface_and_signatures_are_stable import InvestigationPivotCollectorTestsCollectorCompatibilitySurfaceAndSignaturesAreStableCases


class InvestigationPivotCollectorTests(
    InvestigationPivotCollectorTestsCollectorCompatibilitySurfaceAndSignaturesAreStableCases,
    InvestigationPivotCollectorTestsFixtures,
):
    """Compose independently maintained behavior contracts with shared fixtures."""


from investigation_query_pivots_fixtures_incidentevidencebrokererrortests import IncidentEvidenceBrokerErrorTestsFixtures
from cases_investigation_query_pivots_incidentevidencebrokererrortests_nonzero_inner_command_preserves_only_bounded_json_error import IncidentEvidenceBrokerErrorTestsNonzeroInnerCommandPreservesOnlyBoundedJsonErrorCases


class IncidentEvidenceBrokerErrorTests(
    IncidentEvidenceBrokerErrorTestsNonzeroInnerCommandPreservesOnlyBoundedJsonErrorCases,
    IncidentEvidenceBrokerErrorTestsFixtures,
):
    """Compose independently maintained behavior contracts with shared fixtures."""


if __name__ == "__main__":
    unittest.main()
