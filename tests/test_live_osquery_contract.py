"""Discover focused contract suites; preserve historical test identities."""
from __future__ import annotations

import unittest
import sys
from pathlib import Path

_test_directory = str(Path(__file__).resolve().parent)
if _test_directory not in sys.path:
    sys.path.insert(0, _test_directory)

from live_osquery_contract_fixtures import (
    BIN,
    BoundedProcessError,
    LiveOsqueryClientError,
    LiveOsqueryContractError,
    Path,
    RELAY_AUTHORIZED_KEY,
    RELAY_BROKER,
    RELAY_INSTALLER,
    RELAY_LAUNCHER,
    RELAY_SUDOERS,
    ROOT,
    SO_AUTHORIZED_KEY,
    SO_CONFIG_EXAMPLE,
    SO_INSTALLER,
    SO_LAUNCHER,
    SO_WRAPPER,
    SimpleNamespace,
    ThreadPoolExecutor,
    _persist_live_osquery_artifact,
    capability_descriptor,
    collect_live_osquery,
    dt,
    harness_operator_approved,
    importlib,
    io,
    json,
    load_live_osquery_config,
    load_relay_broker,
    load_security_onion_wrapper,
    mock,
    normalize_query,
    normalize_requests,
    os,
    scheduled_inventory_approved,
    stat,
    subprocess,
    sys,
    tempfile,
    time,
    unittest,
    urllib,
    validate_result_artifact,
)

from live_osquery_contract_fixtures_liveosquerycontracttests import LiveOsqueryContractTestsFixtures
from cases_live_osquery_contract_liveosquerycontracttests_normalizes_read_only_select_and_adds_bound import LiveOsqueryContractTestsNormalizesReadOnlySelectAndAddsBoundCases


class LiveOsqueryContractTests(
    LiveOsqueryContractTestsNormalizesReadOnlySelectAndAddsBoundCases,
    LiveOsqueryContractTestsFixtures,
):
    """Compose independently maintained behavior contracts with shared fixtures."""


from live_osquery_contract_fixtures_securityonionliveosqueryresponsetests import SecurityOnionLiveOsqueryResponseTestsFixtures
from cases_live_osquery_contract_securityonionliveosqueryresponsetests_reads_query_level_execution_counters import SecurityOnionLiveOsqueryResponseTestsReadsQueryLevelExecutionCountersCases
from cases_live_osquery_contract_securityonionliveosqueryresponsetests_allows_only_explicit_loopback_http_or_verified_https import SecurityOnionLiveOsqueryResponseTestsAllowsOnlyExplicitLoopbackHttpOrVerifiedHttpsCases


class SecurityOnionLiveOsqueryResponseTests(
    SecurityOnionLiveOsqueryResponseTestsReadsQueryLevelExecutionCountersCases,
    SecurityOnionLiveOsqueryResponseTestsAllowsOnlyExplicitLoopbackHttpOrVerifiedHttpsCases,
    SecurityOnionLiveOsqueryResponseTestsFixtures,
):
    """Compose independently maintained behavior contracts with shared fixtures."""


from live_osquery_contract_fixtures_liveosqueryclientconfigtests import LiveOsqueryClientConfigTestsFixtures
from cases_live_osquery_contract_liveosqueryclientconfigtests_capability_exposes_only_explicit_darwin_schemas import LiveOsqueryClientConfigTestsCapabilityExposesOnlyExplicitDarwinSchemasCases


class LiveOsqueryClientConfigTests(
    LiveOsqueryClientConfigTestsCapabilityExposesOnlyExplicitDarwinSchemasCases,
    LiveOsqueryClientConfigTestsFixtures,
):
    """Compose independently maintained behavior contracts with shared fixtures."""


from live_osquery_contract_fixtures_liveosquerydeploymentcontracttests import LiveOsqueryDeploymentContractTestsFixtures
from cases_live_osquery_contract_liveosquerydeploymentcontracttests_security_onion_example_allows_observed_index_visibility_lag import LiveOsqueryDeploymentContractTestsSecurityOnionExampleAllowsObservedIndexVisibilityLagCases


class LiveOsqueryDeploymentContractTests(
    LiveOsqueryDeploymentContractTestsSecurityOnionExampleAllowsObservedIndexVisibilityLagCases,
    LiveOsqueryDeploymentContractTestsFixtures,
):
    """Compose independently maintained behavior contracts with shared fixtures."""


if __name__ == "__main__":
    unittest.main()
