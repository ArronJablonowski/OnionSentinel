"""Discover focused contract suites; preserve historical test identities."""
from __future__ import annotations

import unittest
import sys
from pathlib import Path

_test_directory = str(Path(__file__).resolve().parent)
if _test_directory not in sys.path:
    sys.path.insert(0, _test_directory)

from dhcp_asset_discovery_fixtures import (
    BROKER,
    BUILDER,
    COLLECTOR,
    INSTALLER,
    PORTAL,
    PROMOTER,
    Path,
    QUERY_CLIENT,
    ROOT,
    SimpleNamespace,
    WRAPPER,
    contextlib,
    dt,
    hashlib,
    importlib,
    inspect,
    io,
    json,
    load_module,
    mock,
    shutil,
    stat,
    subprocess,
    sys,
    tempfile,
    unittest,
)

from dhcp_asset_discovery_fixtures_dhcpwrappertests import DhcpWrapperTestsFixtures
from cases_dhcp_asset_discovery_dhcpwrappertests_contract_rejects_caller_dsl_and_long_windows import DhcpWrapperTestsContractRejectsCallerDslAndLongWindowsCases


class DhcpWrapperTests(DhcpWrapperTestsContractRejectsCallerDslAndLongWindowsCases, DhcpWrapperTestsFixtures):
    """Compose independently maintained behavior contracts with shared fixtures."""


from dhcp_asset_discovery_fixtures_dhcprelaytests import DhcpRelayTestsFixtures
from cases_dhcp_asset_discovery_dhcprelaytests_relay_revalidates_the_fixed_contract import DhcpRelayTestsRelayRevalidatesTheFixedContractCases


class DhcpRelayTests(DhcpRelayTestsRelayRevalidatesTheFixedContractCases, DhcpRelayTestsFixtures):
    """Compose independently maintained behavior contracts with shared fixtures."""


from dhcp_asset_discovery_fixtures_dhcpcollectortests import DhcpCollectorTestsFixtures
from cases_dhcp_asset_discovery_dhcpcollectortests_public_compatibility_surface_and_signatures_are_stable import DhcpCollectorTestsPublicCompatibilitySurfaceAndSignaturesAreStableCases


class DhcpCollectorTests(
    DhcpCollectorTestsPublicCompatibilitySurfaceAndSignaturesAreStableCases,
    DhcpCollectorTestsFixtures,
):
    """Compose independently maintained behavior contracts with shared fixtures."""


from dhcp_asset_discovery_fixtures_securityonionqueryclienttests import SecurityOnionQueryClientTestsFixtures
from cases_dhcp_asset_discovery_securityonionqueryclienttests_manual_query_runs_while_scheduled_collection_is_disabled import SecurityOnionQueryClientTestsManualQueryRunsWhileScheduledCollectionIsDisabledCases


class SecurityOnionQueryClientTests(
    SecurityOnionQueryClientTestsManualQueryRunsWhileScheduledCollectionIsDisabledCases,
    SecurityOnionQueryClientTestsFixtures,
):
    """Compose independently maintained behavior contracts with shared fixtures."""


from dhcp_asset_discovery_fixtures_dhcpassetpromotiontests import DhcpAssetPromotionTestsFixtures
from cases_dhcp_asset_discovery_dhcpassetpromotiontests_explicit_promotion_is_validated_backed_up_and_atomic import DhcpAssetPromotionTestsExplicitPromotionIsValidatedBackedUpAndAtomicCases


class DhcpAssetPromotionTests(
    DhcpAssetPromotionTestsExplicitPromotionIsValidatedBackedUpAndAtomicCases,
    DhcpAssetPromotionTestsFixtures,
):
    """Compose independently maintained behavior contracts with shared fixtures."""


from dhcp_asset_discovery_fixtures_dhcpdiscoveryapiandpagetests import DhcpDiscoveryApiAndPageTestsFixtures
from cases_dhcp_asset_discovery_dhcpdiscoveryapiandpagetests_api_classifies_match_candidate_and_conflict import DhcpDiscoveryApiAndPageTestsApiClassifiesMatchCandidateAndConflictCases


class DhcpDiscoveryApiAndPageTests(
    DhcpDiscoveryApiAndPageTestsApiClassifiesMatchCandidateAndConflictCases,
    DhcpDiscoveryApiAndPageTestsFixtures,
):
    """Compose independently maintained behavior contracts with shared fixtures."""


if __name__ == "__main__":
    unittest.main()
