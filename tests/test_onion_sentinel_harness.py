"""Discover focused contract suites; preserve historical test identities."""
from __future__ import annotations

import unittest
import sys
from pathlib import Path

_test_directory = str(Path(__file__).resolve().parent)
if _test_directory not in sys.path:
    sys.path.insert(0, _test_directory)

from onion_sentinel_harness_fixtures import (
    HARNESS,
    MODULE_PATH,
    Path,
    ROOT,
    SPEC,
    contextlib,
    dataclasses,
    gc,
    importlib,
    inspect,
    json,
    mock,
    os,
    sqlite3,
    stat,
    subprocess,
    sys,
    tempfile,
    threading,
    unittest,
    warnings,
)

from onion_sentinel_harness_fixtures_onionsentinelharnesstests import OnionSentinelHarnessTestsFixtures
from cases_onion_sentinel_harness_onionsentinelharnesstests_harness_policy_compatibility_surface_and_signatures_are_stable import OnionSentinelHarnessTestsHarnessPolicyCompatibilitySurfaceAndSignaturesAreStableCases
from cases_onion_sentinel_harness_onionsentinelharnesstests_sqlite_store_is_owner_only import OnionSentinelHarnessTestsSqliteStoreIsOwnerOnlyCases
from cases_onion_sentinel_harness_onionsentinelharnesstests_model_preflight_binds_primary_and_reviewer_routes import OnionSentinelHarnessTestsModelPreflightBindsPrimaryAndReviewerRoutesCases
from cases_onion_sentinel_harness_onionsentinelharnesstests_query_round_resolves_digest_bound_nested_status_in_partial_batch import OnionSentinelHarnessTestsQueryRoundResolvesDigestBoundNestedStatusInPartialBatchCases


class OnionSentinelHarnessTests(
    OnionSentinelHarnessTestsHarnessPolicyCompatibilitySurfaceAndSignaturesAreStableCases,
    OnionSentinelHarnessTestsSqliteStoreIsOwnerOnlyCases,
    OnionSentinelHarnessTestsModelPreflightBindsPrimaryAndReviewerRoutesCases,
    OnionSentinelHarnessTestsQueryRoundResolvesDigestBoundNestedStatusInPartialBatchCases,
    OnionSentinelHarnessTestsFixtures,
):
    """Compose independently maintained behavior contracts with shared fixtures."""


if __name__ == "__main__":
    unittest.main()
