"""Discover focused contract suites; preserve historical test identities."""
from __future__ import annotations

import unittest
import sys
from pathlib import Path

_test_directory = str(Path(__file__).resolve().parent)
if _test_directory not in sys.path:
    sys.path.insert(0, _test_directory)

from onion_sentinel_server_fixtures import (
    DASHBOARD_DIR,
    Message,
    Path,
    ROOT,
    SimpleNamespace,
    hashlib,
    identity_module,
    importlib,
    json,
    mock,
    observer_runtime_module,
    os,
    principal_module,
    server,
    subprocess,
    sys,
    tempfile,
    unittest,
)

from onion_sentinel_server_fixtures_onionsentinelservertests import OnionSentinelServerTestsFixtures
from cases_onion_sentinel_server_onionsentinelservertests_post_starts_observation_before_preserving_existing_dispatch import OnionSentinelServerTestsPostStartsObservationBeforePreservingExistingDispatchCases
from cases_onion_sentinel_server_onionsentinelservertests_controlled_readiness_projects_mismatch_fields_without_widening import OnionSentinelServerTestsControlledReadinessProjectsMismatchFieldsWithoutWideningCases


class OnionSentinelServerTests(
    OnionSentinelServerTestsPostStartsObservationBeforePreservingExistingDispatchCases,
    OnionSentinelServerTestsControlledReadinessProjectsMismatchFieldsWithoutWideningCases,
    OnionSentinelServerTestsFixtures,
):
    """Compose independently maintained behavior contracts with shared fixtures."""


if __name__ == "__main__":
    unittest.main()
