"""Discover focused contract suites; preserve historical test identities."""
from __future__ import annotations

import unittest
import sys
from pathlib import Path

_test_directory = str(Path(__file__).resolve().parent)
if _test_directory not in sys.path:
    sys.path.insert(0, _test_directory)

from relay_health_wrapper_fixtures import (
    Path,
    REPO_ROOT,
    WRAPPER_PATH,
    completed,
    contextlib,
    importlib,
    io,
    json,
    load_wrapper,
    mock,
    subprocess,
    sys,
    unittest,
)

from relay_health_wrapper_fixtures_relayhealthwrappertest import RelayHealthWrapperTestFixtures
from cases_relay_health_wrapper_relayhealthwrappertest_notification_test_short_circuits_every_component_probe import RelayHealthWrapperTestNotificationTestShortCircuitsEveryComponentProbeCases
from cases_relay_health_wrapper_relayhealthwrappertest_pcap_failure_output_is_rebuilt_from_strict_allowlists import RelayHealthWrapperTestPcapFailureOutputIsRebuiltFromStrictAllowlistsCases


class RelayHealthWrapperTest(
    RelayHealthWrapperTestNotificationTestShortCircuitsEveryComponentProbeCases,
    RelayHealthWrapperTestPcapFailureOutputIsRebuiltFromStrictAllowlistsCases,
    RelayHealthWrapperTestFixtures,
):
    """Compose independently maintained behavior contracts with shared fixtures."""


if __name__ == "__main__":
    unittest.main()
