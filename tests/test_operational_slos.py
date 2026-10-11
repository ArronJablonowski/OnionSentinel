"""Discover focused contract suites; preserve historical test identities."""
from __future__ import annotations

import unittest
import sys
from pathlib import Path

_test_directory = str(Path(__file__).resolve().parent)
if _test_directory not in sys.path:
    sys.path.insert(0, _test_directory)

from operational_slos_fixtures import (
    Path,
    ROOT,
    closing,
    dt,
    importlib,
    io,
    json,
    load_module,
    mock,
    shutil,
    sqlite3,
    subprocess,
    sys,
    tempfile,
    unittest,
)

from operational_slos_fixtures_operationalslotests import OperationalSloTestsFixtures
from cases_operational_slos_operationalslotests_healthy_snapshot_passes import OperationalSloTestsHealthySnapshotPassesCases
from cases_operational_slos_operationalslotests_pending_ai_requires_recent_forward_progress import OperationalSloTestsPendingAiRequiresRecentForwardProgressCases


class OperationalSloTests(
    OperationalSloTestsHealthySnapshotPassesCases,
    OperationalSloTestsPendingAiRequiresRecentForwardProgressCases,
    OperationalSloTestsFixtures,
):
    """Compose independently maintained behavior contracts with shared fixtures."""


if __name__ == "__main__":
    unittest.main()
