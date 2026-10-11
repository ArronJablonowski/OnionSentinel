"""Discover focused contract suites; preserve historical test identities."""
from __future__ import annotations

import unittest
import sys
from pathlib import Path

_test_directory = str(Path(__file__).resolve().parent)
if _test_directory not in sys.path:
    sys.path.insert(0, _test_directory)

from ai_scheduler_priority_fixtures import (
    CONTROLLED_ROUTE_FIELDS,
    DEPLOYED_RELEASE,
    PRIMARY_ROUTE,
    Path,
    REPO_ROOT,
    REVIEWER_ROUTE,
    SCHEDULER_PATH,
    SimpleNamespace,
    importlib,
    io,
    json,
    load_scheduler,
    mock,
    os,
    sqlite3,
    tempfile,
    unittest,
    write_controlled_route_fixture,
)

from ai_scheduler_priority_fixtures_aischedulerprioritytest import AiSchedulerPriorityTestFixtures
from cases_ai_scheduler_priority_aischedulerprioritytest_terminal_success_recovery_proves_exact_ir_commit import AiSchedulerPriorityTestTerminalSuccessRecoveryProvesExactIrCommitCases
from cases_ai_scheduler_priority_aischedulerprioritytest_controlled_prompt_failure_returns_nonzero_and_requeues_owned_job import AiSchedulerPriorityTestControlledPromptFailureReturnsNonzeroAndRequeuesOwnedJobCases
from cases_ai_scheduler_priority_aischedulerprioritytest_cli_lane_reserves_follow_up_headroom_between_builder_and_runner import AiSchedulerPriorityTestCliLaneReservesFollowUpHeadroomBetweenBuilderAndRunnerCases
from cases_ai_scheduler_priority_aischedulerprioritytest_duplicate_groups_use_newest_representative_before_next_group import AiSchedulerPriorityTestDuplicateGroupsUseNewestRepresentativeBeforeNextGroupCases


class AiSchedulerPriorityTest(
    AiSchedulerPriorityTestTerminalSuccessRecoveryProvesExactIrCommitCases,
    AiSchedulerPriorityTestControlledPromptFailureReturnsNonzeroAndRequeuesOwnedJobCases,
    AiSchedulerPriorityTestCliLaneReservesFollowUpHeadroomBetweenBuilderAndRunnerCases,
    AiSchedulerPriorityTestDuplicateGroupsUseNewestRepresentativeBeforeNextGroupCases,
    AiSchedulerPriorityTestFixtures,
):
    """Compose independently maintained behavior contracts with shared fixtures."""


if __name__ == "__main__":
    unittest.main()
