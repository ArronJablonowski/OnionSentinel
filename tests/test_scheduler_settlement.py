from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
BIN_DIR = REPO_ROOT / "n8n" / "bin"
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))

from scheduler_settlement import (  # noqa: E402
    SchedulerSettlement,
    SchedulerSettlementSources,
    settle_scheduler_run,
)


class SchedulerSettlementTests(unittest.TestCase):
    def setUp(self) -> None:
        self.events: list[str] = []
        self.errors: list[str] = []
        self.sources = SchedulerSettlementSources(
            signal_dashboard_refresh=mock.Mock(),
            reconcile_worker_state=mock.Mock(return_value=0),
            emit=self.events.append,
            emit_error=self.errors.append,
            now=lambda: "NOW",
            controlled_failure_exit_code=17,
        )
        self.args = SimpleNamespace()

    def test_success_refreshes_and_reconciles_late_intent(self) -> None:
        self.sources.reconcile_worker_state.return_value = 2
        result = settle_scheduler_run(
            self.sources,
            self.args,
            SchedulerSettlement(
                analyzed_count=3,
                indexed_mode=True,
                controlled_evaluation=False,
            ),
        )
        self.assertEqual(result, 0)
        self.sources.signal_dashboard_refresh.assert_called_once_with(
            self.args,
            controlled_evaluation=False,
        )
        self.sources.reconcile_worker_state.assert_called_once_with(
            self.args,
            True,
            controlled_evaluation=False,
        )
        self.assertTrue(any("analyzed 3" in event for event in self.events))
        self.assertTrue(any("reconciled 2" in event for event in self.events))

    def test_no_work_skips_refresh_but_still_reconciles(self) -> None:
        result = settle_scheduler_run(
            self.sources,
            self.args,
            SchedulerSettlement(
                analyzed_count=0,
                indexed_mode=False,
                controlled_evaluation=False,
            ),
        )
        self.assertEqual(result, 0)
        self.sources.signal_dashboard_refresh.assert_not_called()
        self.sources.reconcile_worker_state.assert_called_once_with(
            self.args,
            False,
            controlled_evaluation=False,
        )

    def test_controlled_owned_failure_returns_distinct_bounded_error(self) -> None:
        result = settle_scheduler_run(
            self.sources,
            self.args,
            SchedulerSettlement(
                analyzed_count=0,
                indexed_mode=True,
                controlled_evaluation=True,
                controlled_owned_job_failed=True,
                controlled_failure_detail="x" * 1200,
                controlled_failure_group_id="0123456789abcdefabcd",
            ),
        )
        self.assertEqual(result, 17)
        self.assertEqual(len(self.errors), 1)
        payload = json.loads(self.errors[0])
        self.assertEqual(payload["controlled_evaluation"], "selected_job_failed")
        self.assertEqual(payload["stable_group_id"], "0123456789abcdefabcd")
        self.assertEqual(len(payload["error"]), 1000)


if __name__ == "__main__":
    unittest.main()
