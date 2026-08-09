#!/usr/bin/env python3
"""Direct contracts for the lock-owning scheduler coordinator."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))

from scheduler_application import (  # noqa: E402
    SchedulerApplicationSources,
    run_scheduler_application,
)


class SchedulerApplicationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.args = SimpleNamespace(
            lock_file=Path(self.temporary.name) / "scheduler.lock",
        )
        self.preflight = SimpleNamespace(
            proceed=True,
            exit_code=0,
            controlled_evaluation_dir=None,
            launch_levels="critical,high",
        )
        self.initialize = mock.Mock(
            return_value=SimpleNamespace(proceed=True, indexed_mode=True)
        )
        self.select = mock.Mock(
            return_value=SimpleNamespace(disposition="empty")
        )
        self.process = mock.Mock(return_value=False)
        self.settle = mock.Mock(return_value=7)
        self.emit = mock.Mock()
        self.acquire = mock.Mock()
        self.sources = SchedulerApplicationSources(
            parse_args=lambda: self.args,
            startup_sources=lambda: "startup",
            prepare_run=lambda *_args, **_kwargs: self.preflight,
            initialize_run=self.initialize,
            drain_sources=lambda: "drain",
            select_work=self.select,
            worker_sources=lambda: "worker",
            process_selection=self.process,
            settlement_sources=lambda: "settlement",
            settle_run=self.settle,
            acquire_nonblocking_lock=self.acquire,
            emit=self.emit,
            now=lambda: "now",
            default_drain_file=Path("/runtime/drain"),
        )

    def test_preflight_exit_never_acquires_lock(self) -> None:
        self.preflight.proceed = False
        self.preflight.exit_code = 2

        self.assertEqual(run_scheduler_application(self.sources), 2)
        self.acquire.assert_not_called()
        self.initialize.assert_not_called()

    def test_lock_contention_exits_without_initialization(self) -> None:
        self.acquire.side_effect = BlockingIOError()

        self.assertEqual(run_scheduler_application(self.sources), 0)
        self.initialize.assert_not_called()
        self.emit.assert_called_once_with(
            "now another AI analysis run is already active"
        )

    def test_initialization_stop_skips_selection_and_settlement(self) -> None:
        self.initialize.return_value.proceed = False

        self.assertEqual(run_scheduler_application(self.sources), 0)
        self.select.assert_not_called()
        self.settle.assert_not_called()

    def test_selected_work_is_processed_then_settled(self) -> None:
        selected = SimpleNamespace(disposition="selected")
        empty = SimpleNamespace(disposition="empty")
        self.select.side_effect = [selected, empty]

        self.assertEqual(run_scheduler_application(self.sources), 7)
        self.process.assert_called_once()
        settlement = self.settle.call_args.args[2]
        self.assertEqual(settlement.analyzed_count, 0)
        self.assertTrue(settlement.indexed_mode)
        self.assertFalse(settlement.controlled_evaluation)

    def test_worker_stop_settles_without_another_selection(self) -> None:
        self.select.return_value = SimpleNamespace(disposition="selected")
        self.process.return_value = True

        self.assertEqual(run_scheduler_application(self.sources), 7)
        self.select.assert_called_once()
        self.settle.assert_called_once()


if __name__ == "__main__":
    unittest.main()
