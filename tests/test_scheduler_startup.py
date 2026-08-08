from __future__ import annotations

import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
BIN_DIR = REPO_ROOT / "n8n" / "bin"
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))

from scheduler_startup import (  # noqa: E402
    SchedulerStartupSources,
    initialize_scheduler_run,
    prepare_scheduler_run,
)


class SchedulerStartupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        root = Path(self.tempdir.name)
        self.args = SimpleNamespace(
            levels="critical,high",
            analysis_dir=root / "analysis",
            prompt_dir=root / "prompts",
            db=root / "alerts.sqlite3",
            wake_file=root / "wake",
            provider_lane="any",
        )
        self.args.db.write_bytes(b"")
        self.events: list[str] = []
        self.sources = SchedulerStartupSources(
            stop_for_drain=mock.Mock(return_value=False),
            controlled_runtime=mock.Mock(return_value=None),
            consume_controlled_token=mock.Mock(return_value=""),
            require_capacity=mock.Mock(),
            path_exists=lambda path: path.exists(),
            consume_wake_marker=mock.Mock(),
            detect_indexed_mode=mock.Mock(return_value=True),
            recover_controlled_spool=mock.Mock(return_value=False),
            flush_deferred_results=mock.Mock(),
            recover_terminal_success=mock.Mock(return_value=0),
            reconcile_worker_state=mock.Mock(return_value=0),
            emit=self.events.append,
            emit_error=self.events.append,
            now=lambda: "NOW",
        )

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_drain_short_circuits_before_controlled_token_and_database(self) -> None:
        self.sources.stop_for_drain.return_value = True
        self.sources.controlled_runtime.side_effect = AssertionError(
            "controlled runtime must not be inspected"
        )
        result = prepare_scheduler_run(
            self.sources,
            SimpleNamespace(),
            drain_file=Path(self.tempdir.name) / "drain",
        )
        self.assertFalse(result.proceed)
        self.assertEqual(result.exit_code, 0)
        self.sources.controlled_runtime.assert_not_called()
        self.sources.consume_controlled_token.assert_not_called()

    def test_missing_database_fails_after_capacity_check(self) -> None:
        self.args.db.unlink()
        result = prepare_scheduler_run(
            self.sources,
            self.args,
            drain_file=Path(self.tempdir.name) / "drain",
        )
        self.assertFalse(result.proceed)
        self.assertEqual(result.exit_code, 2)
        self.sources.require_capacity.assert_called_once_with(
            self.args.analysis_dir,
            0,
            label="AI analysis",
        )
        self.assertIn("SQLite DB not found", self.events[-1])

    def test_controlled_spool_recovery_stops_before_global_reconciliation(self) -> None:
        controlled_dir = Path(self.tempdir.name) / "controlled"
        self.sources.recover_controlled_spool.return_value = True
        result = initialize_scheduler_run(
            self.sources,
            self.args,
            controlled_evaluation_dir=controlled_dir,
        )
        self.assertFalse(result.proceed)
        self.assertTrue(result.indexed_mode)
        self.sources.consume_wake_marker.assert_not_called()
        self.sources.flush_deferred_results.assert_not_called()
        self.sources.reconcile_worker_state.assert_not_called()
        self.assertIn("without inference", self.events[-1])

    def test_cli_lane_fails_closed_without_indexed_schema(self) -> None:
        self.args.provider_lane = "cli"
        self.sources.detect_indexed_mode.return_value = False
        result = initialize_scheduler_run(
            self.sources,
            self.args,
            controlled_evaluation_dir=None,
        )
        self.assertFalse(result.proceed)
        self.assertFalse(result.indexed_mode)
        self.sources.flush_deferred_results.assert_not_called()
        self.sources.reconcile_worker_state.assert_not_called()
        self.assertIn("requires the indexed scheduler", self.events[-1])

    def test_indexed_production_recovers_before_initial_reconciliation(self) -> None:
        self.sources.recover_terminal_success.return_value = 2
        self.sources.reconcile_worker_state.return_value = 3
        result = initialize_scheduler_run(
            self.sources,
            self.args,
            controlled_evaluation_dir=None,
        )
        self.assertTrue(result.proceed)
        self.assertTrue(result.indexed_mode)
        self.sources.consume_wake_marker.assert_called_once_with(
            self.args.wake_file
        )
        self.sources.flush_deferred_results.assert_called_once_with(self.args)
        self.sources.recover_terminal_success.assert_called_once_with(self.args)
        self.sources.reconcile_worker_state.assert_called_once_with(
            self.args,
            True,
            controlled_evaluation=False,
        )
        self.assertTrue(any("recovered 2" in event for event in self.events))
        self.assertTrue(any("reconciled 3" in event for event in self.events))

    def test_terminal_recovery_error_is_deferred_without_stopping_run(self) -> None:
        self.sources.recover_terminal_success.side_effect = sqlite3.Error(
            "database busy"
        )
        result = initialize_scheduler_run(
            self.sources,
            self.args,
            controlled_evaluation_dir=None,
        )
        self.assertTrue(result.proceed)
        self.sources.reconcile_worker_state.assert_called_once()
        self.assertTrue(any("recovery deferred" in event for event in self.events))


if __name__ == "__main__":
    unittest.main()
