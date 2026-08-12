#!/usr/bin/env python3
"""Characterize harness maintenance policy and lock-owned phase ordering."""
from __future__ import annotations

import fcntl
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
BIN_DIR = REPO_ROOT / "n8n" / "bin"
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))


def load_cli():
    path = BIN_DIR / "harness_maintenance_cli.py"
    spec = importlib.util.spec_from_file_location("maintenance_cli_phases", path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


CLI = load_cli()
REAL_FLOCK = fcntl.flock


class TracedArgs:
    def __init__(self, **values: Any) -> None:
        object.__setattr__(self, "values", values)
        object.__setattr__(self, "events", [])

    def __getattr__(self, name: str) -> Any:
        self.events.append(name)
        try:
            return self.values[name]
        except KeyError as exc:
            raise AttributeError(name) from exc


class TracedDict(dict):
    def __init__(self, values: dict[str, Any]) -> None:
        super().__init__(values)
        self.events: list[str] = []

    def __getitem__(self, key: str) -> Any:
        self.events.append(key)
        return super().__getitem__(key)


def policy_args(**overrides: Any) -> TracedArgs:
    values = {
        "retention_days": 30,
        "max_terminal_runs": 500,
        "min_terminal_runs": 100,
        "max_delete_runs": 25,
        "max_live_bytes": 128 * 1024**2,
        "incremental_vacuum_pages": 64,
        "max_backup_age_seconds": 3600,
        "stale_running_seconds": 7200,
        "max_reconcile_runs": 20,
    }
    values.update(overrides)
    return TracedArgs(**values)


class HarnessMaintenanceCliPhasesCharacterizationTests(unittest.TestCase):
    def test_validated_policy_preserves_argument_bound_and_key_order(self) -> None:
        args = policy_args()
        calls: list[tuple[Any, ...]] = []

        def bounded(value: Any, *, name: str, minimum: int, maximum: int) -> int:
            calls.append((value, name, minimum, maximum))
            return 444 if name == "maximum terminal runs" else int(value)

        with mock.patch.object(CLI, "bounded_int", side_effect=bounded):
            result = CLI.validated_policy(args)

        self.assertEqual(
            list(result),
            [
                "retention_days", "max_terminal_runs", "min_terminal_runs",
                "max_delete_runs", "max_live_bytes", "incremental_vacuum_pages",
                "max_backup_age_seconds", "stale_running_seconds",
                "max_reconcile_runs",
            ],
        )
        self.assertEqual(result["max_terminal_runs"], 444)
        self.assertEqual(
            args.events,
            [
                "retention_days", "max_terminal_runs", "min_terminal_runs",
                "max_delete_runs", "max_live_bytes", "incremental_vacuum_pages",
                "max_backup_age_seconds", "stale_running_seconds",
                "max_reconcile_runs",
            ],
        )
        self.assertEqual(
            calls,
            [
                (30, "retention days", 1, 3_650),
                (500, "maximum terminal runs", 100, 1_000_000),
                (100, "minimum terminal runs", 0, 444),
                (25, "maximum deletions per pass", 1, 5_000),
                (128 * 1024**2, "maximum live bytes", 64 * 1024**2, 64 * 1024**3),
                (64, "incremental vacuum pages", 0, 65_536),
                (3600, "maximum backup age", 60, 7 * 24 * 60 * 60),
                (7200, "stale running seconds", 30 * 60, 7 * 24 * 60 * 60),
                (20, "maximum stale run reconciliations", 1, 1_000),
            ],
        )

    def test_validated_policy_stops_at_first_native_failure(self) -> None:
        args = policy_args()
        calls: list[str] = []

        def bounded(value: Any, *, name: str, minimum: int, maximum: int) -> int:
            calls.append(name)
            if name == "maximum live bytes":
                raise CLI.MaintenanceError("live-byte policy rejected")
            return int(value)

        with mock.patch.object(CLI, "bounded_int", side_effect=bounded):
            with self.assertRaisesRegex(
                CLI.MaintenanceError,
                "^live-byte policy rejected$",
            ):
                CLI.validated_policy(args)

        self.assertEqual(
            calls,
            [
                "retention days", "maximum terminal runs",
                "minimum terminal runs", "maximum deletions per pass",
                "maximum live bytes",
            ],
        )
        self.assertEqual(
            args.events,
            [
                "retention_days", "max_terminal_runs", "min_terminal_runs",
                "max_delete_runs", "max_live_bytes",
            ],
        )

    def maintenance_inputs(self, root: Path, *, apply: bool):
        paths = TracedDict(
            {
                "stack_dir": root,
                "db": root / "data/harness.sqlite3",
                "alert_db": root / "data/alerts.sqlite3",
                "backup_root": root / "backups",
                "report": root / "logs/report.json",
            }
        )
        policy = TracedDict(
            {
                "retention_days": 30,
                "max_terminal_runs": 500,
                "min_terminal_runs": 100,
                "max_delete_runs": 25,
                "max_live_bytes": 128 * 1024**2,
                "incremental_vacuum_pages": 64,
                "max_backup_age_seconds": 3600,
                "stale_running_seconds": 7200,
                "max_reconcile_runs": 20,
            }
        )
        return TracedArgs(apply=apply), paths, policy

    @staticmethod
    def assert_lock_is_held(lock_path: Path) -> None:
        with lock_path.open("w", encoding="utf-8") as contender:
            with unittest.TestCase().assertRaises(BlockingIOError):
                REAL_FLOCK(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_dry_run_preserves_lock_lifetime_and_phase_order(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args, paths, policy = self.maintenance_inputs(root, apply=False)
            lock_path = paths["db"].parent / ".investigation-harness-maintenance.lock"
            paths.events.clear()
            events: list[Any] = []
            times = iter(("time-reconcile", "time-preview"))

            def reconcile(*call_args: Any, **kwargs: Any):
                self.assert_lock_is_held(lock_path)
                events.append(("reconcile", call_args, kwargs))
                return {"status": "reconciled"}

            def maintain(*call_args: Any, **kwargs: Any):
                self.assert_lock_is_held(lock_path)
                events.append(("maintain", call_args, kwargs))
                return {
                    "status": "preview",
                    "database_present": True,
                    "candidates": {"selected": 2},
                }

            with (
                mock.patch.object(CLI, "utc_now", side_effect=lambda: next(times)),
                mock.patch.object(CLI, "reconcile_stale_running_runs", side_effect=reconcile),
                mock.patch.object(CLI, "maintain_database", side_effect=maintain),
                mock.patch.object(CLI, "verify_recent_harness_backup") as verify,
                mock.patch.object(CLI.fcntl, "flock", wraps=REAL_FLOCK) as flock,
            ):
                result = CLI.run_maintenance(args, paths, policy)

            self.assertEqual(
                list(result),
                ["stale_run_reconciliation", "status", "database_present", "candidates"],
            )
            self.assertEqual(result["stale_run_reconciliation"], {"status": "reconciled"})
            self.assertEqual(len(events), 2)
            self.assertEqual(events[0][0], "reconcile")
            self.assertEqual(events[0][2]["now"], "time-reconcile")
            self.assertEqual(events[1][0], "maintain")
            self.assertEqual(events[1][2]["now"], "time-preview")
            self.assertFalse(events[1][2]["apply"])
            self.assertIsNone(events[1][2]["backup"])
            verify.assert_not_called()
            self.assertEqual(flock.call_count, 1)
            self.assertEqual(flock.call_args.args[1], fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertTrue(flock.call_args.args[0].closed)
            self.assertEqual(lock_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(args.events, ["apply", "apply", "apply"])
            self.assertEqual(
                paths.events,
                ["db", "alert_db", "stack_dir", "stack_dir"],
            )
            self.assertEqual(
                policy.events,
                [
                    "stale_running_seconds", "max_reconcile_runs",
                    "retention_days", "max_terminal_runs", "min_terminal_runs",
                    "max_delete_runs", "max_live_bytes", "incremental_vacuum_pages",
                ],
            )

    def test_apply_verifies_backup_between_preview_and_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args, paths, policy = self.maintenance_inputs(root, apply=True)
            lock_path = paths["db"].parent / ".investigation-harness-maintenance.lock"
            paths.events.clear()
            events: list[Any] = []
            times = iter(("time-reconcile", "time-preview", "time-backup", "time-apply"))
            preview = {
                "status": "preview",
                "database_present": True,
                "candidates": {"selected": 2},
                "_candidate_run_ids": ("run-2", "run-1"),
            }
            backup = {"verified": True}

            def reconcile(*call_args: Any, **kwargs: Any):
                self.assert_lock_is_held(lock_path)
                events.append(("reconcile", call_args, kwargs))
                return {"status": "reconciled"}

            def maintain(*call_args: Any, **kwargs: Any):
                self.assert_lock_is_held(lock_path)
                events.append(("maintain", call_args, kwargs))
                return preview if kwargs["apply"] is False else {"status": "maintained"}

            def verify(*call_args: Any, **kwargs: Any):
                self.assert_lock_is_held(lock_path)
                events.append(("verify", call_args, kwargs))
                return backup

            with (
                mock.patch.object(CLI, "utc_now", side_effect=lambda: next(times)),
                mock.patch.object(CLI, "reconcile_stale_running_runs", side_effect=reconcile),
                mock.patch.object(CLI, "maintain_database", side_effect=maintain),
                mock.patch.object(CLI, "verify_recent_harness_backup", side_effect=verify),
            ):
                result = CLI.run_maintenance(args, paths, policy)

            self.assertEqual([event[0] for event in events], ["reconcile", "maintain", "verify", "maintain"])
            self.assertEqual(events[0][2]["now"], "time-reconcile")
            self.assertEqual(events[1][2]["now"], "time-preview")
            self.assertEqual(events[2][2]["now"], "time-backup")
            self.assertEqual(events[2][2]["max_age_seconds"], 3600)
            self.assertEqual(events[2][2]["required_run_ids"], ("run-2", "run-1"))
            self.assertEqual(events[3][2]["now"], "time-apply")
            self.assertIs(events[3][2]["backup"], backup)
            self.assertEqual(result, {"stale_run_reconciliation": {"status": "reconciled"}, "status": "maintained"})
            self.assertEqual(args.events, ["apply", "apply", "apply"])
            self.assertEqual(paths.events[-1], "backup_root")

    def test_phase_failure_propagates_and_releases_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args, paths, policy = self.maintenance_inputs(root, apply=False)
            lock_path = paths["db"].parent / ".investigation-harness-maintenance.lock"
            with (
                mock.patch.object(CLI, "utc_now", return_value="time"),
                mock.patch.object(
                    CLI,
                    "reconcile_stale_running_runs",
                    side_effect=RuntimeError("reconciliation failed"),
                ),
                mock.patch.object(CLI, "maintain_database") as maintain,
            ):
                with self.assertRaisesRegex(RuntimeError, "^reconciliation failed$"):
                    CLI.run_maintenance(args, paths, policy)
            maintain.assert_not_called()
            with lock_path.open("w", encoding="utf-8") as contender:
                REAL_FLOCK(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
                REAL_FLOCK(contender, fcntl.LOCK_UN)


if __name__ == "__main__":
    unittest.main()
