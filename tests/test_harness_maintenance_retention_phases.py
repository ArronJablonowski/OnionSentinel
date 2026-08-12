#!/usr/bin/env python3
"""Characterize bounded harness retention selection and maintenance phases."""
from __future__ import annotations

import ast
import copy
import datetime as dt
import importlib.util
import inspect
import sqlite3
import sys
import unittest
from pathlib import Path
from typing import Any
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))


def load_retention():
    path = BIN / "harness_maintenance_retention.py"
    spec = importlib.util.spec_from_file_location(
        "harness_maintenance_retention_phases_characterization",
        path,
    )
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


RETENTION = load_retention()


def function_metrics(name: str) -> tuple[int, int]:
    tree = ast.parse(
        (BIN / "harness_maintenance_retention.py").read_text(encoding="utf-8")
    )
    target = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == name
    )
    complexity = 1
    for node in ast.walk(target):
        if node is target:
            continue
        if isinstance(node, (ast.If, ast.For, ast.While, ast.IfExp, ast.Assert)):
            complexity += 1
        elif isinstance(node, ast.Try):
            complexity += len(node.handlers)
        elif isinstance(node, ast.BoolOp):
            complexity += max(0, len(node.values) - 1)
        elif isinstance(node, ast.comprehension):
            complexity += 1 + len(node.ifs)
    return target.end_lineno - target.lineno + 1, complexity


class TracedRow(dict):
    def __init__(self, values: dict[str, Any]) -> None:
        super().__init__(values)
        self.events: list[str] = []

    def __getitem__(self, key: str) -> Any:
        self.events.append(key)
        return super().__getitem__(key)


class FakeCursor:
    def __init__(
        self,
        *,
        one: Any = None,
        rows: Any = None,
    ) -> None:
        self.one = one
        self.rows = [] if rows is None else rows

    def fetchone(self):
        return self.one

    def fetchall(self):
        return self.rows


class FakeConnection:
    def __init__(self, responses: list[Any] | None = None) -> None:
        self.responses = list(responses or [])
        self.events: list[Any] = []

    def execute(self, query: str, parameters: Any = None):
        normalized = " ".join(query.split())
        self.events.append(("execute", normalized, parameters))
        if not self.responses:
            return FakeCursor()
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response

    def close(self) -> None:
        self.events.append(("close",))


class HarnessMaintenanceRetentionPhasesCharacterizationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = dt.datetime(2026, 8, 12, 12, 0, tzinfo=dt.timezone.utc)
        self.db_path = Path("/synthetic/harness.sqlite3")

    def test_changed_retention_phases_stay_within_architecture_budget(self) -> None:
        functions = (
            "_add_prunable_rows",
            "_terminal_run_count",
            "_expired_run_rows",
            "_oldest_terminal_rows",
            "select_prunable_runs",
            "_maintenance_pass",
            "_follow_up_required",
            "_maintenance_result",
            "maintain_database",
        )
        for name in functions:
            with self.subTest(name=name):
                lines, complexity = function_metrics(name)
                self.assertLessEqual(lines, 50)
                self.assertLessEqual(complexity, 10)

    def test_public_signatures_are_stable(self) -> None:
        self.assertEqual(
            str(inspect.signature(RETENTION.select_prunable_runs)),
            "(connection: 'sqlite3.Connection', *, now: 'dt.datetime', "
            "retention_days: 'int', max_terminal_runs: 'int', "
            "min_terminal_runs: 'int', max_delete_runs: 'int', "
            "live_page_bytes: 'int', max_live_bytes: 'int') -> "
            "'tuple[list[str], dict[str, int | bool]]'",
        )
        self.assertEqual(
            str(inspect.signature(RETENTION.maintain_database)),
            "(db_path: 'Path', *, now: 'dt.datetime', retention_days: 'int', "
            "max_terminal_runs: 'int', min_terminal_runs: 'int', "
            "max_delete_runs: 'int', max_live_bytes: 'int', "
            "incremental_vacuum_pages: 'int', apply: 'bool', "
            "backup: 'dict[str, Any] | None') -> 'dict[str, Any]'",
        )

    def test_selection_preserves_all_tier_queries_deduplication_and_bounds(self) -> None:
        expired = [TracedRow({"run_id": "run-1"}), TracedRow({"run_id": "run-2"})]
        overflow = [
            TracedRow({"run_id": "run-2"}),
            TracedRow({"run_id": "run-3"}),
            TracedRow({"run_id": "run-4"}),
        ]
        pressure = [
            TracedRow({"run_id": "run-1"}),
            TracedRow({"run_id": "run-4"}),
            TracedRow({"run_id": "run-5"}),
            TracedRow({"run_id": "run-6"}),
            TracedRow({"run_id": "run-7"}),
        ]
        connection = FakeConnection(
            [
                FakeCursor(one=(8,)),
                FakeCursor(rows=expired),
                FakeCursor(rows=overflow),
                FakeCursor(rows=pressure),
            ]
        )
        timestamp_calls: list[dt.datetime] = []
        with mock.patch.object(
            RETENTION,
            "timestamp_text",
            side_effect=lambda value: timestamp_calls.append(value) or "cutoff",
        ):
            selected, metrics = RETENTION.select_prunable_runs(
                connection,
                now=self.now,
                retention_days=30,
                max_terminal_runs=5,
                min_terminal_runs=2,
                max_delete_runs=6,
                live_page_bytes=101,
                max_live_bytes=100,
            )

        self.assertEqual(timestamp_calls, [self.now - dt.timedelta(days=30)])
        self.assertEqual(
            [event[1] for event in connection.events],
            [
                "SELECT COUNT(*) FROM harness_runs WHERE status IN (?, ?, ?)",
                "SELECT run_id FROM harness_runs WHERE status IN (?, ?, ?) "
                "AND datetime(replace(COALESCE(completed_at, updated_at), ' ', "
                "'T')) < datetime(?) ORDER BY datetime( replace(COALESCE(" 
                "completed_at, updated_at), ' ', 'T') ), run_id LIMIT ?",
                "SELECT run_id FROM harness_runs WHERE status IN (?, ?, ?) "
                "ORDER BY datetime( replace(COALESCE(completed_at, updated_at), "
                "' ', 'T') ), run_id LIMIT ?",
                "SELECT run_id FROM harness_runs WHERE status IN (?, ?, ?) "
                "ORDER BY datetime( replace(COALESCE(completed_at, updated_at), "
                "' ', 'T') ), run_id LIMIT ?",
            ],
        )
        self.assertEqual(
            [event[2] for event in connection.events],
            [
                RETENTION.TERMINAL_STATUSES,
                (*RETENTION.TERMINAL_STATUSES, "cutoff", 6),
                (*RETENTION.TERMINAL_STATUSES, 3),
                (*RETENTION.TERMINAL_STATUSES, 6),
            ],
        )
        self.assertEqual(
            selected,
            ["run-1", "run-2", "run-3", "run-4", "run-5", "run-6"],
        )
        self.assertEqual(
            metrics,
            {
                "expired_candidates": 2,
                "terminal_overflow": 3,
                "over_live_byte_budget": True,
                "selected": 6,
            },
        )
        for row in (*expired, *overflow, *pressure):
            self.assertEqual(row.events, ["run_id"])

    def test_selection_skips_optional_tiers_without_widening_queries(self) -> None:
        connection = FakeConnection(
            [FakeCursor(one=(2,)), FakeCursor(rows=[TracedRow({"run_id": "old"})])]
        )
        with mock.patch.object(RETENTION, "timestamp_text", return_value="cutoff"):
            selected, metrics = RETENTION.select_prunable_runs(
                connection,
                now=self.now,
                retention_days=1,
                max_terminal_runs=5,
                min_terminal_runs=1,
                max_delete_runs=5,
                live_page_bytes=99,
                max_live_bytes=100,
            )
        self.assertEqual(selected, ["old"])
        self.assertEqual(len(connection.events), 2)
        self.assertEqual(metrics["terminal_overflow"], 0)
        self.assertFalse(metrics["over_live_byte_budget"])

    def test_selection_native_row_failure_propagates_at_exact_tier(self) -> None:
        connection = FakeConnection(
            [FakeCursor(one=(1,)), FakeCursor(rows=[TracedRow({})])]
        )
        with (
            mock.patch.object(RETENTION, "timestamp_text", return_value="cutoff"),
            self.assertRaises(KeyError),
        ):
            RETENTION.select_prunable_runs(
                connection,
                now=self.now,
                retention_days=1,
                max_terminal_runs=5,
                min_terminal_runs=1,
                max_delete_runs=5,
                live_page_bytes=0,
                max_live_bytes=100,
            )
        self.assertEqual(len(connection.events), 2)

    def maintenance_values(self):
        before = {
            "live_page_bytes": 80,
            "allocated_disk_bytes": 90,
            "auto_vacuum": 2,
            "journal_mode": "wal",
            "run_counts": {"terminal": 4},
        }
        after = {
            "live_page_bytes": 70,
            "allocated_disk_bytes": 75,
            "auto_vacuum": 2,
            "journal_mode": "wal",
            "run_counts": {"terminal": 3},
        }
        candidates = {
            "expired_candidates": 1,
            "terminal_overflow": 0,
            "over_live_byte_budget": False,
            "selected": 1,
        }
        checkpoint = {
            "attempted": True,
            "busy": 0,
            "wal_pages": 1,
            "checkpointed_pages": 1,
        }
        return before, after, candidates, checkpoint

    def test_maintenance_preserves_phase_order_result_schema_and_inputs(self) -> None:
        events: list[Any] = []
        connection = FakeConnection()
        before, after, candidates, checkpoint = self.maintenance_values()
        backup = {
            "verified": True,
            "bundle": "bundle-1",
            "_covered_run_ids": ("run-1",),
        }
        original_inputs = copy.deepcopy((before, after, candidates, backup))
        snapshots = iter((before, after))

        def validate(path: Path):
            events.append(("validate", path))
            return None

        def connect(path: Path, *, apply: bool):
            events.append(("connect", path, apply))
            return connection

        def snapshot(active: FakeConnection, path: Path):
            value = next(snapshots)
            events.append(("snapshot", active, path, value is before))
            return value

        def select(active: FakeConnection, **kwargs: Any):
            events.append(("select", active, kwargs))
            return ["run-1"], candidates

        def limit(selected, observed, apply, supplied_backup):
            events.append(("limit", selected, observed, apply, supplied_backup))
            return selected

        def apply_maintenance(active: FakeConnection, **kwargs: Any):
            events.append(("apply", active, kwargs))
            return 1, checkpoint, 128

        with (
            mock.patch.object(RETENTION, "_validate_database_path", side_effect=validate),
            mock.patch.object(RETENTION, "_connect", side_effect=connect),
            mock.patch.object(RETENTION, "database_snapshot", side_effect=snapshot),
            mock.patch.object(RETENTION, "select_prunable_runs", side_effect=select),
            mock.patch.object(RETENTION, "_limit_to_backup", side_effect=limit),
            mock.patch.object(RETENTION, "_apply_maintenance", side_effect=apply_maintenance),
        ):
            result = RETENTION.maintain_database(
                self.db_path,
                now=self.now,
                retention_days=30,
                max_terminal_runs=5,
                min_terminal_runs=2,
                max_delete_runs=3,
                max_live_bytes=100,
                incremental_vacuum_pages=128,
                apply=False,
                backup=backup,
            )

        self.assertEqual(
            connection.events,
            [
                ("execute", "PRAGMA busy_timeout = 10000", None),
                ("execute", "PRAGMA foreign_keys = ON", None),
                ("execute", "PRAGMA query_only = ON", None),
                ("close",),
            ],
        )
        self.assertEqual(
            [event[0] for event in events],
            ["validate", "connect", "snapshot", "select", "limit", "apply", "snapshot"],
        )
        self.assertEqual(
            list(result),
            [
                "status", "applied", "database_present", "policy", "backup",
                "candidates", "_candidate_run_ids", "deleted_runs", "checkpoint",
                "incremental_vacuum_page_limit_applied", "before", "after",
                "follow_up_required",
            ],
        )
        self.assertEqual(result["status"], "ok")
        self.assertFalse(result["applied"])
        self.assertEqual(result["backup"], {"verified": True, "bundle": "bundle-1"})
        self.assertEqual(result["_candidate_run_ids"], ("run-1",))
        self.assertEqual(result["deleted_runs"], 1)
        self.assertEqual(result["incremental_vacuum_page_limit_applied"], 128)
        self.assertFalse(result["follow_up_required"])
        self.assertEqual((before, after, candidates, backup), original_inputs)

    def test_maintenance_absent_short_circuits_before_connection(self) -> None:
        absent = {
            "status": "absent",
            "applied": False,
            "database_present": False,
            "deleted_runs": 0,
        }
        with (
            mock.patch.object(RETENTION, "_validate_database_path", return_value=absent),
            mock.patch.object(RETENTION, "_connect") as connect,
        ):
            result = RETENTION.maintain_database(
                self.db_path,
                now=self.now,
                retention_days=1,
                max_terminal_runs=1,
                min_terminal_runs=1,
                max_delete_runs=1,
                max_live_bytes=1,
                incremental_vacuum_pages=1,
                apply=True,
                backup=None,
            )
        self.assertIs(result, absent)
        connect.assert_not_called()

    def test_apply_mode_skips_query_only_pragma(self) -> None:
        connection = FakeConnection()
        before, after, candidates, checkpoint = self.maintenance_values()
        with (
            mock.patch.object(RETENTION, "_validate_database_path", return_value=None),
            mock.patch.object(RETENTION, "_connect", return_value=connection),
            mock.patch.object(
                RETENTION,
                "database_snapshot",
                side_effect=[before, after],
            ),
            mock.patch.object(
                RETENTION,
                "select_prunable_runs",
                return_value=([], candidates),
            ),
            mock.patch.object(RETENTION, "_limit_to_backup", return_value=[]),
            mock.patch.object(
                RETENTION,
                "_apply_maintenance",
                return_value=(0, checkpoint, 0),
            ),
        ):
            RETENTION.maintain_database(
                self.db_path,
                now=self.now,
                retention_days=1,
                max_terminal_runs=5,
                min_terminal_runs=1,
                max_delete_runs=1,
                max_live_bytes=100,
                incremental_vacuum_pages=1,
                apply=True,
                backup=None,
            )
        self.assertEqual(
            connection.events,
            [
                ("execute", "PRAGMA busy_timeout = 10000", None),
                ("execute", "PRAGMA foreign_keys = ON", None),
                ("close",),
            ],
        )

    def test_sqlite_error_is_projected_after_close(self) -> None:
        connection = FakeConnection()
        with (
            mock.patch.object(RETENTION, "_validate_database_path", return_value=None),
            mock.patch.object(RETENTION, "_connect", return_value=connection),
            mock.patch.object(
                RETENTION,
                "database_snapshot",
                side_effect=sqlite3.OperationalError("synthetic snapshot failure"),
            ),
            self.assertRaisesRegex(
                RETENTION.MaintenanceError,
                "^harness SQLite maintenance failed: synthetic snapshot failure$",
            ),
        ):
            RETENTION.maintain_database(
                self.db_path,
                now=self.now,
                retention_days=1,
                max_terminal_runs=1,
                min_terminal_runs=1,
                max_delete_runs=1,
                max_live_bytes=1,
                incremental_vacuum_pages=1,
                apply=False,
                backup=None,
            )
        self.assertEqual(connection.events[-1], ("close",))

    def test_non_sqlite_error_propagates_after_close(self) -> None:
        connection = FakeConnection()
        with (
            mock.patch.object(RETENTION, "_validate_database_path", return_value=None),
            mock.patch.object(RETENTION, "_connect", return_value=connection),
            mock.patch.object(
                RETENTION,
                "database_snapshot",
                side_effect=RuntimeError("unexpected snapshot failure"),
            ),
            self.assertRaisesRegex(RuntimeError, "^unexpected snapshot failure$"),
        ):
            RETENTION.maintain_database(
                self.db_path,
                now=self.now,
                retention_days=1,
                max_terminal_runs=1,
                min_terminal_runs=1,
                max_delete_runs=1,
                max_live_bytes=1,
                incremental_vacuum_pages=1,
                apply=False,
                backup=None,
            )
        self.assertEqual(connection.events[-1], ("close",))


if __name__ == "__main__":
    unittest.main()
