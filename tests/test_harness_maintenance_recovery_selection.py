#!/usr/bin/env python3
"""Characterize read-only stale harness reconciliation selection."""
from __future__ import annotations

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


def load_recovery():
    path = BIN / "harness_maintenance_recovery.py"
    spec = importlib.util.spec_from_file_location(
        "harness_maintenance_recovery_selection_characterization",
        path,
    )
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


RECOVERY = load_recovery()


class FakeCursor:
    def __init__(self, *, rows: Any = None) -> None:
        self.rows = [] if rows is None else rows

    def fetchall(self):
        return self.rows


class FakeConnection:
    def __init__(
        self,
        name: str,
        responses: list[Any],
        lifecycle: list[Any],
    ) -> None:
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "responses", responses)
        object.__setattr__(self, "lifecycle", lifecycle)
        object.__setattr__(self, "events", [])

    def __setattr__(self, name: str, value: Any) -> None:
        if name == "row_factory":
            self.events.append(("row_factory", value))
        object.__setattr__(self, name, value)

    def execute(self, query: str, parameters: Any = None):
        normalized = " ".join(query.split())
        self.events.append(("execute", normalized, parameters))
        if not self.responses:
            raise AssertionError(f"unexpected {self.name} query: {normalized}")
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response

    def close(self) -> None:
        self.lifecycle.append(("close", self.name))


class HarnessMaintenanceRecoverySelectionCharacterizationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness_db = Path("/synthetic/harness.sqlite3")
        self.alert_db = Path("/synthetic/alerts.sqlite3")
        self.now = dt.datetime(2026, 8, 12, 12, 0, tzinfo=dt.timezone.utc)

    def test_signature_is_stable(self) -> None:
        self.assertEqual(
            str(inspect.signature(RECOVERY.select_stale_running_reconciliations)),
            "(harness_db: 'Path', alert_db: 'Path', *, now: 'dt.datetime', "
            "stale_running_seconds: 'int', limit: 'int') -> "
            "'list[dict[str, Any]]'",
        )

    def test_success_preserves_connection_query_match_and_close_order(self) -> None:
        lifecycle: list[Any] = []
        candidates = [object(), object()]
        harness = FakeConnection(
            "harness",
            [FakeCursor(), FakeCursor(rows=candidates)],
            lifecycle,
        )
        alert = FakeConnection("alert", [FakeCursor()], lifecycle)
        connect_calls: list[Any] = []
        matcher_calls: list[Any] = []

        def connect(uri: str, *, uri_mode: bool = False, **kwargs: Any):
            connect_calls.append((uri, uri_mode, kwargs))
            return harness if len(connect_calls) == 1 else alert

        def match(*args: Any):
            matcher_calls.append(args)
            return [{"run_id": "selected-run"}]

        with (
            mock.patch.object(
                RECOVERY,
                "owner_readable_regular_file",
                side_effect=lambda path: lifecycle.append(("owner", path)) or True,
            ),
            mock.patch.object(
                RECOVERY,
                "timestamp_text",
                side_effect=lambda value: lifecycle.append(("timestamp", value))
                or "cutoff-text",
            ),
            mock.patch.object(
                RECOVERY.sqlite3,
                "connect",
                side_effect=lambda database_uri, **kwargs: connect(
                    database_uri,
                    uri_mode=kwargs.pop("uri"),
                    **kwargs,
                ),
            ),
            mock.patch.object(
                RECOVERY,
                "table_names",
                side_effect=lambda connection: lifecycle.append(
                    ("table_names", connection.name)
                )
                or {"durable_jobs"},
            ),
            mock.patch.object(RECOVERY, "_match_durable_jobs", side_effect=match),
        ):
            result = RECOVERY.select_stale_running_reconciliations(
                self.harness_db,
                self.alert_db,
                now=self.now,
                stale_running_seconds=3600,
                limit=17,
            )

        self.assertEqual(result, [{"run_id": "selected-run"}])
        self.assertEqual(
            connect_calls,
            [
                ("file:///synthetic/harness.sqlite3?mode=ro", True, {"timeout": 10.0}),
                ("file:///synthetic/alerts.sqlite3?mode=ro", True, {"timeout": 10.0}),
            ],
        )
        self.assertEqual(
            harness.events,
            [
                ("row_factory", sqlite3.Row),
                ("execute", "PRAGMA query_only = ON", None),
                (
                    "execute",
                    "SELECT run_id, correlation_id, case_id, role, started_at, "
                    "updated_at FROM harness_runs WHERE status = 'running' "
                    "AND role IN ('soc-analyst', 'incident-responder') AND "
                    "datetime(replace(updated_at, ' ', 'T')) <= datetime(?) "
                    "ORDER BY datetime(replace(updated_at, ' ', 'T')), run_id LIMIT ?",
                    ("cutoff-text", 17),
                ),
            ],
        )
        self.assertEqual(
            alert.events,
            [
                ("row_factory", sqlite3.Row),
                ("execute", "PRAGMA query_only = ON", None),
            ],
        )
        self.assertEqual(matcher_calls, [(harness, alert, candidates)])
        self.assertEqual(
            lifecycle,
            [
                ("owner", self.alert_db),
                ("timestamp", self.now - dt.timedelta(seconds=3600)),
                ("table_names", "alert"),
                ("close", "alert"),
                ("close", "harness"),
            ],
        )

    def test_owner_admission_fails_before_time_or_database_access(self) -> None:
        with (
            mock.patch.object(
                RECOVERY,
                "owner_readable_regular_file",
                return_value=False,
            ) as owner,
            mock.patch.object(RECOVERY, "timestamp_text") as timestamp,
            mock.patch.object(RECOVERY.sqlite3, "connect") as connect,
            self.assertRaisesRegex(
                RECOVERY.MaintenanceError,
                "^alert-store SQLite database must be an owner-owned regular "
                "file without group/world write access$",
            ),
        ):
            RECOVERY.select_stale_running_reconciliations(
                self.harness_db,
                self.alert_db,
                now=self.now,
                stale_running_seconds=1,
                limit=1,
            )
        owner.assert_called_once_with(self.alert_db)
        timestamp.assert_not_called()
        connect.assert_not_called()

    def test_missing_durable_table_closes_both_connections_before_error(self) -> None:
        lifecycle: list[Any] = []
        harness = FakeConnection("harness", [FakeCursor()], lifecycle)
        alert = FakeConnection("alert", [FakeCursor()], lifecycle)
        with (
            mock.patch.object(RECOVERY, "owner_readable_regular_file", return_value=True),
            mock.patch.object(RECOVERY, "timestamp_text", return_value="cutoff"),
            mock.patch.object(
                RECOVERY.sqlite3,
                "connect",
                side_effect=[harness, alert],
            ),
            mock.patch.object(RECOVERY, "table_names", return_value=set()),
            mock.patch.object(RECOVERY, "_match_durable_jobs") as matcher,
            self.assertRaisesRegex(
                RECOVERY.MaintenanceError,
                "^alert-store SQLite is missing durable_jobs$",
            ),
        ):
            RECOVERY.select_stale_running_reconciliations(
                self.harness_db,
                self.alert_db,
                now=self.now,
                stale_running_seconds=1,
                limit=1,
            )
        matcher.assert_not_called()
        self.assertEqual(lifecycle, [("close", "alert"), ("close", "harness")])

    def test_sqlite_error_is_projected_after_connections_close(self) -> None:
        lifecycle: list[Any] = []
        harness = FakeConnection(
            "harness",
            [FakeCursor(), sqlite3.OperationalError("synthetic query failure")],
            lifecycle,
        )
        alert = FakeConnection("alert", [FakeCursor()], lifecycle)
        with (
            mock.patch.object(RECOVERY, "owner_readable_regular_file", return_value=True),
            mock.patch.object(RECOVERY, "timestamp_text", return_value="cutoff"),
            mock.patch.object(
                RECOVERY.sqlite3,
                "connect",
                side_effect=[harness, alert],
            ),
            mock.patch.object(RECOVERY, "table_names", return_value={"durable_jobs"}),
            self.assertRaisesRegex(
                RECOVERY.MaintenanceError,
                "^stale harness reconciliation query failed: synthetic query failure$",
            ),
        ):
            RECOVERY.select_stale_running_reconciliations(
                self.harness_db,
                self.alert_db,
                now=self.now,
                stale_running_seconds=1,
                limit=1,
            )
        self.assertEqual(lifecycle, [("close", "alert"), ("close", "harness")])

    def test_non_sqlite_failure_propagates_after_connections_close(self) -> None:
        lifecycle: list[Any] = []
        harness = FakeConnection(
            "harness",
            [FakeCursor(), RuntimeError("unexpected row failure")],
            lifecycle,
        )
        alert = FakeConnection("alert", [FakeCursor()], lifecycle)
        with (
            mock.patch.object(RECOVERY, "owner_readable_regular_file", return_value=True),
            mock.patch.object(RECOVERY, "timestamp_text", return_value="cutoff"),
            mock.patch.object(
                RECOVERY.sqlite3,
                "connect",
                side_effect=[harness, alert],
            ),
            mock.patch.object(RECOVERY, "table_names", return_value={"durable_jobs"}),
            self.assertRaisesRegex(RuntimeError, "^unexpected row failure$"),
        ):
            RECOVERY.select_stale_running_reconciliations(
                self.harness_db,
                self.alert_db,
                now=self.now,
                stale_running_seconds=1,
                limit=1,
            )
        self.assertEqual(lifecycle, [("close", "alert"), ("close", "harness")])


if __name__ == "__main__":
    unittest.main()
