from __future__ import annotations

import json
import sqlite3
import sys
import tempfile
import threading
import unittest
from contextlib import contextmanager
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "onion-sentinel-dashboard"
sys.path.insert(0, str(DASHBOARD))

from portal_soc_alert_status_service import (  # noqa: E402
    SocAlertStatusPersistenceSources,
    load_soc_alert_statuses,
    retryable_soc_alert_status_error,
    save_soc_alert_statuses,
    write_soc_alert_status,
)


class SocAlertStatusServiceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.db_path = root / "alerts.sqlite3"
        self.db_path.touch()
        self.mirror_path = root / "status.json"
        self.rows = {}
        self.sleep_calls = []
        self.write_failures = []

        @contextmanager
        def connect_read():
            yield object()

        @contextmanager
        def connect_write():
            if self.write_failures:
                raise self.write_failures.pop(0)

            class Connection:
                def execute(self, statement):
                    self.statement = statement

            yield Connection()

        def normalize(value):
            if not isinstance(value, dict):
                return None
            status = value.get("status", "open")
            if status not in {"open", "acknowledged", "suppressed"}:
                return None
            return {
                "status": status,
                "repeat_count": int(value.get("repeat_count", 0)),
                "reason": str(value.get("reason", ""))[:140],
                "updated_at": value.get("updated_at", "2026-08-07T12:00:00Z"),
            }

        def write_one(conn, alert_id, meta):
            if not isinstance(meta, dict) or meta.get("status") == "open":
                self.rows.pop(alert_id, None)
            else:
                self.rows[alert_id] = dict(meta)

        def write_many(conn, statuses):
            for alert_id, meta in statuses.items():
                write_one(conn, alert_id, meta)

        self.sources = SocAlertStatusPersistenceSources(
            db_path=self.db_path,
            mirror_path=self.mirror_path,
            connect_read=connect_read,
            connect_write=connect_write,
            ensure_schema=lambda conn: None,
            load_db=lambda conn: dict(self.rows),
            write_one=write_one,
            write_many=write_many,
            normalize=normalize,
            now_iso=lambda: "2026-08-07T12:00:00Z",
            uuid_hex=lambda: "snapshot",
            lock=threading.RLock(),
            sleep=self.sleep_calls.append,
            retry_attempts=3,
            retry_base_seconds=0.01,
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_write_retries_and_mirrors_committed_readback(self) -> None:
        self.write_failures.extend([
            sqlite3.OperationalError("database is locked"),
            sqlite3.OperationalError("database is busy"),
        ])
        write_soc_alert_status(self.sources, "group-1", {
            "status": "acknowledged",
            "repeat_count": 4,
            "group_key": "stable",
            "updated_by": "analyst",
        })
        self.assertEqual(self.sleep_calls, [0.01, 0.02])
        self.assertEqual(self.rows["group-1"]["group_key"], "stable")
        mirror = json.loads(self.mirror_path.read_text(encoding="utf-8"))
        self.assertEqual(mirror["statuses"], self.rows)
        self.assertEqual(self.mirror_path.stat().st_mode & 0o777, 0o600)

    def test_non_retryable_and_exhausted_errors_propagate_without_mirror(self) -> None:
        self.write_failures.append(sqlite3.OperationalError("syntax error"))
        with self.assertRaises(sqlite3.OperationalError):
            write_soc_alert_status(
                self.sources, "group-1", {"status": "suppressed"}
            )
        self.assertFalse(self.mirror_path.exists())

    def test_database_authority_does_not_fall_back_on_read_failure(self) -> None:
        self.mirror_path.write_text(
            json.dumps({"statuses": {"stale": {"status": "suppressed"}}}),
            encoding="utf-8",
        )
        failing = SocAlertStatusPersistenceSources(
            **{
                **self.sources.__dict__,
                "load_db": lambda conn: (_ for _ in ()).throw(RuntimeError()),
            }
        )
        self.assertEqual(load_soc_alert_statuses(failing), {})

    def test_json_is_used_only_when_database_is_absent(self) -> None:
        self.db_path.unlink()
        self.mirror_path.write_text(
            json.dumps({"statuses": {"fallback": {"status": "suppressed"}}}),
            encoding="utf-8",
        )
        self.assertIn("fallback", load_soc_alert_statuses(self.sources))

    def test_bulk_save_normalizes_and_does_not_mirror_failed_transaction(self) -> None:
        save_soc_alert_statuses(self.sources, {
            "keep": {"status": "suppressed", "reason": "reviewed"},
            "drop": {"status": "open"},
            "invalid": "bad",
        })
        self.assertEqual(set(self.rows), {"keep"})
        self.assertEqual(
            set(json.loads(self.mirror_path.read_text())["statuses"]), {"keep"}
        )
        self.mirror_path.unlink()
        self.write_failures.append(sqlite3.OperationalError("disk full"))
        with self.assertRaises(sqlite3.OperationalError):
            save_soc_alert_statuses(
                self.sources, {"other": {"status": "acknowledged"}}
            )
        self.assertFalse(self.mirror_path.exists())

    def test_retry_classifier_is_bounded_to_known_transient_sqlite_errors(self) -> None:
        self.assertTrue(retryable_soc_alert_status_error(
            sqlite3.OperationalError("disk I/O error")
        ))
        self.assertFalse(retryable_soc_alert_status_error(
            sqlite3.OperationalError("no such table")
        ))
        self.assertFalse(retryable_soc_alert_status_error(RuntimeError("locked")))


if __name__ == "__main__":
    unittest.main()
