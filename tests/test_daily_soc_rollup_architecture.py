from __future__ import annotations

import contextlib
import datetime as dt
import hashlib
import importlib.util
import inspect
import io
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "n8n/bin/write-daily-soc-rollup.py"
BASELINE = ROOT / "operations/quality/module-quality-baseline.json"
FIXED_ZONE = dt.timezone(dt.timedelta(hours=-6))
FIXED_NOW = dt.datetime(2026, 8, 12, 8, 30, tzinfo=FIXED_ZONE)
SINCE = "2026-08-11  12:00:00+00:00"
GENERATED = "2026-08-12  08:30:00-06:00"
REPORT_DATE = "2026-08-12"


def load_rollup_module():
    if str(SCRIPT.parent) not in sys.path:
        sys.path.insert(0, str(SCRIPT.parent))
    spec = importlib.util.spec_from_file_location("daily_soc_rollup", SCRIPT)
    if spec is None or spec.loader is None:
        raise AssertionError("daily SOC rollup script could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def create_schema(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
        CREATE TABLE alerts (
          alert_id TEXT PRIMARY KEY,
          triage_level TEXT,
          triage_score INTEGER,
          filter_status TEXT,
          routing TEXT,
          rule_name TEXT,
          source_ip TEXT,
          destination_ip TEXT,
          seen_count INTEGER,
          suppression_key TEXT,
          first_seen TEXT,
          last_seen TEXT
        );
        CREATE TABLE suppression_log (
          suppression_key TEXT,
          rule_name TEXT,
          reason TEXT,
          seen_count INTEGER,
          suppressed_count INTEGER,
          escalated_count INTEGER,
          ttl_seconds INTEGER,
          last_seen TEXT
        );
        CREATE TABLE notification_log (
          alert_id TEXT,
          channel TEXT,
          triage_level TEXT,
          rule_name TEXT,
          source_ip TEXT,
          destination_ip TEXT,
          sent_count INTEGER,
          last_sent TEXT
        );
        """
    )


def populate(connection: sqlite3.Connection) -> None:
    alerts = [
        (
            "older-pair",
            "low",
            10,
            "accepted",
            "archive",
            "Historical pair",
            "10.0.0.1",
            "10.0.0.2",
            1,
            None,
            "2026-08-10  10:00:00+00:00",
            "2026-08-10  10:00:00+00:00",
        ),
        (
            "alert:accepted-urgent-identifier-long",
            "high",
            88,
            "accepted",
            "soc",
            "Accepted urgent",
            "10.0.0.1",
            "10.0.0.2",
            4,
            None,
            "2026-08-11  12:10:00+00:00",
            "2026-08-11  13:00:00+00:00",
        ),
        (
            "alert:suppressed",
            "critical",
            99,
            "suppressed",
            "evidence",
            "Rule | escaped\nline",
            "10.0.0.3",
            "10.0.0.4",
            7,
            "critical|escaped",
            "2026-08-11  13:10:00+00:00",
            "2026-08-11  14:00:00+00:00",
        ),
        (
            "alert:duplicate",
            "low",
            20,
            "duplicate",
            "archive",
            "Duplicate rule",
            "10.0.0.5",
            "10.0.0.6",
            2,
            None,
            "2026-08-11  14:10:00+00:00",
            "2026-08-11  15:00:00+00:00",
        ),
        (
            "phase-validation-alert",
            "critical",
            100,
            "accepted",
            "test",
            "Validation alert",
            "10.0.0.9",
            "10.0.0.10",
            11,
            None,
            "2026-08-11  15:10:00+00:00",
            "2026-08-11  16:00:00+00:00",
        ),
    ]
    connection.executemany(
        "INSERT INTO alerts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        alerts,
    )
    connection.executemany(
        "INSERT INTO suppression_log VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [
            (
                "critical|escaped",
                "Rule | escaped\nline",
                "threshold | retained",
                7,
                6,
                1,
                600,
                "2026-08-11  14:00:00+00:00",
            ),
            (
                "old",
                "Old suppression",
                "outside",
                1,
                1,
                0,
                60,
                "2026-08-10  14:00:00+00:00",
            ),
        ],
    )
    connection.executemany(
        "INSERT INTO notification_log VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [
            (
                "alert:accepted-urgent-identifier-long",
                "telegram",
                "high",
                "Accepted urgent",
                "10.0.0.1",
                "10.0.0.2",
                2,
                "2026-08-11T13:05:00Z",
            ),
            (
                "phase-validation-alert",
                "telegram-test",
                "critical",
                "Validation alert",
                "10.0.0.9",
                "10.0.0.10",
                1,
                "2026-08-11T16:05:00Z",
            ),
        ],
    )
    connection.commit()


def populated_connection() -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    create_schema(connection)
    populate(connection)
    return connection


class DailySocRollupArchitectureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.rollup = load_rollup_module()

    def render(self, *, include_tests: bool, limit: int = 20) -> str:
        connection = populated_connection()
        try:
            return self.rollup.build_rollup(
                connection,
                since=SINCE,
                generated_at=GENERATED,
                report_date=REPORT_DATE,
                hours=24,
                limit=limit,
                include_tests=include_tests,
            )
        finally:
            connection.close()

    def test_build_rollup_signature_and_exact_filtered_markdown(self) -> None:
        self.assertEqual(
            str(inspect.signature(self.rollup.build_rollup)),
            "(conn: 'sqlite3.Connection', *, since: 'str', generated_at: "
            "'str', report_date: 'str', hours: 'int', limit: 'int', "
            "include_tests: 'bool') -> 'str'",
        )
        rendered = self.render(include_tests=False, limit=2)
        self.assertEqual(
            hashlib.sha256(rendered.encode("utf-8")).hexdigest(),
            "4a93c7afef97cee83180e05001b78f5151bef39c13ebf2fab75e5a04e6f40bde",
        )
        self.assertIn("- 3 raw alert rows were recorded", rendered)
        self.assertIn("Rule \\| escaped line", rendered)
        self.assertIn("threshold \\| retained", rendered)
        self.assertIn("accepted-urgent-id...", rendered)
        self.assertIn("10.0.0.3 | 10.0.0.4", rendered)
        self.assertNotIn("10.0.0.1 | 10.0.0.2 | 1 | 4 | 88", rendered)
        self.assertNotIn("Validation alert", rendered)
        self.assertNotIn("telegram-test", rendered)
        self.assertTrue(rendered.endswith("\n"))

    def test_include_tests_exactly_changes_alert_and_notification_scope(self) -> None:
        rendered = self.render(include_tests=True, limit=20)
        self.assertEqual(
            hashlib.sha256(rendered.encode("utf-8")).hexdigest(),
            "d513bd2009415d5fddb455b9e760c40abb7b131fa325496889672fa24b5ac069",
        )
        self.assertIn("- 4 raw alert rows were recorded", rendered)
        self.assertIn("Validation alert", rendered)
        self.assertIn("telegram-test", rendered)
        self.assertIn("Include test alerts: yes", rendered)

    def test_empty_database_exact_markdown_and_all_empty_tables(self) -> None:
        connection = sqlite3.connect(":memory:")
        connection.row_factory = sqlite3.Row
        create_schema(connection)
        try:
            rendered = self.rollup.build_rollup(
                connection,
                since=SINCE,
                generated_at=GENERATED,
                report_date=REPORT_DATE,
                hours=24,
                limit=3,
                include_tests=False,
            )
        finally:
            connection.close()
        self.assertEqual(
            hashlib.sha256(rendered.encode("utf-8")).hexdigest(),
            "ad55d5bd7523848cec282aacd8e34c0e77e365966707e45a8a12786087cb41bd",
        )
        self.assertEqual(rendered.count("_No rows._"), 6)
        self.assertIn("| 0 | 0 | 0 | 0 | 0 | 0 | none | none |", rendered)

    def test_main_opens_sqlite_read_only_and_preserves_database_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = root / "alerts.sqlite3"
            output = root / "rollups"
            connection = sqlite3.connect(database)
            create_schema(connection)
            populate(connection)
            connection.close()
            before = hashlib.sha256(database.read_bytes()).hexdigest()
            arguments = SimpleNamespace(
                db=database,
                out_dir=output,
                hours=24,
                date=REPORT_DATE,
                limit=2,
                include_tests=False,
            )
            real_connect = sqlite3.connect
            observed: list[tuple[str, dict]] = []

            def tracked_connect(target, *args, **kwargs):
                observed.append((str(target), dict(kwargs)))
                return real_connect(target, *args, **kwargs)

            stdout = io.StringIO()
            with mock.patch.object(
                self.rollup, "parse_args", return_value=arguments
            ), mock.patch.object(
                self.rollup, "project_now", return_value=FIXED_NOW
            ), mock.patch.object(
                self.rollup.sqlite3, "connect", side_effect=tracked_connect
            ), contextlib.redirect_stdout(stdout):
                self.assertEqual(self.rollup.main(), 0)

            expected = output / f"{REPORT_DATE}-soc-daily-rollup.md"
            self.assertEqual(observed, [(f"file:{database}?mode=ro", {"uri": True})])
            self.assertEqual(stdout.getvalue(), f"{expected}\n")
            self.assertEqual(
                hashlib.sha256(expected.read_bytes()).hexdigest(),
                "f5d35ab5c97b281ea294aa0c6e701ce25b793884083f83776192e38ccdf3d0a0",
            )
            self.assertEqual(hashlib.sha256(database.read_bytes()).hexdigest(), before)

    def test_module_budgets_direction_and_installer_contract(self) -> None:
        baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
        self.assertNotIn(
            "n8n/bin/write-daily-soc-rollup.py::build_rollup",
            baseline["functions"],
        )
        data_owner = ROOT / "n8n/bin/daily_soc_rollup_data.py"
        markdown_owner = ROOT / "n8n/bin/daily_soc_rollup_markdown.py"
        self.assertLessEqual(len(SCRIPT.read_text().splitlines()), 250)
        self.assertLessEqual(len(data_owner.read_text().splitlines()), 600)
        self.assertLessEqual(len(markdown_owner.read_text().splitlines()), 600)
        self.assertNotIn("write_daily_soc_rollup", data_owner.read_text())
        self.assertNotIn("write_daily_soc_rollup", markdown_owner.read_text())
        self.assertNotIn("daily_soc_rollup_data", markdown_owner.read_text())
        installer = (ROOT / "n8n/bin/install-macstudio-stack.zsh").read_text(
            encoding="utf-8"
        )
        for filename in (
            "write-daily-soc-rollup.py",
            "daily_soc_rollup_data.py",
            "daily_soc_rollup_markdown.py",
        ):
            self.assertIn(f'{filename}" "$STACK_DIR/bin/', installer)


if __name__ == "__main__":
    unittest.main()
