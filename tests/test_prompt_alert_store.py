#!/usr/bin/env python3
"""Direct contracts for prompt-builder alert-store helpers."""
from __future__ import annotations

from pathlib import Path
import sqlite3
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))

from prompt_alert_store import (  # noqa: E402
    build_test_alert_filter,
    derive_alert_group_key,
    query_row,
    query_rows,
    read_table_columns,
    sqlite_row_value,
    stable_alert_group_id,
)


class PromptAlertStoreTests(unittest.TestCase):
    def setUp(self):
        self.connection = sqlite3.connect(":memory:")
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            "CREATE TABLE alerts (alert_id TEXT PRIMARY KEY, triage_level TEXT)"
        )
        self.connection.executemany(
            "INSERT INTO alerts VALUES (?, ?)",
            [("alert-1", "high"), ("alert-2", "medium")],
        )

    def tearDown(self):
        self.connection.close()

    def test_query_helpers_parameterize_and_preserve_row_shape(self):
        selected = query_row(
            self.connection,
            "SELECT * FROM alerts WHERE alert_id = ?",
            ["alert-1"],
        )
        found = query_rows(
            self.connection,
            "SELECT * FROM alerts WHERE triage_level IN (?, ?)",
            ["high", "medium"],
        )

        self.assertIsInstance(selected, sqlite3.Row)
        self.assertEqual(selected["triage_level"], "high")
        self.assertEqual([item["alert_id"] for item in found], ["alert-1", "alert-2"])

    def test_test_alert_filter_preserves_order_and_column_prefix(self):
        sql, params = build_test_alert_filter(
            ("phase%", "config-%"),
            "a.alert_id",
        )

        self.assertEqual(
            sql,
            "a.alert_id NOT LIKE ? AND a.alert_id NOT LIKE ?",
        )
        self.assertEqual(params, ["phase%", "config-%"])

    def test_row_value_and_group_key_support_legacy_schemas(self):
        self.assertEqual(sqlite_row_value({"known": 1}, "known"), 1)
        self.assertEqual(sqlite_row_value({"known": 1}, "missing", "fallback"), "fallback")
        self.assertEqual(
            derive_alert_group_key({"suppression_key": " stable-key "}),
            "stable-key",
        )
        self.assertEqual(
            derive_alert_group_key(
                {
                    "triage_level": "critical",
                    "rule_name": "Fixture rule",
                    "source_ip": "192.0.2.10",
                    "destination_ip": "198.51.100.20",
                    "filter_status": "escalated",
                }
            ),
            "critical|Fixture rule|192.0.2.10|198.51.100.20|escalated",
        )
        self.assertEqual(
            derive_alert_group_key({}),
            "unscored|unknown-rule|unknown-source|unknown-destination|accepted",
        )

    def test_group_id_is_stable_and_bounded(self):
        group_id = stable_alert_group_id("fixture-key")

        self.assertEqual(group_id, stable_alert_group_id("fixture-key"))
        self.assertEqual(group_id, "fff79e5d3d6c")
        self.assertEqual(len(group_id), 12)

    def test_table_columns_returns_schema_and_missing_table_is_empty(self):
        self.assertEqual(
            read_table_columns(self.connection, "alerts"),
            {"alert_id", "triage_level"},
        )
        self.assertEqual(read_table_columns(self.connection, "missing"), set())


if __name__ == "__main__":
    unittest.main()
