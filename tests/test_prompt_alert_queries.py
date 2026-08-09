#!/usr/bin/env python3
"""Direct contracts for prompt alert selection and related history."""
from __future__ import annotations

import datetime as dt
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))

from prompt_alert_queries import (  # noqa: E402
    AlertQuerySources,
    AlertSelectionRequest,
    related_alert_context,
    select_prompt_alert,
)


NOW = dt.datetime(
    2026,
    8,
    8,
    12,
    tzinfo=dt.timezone(dt.timedelta(hours=-6)),
)


def sources(query_row=None, query_rows=None, test_filter=None) -> AlertQuerySources:
    return AlertQuerySources(
        query_row=query_row or mock.Mock(return_value=None),
        query_rows=query_rows or mock.Mock(return_value=[]),
        test_filter_sql=test_filter
        or mock.Mock(return_value=("alert_id NOT LIKE ?", ["test-%"])),
        row_value=lambda row, key: row.get(key),
        now_local=lambda: NOW,
    )


def request(**changes) -> AlertSelectionRequest:
    values = {
        "connection": "connection",
        "alert_id": "",
        "levels_csv": "critical, high",
        "hours": 6,
        "include_tests": False,
    }
    values.update(changes)
    return AlertSelectionRequest(**values)


class PromptAlertQueryTests(unittest.TestCase):
    def test_explicit_alert_id_bypasses_priority_selection(self):
        selected = {"alert_id": "alert-1"}
        query = mock.Mock(return_value=selected)

        result = select_prompt_alert(
            sources(query_row=query),
            request(alert_id="alert-1", levels_csv=""),
        )

        self.assertIs(result, selected)
        query.assert_called_once_with(
            "connection",
            "SELECT * FROM alerts WHERE alert_id = ?",
            ["alert-1"],
        )

    def test_missing_explicit_alert_has_stable_failure_message(self):
        with self.assertRaisesRegex(SystemExit, "alert_id not found: missing"):
            select_prompt_alert(sources(), request(alert_id="missing"))

    def test_priority_selection_normalizes_levels_time_and_test_filter(self):
        selected = {"alert_id": "priority"}
        query = mock.Mock(return_value=selected)
        test_filter = mock.Mock(
            return_value=("alert_id NOT LIKE ? AND alert_id NOT LIKE ?", ["one-%", "two-%"])
        )

        result = select_prompt_alert(
            sources(query_row=query, test_filter=test_filter),
            request(levels_csv=" Critical, HIGH, "),
        )

        self.assertIs(result, selected)
        sql = query.call_args.args[1]
        self.assertIn("triage_level IN (?, ?)", sql)
        self.assertIn("alert_id NOT LIKE ?", sql)
        self.assertIn("CASE triage_level WHEN 'critical' THEN 1", sql)
        self.assertEqual(
            query.call_args.args[2],
            ["2026-08-08  06:00:00-06:00", "critical", "high", "one-%", "two-%"],
        )
        test_filter.assert_called_once_with("alert_id")

    def test_include_tests_omits_filter_and_empty_selection_fails(self):
        query = mock.Mock(return_value=None)
        test_filter = mock.Mock(side_effect=AssertionError("must not filter"))

        with self.assertRaisesRegex(SystemExit, "no matching alert found"):
            select_prompt_alert(
                sources(query_row=query, test_filter=test_filter),
                request(include_tests=True),
            )

        self.assertNotIn("NOT LIKE", query.call_args.args[1])
        test_filter.assert_not_called()

    def test_empty_levels_fails_before_query(self):
        query = mock.Mock(side_effect=AssertionError("must not query"))

        with self.assertRaisesRegex(SystemExit, "--levels must contain"):
            select_prompt_alert(
                sources(query_row=query),
                request(levels_csv=" , "),
            )

        query.assert_not_called()

    def test_related_history_is_bounded_and_uses_rule_and_endpoint_pivots(self):
        selected = {
            "alert_id": "alert-1",
            "rule_name": "Fixture rule",
            "source_ip": "192.0.2.10",
            "destination_ip": "198.51.100.20",
        }
        rows = mock.Mock(return_value=[{"alert_id": "related-1"}])

        result = related_alert_context(
            sources(query_rows=rows),
            "connection",
            selected,
            7,
            False,
        )

        self.assertEqual(result, [{"alert_id": "related-1"}])
        sql = rows.call_args.args[1]
        self.assertIn("rule_name = ?", sql)
        self.assertIn("OR source_ip = ?", sql)
        self.assertIn("ORDER BY last_seen DESC", sql)
        self.assertEqual(
            rows.call_args.args[2],
            [
                "alert-1",
                "Fixture rule",
                "192.0.2.10",
                "198.51.100.20",
                "192.0.2.10",
                "198.51.100.20",
                "test-%",
                7,
            ],
        )


if __name__ == "__main__":
    unittest.main()
