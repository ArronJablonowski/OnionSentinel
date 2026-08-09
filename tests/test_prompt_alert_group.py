#!/usr/bin/env python3
"""Direct contracts for indexed duplicate-alert group projection."""
from __future__ import annotations

from pathlib import Path
import sqlite3
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))

from prompt_alert_group import (  # noqa: E402
    AlertGroupRowsRequest,
    AlertGroupSources,
    BASE_GROUP_COLUMNS,
    build_execution_lineage,
    build_grouped_alert_context,
    fetch_alert_group_rows,
)


def selected(**changes) -> dict:
    value = {
        "alert_id": "alert-1",
        "first_seen": "2026-08-08T10:00:00Z",
        "last_seen": "2026-08-08T12:00:00Z",
        "seen_count": 1,
        "rule_name": "Fixture rule",
        "source_ip": "192.0.2.10",
        "destination_ip": "198.51.100.20",
        "destination_port": 443,
        "triage_level": "high",
        "triage_score": 80,
        "filter_status": "accepted",
        "suppression_key": "suppression-1",
        "stable_group_id": "stable-1",
    }
    value.update(changes)
    return value


def sources(columns=None, query=None, test_filter=None) -> AlertGroupSources:
    def safe_int(value):
        try:
            return int(value or 0)
        except (TypeError, ValueError):
            return 0

    return AlertGroupSources(
        table_columns=mock.Mock(
            return_value=set(BASE_GROUP_COLUMNS) if columns is None else set(columns)
        ),
        row_value=lambda row, key: row.get(key),
        query_rows=query or mock.Mock(return_value=[]),
        test_filter_sql=test_filter
        or mock.Mock(return_value=("alert_id NOT LIKE ?", ["test-%"])),
        safe_int=safe_int,
        alert_group_key=lambda row: f"key:{row['alert_id']}",
        alert_group_id=lambda key: f"digest:{key}",
    )


def request(record, **changes) -> AlertGroupRowsRequest:
    values = {
        "connection": "connection",
        "selected": record,
        "include_tests": False,
        "maximum_group_rows": 5000,
    }
    values.update(changes)
    return AlertGroupRowsRequest(**values)


class PromptAlertGroupTests(unittest.TestCase):
    def test_stable_group_identity_extra_columns_filter_and_limit_are_bounded(self):
        record = selected()
        query = mock.Mock(return_value=[record])
        test_filter = mock.Mock(return_value=("alert_id NOT LIKE ?", ["test-%"]))
        dependencies = sources(
            columns=(*BASE_GROUP_COLUMNS, "enrichment_json"),
            query=query,
            test_filter=test_filter,
        )

        result = fetch_alert_group_rows(
            dependencies,
            request(
                record,
                extra_columns=("enrichment_json", "not_a_column"),
                row_limit=9000,
                maximum_group_rows=5000,
            ),
        )

        self.assertEqual(result, [record])
        sql = query.call_args.args[1]
        self.assertIn("enrichment_json", sql)
        self.assertNotIn("not_a_column", sql)
        self.assertIn("stable_group_id = ?", sql)
        self.assertIn("alert_id NOT LIKE ?", sql)
        self.assertTrue(sql.endswith("LIMIT 5001"))
        self.assertEqual(query.call_args.args[2], ["stable-1", "test-%"])
        test_filter.assert_called_once_with("alert_id")

    def test_suppression_identity_is_used_when_stable_group_is_blank(self):
        record = selected(stable_group_id="")
        query = mock.Mock(return_value=[record])

        fetch_alert_group_rows(sources(query=query), request(record, include_tests=True))

        self.assertIn("suppression_key = ?", query.call_args.args[1])
        self.assertEqual(query.call_args.args[2], ["suppression-1"])
        self.assertNotIn("NOT LIKE", query.call_args.args[1])

    def test_legacy_schema_uses_exact_available_identity_columns(self):
        record = selected(stable_group_id="", suppression_key="")
        columns = {
            "alert_id",
            "last_seen",
            "triage_level",
            "rule_name",
            "source_ip",
            "destination_ip",
            "filter_status",
        }
        query = mock.Mock(return_value=[record])

        fetch_alert_group_rows(
            sources(columns=columns, query=query),
            request(record, include_tests=True),
        )

        sql = query.call_args.args[1]
        for name in (
            "triage_level",
            "rule_name",
            "source_ip",
            "destination_ip",
            "filter_status",
        ):
            self.assertIn(f"COALESCE({name}, '') = ?", sql)
        self.assertEqual(
            query.call_args.args[2],
            ["high", "Fixture rule", "192.0.2.10", "198.51.100.20", "accepted"],
        )

    def test_missing_schema_or_query_failure_returns_selected_row(self):
        record = selected()
        no_query = mock.Mock(side_effect=AssertionError("must not query"))

        missing = fetch_alert_group_rows(
            sources(columns=set(), query=no_query), request(record)
        )
        failed = fetch_alert_group_rows(
            sources(query=mock.Mock(side_effect=sqlite3.OperationalError("offline"))),
            request(record),
        )

        self.assertEqual(missing, [record])
        self.assertEqual(failed, [record])
        no_query.assert_not_called()

    def test_empty_query_result_preserves_selected_row(self):
        record = selected()

        result = fetch_alert_group_rows(
            sources(query=mock.Mock(return_value=[])), request(record)
        )

        self.assertEqual(result, [record])

    def test_group_summary_counts_observations_and_bounds_timeline(self):
        record = selected()
        group = [
            selected(alert_id="new", first_seen="2026-08-08T11:00:00Z", seen_count=0),
            selected(alert_id="middle", last_seen="2026-08-08T11:00:00Z", seen_count="3"),
            selected(
                alert_id="old",
                first_seen="2026-08-08T09:00:00Z",
                last_seen="2026-08-08T10:00:00Z",
                seen_count="invalid",
            ),
        ]
        dependencies = sources(query=mock.Mock(return_value=group))

        context = build_grouped_alert_context(dependencies, request(record), 2)

        self.assertEqual(context["group_key"], "key:alert-1")
        self.assertEqual(context["raw_alert_rows"], 3)
        self.assertEqual(context["total_observations"], 5)
        self.assertEqual(context["first_seen"], "2026-08-08T09:00:00Z")
        self.assertEqual(context["last_seen"], "2026-08-08T12:00:00Z")
        self.assertEqual(
            [item["alert_id"] for item in context["timeline_sample"]],
            ["new", "middle"],
        )
        self.assertEqual(context["timeline_sample"][0]["seen_count"], 1)
        self.assertEqual(context["timeline_sample_limit"], 2)

    def test_execution_lineage_prefers_stable_identity_and_hashes_legacy_group(self):
        dependencies = sources()

        stable = build_execution_lineage(
            dependencies,
            selected(stable_group_id="  ABCDEF123  "),
            blind_reanalysis=True,
        )
        legacy = build_execution_lineage(
            dependencies,
            selected(stable_group_id=""),
            blind_reanalysis=False,
        )

        self.assertEqual(
            stable,
            {"group_id": "abcdef123", "manual_reanalysis": True},
        )
        self.assertEqual(
            legacy,
            {"group_id": "digest:key:alert-1", "manual_reanalysis": False},
        )


if __name__ == "__main__":
    unittest.main()
