"""Direct contracts for SOC metrics and status read models."""
from __future__ import annotations

import sqlite3
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_soc_metrics import (  # noqa: E402
    SocMetricsQueryPlan,
    compose_metrics_payload,
    compose_status_payload,
    exclude_group_rows,
    metrics_query_plan,
)


class TruthySince:
    def __init__(self) -> None:
        self.bool_calls = 0

    def __bool__(self) -> bool:
        self.bool_calls += 1
        return True


class FormattingGroupExpression:
    def __init__(self, value: str, *, fail: bool = False) -> None:
        self.value = value
        self.fail = fail
        self.format_calls = 0

    def __format__(self, spec: str) -> str:
        self.format_calls += 1
        if self.fail:
            raise AssertionError("summary plan must not format the group expression")
        self.last_spec = spec
        return self.value


class SocMetricsTests(unittest.TestCase):
    def test_query_plan_uses_parameters_and_selects_summary_repository(self) -> None:
        dangerous = "2026-08-07' OR 1=1 --"
        plan = metrics_query_plan(dangerous, "group-expression", True)

        self.assertEqual(plan.source, "sqlite-summary")
        self.assertEqual(plan.args, (dangerous,))
        self.assertNotIn(dangerous, plan.grouped_sql)
        self.assertIn("FROM alert_group_summary", plan.grouped_sql)
        self.assertIn("last_seen >= ?", plan.grouped_sql)

    def test_fallback_plan_groups_raw_alerts_with_original_volume_semantics(self) -> None:
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.execute(
            "CREATE TABLE alerts (group_key TEXT, seen_count INTEGER, last_seen TEXT, "
            "filter_status TEXT, triage_level TEXT, severity_label TEXT, rule_name TEXT)"
        )
        conn.executemany(
            "INSERT INTO alerts VALUES (?, ?, ?, ?, ?, ?, ?)",
            [
                ("g1", 4, "2026-08-07  01:00:00Z", "accepted", "high", "high", "r1"),
                ("g1", 1, "2026-08-07  02:00:00Z", "accepted", "high", "high", "r1"),
            ],
        )
        plan = metrics_query_plan("", "group_key", False)
        rows = conn.execute(plan.grouped_sql, plan.args).fetchall()

        self.assertEqual(plan.source, "sqlite")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["raw_alert_count"], 2)
        self.assertEqual(rows[0]["total_seen_count"], 5)
        conn.close()

    def test_summary_plan_preserves_complete_sql_and_skips_group_formatting(self) -> None:
        group_expr = FormattingGroupExpression("unused", fail=True)

        plan = metrics_query_plan("cutoff", group_expr, True)

        self.assertEqual(plan, SocMetricsQueryPlan(
            source="sqlite-summary",
            args=("cutoff",),
            total_sql="SELECT COUNT(*) FROM alerts WHERE last_seen >= ?",
            latest_sql="SELECT MAX(last_seen) FROM alerts WHERE last_seen >= ?",
            grouped_sql="""
            SELECT group_id, group_key, raw_alert_count, total_seen_count,
                   last_seen, filter_status
            FROM alert_group_summary
             WHERE last_seen >= ?
        """,
            filter_status_sql=(
                "SELECT COALESCE(filter_status, 'accepted'), COUNT(*) "
                "FROM alerts WHERE last_seen >= ? "
                "GROUP BY COALESCE(filter_status, 'accepted')"
            ),
            level_sql=(
                "SELECT COALESCE(triage_level, severity_label, 'unknown'), COUNT(*) "
                "FROM alerts WHERE last_seen >= ? "
                "GROUP BY COALESCE(triage_level, severity_label, 'unknown')"
            ),
            top_rules_sql=(
                "SELECT COALESCE(rule_name, 'unknown'), COUNT(*) AS rule_count "
                "FROM alerts WHERE last_seen >= ? "
                "GROUP BY COALESCE(rule_name, 'unknown') "
                "ORDER BY rule_count DESC LIMIT 10"
            ),
            suppression_sql=(
                "SELECT COUNT(*), COALESCE(SUM(suppressed_count), 0), "
                "COALESCE(SUM(escalated_count), 0) FROM suppression_log"
            ),
        ))
        self.assertEqual(group_expr.format_calls, 0)

    def test_legacy_plan_preserves_truthiness_timing_and_group_formatting(self) -> None:
        since = TruthySince()
        group_expr = FormattingGroupExpression("group-expression")

        plan = metrics_query_plan(since, group_expr, False)

        self.assertEqual(since.bool_calls, 2)
        self.assertEqual(group_expr.format_calls, 1)
        self.assertEqual(group_expr.last_spec, "")
        self.assertIs(plan.args[0], since)
        self.assertIn("SELECT group-expression AS group_key", plan.grouped_sql)
        self.assertIn(" WHERE last_seen >= ?", plan.grouped_sql)

    def test_exclusion_and_payload_preserve_grouped_public_schema(self) -> None:
        rows = [
            {"group_id": "visible", "raw_alert_count": 2, "total_seen_count": 5},
            {"group_id": "escalated", "raw_alert_count": 1, "total_seen_count": 1},
        ]
        visible = exclude_group_rows(rows, {"escalated"}, lambda row: row["group_id"])
        payload = compose_metrics_payload(
            source="sqlite-summary",
            since="",
            total=3,
            latest_seen="now",
            grouped_rows=visible,
            pcap_ingest_size_bytes=12,
            by_filter_status={"accepted": 3},
            by_analyst_status={"open": 1},
            by_level={"high": 3},
            top_rules=[{"rule_name": "r1", "count": 3}],
            suppression_totals=(2, 4, 1),
        )

        self.assertEqual(payload["grouped_total"], 1)
        self.assertEqual(payload["grouped_observations"], 5)
        self.assertIsNone(payload["since"])
        self.assertEqual(payload["suppression_log"]["escalated_count"], 1)

    def test_status_payload_excludes_escalations_and_has_safe_fallback(self) -> None:
        statuses = {
            "ack": {"status": "acknowledged"},
            "supp": {"status": "suppressed"},
            "escalated": {"status": "acknowledged"},
        }
        payload = compose_status_payload(
            statuses,
            group_counts={"open": 1, "ack": 1, "supp": 1, "escalated": 1},
            escalated_group_ids={"escalated"},
            active_group_ids={"open"},
        )
        fallback = compose_status_payload(statuses)

        self.assertEqual(payload["acknowledged"], ["ack"])
        self.assertEqual(payload["counts"]["escalated"], 1)
        self.assertEqual(payload["counts"]["total"], 3)
        self.assertEqual(fallback["counts"]["total"], len(statuses))
        self.assertNotIn("escalated", fallback["counts"])


if __name__ == "__main__":
    unittest.main()
