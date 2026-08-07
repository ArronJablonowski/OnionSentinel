"""Direct contracts for SOC metrics and status read models."""
from __future__ import annotations

import sqlite3
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_soc_metrics import (  # noqa: E402
    compose_metrics_payload,
    compose_status_payload,
    exclude_group_rows,
    metrics_query_plan,
)


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
