"""Direct contracts for grouped SOC enrichment query and merge policy."""
from __future__ import annotations

import sqlite3
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_soc_group_enrichment import (  # noqa: E402
    group_enrichment_query_plan,
    merge_page_enrichment,
    normalized_group_keys,
    page_group_keys,
    project_group_enrichment_rows,
)


class SocGroupEnrichmentTests(unittest.TestCase):
    def test_keys_are_trimmed_deduplicated_and_parameterized(self) -> None:
        dangerous = "group-a') OR 1=1 --"
        keys = normalized_group_keys([" group-b ", dangerous, "group-b", "", None])
        plan = group_enrichment_query_plan(keys, "group_key")

        self.assertEqual(keys, ["group-b", dangerous])
        self.assertEqual(plan.args, keys)
        self.assertNotIn(dangerous, plan.sql)
        self.assertIn("group_key IN (?,?)", plan.sql)
        self.assertEqual(group_enrichment_query_plan([], "group_key").sql, "")

    def test_sql_plan_prefers_records_then_errors_then_skips_before_newness(self) -> None:
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.execute(
            "CREATE TABLE alerts (group_key TEXT, enrichment_json TEXT, "
            "last_seen TEXT, timestamp TEXT, first_seen TEXT, alert_id TEXT)"
        )
        conn.executemany(
            "INSERT INTO alerts VALUES (?, ?, ?, ?, ?, ?)",
            [
                ("g1", '{"external_intel":{"errors":[{}]}}', "30", "30", "30", "new-error"),
                ("g1", '{"external_intel":{"records":[{}]}}', "10", "10", "10", "old-record"),
                ("g2", '{"external_intel":{"skipped":[{}]}}', "20", "20", "20", "skip"),
            ],
        )
        plan = group_enrichment_query_plan(["g1", "g2"], "group_key")

        projected = project_group_enrichment_rows(
            conn.execute(plan.sql, plan.args).fetchall()
        )

        self.assertIn('"records"', projected["g1"])
        self.assertIn('"skipped"', projected["g2"])
        conn.close()

    def test_projection_skips_blank_groups_and_last_duplicate_wins(self) -> None:
        projected = project_group_enrichment_rows([
            {"resolved_group_key": "", "enrichment_json": "ignored"},
            {"resolved_group_key": "g1", "enrichment_json": "old"},
            {"resolved_group_key": "g1", "enrichment_json": "new"},
        ])

        self.assertEqual(projected, {"g1": "new"})

    def test_page_merge_preserves_embedded_enrichment_and_fills_missing_rows(self) -> None:
        rows = [
            {"group_key": "g1", "enrichment_json": "embedded", "alert_id": "a1"},
            {"group_key": "g2", "enrichment_json": "", "alert_id": "a2"},
            {"alert_id": "a3"},
        ]

        self.assertEqual(page_group_keys(rows), ["g1", "g2"])
        merged = merge_page_enrichment(rows, {"g1": "repository-ignored", "g2": "loaded"})

        self.assertEqual(merged[0]["enrichment_json"], "embedded")
        self.assertEqual(merged[1]["enrichment_json"], "loaded")
        self.assertEqual(merged[2]["enrichment_json"], "")
        self.assertIsNot(merged[0], rows[0])


if __name__ == "__main__":
    unittest.main()
