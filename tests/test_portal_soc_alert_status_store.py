from __future__ import annotations

import sqlite3
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "onion-sentinel-dashboard"
sys.path.insert(0, str(DASHBOARD))

from portal_soc_alert_status_store import (  # noqa: E402
    SocAlertStatusStoreSources,
    ensure_soc_alert_status_schema,
    load_soc_group_statuses,
    normalize_soc_alert_status_meta,
    write_soc_group_status,
    write_soc_group_statuses,
)


class SocAlertStatusStoreTest(unittest.TestCase):
    def setUp(self) -> None:
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.counts = {}
        self.sources = SocAlertStatusStoreSources(
            table_exists=lambda conn, table: conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                (table,),
            ).fetchone() is not None,
            group_counts=lambda conn: dict(self.counts),
            now_iso=lambda: "2026-08-07T12:00:00Z",
        )

    def tearDown(self) -> None:
        self.conn.close()

    def test_status_metadata_is_validated_and_bounded(self) -> None:
        self.assertIsNone(
            normalize_soc_alert_status_meta("bad", now_iso=self.sources.now_iso)
        )
        self.assertIsNone(normalize_soc_alert_status_meta(
            {"status": "deleted"}, now_iso=self.sources.now_iso
        ))
        result = normalize_soc_alert_status_meta(
            {
                "status": " ACKNOWLEDGED ",
                "acknowledged_count": "bad",
                "reason": "r" * 200,
            },
            now_iso=self.sources.now_iso,
        )
        self.assertEqual(result["status"], "acknowledged")
        self.assertEqual(result["repeat_count"], 0)
        self.assertEqual(len(result["reason"]), 140)
        self.assertEqual(result["updated_at"], "2026-08-07T12:00:00Z")

    def test_schema_creation_and_legacy_adjudication_migration(self) -> None:
        self.conn.execute(
            """
            CREATE TABLE analyst_adjudications (
              adjudication_id TEXT PRIMARY KEY,
              dashboard_group_id TEXT NOT NULL,
              stable_group_id TEXT NOT NULL,
              case_id TEXT, analysis_id TEXT NOT NULL,
              outcome_override TEXT NOT NULL, confidence TEXT NOT NULL,
              rationale TEXT NOT NULL, evidence_gap TEXT, next_action TEXT,
              reviewer TEXT NOT NULL, case_resolution_reason TEXT,
              created_at TEXT NOT NULL
            )
            """
        )
        ensure_soc_alert_status_schema(self.conn)
        tables = {
            row["name"] for row in self.conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        self.assertIn("analyst_alert_status", tables)
        self.assertIn("analyst_alert_group_state", tables)
        columns = {
            row["name"] for row in self.conn.execute(
                "PRAGMA table_info(analyst_adjudications)"
            )
        }
        self.assertTrue({
            "event_status", "detection_validity", "activity_disposition",
            "handling", "duplicate_of",
        }.issubset(columns))

    def test_acknowledgement_reopens_on_new_repeat_but_suppression_persists(self) -> None:
        ensure_soc_alert_status_schema(self.conn)
        write_soc_group_statuses(self.sources, self.conn, {
            "ack": {"status": "acknowledged", "repeat_count": 3},
            "suppress": {"status": "suppressed", "repeat_count": 3},
        })
        self.counts = {"ack": 4, "suppress": 4}
        statuses = load_soc_group_statuses(self.sources, self.conn)
        self.assertNotIn("ack", statuses)
        self.assertEqual(statuses["suppress"]["status"], "suppressed")

    def test_write_upserts_identity_and_open_deletes(self) -> None:
        ensure_soc_alert_status_schema(self.conn)
        write_soc_group_status(self.sources, self.conn, "group-1", {
            "status": "acknowledged", "repeat_count": 2,
            "group_key": "stable-key", "updated_by": "x" * 100,
        })
        row = self.conn.execute(
            "SELECT * FROM analyst_alert_group_state WHERE group_id='group-1'"
        ).fetchone()
        self.assertEqual(row["group_key"], "stable-key")
        self.assertEqual(len(row["updated_by"]), 80)
        write_soc_group_status(
            self.sources, self.conn, "group-1", {"status": "open"}
        )
        self.assertIsNone(self.conn.execute(
            "SELECT * FROM analyst_alert_group_state WHERE group_id='group-1'"
        ).fetchone())

    def test_bulk_write_merges_without_removing_existing_groups(self) -> None:
        ensure_soc_alert_status_schema(self.conn)
        write_soc_group_status(
            self.sources, self.conn, "existing",
            {"status": "acknowledged", "repeat_count": 1},
        )
        write_soc_group_statuses(self.sources, self.conn, {
            "new": {"status": "suppressed", "reason": "reviewed"}
        })
        statuses = load_soc_group_statuses(self.sources, self.conn)
        self.assertEqual(set(statuses), {"existing", "new"})

    def test_missing_group_table_reads_empty(self) -> None:
        self.assertEqual(load_soc_group_statuses(self.sources, self.conn), {})


if __name__ == "__main__":
    unittest.main()
