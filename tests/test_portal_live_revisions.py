"""Direct contracts for bounded portal live-revision state."""
from __future__ import annotations

import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_live_revisions import (  # noqa: E402
    RevisionSchemaDependencies,
    bounded_file_revision,
    incident_response_revision,
    incident_response_revision_state,
    revision_digest,
    revision_rows,
)


def table_exists(conn: sqlite3.Connection, table: str) -> bool:
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)
    ).fetchone() is not None


def table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {str(row[1]) for row in conn.execute(f"PRAGMA table_info({table})")}


SCHEMA = RevisionSchemaDependencies(table_exists, table_columns)


class PortalLiveRevisionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row

    def tearDown(self) -> None:
        self.conn.close()

    def test_digest_is_deterministic_and_file_revision_is_content_opaque(self) -> None:
        self.assertEqual(revision_digest({"b": 2, "a": 1}), revision_digest({"a": 1, "b": 2}))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            missing = bounded_file_revision(path, 10)
            path.write_text("secret", encoding="utf-8")
            present = bounded_file_revision(path, 10)
            oversized = bounded_file_revision(path, 2)

        self.assertNotEqual(missing, present)
        self.assertNotEqual(present, oversized)
        self.assertNotIn("secret", present)

    def test_revision_rows_tolerates_missing_tables_and_columns(self) -> None:
        self.conn.execute("CREATE TABLE sample (id TEXT, state TEXT)")
        self.conn.execute("INSERT INTO sample VALUES ('one', 'open')")

        rows = revision_rows(
            self.conn, "sample", ("id", "missing"), SCHEMA, order_sql="id"
        )

        self.assertEqual(rows, [{"id": "one"}])
        self.assertEqual(revision_rows(self.conn, "absent", ("id",), SCHEMA), [])

    def test_incident_state_tracks_linked_records_and_latest_reanalysis(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE incident_response_cases (
              case_id TEXT, dashboard_group_id TEXT, representative_alert_id TEXT,
              latest_analysis_id TEXT, status TEXT
            );
            CREATE TABLE alert_group_summary (group_id TEXT, rule_name TEXT);
            CREATE TABLE alerts (alert_id TEXT, rule_name TEXT);
            CREATE TABLE ai_analysis_runs (analysis_id TEXT, model TEXT);
            CREATE TABLE ai_second_opinion_runs (analysis_id TEXT, status TEXT);
            CREATE TABLE analyst_adjudications (case_id TEXT, outcome_override TEXT);
            CREATE TABLE incident_reanalysis_runs (
              run_id TEXT, status TEXT, created_at TEXT
            );
            CREATE TABLE incident_reanalysis_run_cases (
              run_id TEXT, case_id TEXT, status TEXT
            );
            INSERT INTO incident_response_cases VALUES ('c1', 'g1', 'a1', 'x1', 'open');
            INSERT INTO alert_group_summary VALUES ('g1', 'rule');
            INSERT INTO alerts VALUES ('a1', 'rule');
            INSERT INTO ai_analysis_runs VALUES ('x1', 'gpt');
            INSERT INTO ai_second_opinion_runs VALUES ('x1', 'complete');
            INSERT INTO analyst_adjudications VALUES ('c1', 'confirmed');
            INSERT INTO incident_reanalysis_runs VALUES ('old', 'complete', '1');
            INSERT INTO incident_reanalysis_runs VALUES ('new', 'running', '2');
            INSERT INTO incident_reanalysis_run_cases VALUES ('new', 'c1', 'running');
            """
        )
        state = incident_response_revision_state(self.conn, SCHEMA)
        initial = incident_response_revision(self.conn, SCHEMA)
        self.conn.execute("UPDATE ai_analysis_runs SET model = 'gpt-new'")
        changed = incident_response_revision(self.conn, SCHEMA)

        self.assertEqual(state["groups"][0]["group_id"], "g1")
        self.assertEqual(state["reanalysis_runs"][0]["run_id"], "new")
        self.assertEqual(state["reanalysis_cases"][0]["case_id"], "c1")
        self.assertNotEqual(initial, changed)


if __name__ == "__main__":
    unittest.main()
