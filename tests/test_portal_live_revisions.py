"""Direct contracts for bounded portal live-revision state."""
from __future__ import annotations

import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


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
import portal_live_revisions as live_revisions  # noqa: E402


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

    def test_incident_state_empty_projection_has_exact_required_keys(self) -> None:
        state = incident_response_revision_state(self.conn, SCHEMA)

        self.assertEqual(list(state), [
            "cases",
            "groups",
            "alerts",
            "analyses",
            "reviews",
            "adjudications",
            "reanalysis_runs",
        ])
        self.assertEqual(state, {
            "cases": [],
            "groups": [],
            "alerts": [],
            "analyses": [],
            "reviews": [],
            "adjudications": [],
            "reanalysis_runs": [],
        })

    def test_incident_state_preserves_query_contract_order_values_and_identities(self) -> None:
        cases = [
            {
                "case_id": "c1",
                "dashboard_group_id": "g1",
                "representative_alert_id": "a1",
                "latest_analysis_id": "x1",
            },
            {
                "case_id": "",
                "dashboard_group_id": None,
                "representative_alert_id": 0,
                "latest_analysis_id": False,
            },
            {
                "case_id": "c2",
                "dashboard_group_id": "g1",
                "representative_alert_id": 7,
                "latest_analysis_id": None,
            },
        ]
        latest_runs = [{"run_id": 0}]
        calls = []
        related_results = {}

        def fake_revision_rows(conn, table, columns, schema, **kwargs):
            calls.append(("revision_rows", conn, table, columns, schema, kwargs))
            if table == "incident_response_cases":
                return cases
            if table == "incident_reanalysis_runs":
                return latest_runs
            raise AssertionError(f"unexpected direct table: {table}")

        def fake_related_rows(conn, schema, table, columns, key, values):
            calls.append((
                "related_rows", conn, table, columns, schema, key, values,
            ))
            result = [{"table": table}]
            related_results[table] = result
            return result

        with patch.object(live_revisions, "revision_rows", fake_revision_rows), patch.object(
            live_revisions, "_related_rows", fake_related_rows
        ):
            state = incident_response_revision_state(self.conn, SCHEMA)

        self.assertEqual(
            [(call[0], call[2]) for call in calls],
            [
                ("revision_rows", "incident_response_cases"),
                ("related_rows", "alert_group_summary"),
                ("related_rows", "alerts"),
                ("related_rows", "ai_analysis_runs"),
                ("related_rows", "ai_second_opinion_runs"),
                ("related_rows", "analyst_adjudications"),
                ("revision_rows", "incident_reanalysis_runs"),
                ("related_rows", "incident_reanalysis_run_cases"),
            ],
        )
        self.assertEqual(
            [(call[5], call[6]) for call in calls if call[0] == "related_rows"],
            [
                ("group_id", ("g1", "g1")),
                ("alert_id", ("a1", "7")),
                ("analysis_id", ("x1",)),
                ("analysis_id", ("x1",)),
                ("case_id", ("c1", "c2")),
                ("run_id", ("",)),
            ],
        )
        self.assertEqual(calls[0][5], {"order_sql": "case_id"})
        self.assertEqual(
            calls[6][5],
            {"order_sql": "created_at DESC", "limit": 1},
        )
        self.assertEqual(list(state), [
            "cases", "groups", "alerts", "analyses", "reviews",
            "adjudications", "reanalysis_runs", "reanalysis_cases",
        ])
        self.assertIs(state["cases"], cases)
        self.assertIs(state["reanalysis_runs"], latest_runs)
        self.assertIs(state["groups"], related_results["alert_group_summary"])
        self.assertIs(
            state["reanalysis_cases"],
            related_results["incident_reanalysis_run_cases"],
        )


if __name__ == "__main__":
    unittest.main()
