"""Behavior contracts for schema-adaptive read-only LLM history queries."""
from __future__ import annotations

from contextlib import contextmanager
import sqlite3
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_llm_history_store import (  # noqa: E402
    LlmHistoryStoreSources,
    read_adjudication_history_rows,
    read_primary_history_rows,
    read_second_opinion_history_rows,
)


class LlmHistoryStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.database = Path(self.temp.name) / "history.sqlite3"
        self.connection = sqlite3.connect(self.database)
        self.connection.row_factory = sqlite3.Row

    def tearDown(self) -> None:
        self.connection.close()
        self.temp.cleanup()

    def sources(self, maximum: int = 5) -> LlmHistoryStoreSources:
        @contextmanager
        def connect():
            yield self.connection

        return LlmHistoryStoreSources(connect=connect, history_limit=maximum)

    def test_missing_tables_and_connect_failures_return_empty_results(self) -> None:
        sources = self.sources()
        self.assertEqual(read_primary_history_rows(sources, limit=5), [])
        self.assertEqual(read_second_opinion_history_rows(sources, limit=5), [])
        self.assertEqual(read_adjudication_history_rows(sources, limit=5), [])

        @contextmanager
        def missing():
            raise FileNotFoundError("database unavailable")
            yield

        failed = LlmHistoryStoreSources(missing, 5)
        self.assertEqual(read_primary_history_rows(failed, limit=5), [])

    def test_primary_minimal_schema_supplies_legacy_defaults(self) -> None:
        self.connection.execute(
            "CREATE TABLE ai_analysis_runs (analysis_id TEXT, alert_id TEXT, generated_at TEXT)"
        )
        self.connection.execute(
            "INSERT INTO ai_analysis_runs VALUES ('run-1', 'alert-1', '2026-08-07T01:00:00Z')"
        )
        self.connection.commit()

        rows = read_primary_history_rows(self.sources(), limit="bad")

        self.assertEqual(rows[0]["agent_role"], "soc-analyst")
        self.assertIsNone(rows[0]["model"])
        self.assertIsNone(rows[0]["rule_name"])
        self.assertEqual(rows[0]["seen_count"], 1)

    def test_primary_full_schema_joins_alerts_orders_and_bounds_limit(self) -> None:
        self.connection.executescript(
            """
            CREATE TABLE ai_analysis_runs (
              analysis_id TEXT, alert_id TEXT, generated_at TEXT,
              agent_role TEXT, model TEXT, model_path TEXT
            );
            CREATE TABLE alerts (
              alert_id TEXT, rule_name TEXT, source_ip TEXT,
              destination_ip TEXT, destination_port INTEGER, seen_count INTEGER
            );
            INSERT INTO alerts VALUES ('alert-1', 'Detection', '192.0.2.1', '198.51.100.1', 443, 4);
            INSERT INTO ai_analysis_runs VALUES ('old', 'alert-1', '2026-08-07T01:00:00Z', '', 'old-model', 'ollama');
            INSERT INTO ai_analysis_runs VALUES ('new', 'alert-1', '2026-08-07T02:00:00Z', 'siem-engineer', 'new-model', 'frontier-codex-cli');
            """
        )
        rows = read_primary_history_rows(self.sources(maximum=1), limit=99)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["analysis_id"], "new")
        self.assertEqual(rows[0]["agent_role"], "siem-engineer")
        self.assertEqual(rows[0]["rule_name"], "Detection")
        self.assertEqual(rows[0]["seen_count"], 4)

    def test_primary_rejects_incomplete_required_schema(self) -> None:
        self.connection.execute(
            "CREATE TABLE ai_analysis_runs (analysis_id TEXT, alert_id TEXT)"
        )
        self.assertEqual(read_primary_history_rows(self.sources(), limit=5), [])

    def test_second_opinion_supports_schema_without_reviewer_error(self) -> None:
        self.connection.execute(
            """
            CREATE TABLE ai_second_opinion_runs (
              analysis_id TEXT, alert_id TEXT, agent_role TEXT, trigger TEXT,
              status TEXT, reviewer_model TEXT, reviewer_model_path TEXT,
              reviewer_outcome TEXT, reviewer_confidence TEXT, agreement TEXT,
              material_disagreement INTEGER, reviewer_runtime_seconds REAL,
              generated_at TEXT
            )
            """
        )
        self.connection.execute(
            "INSERT INTO ai_second_opinion_runs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("run-1", "alert-1", "soc-analyst", "trigger", "completed", "model", "ollama", "benign", "high", "agreement", 0, 5.0, "2026-08-07T01:00:00Z"),
        )
        rows = read_second_opinion_history_rows(self.sources(), limit=5)
        self.assertEqual(rows[0]["analysis_id"], "run-1")
        self.assertIsNone(rows[0]["reviewer_error"])
        self.assertIsNone(rows[0]["reviewer_model_route"])

    def test_second_opinion_reads_exact_reviewer_route_when_available(self) -> None:
        self.connection.execute(
            """
            CREATE TABLE ai_second_opinion_runs (
              analysis_id TEXT, alert_id TEXT, agent_role TEXT, trigger TEXT,
              status TEXT, reviewer_error TEXT, reviewer_model TEXT,
              reviewer_model_path TEXT, reviewer_model_route TEXT,
              reviewer_outcome TEXT, reviewer_confidence TEXT, agreement TEXT,
              material_disagreement INTEGER, reviewer_runtime_seconds REAL,
              generated_at TEXT
            )
            """
        )
        self.connection.execute(
            "INSERT INTO ai_second_opinion_runs VALUES "
            "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "run-2", "alert-2", "soc-analyst", "trigger", "completed",
                None, "gpt-5.6-sol", "frontier-codex-cli",
                "codex-cli:gpt-5.6-sol:xhigh", "suspicious", "high",
                "agreement", 0, 5.0, "2026-08-07T01:00:00Z",
            ),
        )

        rows = read_second_opinion_history_rows(self.sources(), limit=5)

        self.assertEqual(
            rows[0]["reviewer_model_route"], "codex-cli:gpt-5.6-sol:xhigh"
        )

    def test_adjudication_query_returns_bounded_newest_rows(self) -> None:
        self.connection.execute(
            """
            CREATE TABLE ai_disagreement_adjudication_runs (
              analysis_id TEXT, alert_id TEXT, agent_role TEXT, status TEXT,
              mode TEXT, adjudicator_error TEXT, model_route TEXT,
              decision TEXT, confidence TEXT, confidence_score REAL,
              adjudicator_runtime_seconds REAL,
              human_adjudication_required INTEGER, generated_at TEXT
            )
            """
        )
        values = ("run-1", "alert-1", "soc-analyst", "completed", "shadow", None, "codex-cli:model:high", "agree", "high", 0.9, 4.0, 0, "2026-08-07T01:00:00Z")
        self.connection.execute(
            "INSERT INTO ai_disagreement_adjudication_runs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            values,
        )
        rows = read_adjudication_history_rows(self.sources(), limit=1)
        self.assertEqual(rows[0]["model_route"], "codex-cli:model:high")
        self.assertEqual(rows[0]["decision"], "agree")


if __name__ == "__main__":
    unittest.main()
