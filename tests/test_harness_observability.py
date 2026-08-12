import datetime as dt
import gc
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
import warnings


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "n8n/bin/report-harness-observability.py"
SPEC = importlib.util.spec_from_file_location("harness_observability", SCRIPT)
REPORT = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(REPORT)


class HarnessObservabilityTests(unittest.TestCase):
    def make_database(self, root: Path) -> Path:
        path = root / "harness.sqlite3"
        with sqlite3.connect(path) as connection:
            connection.executescript("""
                CREATE TABLE harness_runs (status TEXT, stage TEXT, started_at TEXT, updated_at TEXT, completed_at TEXT, terminal_reason TEXT);
                CREATE TABLE harness_events (event_type TEXT);
                CREATE TABLE harness_evidence (id TEXT);
                CREATE TABLE harness_hypotheses (id TEXT);
                CREATE TABLE harness_decisions (id TEXT);
                CREATE TABLE harness_model_calls (observed_provider TEXT, observed_model TEXT, observed_harness TEXT, status TEXT, duration_ms INTEGER);
                CREATE TABLE harness_tool_calls (backend TEXT, capability TEXT, status TEXT, truncated INTEGER);
            """)
            connection.execute("INSERT INTO harness_runs VALUES (?,?,?,?,?,?)", (
                "failed", "failed", "2026-08-05T00:00:00+00:00", "2026-08-05T00:01:00+00:00", "2026-08-05T00:01:00+00:00", "provider timeout",
            ))
            connection.execute("INSERT INTO harness_runs VALUES (?,?,?,?,?,?)", (
                "running", "query-execution", "2026-08-05T00:01:00+00:00", "2026-08-05T00:02:00+00:00", None, "",
            ))
            connection.execute("INSERT INTO harness_events VALUES ('run.failed')")
            connection.execute("INSERT INTO harness_evidence VALUES ('one')")
            connection.execute("INSERT INTO harness_hypotheses VALUES ('one')")
            connection.execute("INSERT INTO harness_decisions VALUES ('one')")
            connection.execute("INSERT INTO harness_model_calls VALUES ('codex-cli','gpt-test','native','failed',60000)")
            connection.execute("INSERT INTO harness_tool_calls VALUES ('elastic','events.read','ok',0)")
        return path

    def test_database_fixture_closes_its_connection(self):
        gc.collect()
        with tempfile.TemporaryDirectory() as directory:
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always", ResourceWarning)
                self.make_database(Path(directory))
                gc.collect()
        unclosed = [
            warning
            for warning in caught
            if "unclosed database" in str(warning.message)
        ]
        self.assertEqual(unclosed, [])

    def test_report_is_aggregate_and_marks_unavailable_usage(self):
        with tempfile.TemporaryDirectory() as directory:
            value = REPORT.summarize_database(
                self.make_database(Path(directory)),
                dt.datetime(2026, 8, 5, 0, 3, tzinfo=dt.timezone.utc),
            )
            self.assertEqual(value["failure_classes"], [{"failure_class": "provider_or_model", "count": 1}])
            self.assertEqual(value["active_run_age_seconds"], {"maximum": 120, "count": 1})
            self.assertFalse(value["token_usage"]["available"])
            self.assertFalse(value["retry_usage"]["available"])
            serialized = json.dumps(value)
            self.assertNotIn("provider timeout", serialized)

    def test_slo_projection_omits_sensitive_payloads(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "slo.json"
            path.write_text(json.dumps({
                "status": "healthy",
                "generated_at": "now",
                "signals": {"pending_ai_job_count": 2, "disk_used_percent": 55.0},
                "secret": "must-not-appear",
            }))
            value = REPORT.project_slo(path)
            self.assertEqual(value["pending_jobs"]["ai_analysis"], 2)
            self.assertNotIn("must-not-appear", json.dumps(value))

    def test_failure_class_never_returns_raw_reason(self):
        self.assertEqual(REPORT.failure_class("unknown opaque detail"), "unclassified")
        self.assertEqual(REPORT.failure_class("SQLite database failure"), "persistence_or_integrity")


if __name__ == "__main__":
    unittest.main()
