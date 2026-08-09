#!/usr/bin/env python3
"""Direct contracts for prompt correlation projection."""
from __future__ import annotations

import datetime as dt
from pathlib import Path
import sqlite3
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))

from prompt_correlation_context import (  # noqa: E402
    CorrelationContextSources,
    build_correlated_alert_context,
)


def row_value(row, key, default=None):
    if isinstance(row, dict):
        return row.get(key, default)
    return row[key] if key in row.keys() else default


def parse_time(value):
    text = str(value or "").replace("  ", "T", 1)
    return dt.datetime.fromisoformat(text) if text else None


def row_facts(row):
    timestamp = parse_time(row_value(row, "last_seen"))
    return {
        "source_ip": row_value(row, "source_ip"),
        "destination_ip": row_value(row, "destination_ip"),
        "timestamp": timestamp,
        "timestamp_text": timestamp.isoformat() if timestamp else None,
    }


class PromptCorrelationContextTests(unittest.TestCase):
    def setUp(self) -> None:
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(
            """
            CREATE TABLE alerts (
              alert_id TEXT PRIMARY KEY, stable_group_id TEXT,
              first_seen TEXT, last_seen TEXT, timestamp TEXT,
              rule_name TEXT, source_ip TEXT, source_port INTEGER,
              destination_ip TEXT, destination_port INTEGER,
              network_protocol TEXT, transport_protocol TEXT,
              triage_level TEXT, triage_score INTEGER,
              filter_status TEXT, seen_count INTEGER,
              alert_json TEXT, raw_event_json TEXT
            );
            CREATE TABLE alert_observables (
              group_id TEXT, observable_type TEXT, observable_value TEXT,
              role TEXT
            );
            CREATE TABLE alert_correlations (
              source_group_id TEXT, related_group_id TEXT,
              correlation_score REAL, reasons_json TEXT,
              shared_observables_json TEXT, model_status TEXT,
              model_confidence TEXT, model_hypothesis TEXT, updated_at TEXT
            );
            CREATE TABLE ai_analysis_runs (
              analysis_id TEXT, group_id TEXT, generated_at TEXT, model TEXT,
              detection_outcome TEXT, bluf TEXT, summary TEXT, confidence TEXT
            );
            """
        )
        self.sources = CorrelationContextSources(
            rows=lambda conn, sql, params=(): list(conn.execute(sql, params)),
            table_columns=lambda conn, table: {
                str(item[1]) for item in conn.execute(f"PRAGMA table_info({table})")
            },
            row_value=row_value,
            observable_weight=lambda kind, _value: 35 if kind == "ip" else 4,
            time_bonus=lambda _selected, _related: (20, "within one hour"),
            row_facts=row_facts,
            relationships=lambda _selected, _related: [],
            safe_int=lambda value: int(value or 0),
            max_raw_json_bytes=256 * 1024,
        )

    def tearDown(self) -> None:
        self.conn.close()

    def test_missing_stable_identity_never_queries_correlation_index(self):
        context = build_correlated_alert_context(
            self.sources,
            self.conn,
            {"stable_group_id": ""},
            8,
            15,
        )

        self.assertEqual(context["status"], "stable group identity unavailable")
        self.assertEqual(context["candidates"], [])

    def test_missing_index_fails_closed_with_bounded_status(self):
        self.conn.execute("DROP TABLE alert_observables")

        context = build_correlated_alert_context(
            self.sources,
            self.conn,
            {"stable_group_id": "a" * 20},
            8,
            15,
        )

        self.assertEqual(context["status"], "correlation index unavailable")
        self.assertEqual(context["candidates"], [])

    def test_projection_uses_observables_but_excludes_raw_json(self):
        selected_id = "a" * 20
        related_id = "b" * 20
        alerts = [
            (
                "selected", selected_id, "2026-07-15  09:00:00+00:00",
                "2026-07-15  10:00:00+00:00", "2026-07-15  10:00:00+00:00",
                "Selected", "10.0.0.10", 51000, "198.51.100.20", 443,
                "tls", "tcp", "high", 75, "accepted", 1, "{}", "{}",
            ),
            (
                "related", related_id, "2026-07-15  09:10:00+00:00",
                "2026-07-15  09:55:00+00:00", "2026-07-15  09:55:00+00:00",
                "Related", "10.0.0.10", 52000, "203.0.113.30", 443,
                "tls", "tcp", "medium", 55, "accepted", 2,
                '{"secret":"must-not-cross"}', "{}",
            ),
        ]
        self.conn.executemany(
            "INSERT INTO alerts VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            alerts,
        )
        self.conn.executemany(
            "INSERT INTO alert_observables VALUES (?,?,?,?)",
            [
                (selected_id, "ip", "10.0.0.10", "source"),
                (related_id, "ip", "10.0.0.10", "source"),
            ],
        )
        self.conn.commit()
        selected = self.conn.execute(
            "SELECT * FROM alerts WHERE alert_id = 'selected'"
        ).fetchone()

        context = build_correlated_alert_context(
            self.sources,
            self.conn,
            selected,
            8,
            15,
        )

        self.assertEqual([item["group_id"] for item in context["candidates"]], [related_id])
        candidate = context["candidates"][0]
        self.assertEqual(candidate["score"], 55)
        self.assertEqual(candidate["shared_observables"][0]["value"], "10.0.0.10")
        self.assertNotIn("alert_json", candidate["alert"])
        self.assertNotIn("raw_event_json", candidate["alert"])


if __name__ == "__main__":
    unittest.main()
