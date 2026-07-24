#!/usr/bin/env python3
"""Regression tests for exact Home activity and cache telemetry."""
from __future__ import annotations

import datetime as dt
import importlib.util
import sqlite3
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = REPO_ROOT / "onion-sentinel-dashboard" / "scripts"
BUILDER_PATH = SCRIPT_DIR / "build_soc_alerts_dashboard.py"
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from dashboard_executive_metrics import (  # noqa: E402
    EnrichmentCacheMetrics,
    HourlyIntakeBucket,
    HourlyIntakeMetrics,
    load_enrichment_cache_metrics,
    load_hourly_alert_intake,
)


def load_builder():
    spec = importlib.util.spec_from_file_location("dashboard_builder_executive_test", BUILDER_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class DashboardExecutiveMetricsTest(unittest.TestCase):
    def test_hourly_intake_counts_each_committed_alert_once(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "alerts.sqlite3"
            with closing(sqlite3.connect(database)) as connection, connection:
                connection.execute(
                    """
                    CREATE TABLE pipeline_stage_events (
                      stage TEXT,
                      event_type TEXT,
                      item_key TEXT,
                      occurred_at TEXT
                    )
                    """
                )
                connection.executemany(
                    "INSERT INTO pipeline_stage_events VALUES (?, ?, ?, ?)",
                    [
                        ("alert_ingest", "completed", "alert-a", "2026-07-21T20:10:00Z"),
                        # Reconciliation replay in a later hour must not double-count.
                        ("alert_ingest", "completed", "alert-a", "2026-07-21T21:10:00Z"),
                        ("alert_ingest", "completed", "alert-b", "2026-07-21T21:20:00Z"),
                        ("alert_ingest", "completed", "alert-c", "2026-07-21T11:05:00Z"),
                        ("public_enrichment", "completed", "alert-d", "2026-07-21T21:25:00Z"),
                    ],
                )

            metrics = load_hourly_alert_intake(
                database,
                now=dt.datetime(2026, 7, 21, 21, 35, tzinfo=dt.timezone.utc),
            )

            self.assertEqual("pipeline_stage_events", metrics.source)
            self.assertTrue(metrics.exact)
            self.assertEqual(12, len(metrics.buckets))
            self.assertEqual(3, sum(bucket.count for bucket in metrics.buckets))
            self.assertEqual(1, metrics.buckets[-2].count)
            self.assertEqual(1, metrics.buckets[-1].count)
            self.assertTrue(metrics.buckets[-1].current)

    def test_hourly_intake_falls_back_to_alert_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "alerts.sqlite3"
            with closing(sqlite3.connect(database)) as connection, connection:
                connection.execute("CREATE TABLE alerts (alert_id TEXT, last_seen TEXT)")
                connection.executemany(
                    "INSERT INTO alerts VALUES (?, ?)",
                    [
                        ("alert-a", "2026-07-21  20:10:00+00:00"),
                        ("alert-b", "2026-07-21  21:20:00+00:00"),
                    ],
                )

            metrics = load_hourly_alert_intake(
                database,
                now=dt.datetime(2026, 7, 21, 21, 35, tzinfo=dt.timezone.utc),
            )

            self.assertEqual("alerts", metrics.source)
            self.assertEqual(2, sum(bucket.count for bucket in metrics.buckets))

    def test_cache_metrics_separate_durable_and_process_lifetimes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "alerts.sqlite3"
            future = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=1)).isoformat()
            past = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1)).isoformat()
            with closing(sqlite3.connect(database)) as connection, connection:
                connection.execute(
                    """
                    CREATE TABLE enrichment_cache (
                      source TEXT,
                      indicator TEXT,
                      indicator_type TEXT,
                      verdict TEXT,
                      tags_json TEXT,
                      first_seen TEXT,
                      last_seen TEXT,
                      raw_response_json TEXT,
                      cached_at TEXT,
                      expires_at TEXT
                    )
                    """
                )
                connection.executemany(
                    "INSERT INTO enrichment_cache VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    [
                        ("provider-a", "example.test", "domain", "benign", "[]", "", "", "{}", past, future),
                        ("provider-b", "192.0.2.10", "ip", "unknown", "[]", "", "", "{}", past, past),
                    ],
                )

            metrics = load_enrichment_cache_metrics(
                database,
                runtime_metrics={
                    "l1_hits": 6,
                    "l2_hits": 3,
                    "misses": 1,
                    "coalesced": 2,
                    "provider_loads": 1,
                    "provider_errors": 0,
                    "stale_fallbacks": 1,
                },
                fetch_runtime=False,
            )

            self.assertTrue(metrics.available)
            self.assertTrue(metrics.runtime_available)
            self.assertEqual(2, metrics.entries)
            self.assertEqual(1, metrics.fresh_entries)
            self.assertEqual(1, metrics.stale_entries)
            self.assertEqual(11, metrics.api_calls_avoided)
            self.assertEqual(90.0, metrics.hit_rate)

    def test_home_copy_explains_local_time_and_counter_lifetimes(self) -> None:
        builder = load_builder()
        hourly = HourlyIntakeMetrics(
            buckets=(
                HourlyIntakeBucket(
                    start_utc=dt.datetime(2026, 7, 21, 21, tzinfo=dt.timezone.utc),
                    count=7,
                    current=True,
                ),
            ),
            source="pipeline_stage_events",
            exact=True,
            note="Synthetic exact intake.",
        )
        cache = EnrichmentCacheMetrics(
            available=True,
            entries=10,
            fresh_entries=8,
            stale_entries=2,
            l1_hits=4,
            l2_hits=3,
            misses=1,
            coalesced=2,
            provider_loads=1,
            runtime_available=True,
        )

        rendered = builder.executive_home_section([], hourly, cache)

        self.assertIn("Alert intake", rendered)
        self.assertIn("Completed ingests by local hour", rendered)
        self.assertIn('data-hour-start="2026-07-21T21:00:00Z"', rendered)
        self.assertIn("Threat-intel cache", rendered)
        self.assertIn("API calls avoided", rendered)
        self.assertIn("Process counters reset when alert-store restarts", rendered)
        self.assertNotIn("Recent volume", rendered)
        self.assertNotIn("Last 12 hours by UTC hour", rendered)
        self.assertIn("Intl.DateTimeFormat", builder.EXECUTIVE_HOME_JS)


if __name__ == "__main__":
    unittest.main()
