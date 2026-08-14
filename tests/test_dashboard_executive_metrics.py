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
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = REPO_ROOT / "onion-sentinel-dashboard" / "scripts"
BUILDER_PATH = SCRIPT_DIR / "build_soc_alerts_dashboard.py"
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import dashboard_executive_metrics as executive_metrics  # noqa: E402
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

    def test_hourly_intake_preserves_query_close_and_observation_order(self) -> None:
        now = dt.datetime(2026, 7, 21, 21, 35, tzinfo=dt.timezone.utc)
        first_hour = dt.datetime(2026, 7, 21, 19, tzinfo=dt.timezone.utc)
        rows = [
            ("alert-a", "a-later"),
            ("alert-a", "a-latest"),
            ("alert-a", "a-earlier"),
            (None, "missing-key"),
            ("", "blank-key"),
            ("before", "before"),
            ("end", "end"),
            ("invalid", "invalid"),
        ]
        parsed = {
            "a-later": first_hour + dt.timedelta(hours=1, minutes=10),
            "a-latest": first_hour + dt.timedelta(hours=2, minutes=10),
            "a-earlier": first_hour + dt.timedelta(minutes=30),
            "missing-key": first_hour + dt.timedelta(hours=2, minutes=20),
            "blank-key": first_hour + dt.timedelta(hours=1, minutes=20),
            "before": first_hour - dt.timedelta(seconds=1),
            "end": first_hour + dt.timedelta(hours=3),
            "invalid": None,
        }
        trace: list[tuple[object, ...]] = []

        class ConnectionProbe:
            def close(self) -> None:
                trace.append(("close",))

        connection = ConnectionProbe()
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "alerts.sqlite3"
            database.touch()

            def open_read_only(path: Path) -> ConnectionProbe:
                trace.append(("open", path))
                return connection

            def hourly_rows(candidate: object, start: dt.datetime):
                trace.append(("rows", candidate, start))
                return rows, "synthetic", True, "Synthetic intake."

            def parse_timestamp(value: object):
                trace.append(("parse", value))
                return parsed[value]

            with (
                mock.patch.object(
                    executive_metrics,
                    "_open_read_only",
                    side_effect=open_read_only,
                ),
                mock.patch.object(
                    executive_metrics,
                    "_hourly_rows",
                    side_effect=hourly_rows,
                ),
                mock.patch.object(
                    executive_metrics,
                    "_parse_timestamp",
                    side_effect=parse_timestamp,
                ),
            ):
                metrics = load_hourly_alert_intake(database, now=now, hours=3)

        self.assertEqual([bucket.count for bucket in metrics.buckets], [1, 1, 1])
        self.assertEqual(metrics.source, "synthetic")
        self.assertTrue(metrics.exact)
        self.assertEqual(trace[:3], [("open", database), ("rows", connection, first_hour), ("close",)])
        self.assertEqual(
            trace[3:],
            [("parse", value) for _item_key, value in rows],
        )

    def test_hourly_intake_closes_and_falls_back_on_query_error(self) -> None:
        trace: list[str] = []

        class ConnectionProbe:
            def close(self) -> None:
                trace.append("close")

        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "alerts.sqlite3"
            database.touch()
            with (
                mock.patch.object(
                    executive_metrics,
                    "_open_read_only",
                    side_effect=lambda path: trace.append("open") or ConnectionProbe(),
                ),
                mock.patch.object(
                    executive_metrics,
                    "_hourly_rows",
                    side_effect=sqlite3.OperationalError("synthetic"),
                ),
            ):
                metrics = load_hourly_alert_intake(database, hours=2)

        self.assertEqual(trace, ["open", "close"])
        self.assertEqual(metrics.source, "unavailable")
        self.assertEqual(metrics.note, "Alert intake could not be read safely.")
        self.assertEqual([bucket.count for bucket in metrics.buckets], [0, 0])

    def test_hourly_intake_preserves_hour_bounds_before_missing_path_fallback(self) -> None:
        now = dt.datetime(2026, 7, 21, 21, 35, tzinfo=dt.timezone.utc)
        self.assertEqual(len(load_hourly_alert_intake(Path("missing"), now, 0).buckets), 1)
        self.assertEqual(len(load_hourly_alert_intake(Path("missing"), now, 100).buckets), 48)

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

    def test_cache_metrics_preserve_query_row_close_and_projection_order(self) -> None:
        trace: list[tuple[object, ...]] = []
        expected_query = """
                        SELECT
                          COUNT(*) AS entries,
                          SUM(CASE WHEN julianday(replace(expires_at, '  ', 'T')) > julianday('now') THEN 1 ELSE 0 END) AS fresh_entries,
                          SUM(CASE WHEN julianday(replace(expires_at, '  ', 'T')) <= julianday('now') THEN 1 ELSE 0 END) AS stale_entries,
                          SUM(
                            COALESCE(length(source), 0) + COALESCE(length(indicator), 0) +
                            COALESCE(length(indicator_type), 0) + COALESCE(length(verdict), 0) +
                            COALESCE(length(tags_json), 0) + COALESCE(length(first_seen), 0) +
                            COALESCE(length(last_seen), 0) + COALESCE(length(raw_response_json), 0) +
                            COALESCE(length(cached_at), 0) + COALESCE(length(expires_at), 0)
                          ) AS payload_bytes,
                          SUM(COALESCE(length(raw_response_json), 0)) AS raw_response_bytes
                        FROM enrichment_cache
                        """

        class RowProbe:
            values = (7, 5, 2, 101, 41)

            def __bool__(self) -> bool:
                trace.append(("row_bool",))
                return True

            def __getitem__(self, index: int) -> int:
                trace.append(("row_get", index))
                return self.values[index]

        class CursorProbe:
            def fetchone(self) -> RowProbe:
                trace.append(("fetchone",))
                return RowProbe()

        class ConnectionProbe:
            def execute(self, query: str) -> CursorProbe:
                trace.append(("execute", query))
                return CursorProbe()

            def close(self) -> None:
                trace.append(("close",))

        class RuntimeProbe(dict[str, int]):
            def get(self, key: str, default: object = None) -> object:
                trace.append(("runtime_get", key, default))
                return super().get(key, default)

            def __len__(self) -> int:
                trace.append(("runtime_len",))
                return super().__len__()

        connection = ConnectionProbe()
        runtime = RuntimeProbe(
            l1_hits=11,
            l2_hits=12,
            misses=13,
            coalesced=14,
            provider_loads=15,
            provider_errors=16,
            stale_fallbacks=17,
        )
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "alerts.sqlite3"
            database.touch()

            def open_read_only(path: Path) -> ConnectionProbe:
                trace.append(("open", path))
                return connection

            def table_exists(candidate: object, table: str) -> bool:
                trace.append(("table", candidate, table))
                return True

            def nonnegative(value: object) -> int:
                trace.append(("nonnegative", value))
                return int(value)

            with (
                mock.patch.object(
                    executive_metrics,
                    "_open_read_only",
                    side_effect=open_read_only,
                ),
                mock.patch.object(
                    executive_metrics,
                    "_table_exists",
                    side_effect=table_exists,
                ),
                mock.patch.object(
                    executive_metrics,
                    "_nonnegative_int",
                    side_effect=nonnegative,
                ),
                mock.patch.object(
                    executive_metrics,
                    "fetch_enrichment_cache_runtime",
                    side_effect=AssertionError("runtime fetch must remain skipped"),
                ),
            ):
                metrics = load_enrichment_cache_metrics(database, runtime)

        self.assertEqual(
            trace[:11],
            [
                ("open", database),
                ("table", connection, "enrichment_cache"),
                ("execute", expected_query),
                ("fetchone",),
                ("row_bool",),
                ("row_get", 0),
                ("row_get", 1),
                ("row_get", 2),
                ("row_get", 3),
                ("row_get", 4),
                ("close",),
            ],
        )
        self.assertEqual(
            trace[11:],
            [
                ("nonnegative", 7),
                ("nonnegative", 5),
                ("nonnegative", 2),
                ("nonnegative", 101),
                ("nonnegative", 41),
                ("runtime_get", "l1_hits", None),
                ("nonnegative", 11),
                ("runtime_get", "l2_hits", None),
                ("nonnegative", 12),
                ("runtime_get", "misses", None),
                ("nonnegative", 13),
                ("runtime_get", "coalesced", None),
                ("nonnegative", 14),
                ("runtime_get", "provider_loads", None),
                ("nonnegative", 15),
                ("runtime_get", "provider_errors", None),
                ("nonnegative", 16),
                ("runtime_get", "stale_fallbacks", None),
                ("nonnegative", 17),
                ("runtime_len",),
            ],
        )
        self.assertEqual(metrics.entries, 7)
        self.assertEqual(metrics.raw_response_bytes, 41)
        self.assertEqual(metrics.stale_fallbacks, 17)
        self.assertTrue(metrics.available)
        self.assertTrue(metrics.runtime_available)

    def test_cache_metrics_close_and_fetch_runtime_after_database_error(self) -> None:
        trace: list[tuple[object, ...]] = []

        class ConnectionProbe:
            def close(self) -> None:
                trace.append(("close",))

        connection = ConnectionProbe()
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "alerts.sqlite3"
            database.touch()

            def open_read_only(path: Path) -> ConnectionProbe:
                trace.append(("open", path))
                return connection

            def table_exists(candidate: object, table: str) -> bool:
                trace.append(("table", candidate, table))
                raise sqlite3.OperationalError("synthetic")

            def fetch_runtime() -> dict[str, int]:
                trace.append(("fetch_runtime",))
                return {"misses": 4}

            with (
                mock.patch.object(
                    executive_metrics,
                    "_open_read_only",
                    side_effect=open_read_only,
                ),
                mock.patch.object(
                    executive_metrics,
                    "_table_exists",
                    side_effect=table_exists,
                ),
                mock.patch.object(
                    executive_metrics,
                    "fetch_enrichment_cache_runtime",
                    side_effect=fetch_runtime,
                ),
            ):
                metrics = load_enrichment_cache_metrics(database)

        self.assertEqual(
            trace,
            [
                ("open", database),
                ("table", connection, "enrichment_cache"),
                ("close",),
                ("fetch_runtime",),
            ],
        )
        self.assertFalse(metrics.available)
        self.assertTrue(metrics.runtime_available)
        self.assertEqual(metrics.misses, 4)

    def test_cache_metrics_skip_query_and_fetch_for_absent_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "missing.sqlite3"
            with (
                mock.patch.object(
                    executive_metrics,
                    "_open_read_only",
                    side_effect=AssertionError("database must remain unopened"),
                ),
                mock.patch.object(
                    executive_metrics,
                    "fetch_enrichment_cache_runtime",
                    side_effect=AssertionError("runtime fetch must remain skipped"),
                ),
            ):
                metrics = load_enrichment_cache_metrics(
                    missing,
                    runtime_metrics=[("l1_hits", 99)],
                    fetch_runtime=True,
                )

        self.assertEqual(metrics, EnrichmentCacheMetrics())

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
