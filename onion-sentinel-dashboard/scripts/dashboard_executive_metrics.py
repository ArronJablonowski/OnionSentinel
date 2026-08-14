#!/usr/bin/env python3
"""Read bounded executive-dashboard telemetry from the alert-store.

The Home page combines two different kinds of facts:

* durable inventory from SQLite, which survives process restarts; and
* process counters from ``GET /metrics``, which intentionally reset whenever
  alert-store restarts.

Keeping that distinction here prevents the UI from presenting a volatile hit
counter as a lifetime total. All database access is read-only and all HTTP
access is restricted to loopback with a short timeout so dashboard generation
cannot be held hostage by a busy or unavailable alert-store process.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional
from urllib import request as urllib_request
from urllib.parse import urlsplit


UTC = dt.timezone.utc
DEFAULT_METRICS_URL = "http://127.0.0.1:8787/metrics"
MAX_METRICS_RESPONSE_BYTES = 512 * 1024


@dataclass(frozen=True)
class HourlyIntakeBucket:
    """One fixed UTC clock-hour bucket rendered in the viewer's timezone."""

    start_utc: dt.datetime
    count: int
    current: bool


@dataclass(frozen=True)
class HourlyIntakeMetrics:
    """Recent committed alert intake and the source used to derive it."""

    buckets: tuple[HourlyIntakeBucket, ...]
    source: str
    exact: bool
    note: str


@dataclass(frozen=True)
class EnrichmentCacheMetrics:
    """Durable cache inventory plus optional since-restart process counters."""

    available: bool = False
    entries: int = 0
    fresh_entries: int = 0
    stale_entries: int = 0
    payload_bytes: int = 0
    raw_response_bytes: int = 0
    l1_hits: int = 0
    l2_hits: int = 0
    misses: int = 0
    coalesced: int = 0
    provider_loads: int = 0
    provider_errors: int = 0
    stale_fallbacks: int = 0
    runtime_available: bool = False

    @property
    def cache_hits(self) -> int:
        return self.l1_hits + self.l2_hits

    @property
    def api_calls_avoided(self) -> int:
        return self.cache_hits + self.coalesced

    @property
    def hit_rate(self) -> Optional[float]:
        attempts = self.cache_hits + self.misses
        if attempts <= 0:
            return None
        return round((self.cache_hits / attempts) * 100, 1)


def _nonnegative_int(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _parse_timestamp(value: Any) -> Optional[dt.datetime]:
    text = str(value or "").strip().replace("  ", "T")
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _clock_hour(value: dt.datetime) -> dt.datetime:
    return value.astimezone(UTC).replace(minute=0, second=0, microsecond=0)


def _empty_hourly_metrics(now: dt.datetime, hours: int, note: str) -> HourlyIntakeMetrics:
    current_hour = _clock_hour(now)
    first_hour = current_hour - dt.timedelta(hours=hours - 1)
    buckets = tuple(
        HourlyIntakeBucket(
            start_utc=first_hour + dt.timedelta(hours=index),
            count=0,
            current=index == hours - 1,
        )
        for index in range(hours)
    )
    return HourlyIntakeMetrics(buckets, "unavailable", False, note)


def _open_read_only(db_path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(
        f"file:{db_path}?mode=ro",
        uri=True,
        timeout=1.0,
    )
    connection.execute("PRAGMA query_only = ON")
    connection.execute("PRAGMA busy_timeout = 1000")
    return connection


def _table_exists(connection: sqlite3.Connection, table: str) -> bool:
    row = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table,),
    ).fetchone()
    return row is not None


def _hourly_rows(
    connection: sqlite3.Connection,
    first_hour: dt.datetime,
) -> tuple[list[tuple[Any, Any]], str, bool, str]:
    # A one-day lexical guard keeps the indexed candidate scan bounded. Exact
    # timezone conversion and bucket assignment happen in Python below.
    guard = (first_hour - dt.timedelta(days=1)).strftime("%Y-%m-%d")
    if _table_exists(connection, "pipeline_stage_events"):
        rows = connection.execute(
            """
            SELECT item_key, occurred_at
            FROM pipeline_stage_events
            WHERE stage = 'alert_ingest'
              AND event_type = 'completed'
              AND occurred_at >= ?
            """,
            (guard,),
        ).fetchall()
        if rows:
            return (
                rows,
                "pipeline_stage_events",
                True,
                "Committed alert observations; duplicate bootstrap telemetry is removed by alert ID.",
            )

    if _table_exists(connection, "alerts"):
        rows = connection.execute(
            "SELECT alert_id, last_seen FROM alerts WHERE last_seen >= ?",
            (guard,),
        ).fetchall()
        return (
            rows,
            "alerts",
            True,
            "Committed alert rows; pipeline telemetry was not available for this window.",
        )

    return [], "unavailable", False, "No committed alert-intake telemetry table was available."


def _hourly_observations(
    rows: list[tuple[Any, Any]],
    first_hour: dt.datetime,
    window_end: dt.datetime,
) -> dict[str, dt.datetime]:
    """Retain the earliest in-window completion for each alert identity."""
    observations: dict[str, dt.datetime] = {}
    for row_index, (item_key, occurred_at) in enumerate(rows):
        timestamp = _parse_timestamp(occurred_at)
        if timestamp is None or timestamp < first_hour or timestamp >= window_end:
            continue
        identity = str(item_key or f"row-{row_index}")
        previous = observations.get(identity)
        if previous is not None and previous <= timestamp:
            continue
        observations[identity] = timestamp
    return observations


def load_hourly_alert_intake(
    db_path: Path,
    now: Optional[dt.datetime] = None,
    hours: int = 12,
) -> HourlyIntakeMetrics:
    """Load exact committed alert observations into fixed clock-hour buckets."""
    bounded_hours = min(48, max(1, int(hours)))
    current = (now or dt.datetime.now(UTC)).astimezone(UTC)
    current_hour = _clock_hour(current)
    first_hour = current_hour - dt.timedelta(hours=bounded_hours - 1)
    window_end = current_hour + dt.timedelta(hours=1)
    if not Path(db_path).is_file():
        return _empty_hourly_metrics(current, bounded_hours, "Alert-store database was unavailable.")

    try:
        with closing(_open_read_only(Path(db_path))) as connection:
            rows, source, exact, note = _hourly_rows(connection, first_hour)
    except (OSError, sqlite3.Error):
        return _empty_hourly_metrics(current, bounded_hours, "Alert intake could not be read safely.")

    counts = [0 for _index in range(bounded_hours)]
    # Bootstrap/reconciliation events can repeat the same alert ID. Collapse
    # those copies before bucketing so a delayed duplicate cannot inflate a
    # second hour. The earliest completion is the canonical ingest time.
    observations = _hourly_observations(rows, first_hour, window_end)

    for timestamp in observations.values():
        bucket_index = int((timestamp - first_hour).total_seconds() // 3600)
        if not 0 <= bucket_index < bounded_hours:
            continue
        counts[bucket_index] += 1

    buckets = tuple(
        HourlyIntakeBucket(
            start_utc=first_hour + dt.timedelta(hours=index),
            count=count,
            current=index == bounded_hours - 1,
        )
        for index, count in enumerate(counts)
    )
    return HourlyIntakeMetrics(buckets, source, exact, note)


def fetch_enrichment_cache_runtime(
    metrics_url: Optional[str] = None,
    timeout_seconds: float = 0.75,
) -> Optional[dict[str, Any]]:
    """Fetch bounded cache process counters from a loopback-only endpoint."""
    url = metrics_url or os.environ.get(
        "ONION_SENTINEL_ALERT_STORE_METRICS_URL",
        DEFAULT_METRICS_URL,
    )
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        return None
    try:
        request = urllib_request.Request(url, headers={"Accept": "application/json"})
        with urllib_request.urlopen(request, timeout=max(0.1, timeout_seconds)) as response:
            body = response.read(MAX_METRICS_RESPONSE_BYTES + 1)
        if len(body) > MAX_METRICS_RESPONSE_BYTES:
            return None
        payload = json.loads(body.decode("utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return None
    metrics = payload.get("metrics") if isinstance(payload, dict) else None
    cache = metrics.get("enrichment_cache") if isinstance(metrics, dict) else None
    return cache if isinstance(cache, dict) else None


def _durable_enrichment_cache_metrics(db_path: Path) -> dict[str, Any]:
    """Load the sanitized durable enrichment-cache inventory."""
    durable: dict[str, Any] = {}
    path = Path(db_path)
    if path.is_file():
        try:
            with closing(_open_read_only(path)) as connection:
                if _table_exists(connection, "enrichment_cache"):
                    row = connection.execute(
                        """
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
                    ).fetchone()
                    if row:
                        durable = {
                            "entries": row[0],
                            "fresh_entries": row[1],
                            "stale_entries": row[2],
                            "payload_bytes": row[3],
                            "raw_response_bytes": row[4],
                        }
        except (OSError, sqlite3.Error):
            durable = {}
    return durable


def load_enrichment_cache_metrics(
    db_path: Path,
    runtime_metrics: Optional[dict[str, Any]] = None,
    fetch_runtime: bool = True,
) -> EnrichmentCacheMetrics:
    """Load sanitized cache telemetry without returning indicators or evidence."""
    durable = _durable_enrichment_cache_metrics(db_path)

    runtime = runtime_metrics
    if runtime is None and fetch_runtime:
        runtime = fetch_enrichment_cache_runtime()
    runtime = runtime if isinstance(runtime, dict) else {}
    return EnrichmentCacheMetrics(
        available=bool(durable),
        entries=_nonnegative_int(durable.get("entries")),
        fresh_entries=_nonnegative_int(durable.get("fresh_entries")),
        stale_entries=_nonnegative_int(durable.get("stale_entries")),
        payload_bytes=_nonnegative_int(durable.get("payload_bytes")),
        raw_response_bytes=_nonnegative_int(durable.get("raw_response_bytes")),
        l1_hits=_nonnegative_int(runtime.get("l1_hits")),
        l2_hits=_nonnegative_int(runtime.get("l2_hits")),
        misses=_nonnegative_int(runtime.get("misses")),
        coalesced=_nonnegative_int(runtime.get("coalesced")),
        provider_loads=_nonnegative_int(runtime.get("provider_loads")),
        provider_errors=_nonnegative_int(runtime.get("provider_errors")),
        stale_fallbacks=_nonnegative_int(runtime.get("stale_fallbacks")),
        runtime_available=bool(runtime),
    )
