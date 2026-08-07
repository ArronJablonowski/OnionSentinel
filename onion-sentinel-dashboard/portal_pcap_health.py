"""PCAP workflow health collection and warning policy for the report portal."""
from __future__ import annotations

import datetime as dt
import sqlite3
from contextlib import AbstractContextManager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


JsonObject = dict[str, object]


@dataclass(frozen=True)
class PcapHealthSources:
    """Runtime dependencies used to compose the PCAP health response."""

    store_db: Path
    artifact_dir: Path
    analysis_dir: Path
    relay_state_paths: tuple[Path, ...]
    db_connect: Callable[[], AbstractContextManager[sqlite3.Connection]]
    table_exists: Callable[[sqlite3.Connection, str], bool]
    parse_timestamp: Callable[[object], dt.datetime]
    format_timestamp: Callable[..., str]
    directory_size: Callable[[Path], int]
    freshest_path: Callable[[list[Path]], Path | None]
    read_json: Callable[[Path, object], object]


def _nonnegative_int(value: object) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError, OverflowError):
        return 0


def _empty_summary(sources: PcapHealthSources) -> JsonObject:
    return {
        "available": False,
        "request_counts": {"pending": 0, "claimed": 0, "fulfilled": 0, "failed": 0, "total": 0},
        "no_packet_failures": 0,
        "oversize_failures": 0,
        "outcome_counts": {},
        "storage": {},
        "warning_count": 0,
        "warnings": [],
        "advisories": [],
        "active_transfers": [],
        "queue_progressing": False,
        "last_progress_at": None,
        "last_progress_age_seconds": None,
        "recent_requests": [],
        "latest_request": None,
        "analysis_count": 0,
        "latest_analysis": None,
        "artifact_size_bytes": sources.directory_size(sources.artifact_dir),
    }


def _relay_workflow_state(sources: PcapHealthSources, now_utc: dt.datetime) -> JsonObject:
    state_path = sources.freshest_path(list(sources.relay_state_paths))
    raw = sources.read_json(state_path, {}) if state_path else {}
    raw = raw if isinstance(raw, dict) else {}
    workflow = raw.get("pcap_workflow")
    workflow = workflow if isinstance(workflow, dict) else {}
    generated_at = raw.get("generated_at")
    generated_at, report_age_seconds = _relay_report_age(
        generated_at, sources.parse_timestamp, now_utc
    )
    state = str(workflow.get("state") or "unknown")
    fresh = report_age_seconds is not None and report_age_seconds <= 3 * 60
    return {
        "available": bool(state_path and workflow),
        "state": state,
        "active": _capture_hold_active(fresh, state, workflow.get("deferred")),
        "fresh": fresh,
        "reported_at": generated_at,
        "report_age_seconds": report_age_seconds,
        "relay_host": raw.get("relay_host"),
        "reason": str(workflow.get("reason") or "")[:300],
        "metric": str(workflow.get("metric") or "")[:64],
        "observed_percent": workflow.get("observed_percent"),
        "threshold_percent": workflow.get("threshold_percent"),
        "telemetry_age_seconds": workflow.get("telemetry_age_seconds"),
        "processed": _nonnegative_int(workflow.get("processed")),
        "operational_failures": _nonnegative_int(workflow.get("operational_failures")),
    }


def _capture_hold_active(fresh: bool, state: str, deferred: object) -> bool:
    return bool(fresh and state == "capture_protection_hold" and deferred)


def _relay_report_age(generated_at: object, parse_timestamp: Callable[[object], dt.datetime],
                      now_utc: dt.datetime) -> tuple[object, int | None]:
    if not generated_at:
        return generated_at, None
    try:
        reported_at = parse_timestamp(generated_at).astimezone(dt.timezone.utc)
        return generated_at, max(0, int((now_utc - reported_at).total_seconds()))
    except Exception:
        return None, None


def _request_counts(conn: sqlite3.Connection) -> JsonObject:
    counts = {
        str(row["status"] or "unknown").lower(): int(row["count"] or 0)
        for row in conn.execute("SELECT status, COUNT(*) AS count FROM pcap_requests GROUP BY status")
    }
    return {
        "pending": counts.get("pending", 0),
        "claimed": counts.get("claimed", 0),
        "fulfilled": counts.get("fulfilled", 0),
        "failed": counts.get("failed", 0),
        "total": sum(counts.values()),
    }


def _outcome_counts(conn: sqlite3.Connection, has_outcome: bool) -> JsonObject:
    if not has_outcome:
        return {}
    return {
        str(row["outcome"] or "unknown"): int(row["count"] or 0)
        for row in conn.execute(
            "SELECT COALESCE(outcome, 'unknown') AS outcome, COUNT(*) AS count "
            "FROM pcap_requests GROUP BY COALESCE(outcome, 'unknown')"
        )
    }


def _storage_stats(conn: sqlite3.Connection) -> JsonObject:
    row = conn.execute(
        """
        SELECT COUNT(*) AS fulfilled_count,
               COALESCE(SUM(artifact_size_bytes), 0) AS bytes_total,
               COALESCE(AVG(artifact_size_bytes), 0) AS bytes_average,
               COALESCE(MAX(artifact_size_bytes), 0) AS bytes_maximum,
               COALESCE(SUM(CASE WHEN datetime(replace(completed_at, '  ', 'T')) >=
                    datetime('now', '-24 hours') THEN artifact_size_bytes ELSE 0 END), 0) AS bytes_24h
        FROM pcap_requests WHERE status = 'fulfilled'
        """
    ).fetchone()
    return {key: int(row[key] or 0) for key in row.keys()} if row else {}


def _failure_counts(conn: sqlite3.Connection, has_outcome: bool, sources: PcapHealthSources,
                    now_utc: dt.datetime) -> tuple[int, int, int]:
    no_packets_where = (
        "outcome = 'no_packets_available'" if has_outcome
        else "status = 'failed' AND lower(coalesce(error, '')) LIKE '%no matching packets%'"
    )
    oversize_where = (
        "outcome = 'oversize'" if has_outcome
        else "status = 'failed' AND lower(coalesce(error, '')) LIKE '%artifact exceeds inline transfer limit%'"
    )
    no_packets = conn.execute(f"SELECT COUNT(*) AS count FROM pcap_requests WHERE {no_packets_where}").fetchone()
    oversize = conn.execute(f"SELECT COUNT(*) AS count FROM pcap_requests WHERE {oversize_where}").fetchone()
    rows = _unexpected_failure_rows(conn, has_outcome)
    cutoff = now_utc - dt.timedelta(hours=24)
    unexpected = sum(_failure_needs_review(row, sources, cutoff) for row in rows)
    return (
        int(no_packets["count"] or 0) if no_packets else 0,
        int(oversize["count"] or 0) if oversize else 0,
        unexpected,
    )


def _unexpected_failure_rows(conn: sqlite3.Connection, has_outcome: bool) -> list[sqlite3.Row]:
    unexpected_where = (
        "outcome NOT IN ('no_packets_available', 'expired', 'oversize')" if has_outcome
        else "lower(coalesce(error, '')) NOT LIKE '%no matching packets%' "
        "AND lower(coalesce(error, '')) NOT LIKE '%artifact exceeds inline transfer limit%' "
        "AND lower(coalesce(error, '')) NOT LIKE '%invalid json:%preview=''''%'"
    )
    return conn.execute(
        "SELECT error, completed_at, updated_at, created_at FROM pcap_requests "
        f"WHERE status = 'failed' AND {unexpected_where}"
    ).fetchall()


def _failure_needs_review(row: sqlite3.Row, sources: PcapHealthSources, cutoff: dt.datetime) -> int:
    try:
        failure_at = sources.parse_timestamp(row["completed_at"] or row["updated_at"] or row["created_at"])
    except Exception:
        return 1
    return int(failure_at.astimezone(dt.timezone.utc) >= cutoff)


def _active_transfers(conn: sqlite3.Connection, has_progress: bool, sources: PcapHealthSources,
                      now_utc: dt.datetime) -> list[JsonObject]:
    if not has_progress:
        return []
    rows = conn.execute(
        """
        SELECT request_id, transfer_stage, transfer_bytes, transfer_total_bytes, transfer_progress_at
        FROM pcap_requests WHERE status = 'claimed' AND transfer_progress_at IS NOT NULL
        """
    ).fetchall()
    cutoff = now_utc - dt.timedelta(minutes=2)
    active: list[JsonObject] = []
    for row in rows:
        try:
            progress_at = sources.parse_timestamp(row["transfer_progress_at"]).astimezone(dt.timezone.utc)
        except Exception:
            continue
        if progress_at >= cutoff:
            active.append({
                "request_id": row["request_id"] or "",
                "stage": row["transfer_stage"] or "",
                "transferred_bytes": int(row["transfer_bytes"] or 0),
                "total_bytes": int(row["transfer_total_bytes"] or 0),
                "progress_at": row["transfer_progress_at"] or "",
            })
    return active


def _last_progress(conn: sqlite3.Connection, sources: PcapHealthSources,
                   now_utc: dt.datetime) -> tuple[object, int | None]:
    row = conn.execute(
        """
        SELECT COALESCE(completed_at, updated_at) AS progress_at FROM pcap_requests
        WHERE status IN ('fulfilled', 'failed') AND COALESCE(completed_at, updated_at) IS NOT NULL
        ORDER BY COALESCE(completed_at, updated_at) DESC LIMIT 1
        """
    ).fetchone()
    value = row["progress_at"] if row else None
    if not value:
        return None, None
    try:
        parsed = sources.parse_timestamp(value).astimezone(dt.timezone.utc)
        return value, max(0, int((now_utc - parsed).total_seconds()))
    except Exception:
        return None, None


def _pending_grace(active: list[JsonObject], pending_total: int) -> dt.timedelta:
    if not active:
        return dt.timedelta(minutes=20)
    largest = max(int(item["total_bytes"] or 0) for item in active)
    transfer_seconds = min(
        6 * 60 * 60,
        max(20 * 60, int(largest / (4 * 1024 * 1024) * 1.5) + 10 * 60),
    )
    seconds = min(12 * 60 * 60, 20 * 60 + transfer_seconds * max(1, pending_total))
    return dt.timedelta(seconds=seconds)


def _stale_counts(conn: sqlite3.Connection, has_progress: bool, sources: PcapHealthSources,
                  now_utc: dt.datetime, pending_grace: dt.timedelta, queue_progressing: bool,
                  capture_hold: bool) -> dict[str, int]:
    progress_column = ", transfer_progress_at" if has_progress else ""
    rows = conn.execute(
        "SELECT status, updated_at, created_at" + progress_column
        + " FROM pcap_requests WHERE status IN ('pending', 'claimed')"
    ).fetchall()
    counts: dict[str, int] = {}
    for row in rows:
        freshness = _row_freshness(row, has_progress)
        try:
            updated_at = sources.parse_timestamp(freshness).astimezone(dt.timezone.utc)
        except Exception:
            continue
        if row["status"] == "pending" and (queue_progressing or capture_hold):
            continue
        grace = pending_grace if row["status"] == "pending" else dt.timedelta(minutes=20)
        if updated_at < now_utc - grace:
            status = str(row["status"] or "unknown")
            counts[status] = counts.get(status, 0) + 1
    return counts


def _row_freshness(row: sqlite3.Row, has_progress: bool) -> object:
    if has_progress and row["status"] == "claimed" and row["transfer_progress_at"]:
        return row["transfer_progress_at"]
    return row["updated_at"] or row["created_at"]


def _warnings(stale_counts: dict[str, int], unexpected_failures: int, relay: JsonObject,
              pending_total: int, queue_progressing: bool) -> list[str]:
    warnings = [
        f"{count} {status} PCAP request(s) older than 20 minutes"
        for status, count in sorted(stale_counts.items())
    ]
    if unexpected_failures:
        warnings.append(f"{unexpected_failures} PCAP request failure(s) need review")
    if relay.get("available") and not relay.get("fresh") and pending_total > 0 and not queue_progressing:
        warnings.append("PCAP broker safety telemetry is stale")
    if relay.get("fresh") and relay.get("state") == "operational_failure":
        warnings.append("PCAP broker reports an operational failure")
    return warnings


def _request_row(row: sqlite3.Row, has_outcome: bool, has_duration: bool,
                 duration: Callable[..., int | None], *, include_size: bool) -> JsonObject:
    result: JsonObject = {
        "request_id": row["request_id"] or "",
        "status": row["status"] or "",
        "outcome": row["outcome"] if has_outcome else "",
        "error": row["error"] or "",
        "group_id": row["group_id"] or "",
        "transfer_duration_seconds": duration(row, has_transfer_duration=has_duration),
        "updated_at": _request_updated_at(row, include_size),
    }
    if include_size:
        result["artifact_size_bytes"] = int(row["artifact_size_bytes"] or 0)
    return result


def _request_updated_at(row: sqlite3.Row, include_created_at: bool) -> object:
    value = row["completed_at"] or row["updated_at"]
    if not value and include_created_at:
        value = row["created_at"]
    return value or ""


def _attach_requests(summary: JsonObject, conn: sqlite3.Connection, has_outcome: bool,
                     has_duration: bool, duration: Callable[..., int | None]) -> None:
    outcome_column = ", outcome" if has_outcome else ""
    duration_column = ", transfer_duration_seconds" if has_duration else ""
    latest = conn.execute(
        "SELECT request_id, status, error, group_id, claimed_at, updated_at, completed_at"
        + outcome_column + duration_column
        + " FROM pcap_requests ORDER BY COALESCE(completed_at, updated_at, created_at) DESC LIMIT 1"
    ).fetchone()
    if latest:
        summary["latest_request"] = _request_row(latest, has_outcome, has_duration, duration, include_size=False)
    recent = conn.execute(
        "SELECT request_id, status, error, group_id, artifact_size_bytes, claimed_at, "
        "updated_at, completed_at, created_at" + outcome_column + duration_column
        + " FROM pcap_requests ORDER BY COALESCE(completed_at, updated_at, created_at) DESC LIMIT 250"
    ).fetchall()
    summary["recent_requests"] = [
        _request_row(row, has_outcome, has_duration, duration, include_size=True) for row in recent
    ]


def _populate_database(summary: JsonObject, conn: sqlite3.Connection, sources: PcapHealthSources,
                       relay: JsonObject, now_utc: dt.datetime,
                       duration: Callable[..., int | None]) -> None:
    columns = {str(row["name"]) for row in conn.execute("PRAGMA table_info(pcap_requests)")}
    has_outcome = "outcome" in columns
    has_duration = "transfer_duration_seconds" in columns
    has_progress = {"transfer_stage", "transfer_bytes", "transfer_total_bytes", "transfer_progress_at"}.issubset(columns)
    counts = _request_counts(conn)
    summary["request_counts"] = counts
    summary["outcome_counts"] = _outcome_counts(conn, has_outcome)
    summary["storage"] = _storage_stats(conn)
    no_packets, oversize, unexpected = _failure_counts(conn, has_outcome, sources, now_utc)
    summary["no_packet_failures"] = no_packets
    summary["oversize_failures"] = oversize
    active = _active_transfers(conn, has_progress, sources, now_utc)
    last_at, last_age = _last_progress(conn, sources, now_utc)
    progressing = bool(active) or bool(int(counts["pending"] or 0) > 0 and last_age is not None and last_age <= 180)
    summary.update({"active_transfers": active, "queue_progressing": progressing,
                    "last_progress_at": last_at, "last_progress_age_seconds": last_age})
    stale = _stale_counts(conn, has_progress, sources, now_utc,
                          _pending_grace(active, int(counts["pending"] or 0)), progressing,
                          bool(relay.get("active")))
    warnings = _warnings(stale, unexpected, relay, int(counts["pending"] or 0), progressing)
    summary.update({"warnings": warnings, "warning_count": len(warnings)})
    _attach_requests(summary, conn, has_outcome, has_duration, duration)
    summary["available"] = True


def _attach_analysis(summary: JsonObject, sources: PcapHealthSources) -> None:
    if not sources.analysis_dir.exists():
        return
    files = [path for path in sources.analysis_dir.glob("*-pcap-analysis.json") if path.is_file()]
    summary["analysis_count"] = len(files)
    if not files:
        return
    latest = max(files, key=lambda path: path.stat().st_mtime)
    updated = dt.datetime.fromtimestamp(latest.stat().st_mtime, dt.timezone.utc).astimezone()
    summary["latest_analysis"] = {
        "name": latest.name,
        "updated_at": sources.format_timestamp(updated, timespec="seconds"),
        "size_bytes": latest.stat().st_size,
    }


def compose_pcap_workflow_health(sources: PcapHealthSources,
                                 duration: Callable[..., int | None], *,
                                 now_utc: dt.datetime | None = None) -> JsonObject:
    """Compose the stable System Health PCAP payload from explicit sources."""
    now = now_utc or dt.datetime.now(dt.timezone.utc)
    summary = _empty_summary(sources)
    relay = _relay_workflow_state(sources, now)
    summary["capture_protection"] = relay
    if relay.get("active"):
        reason = str(relay.get("reason") or "Security Onion capture telemetry is above its safety threshold")
        summary["advisories"] = [f"PCAP reads are safely paused: {reason}"]
    try:
        if sources.store_db.exists():
            with sources.db_connect() as conn:
                if sources.table_exists(conn, "pcap_requests"):
                    _populate_database(summary, conn, sources, relay, now, duration)
    except Exception as exc:
        summary["error"] = str(exc)[:240]
    _attach_analysis(summary, sources)
    return summary
