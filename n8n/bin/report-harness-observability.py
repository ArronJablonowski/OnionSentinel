#!/usr/bin/env python3
"""Report bounded aggregate harness telemetry without case or evidence content."""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import sqlite3
import stat
from typing import Any, Iterable


MAX_INPUT_BYTES = 8 * 1024 * 1024
TERMINAL = {"succeeded", "failed", "cancelled"}


def parse_time(value: object) -> dt.datetime | None:
    text = str(value or "").strip().replace("  ", "T", 1)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def percentile(values: Iterable[int], fraction: float) -> int | None:
    ordered = sorted(max(0, int(value)) for value in values)
    if not ordered:
        return None
    index = min(len(ordered) - 1, max(0, int((len(ordered) - 1) * fraction)))
    return ordered[index]


def failure_class(reason: object) -> str:
    text = str(reason or "").lower()
    classes = (
        ("budget_or_policy", ("budget", "policy", "unauthorized", "approval")),
        ("provider_or_model", ("model", "provider", "codex", "ollama", "timeout")),
        ("evidence_or_query", ("evidence", "query", "relay", "elastic", "pcap", "osquery")),
        ("persistence_or_integrity", ("database", "sqlite", "persist", "integrity", "digest")),
        ("cancelled_or_interrupted", ("cancel", "interrupt", "shutdown", "signal")),
    )
    for label, words in classes:
        if any(word in text for word in words):
            return label
    return "unclassified"


def safe_regular_file(path: Path, *, maximum_bytes: int | None = None) -> None:
    metadata = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise RuntimeError("observability input must be a regular file")
    if metadata.st_uid != os.getuid() or metadata.st_mode & 0o022:
        raise RuntimeError("observability input ownership or permissions are unsafe")
    if maximum_bytes is not None and metadata.st_size > maximum_bytes:
        raise RuntimeError("observability input exceeds its byte limit")


def table_columns(connection: sqlite3.Connection, table: str) -> set[str]:
    if table not in {"harness_model_calls"}:
        raise RuntimeError("unsupported telemetry table")
    return {
        str(row[1])
        for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
    }


def grouped_rows(connection: sqlite3.Connection, sql: str) -> list[dict[str, Any]]:
    return [dict(row) for row in connection.execute(sql).fetchall()]


def summarize_database(path: Path, now: dt.datetime) -> dict[str, Any]:
    connection = _open_observability_database(path)
    try:
        _validate_observability_database(connection)
        statuses, stages, event_counts = _grouped_run_telemetry(connection)
        durations, active_ages, failures = _run_time_telemetry(connection, now)
        model_columns, model_routes, model_durations = _model_telemetry(connection)
        tool_calls = _tool_telemetry(connection)
        counts = _entity_counts(connection)
        token_usage, retry_usage = _usage_telemetry(connection, model_columns)
    finally:
        connection.close()
    return _database_summary(
        statuses=statuses,
        stages=stages,
        event_counts=event_counts,
        durations=durations,
        active_ages=active_ages,
        failures=failures,
        model_routes=model_routes,
        model_durations=model_durations,
        tool_calls=tool_calls,
        counts=counts,
        token_usage=token_usage,
        retry_usage=retry_usage,
    )


def _open_observability_database(path: Path) -> sqlite3.Connection:
    safe_regular_file(path)
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5.0)
    connection.row_factory = sqlite3.Row
    return connection


def _validate_observability_database(connection: sqlite3.Connection) -> None:
    connection.execute("PRAGMA query_only=ON")
    if connection.execute("PRAGMA quick_check(1)").fetchone()[0] != "ok":
        raise RuntimeError("harness database quick check failed")


def _grouped_run_telemetry(
    connection: sqlite3.Connection,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    statuses = grouped_rows(
        connection,
        "SELECT status, COUNT(*) count FROM harness_runs GROUP BY status ORDER BY status",
    )
    stages = grouped_rows(
        connection,
        "SELECT stage, COUNT(*) count FROM harness_runs WHERE status NOT IN ('succeeded','failed','cancelled') GROUP BY stage ORDER BY stage",
    )
    event_counts = grouped_rows(
        connection,
        "SELECT event_type, COUNT(*) count FROM harness_events GROUP BY event_type ORDER BY event_type",
    )
    return statuses, stages, event_counts


def _run_time_telemetry(
    connection: sqlite3.Connection,
    now: dt.datetime,
) -> tuple[list[int], list[int], dict[str, int]]:
    durations: list[int] = []
    active_ages: list[int] = []
    failures: dict[str, int] = {}
    for row in connection.execute(
        "SELECT status, started_at, updated_at, completed_at, terminal_reason FROM harness_runs"
    ):
        started = parse_time(row["started_at"])
        ended = parse_time(row["completed_at"] or row["updated_at"])
        if started and ended and row["status"] in TERMINAL:
            durations.append(max(0, int((ended - started).total_seconds() * 1000)))
        if started and row["status"] not in TERMINAL:
            active_ages.append(max(0, int((now - started).total_seconds())))
        if row["status"] == "failed":
            label = failure_class(row["terminal_reason"])
            failures[label] = failures.get(label, 0) + 1
    return durations, active_ages, failures


def _model_telemetry(
    connection: sqlite3.Connection,
) -> tuple[set[str], list[dict[str, Any]], list[int]]:
    model_columns = table_columns(connection, "harness_model_calls")
    model_routes = grouped_rows(
        connection,
        """
        SELECT observed_provider provider, observed_model model,
               observed_harness harness, status, COUNT(*) count,
               CAST(AVG(duration_ms) AS INTEGER) average_duration_ms
        FROM harness_model_calls
        GROUP BY observed_provider, observed_model, observed_harness, status
        ORDER BY observed_provider, observed_model, observed_harness, status
        """,
    )
    model_durations = [
        int(row[0])
        for row in connection.execute("SELECT duration_ms FROM harness_model_calls")
    ]
    return model_columns, model_routes, model_durations


def _tool_telemetry(connection: sqlite3.Connection) -> list[dict[str, Any]]:
    return grouped_rows(
        connection,
        """
        SELECT backend, capability, status, COUNT(*) count,
               SUM(CASE WHEN truncated = 1 THEN 1 ELSE 0 END) truncated_count
        FROM harness_tool_calls
        GROUP BY backend, capability, status
        ORDER BY backend, capability, status
        """,
    )


def _entity_counts(connection: sqlite3.Connection) -> dict[str, int]:
    return {
        "runs": int(connection.execute("SELECT COUNT(*) FROM harness_runs").fetchone()[0]),
        "events": int(connection.execute("SELECT COUNT(*) FROM harness_events").fetchone()[0]),
        "evidence_refs": int(connection.execute("SELECT COUNT(*) FROM harness_evidence").fetchone()[0]),
        "hypotheses": int(connection.execute("SELECT COUNT(*) FROM harness_hypotheses").fetchone()[0]),
        "decisions": int(connection.execute("SELECT COUNT(*) FROM harness_decisions").fetchone()[0]),
        "model_calls": int(connection.execute("SELECT COUNT(*) FROM harness_model_calls").fetchone()[0]),
        "tool_calls": int(connection.execute("SELECT COUNT(*) FROM harness_tool_calls").fetchone()[0]),
    }


def _usage_telemetry(
    connection: sqlite3.Connection,
    model_columns: set[str],
) -> tuple[dict[str, Any], dict[str, Any]]:
    token_columns = {"input_tokens", "output_tokens"}.issubset(model_columns)
    retry_column = "attempt_count" in model_columns
    token_usage = {"available": token_columns}
    if token_columns:
        token_row = connection.execute(
            "SELECT COALESCE(SUM(input_tokens),0), COALESCE(SUM(output_tokens),0) FROM harness_model_calls"
        ).fetchone()
        token_usage.update({"input_tokens": int(token_row[0]), "output_tokens": int(token_row[1])})
    retry_usage = {"available": retry_column}
    if retry_column:
        retry_usage["retry_attempts"] = int(connection.execute(
            "SELECT COALESCE(SUM(MAX(attempt_count - 1, 0)),0) FROM harness_model_calls"
        ).fetchone()[0])
    return token_usage, retry_usage


def _database_summary(
    *,
    statuses: list[dict[str, Any]],
    stages: list[dict[str, Any]],
    event_counts: list[dict[str, Any]],
    durations: list[int],
    active_ages: list[int],
    failures: dict[str, int],
    model_routes: list[dict[str, Any]],
    model_durations: list[int],
    tool_calls: list[dict[str, Any]],
    counts: dict[str, int],
    token_usage: dict[str, Any],
    retry_usage: dict[str, Any],
) -> dict[str, Any]:
    return {
        "status_counts": statuses,
        "active_stage_counts": stages,
        "active_run_age_seconds": {
            "maximum": max(active_ages) if active_ages else None,
            "count": len(active_ages),
        },
        "terminal_latency_ms": {
            "p50": percentile(durations, 0.50),
            "p95": percentile(durations, 0.95),
            "maximum": max(durations) if durations else None,
        },
        "model_latency_ms": {
            "p50": percentile(model_durations, 0.50),
            "p95": percentile(model_durations, 0.95),
            "maximum": max(model_durations) if model_durations else None,
        },
        "failure_classes": [
            {"failure_class": label, "count": count}
            for label, count in sorted(failures.items())
        ],
        "counts": counts,
        "event_counts": event_counts,
        "model_routes": model_routes,
        "tool_calls": tool_calls,
        "token_usage": token_usage,
        "retry_usage": retry_usage,
    }


def project_slo(path: Path) -> dict[str, Any]:
    safe_regular_file(path, maximum_bytes=MAX_INPUT_BYTES)
    value = json.loads(path.read_text(encoding="utf-8"))
    signals = dict(value.get("signals") or {}) if isinstance(value, dict) else {}
    return {
        "status": value.get("status") if isinstance(value, dict) else "invalid",
        "generated_at": value.get("generated_at") if isinstance(value, dict) else None,
        "pending_jobs": {
            "ai_analysis": int(signals.get("pending_ai_job_count") or 0),
            "incident_response": int(signals.get("pending_incident_response_job_count") or 0),
        },
        "processing_jobs": {
            "ai_analysis": int(signals.get("processing_ai_job_count") or 0),
            "incident_response": int(signals.get("processing_incident_response_job_count") or 0),
        },
        "oldest_pending_seconds": {
            "ai_analysis": signals.get("oldest_pending_ai_job_seconds"),
            "incident_response": signals.get("oldest_pending_incident_response_job_seconds"),
        },
        "disk_used_percent": signals.get("disk_used_percent"),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", type=Path, default=Path.home() / "n8n-local/alert_store_data/investigation-harness.sqlite3")
    parser.add_argument("--slo-snapshot", type=Path, default=Path.home() / "n8n-local/logs/operational-slo-snapshot.json")
    args = parser.parse_args()
    now = dt.datetime.now(dt.timezone.utc)
    try:
        report = {
            "schema": "onion-sentinel-harness-observability-v1",
            "generated_at": now.isoformat(timespec="seconds"),
            "database": summarize_database(args.database.expanduser(), now),
            "operational_slo": project_slo(args.slo_snapshot.expanduser()),
            "content_policy": "aggregate_only_no_case_ids_queries_evidence_or_transcripts",
        }
    except (OSError, RuntimeError, sqlite3.Error, ValueError, TypeError, json.JSONDecodeError) as exc:
        print(json.dumps({"ok": False, "reason": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
