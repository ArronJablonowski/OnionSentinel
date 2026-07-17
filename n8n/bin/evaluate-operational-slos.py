#!/usr/bin/env python3
"""Evaluate Onion Sentinel production SLOs from local, read-only endpoints."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import shutil
import sys
import urllib.request


def parse_timestamp(value: object) -> dt.datetime | None:
    text = str(value or "").strip().replace("  ", "T", 1)
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed


def age_seconds(value: object, now: dt.datetime) -> int | None:
    parsed = parse_timestamp(value)
    if parsed is None:
        return None
    return max(0, int((now.astimezone(dt.timezone.utc) - parsed.astimezone(dt.timezone.utc)).total_seconds()))


def newest_file_age(directory: Path, pattern: str, now: dt.datetime) -> int | None:
    matches = [path for path in directory.glob(pattern) if path.is_file()]
    if not matches:
        return None
    newest = max(path.stat().st_mtime for path in matches)
    return max(0, int(now.timestamp() - newest))


def update_soak_state(previous: dict[str, object], failures: list[str], now: dt.datetime) -> dict[str, object]:
    healthy_since = None if failures else parse_timestamp(previous.get("healthy_since"))
    if not failures and healthy_since is None:
        healthy_since = now
    elapsed = int((now - healthy_since.astimezone(dt.timezone.utc)).total_seconds()) if healthy_since else 0
    return {
        "healthy_since": healthy_since.astimezone().replace(microsecond=0).isoformat().replace("T", "  ") if healthy_since else None,
        "healthy_elapsed_seconds": max(0, elapsed),
        "qualified_48h": bool(healthy_since and elapsed >= 48 * 60 * 60),
    }


def append_bounded_history(path: Path, snapshot: dict[str, object], keep: int = 4032) -> None:
    lines: list[str] = []
    try:
        lines = path.read_text().splitlines()
    except OSError:
        pass
    lines.append(json.dumps(snapshot, sort_keys=True, separators=(",", ":")))
    path.write_text("\n".join(lines[-keep:]) + "\n")
    os.chmod(path, 0o600)


def evaluate(
    metrics_payload: dict[str, object],
    health_payload: dict[str, object],
    *,
    now: dt.datetime,
    disk_used_percent: float,
    sqlite_backup_age: int | None,
    postgres_backup_age: int | None,
    previous_ingest_errors: int | None,
) -> tuple[list[str], dict[str, object]]:
    metrics = dict(metrics_payload.get("metrics") or {})
    process = dict(metrics.get("process") or {})
    summary = dict(health_payload.get("summary") or {})
    latest = dict(summary.get("latest") or {})
    pcap = dict(health_payload.get("pcap") or {})
    pipeline = dict(metrics.get("pipeline") or {})
    pipeline_disk = dict(pipeline.get("disk") or {})
    pipeline_stages = {
        str(item.get("stage") or ""): dict(item)
        for item in (pipeline.get("stages") or [])
        if isinstance(item, dict)
    }
    failures: list[str] = []
    pending_job_ages = {
        str(item.get("job_type") or ""): int(item.get("seconds") or 0)
        for item in (metrics.get("oldest_pending_jobs") or [])
        if isinstance(item, dict)
    }
    latest_completion_ages = {
        str(item.get("job_type") or ""): int(item.get("seconds") or 0)
        for item in (metrics.get("latest_completed_jobs") or [])
        if isinstance(item, dict)
    }
    processing_job_ages = {
        str(item.get("job_type") or ""): int(item.get("seconds") or 0)
        for item in (metrics.get("oldest_processing_jobs") or [])
        if isinstance(item, dict)
    }
    pending_job_counts = {
        str(item.get("job_type") or ""): int(item.get("count") or 0)
        for item in (metrics.get("durable_jobs") or [])
        if isinstance(item, dict) and str(item.get("status") or "") == "pending"
    }
    processing_job_counts = {
        str(item.get("job_type") or ""): int(item.get("count") or 0)
        for item in (metrics.get("durable_jobs") or [])
        if isinstance(item, dict) and str(item.get("status") or "") == "processing"
    }
    # Older alert-store versions expose only the aggregate age. Preserve that
    # signal during rolling deployment, then use type-specific deadlines once
    # the richer metric is available.
    aggregate_job_age = int(metrics.get("oldest_pending_job_seconds") or 0)
    enrichment_job_age = pending_job_ages.get("public_enrichment", aggregate_job_age if not pending_job_ages else 0)
    ai_job_age = pending_job_ages.get("ai_analysis", aggregate_job_age if not pending_job_ages else 0)
    ai_completion_age = latest_completion_ages.get("ai_analysis")
    ai_processing_age = processing_job_ages.get("ai_analysis")

    heartbeat_age = age_seconds(latest.get("timestamp_utc") or latest.get("timestamp"), now)
    if heartbeat_age is None or heartbeat_age > 20 * 60:
        failures.append(f"relay heartbeat stale ({heartbeat_age if heartbeat_age is not None else 'unknown'}s)")
    if enrichment_job_age > 15 * 60:
        failures.append("enrichment job backlog exceeds 15 minutes")
    # The scheduler intentionally favors severity over age, so an old low job
    # can remain pending while newer higher-severity groups are completed. When
    # work exists, detect a stuck worker by lack of forward progress instead.
    ai_pending_count = pending_job_counts.get("ai_analysis", 0)
    ai_processing_count = processing_job_counts.get("ai_analysis", 0)
    if ai_processing_count and (ai_processing_age is None or ai_processing_age > 15 * 60):
        failures.append("AI analysis has been processing without state progress for 15 minutes")
    elif ai_pending_count and not ai_processing_count and (ai_completion_age is None or ai_completion_age > 30 * 60):
        # One inference may legitimately consume the configured ten-minute
        # timeout and retry on the next five-minute scheduler tick. Alert only
        # after two complete retry windows have passed without forward progress.
        failures.append("AI analysis has pending work but no completion within 30 minutes")
    active_pcap_transfers = [
        item for item in (pcap.get("active_transfers") or [])
        if isinstance(item, dict) and item.get("progress_at")
    ]
    pcap_queue_progressing = bool(pcap.get("queue_progressing")) or bool(active_pcap_transfers)
    if int(metrics.get("oldest_pending_pcap_seconds") or 0) > 60 * 60 and not pcap_queue_progressing:
        failures.append("PCAP backlog exceeds 60 minutes")
    if int(pcap.get("warning_count") or 0) > 0:
        failures.append(f"PCAP workflow has {int(pcap.get('warning_count') or 0)} warning(s)")
    ingest_errors = int(process.get("ingest_errors") or 0)
    if previous_ingest_errors is not None and ingest_errors > previous_ingest_errors:
        failures.append(f"alert ingest errors increased by {ingest_errors - previous_ingest_errors}")
    if disk_used_percent >= 75:
        failures.append(f"Mac runtime disk is {disk_used_percent:.1f}% used")
    projected_disk_percent = float(pipeline_disk.get("projected_used_percent_with_known_backlog") or 0)
    if disk_used_percent < 75 and projected_disk_percent >= 75:
        failures.append(f"known pipeline backlog projects Mac runtime disk to {projected_disk_percent:.1f}% used")
    if sqlite_backup_age is None or sqlite_backup_age > 2 * 60 * 60:
        failures.append("verified SQLite backup is missing or older than 2 hours")
    if postgres_backup_age is None or postgres_backup_age > 26 * 60 * 60:
        failures.append("verified PostgreSQL recovery bundle is missing or older than 26 hours")

    snapshot = {
        "generated_at": now.astimezone().replace(microsecond=0).isoformat().replace("T", "  "),
        "ok": not failures,
        "failures": failures,
        "signals": {
            "heartbeat_age_seconds": heartbeat_age,
            "oldest_pending_job_seconds": int(metrics.get("oldest_pending_job_seconds") or 0),
            "oldest_pending_enrichment_job_seconds": enrichment_job_age,
            "oldest_pending_ai_job_seconds": ai_job_age,
            "latest_ai_completion_age_seconds": ai_completion_age,
            "oldest_ai_processing_seconds": ai_processing_age,
            "pending_ai_job_count": ai_pending_count,
            "processing_ai_job_count": ai_processing_count,
            "oldest_pending_pcap_seconds": int(metrics.get("oldest_pending_pcap_seconds") or 0),
            "pcap_warning_count": int(pcap.get("warning_count") or 0),
            "active_pcap_transfer_count": len(active_pcap_transfers),
            "pcap_queue_progressing": pcap_queue_progressing,
            "pcap_last_progress_age_seconds": pcap.get("last_progress_age_seconds"),
            "ingest_errors": ingest_errors,
            "disk_used_percent": round(disk_used_percent, 1),
            "disk_new_work_limit_percent": 75,
            "disk_hard_limit_percent": 80,
            "pipeline_stages": {
                stage: {
                    "pending": int(values.get("pending") or 0),
                    "processing": int(values.get("processing") or 0),
                    "oldest_pending_seconds": int(values.get("oldest_pending_seconds") or 0),
                    "backlog_bytes_known": int(values.get("backlog_bytes_known") or 0),
                    "backlog_bytes_unknown_items": int(values.get("backlog_bytes_unknown_items") or 0),
                    "drain_eta_seconds": values.get("drain_eta_seconds"),
                    "byte_drain_eta_seconds": values.get("byte_drain_eta_seconds"),
                    "throughput_1h": dict(values.get("throughput") or {}).get("1h", {}),
                }
                for stage, values in pipeline_stages.items()
            },
            "pipeline_known_backlog_bytes": int(pipeline_disk.get("known_pipeline_backlog_bytes") or 0),
            "pipeline_unknown_backlog_items": int(pipeline_disk.get("unknown_pipeline_backlog_items") or 0),
            "pipeline_projected_disk_used_percent": projected_disk_percent,
            "pipeline_disk_growth_1h": dict(pipeline_disk.get("net_growth") or {}).get("1h", {}),
            "sqlite_backup_age_seconds": sqlite_backup_age,
            "postgres_backup_age_seconds": postgres_backup_age,
        },
    }
    return failures, snapshot


def fetch_json(url: str) -> dict[str, object]:
    with urllib.request.urlopen(url, timeout=8) as response:
        return json.load(response)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stack-dir", type=Path, default=Path.home() / "n8n-local")
    parser.add_argument("--metrics-url", default="http://127.0.0.1:8787/metrics")
    parser.add_argument("--health-url", default="http://127.0.0.1:8766/api/system-health/beacons?hours=1")
    args = parser.parse_args()
    log_dir = args.stack_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    state_path = log_dir / "operational-slo-counter-state.json"
    snapshot_path = log_dir / "operational-slo-snapshot.json"
    history_path = log_dir / "operational-slo-history.jsonl"
    previous: dict[str, object] = {}
    try:
        previous = json.loads(state_path.read_text())
    except (OSError, ValueError, TypeError):
        pass

    now = dt.datetime.now(dt.timezone.utc)
    usage = shutil.disk_usage(args.stack_dir)
    disk_percent = (usage.used / usage.total * 100) if usage.total else 100.0
    failures, snapshot = evaluate(
        fetch_json(args.metrics_url),
        fetch_json(args.health_url),
        now=now,
        disk_used_percent=disk_percent,
        sqlite_backup_age=newest_file_age(args.stack_dir / "alert_store_backups", "*.backup", now),
        postgres_backup_age=newest_file_age(args.stack_dir / "recovery_backups", "*/n8n-postgres.dump", now),
        previous_ingest_errors=int(previous["ingest_errors"]) if "ingest_errors" in previous else None,
    )
    snapshot["soak"] = update_soak_state(previous, failures, now)
    snapshot_path.write_text(json.dumps(snapshot, indent=2, sort_keys=True) + "\n")
    os.chmod(snapshot_path, 0o600)
    append_bounded_history(history_path, snapshot)
    state_path.write_text(json.dumps({
        "ingest_errors": snapshot["signals"]["ingest_errors"],
        "healthy_since": snapshot["soak"]["healthy_since"],
    }) + "\n")
    os.chmod(state_path, 0o600)
    if failures:
        print("; ".join(failures))
        return 2
    print("operational SLOs healthy")
    return 0


if __name__ == "__main__":
    sys.exit(main())
