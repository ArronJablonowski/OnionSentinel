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
import time
import urllib.error
import urllib.request

BIN_DIR = Path(__file__).resolve().parent
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))
from bounded_http import BoundedHttpError, read_bounded_json


MAX_PROBE_RESPONSE_BYTES = 8 * 1024 * 1024
DEFAULT_PROBE_ATTEMPTS = 2
DEFAULT_PROBE_RETRY_DELAY_SECONDS = 0.2
CAPTURE_TELEMETRY_UNAVAILABLE_GRACE_SECONDS = 3 * 60


class ProbeError(RuntimeError):
    """A concise, operator-safe failure from a local read-only health probe."""


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


def read_json_object(path: Path) -> dict[str, object] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return None
    return value if isinstance(value, dict) else None


def env_flag(path: Path, name: str) -> bool:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return False
    prefix = f"{name}="
    return any(
        line.startswith(prefix)
        and line[len(prefix):].strip().strip("\"'") == "1"
        for line in lines
    )


def evaluate(
    metrics_payload: dict[str, object],
    health_payload: dict[str, object],
    *,
    now: dt.datetime,
    disk_used_percent: float,
    sqlite_backup_age: int | None,
    postgres_backup_age: int | None,
    previous_ingest_errors: int | None,
    previous_pending_job_counts: dict[str, int] | None = None,
    harness_database_present: bool = False,
    harness_maintenance: dict[str, object] | None = None,
    alert_store_postgres_shadow_enabled: bool = False,
    alert_store_postgres_backup_age: int | None = None,
    previous_capture_telemetry_unavailable_since: object = None,
    capture_telemetry_unavailable_grace_seconds: int = CAPTURE_TELEMETRY_UNAVAILABLE_GRACE_SECONDS,
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
    advisories: list[str] = []
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
    incident_job_age = pending_job_ages.get("incident_response_analysis", 0)
    incident_completion_age = latest_completion_ages.get("incident_response_analysis")
    incident_processing_age = processing_job_ages.get("incident_response_analysis")

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
    elif (
        ai_pending_count
        and not ai_processing_count
        and ai_job_age > 30 * 60
        and (ai_completion_age is None or ai_completion_age > 30 * 60)
    ):
        # The completion clock may be old simply because the queue was idle.
        # Require the pending work itself to be stale so a newly arrived job
        # gets its normal scheduler/inference window before it can page.
        failures.append("AI analysis has pending work but no completion within 30 minutes")
    incident_pending_count = pending_job_counts.get("incident_response_analysis", 0)
    incident_processing_count = processing_job_counts.get("incident_response_analysis", 0)
    if incident_processing_count and (
        incident_processing_age is None or incident_processing_age > 15 * 60
    ):
        failures.append(
            "incident-response analysis has been processing without state progress for 15 minutes"
        )
    elif (
        incident_pending_count
        and not incident_processing_count
        and incident_job_age > 30 * 60
        and (
            incident_completion_age is None
            or incident_completion_age > 30 * 60
        )
    ):
        failures.append(
            "incident-response analysis has pending work but no completion within 30 minutes"
        )

    previous_counts = previous_pending_job_counts or {}
    analysis_pending_count = ai_pending_count + incident_pending_count
    previous_analysis_pending = int(previous_counts.get("ai_analysis") or 0) + int(
        previous_counts.get("incident_response_analysis") or 0
    )
    material_growth = max(5, int(previous_analysis_pending * 0.05))
    if (
        previous_analysis_pending > 0
        and analysis_pending_count >= 25
        and analysis_pending_count - previous_analysis_pending >= material_growth
    ):
        advisories.append(
            "combined AI and incident-response queues are growing faster than the bounded soak gate"
        )
    for stage_name, label in (
        ("ai_analysis", "AI analysis"),
        ("incident_response_analysis", "incident-response analysis"),
        ("pcap_transfer", "PCAP transfer"),
    ):
        stage = pipeline_stages.get(stage_name, {})
        pending = int(stage.get("pending") or 0)
        throughput = dict(stage.get("throughput") or {}).get("15m", {})
        arrivals = int(throughput.get("enqueued") or 0)
        completions = int(throughput.get("completed") or 0)
        drain_eta = stage.get("drain_eta_seconds")
        if pending >= 25 and arrivals > completions:
            advisories.append(
                f"{label} 15-minute arrivals exceed completions"
            )
        if pending >= 25 and drain_eta is not None and int(drain_eta) > 4 * 60 * 60:
            advisories.append(
                f"{label} projected drain time exceeds 4 hours"
            )
    active_pcap_transfers = [
        item for item in (pcap.get("active_transfers") or [])
        if isinstance(item, dict) and item.get("progress_at")
    ]
    capture_protection = dict(pcap.get("capture_protection") or {})
    capture_protection_active = bool(capture_protection.get("active"))
    capture_protection_reason = str(
        capture_protection.get("reason")
        or "Security Onion capture telemetry is above threshold"
    )
    normalized_capture_reason = capture_protection_reason.strip().lower().replace("-", "_").replace(" ", "_")
    capture_telemetry_unavailable = (
        capture_protection_active
        and "telemetry_unavailable" in normalized_capture_reason
    )
    capture_telemetry_unavailable_since = None
    capture_telemetry_unavailable_age_seconds = 0
    if capture_telemetry_unavailable:
        capture_telemetry_unavailable_since = parse_timestamp(
            previous_capture_telemetry_unavailable_since
        ) or now
        capture_telemetry_unavailable_age_seconds = max(
            0,
            int(
                (
                    now.astimezone(dt.timezone.utc)
                    - capture_telemetry_unavailable_since.astimezone(dt.timezone.utc)
                ).total_seconds()
            ),
        )
    capture_grace = max(
        0,
        min(int(capture_telemetry_unavailable_grace_seconds), 15 * 60),
    )
    if capture_protection_active and (
        not capture_telemetry_unavailable
        or capture_telemetry_unavailable_age_seconds >= capture_grace
    ):
        reason = capture_protection_reason
        advisories.append(f"PCAP capture-protection hold: {reason}")
    pcap_queue_progressing = bool(pcap.get("queue_progressing")) or bool(active_pcap_transfers)
    pcap_workflow_operational = pcap_queue_progressing or capture_protection_active
    if int(metrics.get("oldest_pending_pcap_seconds") or 0) > 60 * 60 and not pcap_workflow_operational:
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
    if (
        alert_store_postgres_shadow_enabled
        and (
            alert_store_postgres_backup_age is None
            or alert_store_postgres_backup_age > 26 * 60 * 60
        )
    ):
        failures.append(
            "verified alert-store PostgreSQL shadow backup is missing or "
            "older than 26 hours"
        )

    harness_signal: dict[str, object] = {
        "database_present": harness_database_present,
    }
    if harness_database_present:
        maintenance = dict(harness_maintenance or {})
        maintenance_age = age_seconds(maintenance.get("generated_at"), now)
        maintenance_status = str(maintenance.get("status") or "missing")
        after = dict(maintenance.get("after") or {})
        run_counts = dict(after.get("run_counts") or {})
        policy = dict(maintenance.get("policy") or {})
        checkpoint = dict(maintenance.get("checkpoint") or {})
        if maintenance_age is None or maintenance_age > 2 * 60 * 60:
            failures.append(
                "investigation harness maintenance report is missing or "
                "older than 2 hours"
            )
        if maintenance_status in {"missing", "blocked", "absent"}:
            failures.append(
                "investigation harness maintenance is not healthy "
                f"({maintenance_status})"
            )
        if (
            after
            and (
                str(after.get("quick_check") or "") != "ok"
                or int(after.get("foreign_key_check_rows") or 0) != 0
            )
        ):
            failures.append(
                "investigation harness SQLite integrity verification failed"
            )
        if maintenance_status == "follow-up-required":
            advisories.append(
                "investigation harness retention requires another bounded pass"
            )
        if int(checkpoint.get("busy") or 0) > 0:
            advisories.append(
                "investigation harness WAL checkpoint was busy"
            )
        harness_signal.update(
            {
                "maintenance_status": maintenance_status,
                "maintenance_age_seconds": maintenance_age,
                "terminal_runs": int(run_counts.get("terminal") or 0),
                "active_runs": int(run_counts.get("active") or 0),
                "live_page_bytes": int(after.get("live_page_bytes") or 0),
                "allocated_disk_bytes": int(
                    after.get("allocated_disk_bytes") or 0
                ),
                "reclaimable_page_bytes": int(
                    after.get("reclaimable_page_bytes") or 0
                ),
                "max_live_bytes": int(policy.get("max_live_bytes") or 0),
                "follow_up_required": bool(
                    maintenance.get("follow_up_required")
                ),
                "checkpoint_busy": int(checkpoint.get("busy") or 0),
            }
        )

    snapshot = {
        "generated_at": now.astimezone().replace(microsecond=0).isoformat().replace("T", "  "),
        "ok": not failures,
        "status": "failed" if failures else ("degraded" if advisories else "healthy"),
        "failures": failures,
        "advisories": advisories,
        "signals": {
            "heartbeat_age_seconds": heartbeat_age,
            "oldest_pending_job_seconds": int(metrics.get("oldest_pending_job_seconds") or 0),
            "oldest_pending_enrichment_job_seconds": enrichment_job_age,
            "oldest_pending_ai_job_seconds": ai_job_age,
            "latest_ai_completion_age_seconds": ai_completion_age,
            "oldest_ai_processing_seconds": ai_processing_age,
            "pending_ai_job_count": ai_pending_count,
            "processing_ai_job_count": ai_processing_count,
            "oldest_pending_incident_response_job_seconds": incident_job_age,
            "latest_incident_response_completion_age_seconds": incident_completion_age,
            "oldest_incident_response_processing_seconds": incident_processing_age,
            "pending_incident_response_job_count": incident_pending_count,
            "processing_incident_response_job_count": incident_processing_count,
            "combined_analysis_pending_job_count": analysis_pending_count,
            "oldest_pending_pcap_seconds": int(metrics.get("oldest_pending_pcap_seconds") or 0),
            "pcap_warning_count": int(pcap.get("warning_count") or 0),
            "active_pcap_transfer_count": len(active_pcap_transfers),
            "pcap_queue_progressing": pcap_queue_progressing,
            "pcap_workflow_operational": pcap_workflow_operational,
            "pcap_capture_protection_active": capture_protection_active,
            "pcap_capture_protection_state": capture_protection.get("state"),
            "pcap_capture_protection_report_age_seconds": capture_protection.get("report_age_seconds"),
            "pcap_capture_telemetry_unavailable_since": (
                capture_telemetry_unavailable_since.astimezone()
                .replace(microsecond=0)
                .isoformat()
                .replace("T", "  ")
                if capture_telemetry_unavailable_since
                else None
            ),
            "pcap_capture_telemetry_unavailable_age_seconds": capture_telemetry_unavailable_age_seconds,
            "pcap_capture_telemetry_unavailable_grace_seconds": capture_grace,
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
            "alert_store_postgres_shadow_enabled": (
                alert_store_postgres_shadow_enabled
            ),
            "alert_store_postgres_backup_age_seconds": (
                alert_store_postgres_backup_age
            ),
            "investigation_harness": harness_signal,
        },
    }
    return failures, snapshot


def fetch_json(
    url: str,
    name: str,
    *,
    attempts: int = DEFAULT_PROBE_ATTEMPTS,
    retry_delay_seconds: float = DEFAULT_PROBE_RETRY_DELAY_SECONDS,
) -> dict[str, object]:
    """Fetch one bounded local probe, tolerating one transient I/O stall.

    Alert-store metrics are read-only but can briefly queue behind a large
    SQLite transaction. A single bounded retry avoids converting that tail
    latency into a stack-wide failure while persistent transport errors still
    fail the same monitor run.
    """
    bounded_attempts = max(1, min(int(attempts), 3))
    delay = max(0.0, min(float(retry_delay_seconds), 1.0))
    last_error: BaseException | None = None
    for attempt in range(bounded_attempts):
        try:
            with urllib.request.urlopen(url, timeout=8) as response:
                return read_bounded_json(response, max_bytes=MAX_PROBE_RESPONSE_BYTES)
        except (BoundedHttpError, ValueError) as exc:
            # Invalid or oversized data is a contract failure, not a transient
            # socket condition, so retrying the same response would hide it.
            raise ProbeError(f"{name} probe unavailable ({type(exc).__name__})") from None
        except (OSError, urllib.error.URLError) as exc:
            last_error = exc
            if attempt + 1 < bounded_attempts:
                time.sleep(delay)
    raise ProbeError(f"{name} probe unavailable ({type(last_error).__name__})") from None


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
    shadow_enabled = env_flag(
        args.stack_dir / ".env",
        "ALERT_STORE_POSTGRES_SHADOW_ENABLED",
    )
    usage = shutil.disk_usage(args.stack_dir)
    disk_percent = (usage.used / usage.total * 100) if usage.total else 100.0
    try:
        metrics_payload = fetch_json(args.metrics_url, "alert-store metrics")
        health_payload = fetch_json(args.health_url, "Onion Sentinel health")
    except ProbeError as exc:
        print(str(exc))
        return 2
    failures, snapshot = evaluate(
        metrics_payload,
        health_payload,
        now=now,
        disk_used_percent=disk_percent,
        sqlite_backup_age=newest_file_age(args.stack_dir / "alert_store_backups", "*.backup", now),
        postgres_backup_age=newest_file_age(args.stack_dir / "recovery_backups", "*/n8n-postgres.dump", now),
        previous_ingest_errors=int(previous["ingest_errors"]) if "ingest_errors" in previous else None,
        previous_pending_job_counts={
            str(key): int(value)
            for key, value in dict(previous.get("pending_job_counts") or {}).items()
        },
        harness_database_present=(
            args.stack_dir
            / "alert_store_data/investigation-harness.sqlite3"
        ).is_file(),
        harness_maintenance=read_json_object(
            args.stack_dir
            / "logs/investigation-harness-maintenance.json"
        ),
        alert_store_postgres_shadow_enabled=shadow_enabled,
        alert_store_postgres_backup_age=newest_file_age(
            args.stack_dir / "recovery_backups",
            "*/alert-store-postgres.dump",
            now,
        ),
        previous_capture_telemetry_unavailable_since=previous.get(
            "capture_telemetry_unavailable_since"
        ),
    )
    # A sustained or threshold-triggered capture-protection hold is not a stack
    # failure, but it must not count toward the 48-hour qualification. Brief
    # telemetry rollover gaps remain inside the bounded grace window above.
    snapshot["soak"] = update_soak_state(previous, failures + list(snapshot.get("advisories") or []), now)
    snapshot_path.write_text(json.dumps(snapshot, indent=2, sort_keys=True) + "\n")
    os.chmod(snapshot_path, 0o600)
    append_bounded_history(history_path, snapshot)
    state_path.write_text(json.dumps({
        "ingest_errors": snapshot["signals"]["ingest_errors"],
        "healthy_since": snapshot["soak"]["healthy_since"],
        "pending_job_counts": {
            "ai_analysis": snapshot["signals"]["pending_ai_job_count"],
            "incident_response_analysis": snapshot["signals"]["pending_incident_response_job_count"],
        },
        "capture_telemetry_unavailable_since": snapshot["signals"].get(
            "pcap_capture_telemetry_unavailable_since"
        ),
    }) + "\n")
    os.chmod(state_path, 0o600)
    if failures:
        print("; ".join(failures))
        return 2
    if snapshot.get("advisories"):
        print("operational SLOs degraded: " + "; ".join(snapshot["advisories"]))
        return 0
    print("operational SLOs healthy")
    return 0


if __name__ == "__main__":
    sys.exit(main())
