"""Pure signal evaluation and snapshot projection for operational SLOs.

This module owns thresholds and read-model composition only.  It performs no
network, filesystem, database, process, credential, or persistence work.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

from operational_slo_primitives import age_seconds, parse_timestamp
from operational_slo_queue_policy import evaluate_jobs
from operational_slo_resilience_policy import evaluate_harness, evaluate_storage


CAPTURE_TELEMETRY_UNAVAILABLE_GRACE_SECONDS = 3 * 60
SOFTWARE_INVENTORY_MAX_AGE_SECONDS = 3 * 60 * 60


@dataclass(frozen=True)
class EvaluationInputs:
    now: dt.datetime
    disk_used_percent: float
    sqlite_backup_age: int | None
    postgres_backup_age: int | None
    previous_ingest_errors: int | None
    previous_pending_job_counts: dict[str, int]
    harness_database_present: bool
    harness_maintenance: dict[str, object]
    alert_store_postgres_shadow_enabled: bool
    alert_store_postgres_backup_age: int | None
    previous_capture_telemetry_unavailable_since: object
    capture_telemetry_unavailable_grace_seconds: int
    software_inventory_health: dict[str, object]


def _pipeline_stages(pipeline: dict[str, object]) -> dict[str, dict[str, object]]:
    return {
        str(item.get("stage") or ""): dict(item)
        for item in (pipeline.get("stages") or [])
        if isinstance(item, dict)
    }


def _evaluate_software_inventory(
    health: dict[str, object],
    now: dt.datetime,
    failures: list[str],
    advisories: list[str],
) -> dict[str, object]:
    enabled = bool(health.get("enabled"))
    available = bool(health.get("available"))
    updated_age = age_seconds(health.get("updated_at"), now)
    statuses = {
        str(source): dict(status)
        for source, status in dict(health.get("source_statuses") or {}).items()
        if isinstance(status, dict)
    }
    if enabled:
        _evaluate_inventory_availability(available, updated_age, failures)
        _evaluate_osquery_inventory(statuses, failures, advisories)
    return {
        "software_inventory_enabled": enabled,
        "software_inventory_available": available,
        "software_inventory_updated_age_seconds": updated_age,
        "software_inventory_record_count": health.get("records"),
        "software_inventory_source_statuses": statuses,
    }


def _evaluate_inventory_availability(
    available: bool,
    updated_age: int | None,
    failures: list[str],
) -> None:
    if not available:
        failures.append("Software Inventory database is unavailable")
    elif updated_age is None:
        failures.append("Software Inventory has no successful snapshot")
    elif updated_age > SOFTWARE_INVENTORY_MAX_AGE_SECONDS:
        failures.append(f"Software Inventory snapshot is stale ({updated_age}s old)")


def _evaluate_osquery_inventory(
    statuses: dict[str, dict[str, object]],
    failures: list[str],
    advisories: list[str],
) -> None:
    osquery = statuses.get("osquery_apps", {})
    freshness = str(osquery.get("freshness") or "unknown").lower()
    returned = int(osquery.get("returned") or 0)
    if returned > 0 and freshness in {"stale", "expired"}:
        failures.append(f"Software Inventory OSQuery endpoint evidence is {freshness}")
    elif freshness == "empty":
        advisories.append("Software Inventory has no OSQuery endpoint evidence")


def _capture_unavailable_state(
    active: bool,
    reason: str,
    previous_since: object,
    now: dt.datetime,
) -> tuple[bool, dt.datetime | None, int]:
    normalized = reason.strip().lower().replace("-", "_").replace(" ", "_")
    unavailable = active and "telemetry_unavailable" in normalized
    if not unavailable:
        return False, None, 0
    since = parse_timestamp(previous_since) or now
    age = max(
        0,
        int(
            (
                now.astimezone(dt.timezone.utc)
                - since.astimezone(dt.timezone.utc)
            ).total_seconds()
        ),
    )
    return True, since, age


def _evaluate_pcap(
    metrics: dict[str, object],
    pcap: dict[str, object],
    inputs: EvaluationInputs,
    failures: list[str],
    advisories: list[str],
) -> dict[str, object]:
    active_transfers = _active_pcap_transfers(pcap)
    protection = dict(pcap.get("capture_protection") or {})
    protection_signals = _pcap_protection_signals(
        protection, inputs, advisories
    )
    protection_active = bool(protection_signals["active"])
    queue_progressing = bool(pcap.get("queue_progressing")) or bool(active_transfers)
    operational = queue_progressing or protection_active
    pending_age = int(metrics.get("oldest_pending_pcap_seconds") or 0)
    warning_count = int(pcap.get("warning_count") or 0)
    if pending_age > 60 * 60 and not operational:
        failures.append("PCAP backlog exceeds 60 minutes")
    if warning_count > 0:
        failures.append(f"PCAP workflow has {warning_count} warning(s)")
    return {
        "oldest_pending_pcap_seconds": pending_age,
        "pcap_warning_count": warning_count,
        "active_pcap_transfer_count": len(active_transfers),
        "pcap_queue_progressing": queue_progressing,
        "pcap_workflow_operational": operational,
        "pcap_capture_protection_active": protection_active,
        "pcap_capture_protection_state": protection.get("state"),
        "pcap_capture_protection_report_age_seconds": protection.get(
            "report_age_seconds"
        ),
        "pcap_capture_telemetry_unavailable_since": protection_signals["since"],
        "pcap_capture_telemetry_unavailable_age_seconds": protection_signals["age"],
        "pcap_capture_telemetry_unavailable_grace_seconds": protection_signals["grace"],
        "pcap_last_progress_age_seconds": pcap.get("last_progress_age_seconds"),
    }


def _active_pcap_transfers(pcap: dict[str, object]) -> list[dict[str, object]]:
    return [
        item
        for item in (pcap.get("active_transfers") or [])
        if isinstance(item, dict) and item.get("progress_at")
    ]


def _pcap_protection_signals(
    protection: dict[str, object],
    inputs: EvaluationInputs,
    advisories: list[str],
) -> dict[str, object]:
    active = bool(protection.get("active"))
    reason = str(
        protection.get("reason")
        or "Security Onion capture telemetry is above threshold"
    )
    unavailable, since, age = _capture_unavailable_state(
        active,
        reason,
        inputs.previous_capture_telemetry_unavailable_since,
        inputs.now,
    )
    grace = max(
        0,
        min(int(inputs.capture_telemetry_unavailable_grace_seconds), 15 * 60),
    )
    if active and (not unavailable or age >= grace):
        advisories.append(f"PCAP capture-protection hold: {reason}")
    since_text = None
    if since:
        since_text = (
            since.astimezone()
            .replace(microsecond=0)
            .isoformat()
            .replace("T", "  ")
        )
    return {"active": active, "since": since_text, "age": age, "grace": grace}


def _project_pipeline_stages(
    stages: dict[str, dict[str, object]],
) -> dict[str, dict[str, object]]:
    return {
        stage: {
            "pending": int(values.get("pending") or 0),
            "processing": int(values.get("processing") or 0),
            "oldest_pending_seconds": int(
                values.get("oldest_pending_seconds") or 0
            ),
            "backlog_bytes_known": int(values.get("backlog_bytes_known") or 0),
            "backlog_bytes_unknown_items": int(
                values.get("backlog_bytes_unknown_items") or 0
            ),
            "drain_eta_seconds": values.get("drain_eta_seconds"),
            "byte_drain_eta_seconds": values.get("byte_drain_eta_seconds"),
            "throughput_1h": dict(values.get("throughput") or {}).get("1h", {}),
        }
        for stage, values in stages.items()
    }


def _build_inputs(
    *,
    now: dt.datetime,
    disk_used_percent: float,
    sqlite_backup_age: int | None,
    postgres_backup_age: int | None,
    previous_ingest_errors: int | None,
    previous_pending_job_counts: dict[str, int] | None,
    harness_database_present: bool,
    harness_maintenance: dict[str, object] | None,
    alert_store_postgres_shadow_enabled: bool,
    alert_store_postgres_backup_age: int | None,
    previous_capture_telemetry_unavailable_since: object,
    capture_telemetry_unavailable_grace_seconds: int,
    software_inventory_health: dict[str, object] | None,
) -> EvaluationInputs:
    return EvaluationInputs(
        now=now,
        disk_used_percent=disk_used_percent,
        sqlite_backup_age=sqlite_backup_age,
        postgres_backup_age=postgres_backup_age,
        previous_ingest_errors=previous_ingest_errors,
        previous_pending_job_counts=previous_pending_job_counts or {},
        harness_database_present=harness_database_present,
        harness_maintenance=dict(harness_maintenance or {}),
        alert_store_postgres_shadow_enabled=alert_store_postgres_shadow_enabled,
        alert_store_postgres_backup_age=alert_store_postgres_backup_age,
        previous_capture_telemetry_unavailable_since=previous_capture_telemetry_unavailable_since,
        capture_telemetry_unavailable_grace_seconds=capture_telemetry_unavailable_grace_seconds,
        software_inventory_health=dict(software_inventory_health or {}),
    )


def _payload_views(
    metrics_payload: dict[str, object],
    health_payload: dict[str, object],
) -> tuple[
    dict[str, object],
    dict[str, object],
    dict[str, object],
    dict[str, object],
    dict[str, dict[str, object]],
]:
    metrics = dict(metrics_payload.get("metrics") or {})
    latest = dict(dict(health_payload.get("summary") or {}).get("latest") or {})
    pcap = dict(health_payload.get("pcap") or {})
    pipeline = dict(metrics.get("pipeline") or {})
    return (
        metrics,
        latest,
        pcap,
        dict(pipeline.get("disk") or {}),
        _pipeline_stages(pipeline),
    )


def _heartbeat_signal(
    latest: dict[str, object],
    now: dt.datetime,
    failures: list[str],
) -> int | None:
    heartbeat_age = age_seconds(
        latest.get("timestamp_utc") or latest.get("timestamp"), now
    )
    if heartbeat_age is None or heartbeat_age > 20 * 60:
        rendered_age = heartbeat_age if heartbeat_age is not None else "unknown"
        failures.append(f"relay heartbeat stale ({rendered_age}s)")
    return heartbeat_age


def _ingest_signal(
    metrics: dict[str, object],
    previous_ingest_errors: int | None,
    failures: list[str],
) -> int:
    ingest_errors = int(dict(metrics.get("process") or {}).get("ingest_errors") or 0)
    if previous_ingest_errors is not None and ingest_errors > previous_ingest_errors:
        failures.append(
            f"alert ingest errors increased by {ingest_errors - previous_ingest_errors}"
        )
    return ingest_errors


def _snapshot_status(failures: list[str], advisories: list[str]) -> str:
    if failures:
        return "failed"
    return "degraded" if advisories else "healthy"


def _compose_signals(
    metrics: dict[str, object],
    latest: dict[str, object],
    pcap: dict[str, object],
    pipeline_disk: dict[str, object],
    stages: dict[str, dict[str, object]],
    inputs: EvaluationInputs,
    failures: list[str],
    advisories: list[str],
) -> dict[str, object]:
    inventory = _evaluate_software_inventory(
        inputs.software_inventory_health, inputs.now, failures, advisories
    )
    signals = {
        "heartbeat_age_seconds": _heartbeat_signal(
            latest, inputs.now, failures
        ),
        **evaluate_jobs(
            metrics,
            stages,
            inputs.previous_pending_job_counts,
            failures,
            advisories,
        ),
        **_evaluate_pcap(metrics, pcap, inputs, failures, advisories),
        **inventory,
    }
    signals["ingest_errors"] = _ingest_signal(
        metrics, inputs.previous_ingest_errors, failures
    )
    signals.update(_storage_signals(pipeline_disk, inputs, failures))
    signals["pipeline_stages"] = _project_pipeline_stages(stages)
    signals["investigation_harness"] = evaluate_harness(
        database_present=inputs.harness_database_present,
        maintenance=inputs.harness_maintenance,
        now=inputs.now,
        failures=failures,
        advisories=advisories,
    )
    return signals


def _storage_signals(
    pipeline_disk: dict[str, object],
    inputs: EvaluationInputs,
    failures: list[str],
) -> dict[str, object]:
    return evaluate_storage(
        pipeline_disk,
        disk_used_percent=inputs.disk_used_percent,
        sqlite_backup_age=inputs.sqlite_backup_age,
        postgres_backup_age=inputs.postgres_backup_age,
        alert_store_postgres_shadow_enabled=(
            inputs.alert_store_postgres_shadow_enabled
        ),
        alert_store_postgres_backup_age=inputs.alert_store_postgres_backup_age,
        failures=failures,
    )


def _evaluate_inputs(
    metrics_payload: dict[str, object],
    health_payload: dict[str, object],
    inputs: EvaluationInputs,
) -> tuple[list[str], dict[str, object]]:
    metrics, latest, pcap, pipeline_disk, stages = _payload_views(
        metrics_payload, health_payload
    )
    failures: list[str] = []
    advisories: list[str] = []
    signals = _compose_signals(
        metrics,
        latest,
        pcap,
        pipeline_disk,
        stages,
        inputs,
        failures,
        advisories,
    )
    snapshot = {
        "generated_at": inputs.now.astimezone()
        .replace(microsecond=0)
        .isoformat()
        .replace("T", "  "),
        "ok": not failures,
        "status": _snapshot_status(failures, advisories),
        "failures": failures,
        "advisories": advisories,
        "signals": signals,
    }
    return failures, snapshot


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
    software_inventory_health: dict[str, object] | None = None,
) -> tuple[list[str], dict[str, object]]:
    inputs = _build_inputs(
        now=now,
        disk_used_percent=disk_used_percent,
        sqlite_backup_age=sqlite_backup_age,
        postgres_backup_age=postgres_backup_age,
        previous_ingest_errors=previous_ingest_errors,
        previous_pending_job_counts=previous_pending_job_counts,
        harness_database_present=harness_database_present,
        harness_maintenance=harness_maintenance,
        alert_store_postgres_shadow_enabled=alert_store_postgres_shadow_enabled,
        alert_store_postgres_backup_age=alert_store_postgres_backup_age,
        previous_capture_telemetry_unavailable_since=previous_capture_telemetry_unavailable_since,
        capture_telemetry_unavailable_grace_seconds=capture_telemetry_unavailable_grace_seconds,
        software_inventory_health=software_inventory_health,
    )
    return _evaluate_inputs(metrics_payload, health_payload, inputs)
