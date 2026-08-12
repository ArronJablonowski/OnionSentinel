"""Pure capacity, backup, and harness-maintenance SLO evaluation."""

from __future__ import annotations

import datetime as dt

from operational_slo_primitives import age_seconds


def evaluate_storage(
    pipeline_disk: dict[str, object],
    *,
    disk_used_percent: float,
    sqlite_backup_age: int | None,
    postgres_backup_age: int | None,
    alert_store_postgres_shadow_enabled: bool,
    alert_store_postgres_backup_age: int | None,
    failures: list[str],
) -> dict[str, object]:
    projected = float(
        pipeline_disk.get("projected_used_percent_with_known_backlog") or 0
    )
    _evaluate_capacity(disk_used_percent, projected, failures)
    _evaluate_backups(
        sqlite_backup_age,
        postgres_backup_age,
        alert_store_postgres_shadow_enabled,
        alert_store_postgres_backup_age,
        failures,
    )
    return _storage_signals(
        pipeline_disk,
        disk_used_percent=disk_used_percent,
        projected=projected,
        sqlite_backup_age=sqlite_backup_age,
        postgres_backup_age=postgres_backup_age,
        alert_store_postgres_shadow_enabled=alert_store_postgres_shadow_enabled,
        alert_store_postgres_backup_age=alert_store_postgres_backup_age,
    )


def _evaluate_capacity(
    disk_used_percent: float,
    projected: float,
    failures: list[str],
) -> None:
    if disk_used_percent >= 75:
        failures.append(f"Mac runtime disk is {disk_used_percent:.1f}% used")
    if disk_used_percent < 75 and projected >= 75:
        failures.append(
            f"known pipeline backlog projects Mac runtime disk to {projected:.1f}% used"
        )


def _evaluate_backups(
    sqlite_backup_age: int | None,
    postgres_backup_age: int | None,
    shadow_enabled: bool,
    shadow_backup_age: int | None,
    failures: list[str],
) -> None:
    if sqlite_backup_age is None or sqlite_backup_age > 2 * 60 * 60:
        failures.append("verified SQLite backup is missing or older than 2 hours")
    if postgres_backup_age is None or postgres_backup_age > 26 * 60 * 60:
        failures.append(
            "verified PostgreSQL recovery bundle is missing or older than 26 hours"
        )
    if shadow_enabled and (
        shadow_backup_age is None or shadow_backup_age > 26 * 60 * 60
    ):
        failures.append(
            "verified alert-store PostgreSQL shadow backup is missing or older than 26 hours"
        )


def _storage_signals(
    pipeline_disk: dict[str, object],
    *,
    disk_used_percent: float,
    projected: float,
    sqlite_backup_age: int | None,
    postgres_backup_age: int | None,
    alert_store_postgres_shadow_enabled: bool,
    alert_store_postgres_backup_age: int | None,
) -> dict[str, object]:
    return {
        "disk_used_percent": round(disk_used_percent, 1),
        "disk_new_work_limit_percent": 75,
        "disk_hard_limit_percent": 80,
        "pipeline_known_backlog_bytes": int(
            pipeline_disk.get("known_pipeline_backlog_bytes") or 0
        ),
        "pipeline_unknown_backlog_items": int(
            pipeline_disk.get("unknown_pipeline_backlog_items") or 0
        ),
        "pipeline_projected_disk_used_percent": projected,
        "pipeline_disk_growth_1h": dict(pipeline_disk.get("net_growth") or {}).get(
            "1h", {}
        ),
        "sqlite_backup_age_seconds": sqlite_backup_age,
        "postgres_backup_age_seconds": postgres_backup_age,
        "alert_store_postgres_shadow_enabled": alert_store_postgres_shadow_enabled,
        "alert_store_postgres_backup_age_seconds": alert_store_postgres_backup_age,
    }


def evaluate_harness(
    *,
    database_present: bool,
    maintenance: dict[str, object],
    now: dt.datetime,
    failures: list[str],
    advisories: list[str],
) -> dict[str, object]:
    signal: dict[str, object] = {"database_present": database_present}
    if not database_present:
        return signal
    maintenance_age = age_seconds(maintenance.get("generated_at"), now)
    status = str(maintenance.get("status") or "missing")
    after = dict(maintenance.get("after") or {})
    checkpoint = dict(maintenance.get("checkpoint") or {})
    _evaluate_harness_health(
        maintenance_age,
        status,
        after,
        checkpoint,
        failures,
        advisories,
    )
    signal.update(
        _harness_projection(
            maintenance,
            maintenance_age,
            status,
            after,
            checkpoint,
        )
    )
    return signal


def _evaluate_harness_health(
    maintenance_age: int | None,
    status: str,
    after: dict[str, object],
    checkpoint: dict[str, object],
    failures: list[str],
    advisories: list[str],
) -> None:
    _evaluate_harness_required_state(
        maintenance_age, status, failures
    )
    if _harness_integrity_failed(after):
        failures.append("investigation harness SQLite integrity verification failed")
    _evaluate_harness_advisories(status, checkpoint, advisories)


def _evaluate_harness_required_state(
    maintenance_age: int | None,
    status: str,
    failures: list[str],
) -> None:
    if maintenance_age is None or maintenance_age > 2 * 60 * 60:
        failures.append(
            "investigation harness maintenance report is missing or older than 2 hours"
        )
    if status in {"missing", "blocked", "absent"}:
        failures.append(f"investigation harness maintenance is not healthy ({status})")


def _harness_integrity_failed(after: dict[str, object]) -> bool:
    return bool(
        after
        and (
            str(after.get("quick_check") or "") != "ok"
            or int(after.get("foreign_key_check_rows") or 0) != 0
        )
    )


def _evaluate_harness_advisories(
    status: str,
    checkpoint: dict[str, object],
    advisories: list[str],
) -> None:
    if status == "follow-up-required":
        advisories.append(
            "investigation harness retention requires another bounded pass"
        )
    if int(checkpoint.get("busy") or 0) > 0:
        advisories.append("investigation harness WAL checkpoint was busy")


def _harness_projection(
    maintenance: dict[str, object],
    maintenance_age: int | None,
    status: str,
    after: dict[str, object],
    checkpoint: dict[str, object],
) -> dict[str, object]:
    run_counts = dict(after.get("run_counts") or {})
    policy = dict(maintenance.get("policy") or {})
    return {
        "maintenance_status": status,
        "maintenance_age_seconds": maintenance_age,
        "terminal_runs": int(run_counts.get("terminal") or 0),
        "active_runs": int(run_counts.get("active") or 0),
        "live_page_bytes": int(after.get("live_page_bytes") or 0),
        "allocated_disk_bytes": int(after.get("allocated_disk_bytes") or 0),
        "reclaimable_page_bytes": int(after.get("reclaimable_page_bytes") or 0),
        "max_live_bytes": int(policy.get("max_live_bytes") or 0),
        "follow_up_required": bool(maintenance.get("follow_up_required")),
        "checkpoint_busy": int(checkpoint.get("busy") or 0),
    }
