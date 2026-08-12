"""Command-line orchestration for investigation-harness maintenance."""

from __future__ import annotations

import argparse
import fcntl
import json
import os
from pathlib import Path
from typing import Any

from harness_maintenance_contract import (
    DEFAULT_INCREMENTAL_VACUUM_PAGES,
    DEFAULT_MAX_BACKUP_AGE_SECONDS,
    DEFAULT_MAX_DELETE_RUNS,
    DEFAULT_MAX_LIVE_BYTES,
    DEFAULT_MAX_RECONCILE_RUNS,
    DEFAULT_MAX_TERMINAL_RUNS,
    DEFAULT_MIN_TERMINAL_RUNS,
    DEFAULT_RETENTION_DAYS,
    DEFAULT_STALE_RUNNING_SECONDS,
    MaintenanceError,
    bounded_int,
    timestamp_text,
    utc_now,
)
from harness_maintenance_integrity import verify_recent_harness_backup
from harness_maintenance_recovery import reconcile_stale_running_runs
from harness_maintenance_reporting import atomic_write_report
from harness_maintenance_retention import maintain_database


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stack-dir", type=Path, default=Path.home() / "n8n-local")
    parser.add_argument("--db", type=Path)
    parser.add_argument("--alert-db", type=Path)
    parser.add_argument("--backup-root", type=Path)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--retention-days", type=int, default=DEFAULT_RETENTION_DAYS)
    parser.add_argument(
        "--max-terminal-runs", type=int, default=DEFAULT_MAX_TERMINAL_RUNS
    )
    parser.add_argument(
        "--min-terminal-runs", type=int, default=DEFAULT_MIN_TERMINAL_RUNS
    )
    parser.add_argument(
        "--max-delete-runs", type=int, default=DEFAULT_MAX_DELETE_RUNS
    )
    parser.add_argument("--max-live-bytes", type=int, default=DEFAULT_MAX_LIVE_BYTES)
    parser.add_argument(
        "--incremental-vacuum-pages",
        type=int,
        default=DEFAULT_INCREMENTAL_VACUUM_PAGES,
    )
    parser.add_argument(
        "--max-backup-age-seconds",
        type=int,
        default=DEFAULT_MAX_BACKUP_AGE_SECONDS,
    )
    parser.add_argument(
        "--stale-running-seconds",
        type=int,
        default=DEFAULT_STALE_RUNNING_SECONDS,
    )
    parser.add_argument(
        "--max-reconcile-runs", type=int, default=DEFAULT_MAX_RECONCILE_RUNS
    )
    parser.add_argument("--apply", action="store_true")
    return parser


def validated_policy(args: argparse.Namespace) -> dict[str, int]:
    return {
        **_retention_policy(args),
        **_database_limits(args),
        **_recovery_policy(args),
    }


def _retention_policy(args: argparse.Namespace) -> dict[str, int]:
    retention_days = bounded_int(
        args.retention_days,
        name="retention days",
        minimum=1,
        maximum=3_650,
    )
    max_terminal_runs = bounded_int(
        args.max_terminal_runs,
        name="maximum terminal runs",
        minimum=100,
        maximum=1_000_000,
    )
    return {
        "retention_days": retention_days,
        "max_terminal_runs": max_terminal_runs,
        "min_terminal_runs": bounded_int(
            args.min_terminal_runs,
            name="minimum terminal runs",
            minimum=0,
            maximum=max_terminal_runs,
        ),
    }


def _database_limits(args: argparse.Namespace) -> dict[str, int]:
    return {
        "max_delete_runs": bounded_int(
            args.max_delete_runs,
            name="maximum deletions per pass",
            minimum=1,
            maximum=5_000,
        ),
        "max_live_bytes": bounded_int(
            args.max_live_bytes,
            name="maximum live bytes",
            minimum=64 * 1024**2,
            maximum=64 * 1024**3,
        ),
        "incremental_vacuum_pages": bounded_int(
            args.incremental_vacuum_pages,
            name="incremental vacuum pages",
            minimum=0,
            maximum=65_536,
        ),
    }


def _recovery_policy(args: argparse.Namespace) -> dict[str, int]:
    return {
        "max_backup_age_seconds": bounded_int(
            args.max_backup_age_seconds,
            name="maximum backup age",
            minimum=60,
            maximum=7 * 24 * 60 * 60,
        ),
        "stale_running_seconds": bounded_int(
            args.stale_running_seconds,
            name="stale running seconds",
            minimum=30 * 60,
            maximum=7 * 24 * 60 * 60,
        ),
        "max_reconcile_runs": bounded_int(
            args.max_reconcile_runs,
            name="maximum stale run reconciliations",
            minimum=1,
            maximum=1_000,
        ),
    }


def resolved_paths(args: argparse.Namespace) -> dict[str, Path]:
    stack_dir = args.stack_dir.expanduser()
    return {
        "stack_dir": stack_dir,
        "db": (
            args.db.expanduser()
            if args.db
            else stack_dir / "alert_store_data/investigation-harness.sqlite3"
        ),
        "alert_db": (
            args.alert_db.expanduser()
            if args.alert_db
            else stack_dir / "alert_store_data/alerts.sqlite3"
        ),
        "backup_root": (
            args.backup_root.expanduser()
            if args.backup_root
            else stack_dir / "recovery_backups"
        ),
        "report": (
            args.report.expanduser()
            if args.report
            else stack_dir / "logs/investigation-harness-maintenance.json"
        ),
    }


def run_maintenance(
    args: argparse.Namespace,
    paths: dict[str, Path],
    policy: dict[str, int],
) -> dict[str, Any]:
    db_path = paths["db"]
    lock_path = db_path.parent / ".investigation-harness-maintenance.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with lock_path.open("w", encoding="utf-8") as lock:
        os.chmod(lock_path, 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        reconciliation = _reconcile_stale_runs(args, paths, policy, db_path)
        result = _maintain_locked_database(
            args,
            paths,
            policy,
            db_path,
        )
    return {"stale_run_reconciliation": reconciliation, **result}


def _reconcile_stale_runs(
    args: argparse.Namespace,
    paths: dict[str, Path],
    policy: dict[str, int],
    db_path: Path,
) -> dict[str, Any]:
    return reconcile_stale_running_runs(
        db_path,
        paths["alert_db"],
        worker_lock_paths=(
            paths["stack_dir"] / "run/ai-analysis-ollama-worker.lock",
            paths["stack_dir"] / "run/ai-analysis-cli-worker.lock",
        ),
        now=utc_now(),
        stale_running_seconds=policy["stale_running_seconds"],
        limit=policy["max_reconcile_runs"],
        apply=args.apply,
    )


def _database_policy(policy: dict[str, int]) -> dict[str, int]:
    return {
        key: policy[key]
        for key in (
            "retention_days",
            "max_terminal_runs",
            "min_terminal_runs",
            "max_delete_runs",
            "max_live_bytes",
            "incremental_vacuum_pages",
        )
    }


def _maintain_locked_database(
    args: argparse.Namespace,
    paths: dict[str, Path],
    policy: dict[str, int],
    db_path: Path,
) -> dict[str, Any]:
    database_policy = _database_policy(policy)
    preview = maintain_database(
        db_path,
        now=utc_now(),
        apply=False,
        backup=None,
        **database_policy,
    )
    backup = _verified_backup_for_candidates(args, paths, policy, preview)
    return (
        maintain_database(
            db_path,
            now=utc_now(),
            apply=True,
            backup=backup,
            **database_policy,
        )
        if args.apply
        else preview
    )


def _verified_backup_for_candidates(
    args: argparse.Namespace,
    paths: dict[str, Path],
    policy: dict[str, int],
    preview: dict[str, Any],
) -> dict[str, Any] | None:
    selected = int(dict(preview.get("candidates") or {}).get("selected") or 0)
    if not args.apply or not preview.get("database_present") or not selected:
        return None
    return verify_recent_harness_backup(
        paths["backup_root"],
        now=utc_now(),
        max_age_seconds=policy["max_backup_age_seconds"],
        required_run_ids=tuple(
            str(value) for value in preview.get("_candidate_run_ids", ())
        ),
    )


def main() -> int:
    args = build_parser().parse_args()
    paths = resolved_paths(args)
    report: dict[str, Any] = {
        "generated_at": timestamp_text(utc_now()),
        "status": "running",
        "database": str(paths["db"]),
    }
    return_code = 0
    try:
        report.update(run_maintenance(args, paths, validated_policy(args)))
        report.pop("_candidate_run_ids", None)
        report["generated_at"] = timestamp_text(utc_now())
        if report.get("status") == "follow-up-required":
            return_code = 1
    except (MaintenanceError, BlockingIOError, OSError, ValueError) as exc:
        report.update(
            {
                "status": "blocked",
                "error": str(exc),
                "generated_at": timestamp_text(utc_now()),
            }
        )
        return_code = 2
    atomic_write_report(paths["report"], report)
    print(json.dumps({"ok": return_code == 0, **report}, sort_keys=True))
    return return_code
