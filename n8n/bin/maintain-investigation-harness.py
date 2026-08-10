#!/usr/bin/env python3
"""Compatibility CLI for bounded investigation-harness maintenance."""

import sys
from pathlib import Path

BIN_DIR = Path(__file__).resolve().parent
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))

from harness_maintenance_cli import main
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
    MAX_BACKUP_MANIFEST_BYTES,
    RECONCILABLE_JOB_TYPES,
    REQUIRED_TABLES,
    TERMINAL_STATUSES,
    MaintenanceError,
    bounded_int,
    canonical_json,
    digest_json,
    load_harness_runtime,
    parse_timestamp,
    sha256_file,
    timestamp_text,
    utc_now,
)
from harness_maintenance_integrity import (
    database_snapshot,
    sqlite_file_accounting,
    verify_event_chains,
    verify_recent_harness_backup,
)
from harness_maintenance_recovery import (
    reconcile_stale_running_runs,
    select_stale_running_reconciliations,
)
from harness_maintenance_reporting import atomic_write_report
from harness_maintenance_retention import maintain_database, select_prunable_runs


if __name__ == "__main__":
    raise SystemExit(main())
