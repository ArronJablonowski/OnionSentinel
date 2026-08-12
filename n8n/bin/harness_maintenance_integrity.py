"""SQLite and recovery-bundle integrity checks for harness maintenance."""

from __future__ import annotations

from contextlib import closing
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
from typing import Any

from harness_maintenance_contract import (
    MAX_BACKUP_MANIFEST_BYTES,
    REQUIRED_TABLES,
    TERMINAL_STATUSES,
    MaintenanceError,
    digest_json,
    parse_timestamp,
    sha256_file,
)


def owner_only_regular_file(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    return (
        stat.S_ISREG(metadata.st_mode)
        and not stat.S_ISLNK(metadata.st_mode)
        and stat.S_IMODE(metadata.st_mode) & 0o077 == 0
        and metadata.st_uid == os.getuid()
    )


def owner_readable_regular_file(path: Path) -> bool:
    """Accept read-only source databases that only their owner may modify."""
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    return (
        stat.S_ISREG(metadata.st_mode)
        and not stat.S_ISLNK(metadata.st_mode)
        and stat.S_IMODE(metadata.st_mode) & 0o022 == 0
        and metadata.st_uid == os.getuid()
    )


def owner_only_directory(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    return (
        stat.S_ISDIR(metadata.st_mode)
        and not stat.S_ISLNK(metadata.st_mode)
        and stat.S_IMODE(metadata.st_mode) & 0o077 == 0
        and metadata.st_uid == os.getuid()
    )


def sqlite_file_accounting(path: Path) -> dict[str, int]:
    logical = 0
    allocated = 0
    for candidate in (path, Path(f"{path}-wal"), Path(f"{path}-shm")):
        try:
            metadata = candidate.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise MaintenanceError(
                f"harness SQLite sidecar is not a regular file: {candidate}"
            )
        logical += int(metadata.st_size)
        allocated += int(getattr(metadata, "st_blocks", 0) or 0) * 512
    return {
        "logical_file_bytes": logical,
        "allocated_disk_bytes": allocated or logical,
    }


def table_names(connection: sqlite3.Connection) -> set[str]:
    return {
        str(row[0])
        for row in connection.execute(
            """
            SELECT name FROM sqlite_master
            WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
            """
        ).fetchall()
    }


def verify_event_chains(
    connection: sqlite3.Connection,
    run_ids: tuple[str, ...],
) -> bool:
    """Verify the hash-chained event ledger for exact retention candidates."""
    if not run_ids:
        return True
    events_by_run: dict[str, list[sqlite3.Row]] = {
        run_id: [] for run_id in run_ids
    }
    status_by_run: dict[str, str] = {}
    for offset in range(0, len(run_ids), 400):
        batch = run_ids[offset : offset + 400]
        placeholders = ",".join("?" for _ in batch)
        status_by_run.update(
            {
                str(row["run_id"]): str(row["status"])
                for row in connection.execute(
                    f"""
                    SELECT run_id, status FROM harness_runs
                    WHERE run_id IN ({placeholders})
                    """,
                    batch,
                ).fetchall()
            }
        )
        rows = connection.execute(
            f"""
            SELECT * FROM harness_events
            WHERE run_id IN ({placeholders})
            ORDER BY run_id, sequence
            """,
            batch,
        ).fetchall()
        for row in rows:
            events_by_run.setdefault(str(row["run_id"]), []).append(row)
    for run_id in run_ids:
        rows = events_by_run.get(run_id) or []
        status = status_by_run.get(run_id, "")
        if not _verify_run_event_chain(run_id, status, rows):
            return False
    return True


def _verify_run_event_chain(
    run_id: str,
    status: str,
    rows: list[sqlite3.Row],
) -> bool:
    if (
        not rows
        or status not in TERMINAL_STATUSES
        or str(rows[-1]["event_type"]) != f"run.{status}"
    ):
        return False
    previous = "0" * 64
    for expected_sequence, row in enumerate(rows, start=1):
        try:
            sequence, payload_digest, event_digest = _event_chain_digests(
                run_id,
                row,
            )
        except (IndexError, KeyError, TypeError, ValueError, OverflowError):
            return False
        if not _event_chain_row_is_valid(
            row,
            sequence=sequence,
            expected_sequence=expected_sequence,
            payload_digest=payload_digest,
            previous=previous,
            event_digest=event_digest,
        ):
            return False
        previous = str(row["event_sha256"])
    return True


def _event_chain_digests(
    run_id: str,
    row: sqlite3.Row,
) -> tuple[int, str, str]:
    sequence = int(row["sequence"])
    payload_json = str(row["payload_json"])
    payload_digest = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
    body = {
        "run_id": run_id,
        "sequence": sequence,
        "idempotency_key": row["idempotency_key"],
        "event_type": row["event_type"],
        "stage": row["stage"],
        "created_at": row["created_at"],
        "payload_sha256": row["payload_sha256"],
        "previous_event_sha256": row["previous_event_sha256"],
    }
    return sequence, payload_digest, digest_json(body)


def _event_chain_row_is_valid(
    row: sqlite3.Row,
    *,
    sequence: int,
    expected_sequence: int,
    payload_digest: str,
    previous: str,
    event_digest: str,
) -> bool:
    return (
        sequence == expected_sequence
        and str(row["payload_sha256"]) == payload_digest
        and str(row["previous_event_sha256"]) == previous
        and str(row["event_sha256"]) == event_digest
        and str(row["event_id"]) == f"evt-{event_digest[:32]}"
    )


def database_snapshot(
    connection: sqlite3.Connection,
    path: Path,
) -> dict[str, Any]:
    quick_check, foreign_key_errors = _validated_database_health(connection)
    pages = _database_page_state(connection)
    run_counts = _database_run_counts(connection)
    accounting = sqlite_file_accounting(path)
    return {
        "quick_check": quick_check,
        "foreign_key_check_rows": foreign_key_errors,
        "journal_mode": pages["journal_mode"],
        "auto_vacuum": pages["auto_vacuum"],
        "page_size": pages["page_size"],
        "page_count": pages["page_count"],
        "freelist_pages": pages["freelist_pages"],
        "live_page_bytes": pages["live_page_bytes"],
        "reclaimable_page_bytes": pages["reclaimable_page_bytes"],
        "run_counts": run_counts,
        **accounting,
    }


def _validated_database_health(
    connection: sqlite3.Connection,
) -> tuple[str, int]:
    quick_check = str(connection.execute("PRAGMA quick_check").fetchone()[0])
    if quick_check != "ok":
        raise MaintenanceError(
            f"harness SQLite quick_check failed: {quick_check}"
        )
    missing = sorted(REQUIRED_TABLES.difference(table_names(connection)))
    if missing:
        raise MaintenanceError(
            "harness SQLite is missing table(s): " + ", ".join(missing)
        )
    foreign_key_errors = len(
        connection.execute("PRAGMA foreign_key_check").fetchall()
    )
    if foreign_key_errors:
        raise MaintenanceError(
            "harness SQLite foreign_key_check failed: "
            f"{foreign_key_errors} row(s)"
        )
    return quick_check, foreign_key_errors


def _database_page_state(connection: sqlite3.Connection) -> dict[str, Any]:
    page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
    page_count = int(connection.execute("PRAGMA page_count").fetchone()[0])
    freelist_count = int(
        connection.execute("PRAGMA freelist_count").fetchone()[0]
    )
    journal_mode = str(connection.execute("PRAGMA journal_mode").fetchone()[0])
    auto_vacuum = int(connection.execute("PRAGMA auto_vacuum").fetchone()[0])
    return {
        "journal_mode": journal_mode.lower(),
        "auto_vacuum": auto_vacuum,
        "page_size": page_size,
        "page_count": page_count,
        "freelist_pages": freelist_count,
        "live_page_bytes": max(0, page_count - freelist_count) * page_size,
        "reclaimable_page_bytes": freelist_count * page_size,
    }


def _database_run_counts(connection: sqlite3.Connection) -> dict[str, int]:
    counts = connection.execute(
        """
        SELECT
          COUNT(*) AS total,
          SUM(CASE WHEN status IN (?, ?, ?) THEN 1 ELSE 0 END) AS terminal,
          SUM(CASE WHEN status NOT IN (?, ?, ?) THEN 1 ELSE 0 END) AS active
        FROM harness_runs
        """,
        (*TERMINAL_STATUSES, *TERMINAL_STATUSES),
    ).fetchone()
    return {
        "total": int(counts[0] or 0),
        "terminal": int(counts[1] or 0),
        "active": int(counts[2] or 0),
    }


def verify_recent_harness_backup(
    backup_root: Path,
    *,
    now: dt.datetime,
    max_age_seconds: int,
    required_run_ids: tuple[str, ...] = (),
) -> dict[str, Any]:
    if not owner_only_directory(backup_root):
        raise MaintenanceError(
            "recovery backup directory must be owner-only and not a symlink"
        )
    bundles = sorted(
        (
            path
            for path in backup_root.iterdir()
            if owner_only_directory(path) and not path.name.startswith(".")
        ),
        reverse=True,
    )
    for bundle in bundles:
        verified = _verify_backup_bundle(
            bundle,
            now=now,
            max_age_seconds=max_age_seconds,
            required_run_ids=required_run_ids,
        )
        if verified is not None:
            return verified
    raise MaintenanceError(
        "no recent hash-verified harness recovery snapshot is available"
    )


def _verify_backup_bundle(
    bundle: Path,
    *,
    now: dt.datetime,
    max_age_seconds: int,
    required_run_ids: tuple[str, ...],
) -> dict[str, Any] | None:
    manifest_path = bundle / "manifest.json"
    harness_path = bundle / "investigation-harness.sqlite3"
    if not _backup_files_are_admissible(manifest_path, harness_path):
        return None
    metadata = _load_backup_metadata(manifest_path)
    if metadata is None:
        return None
    manifest, created, harness_manifest, file_manifest = metadata
    age_seconds = _backup_age_seconds(now, created, max_age_seconds)
    if not _backup_age_is_valid(
        created,
        harness_manifest,
        age_seconds,
        max_age_seconds,
    ):
        return None
    expected_digest = str(file_manifest.get("sha256") or "")
    snapshot = _verified_backup_snapshot(
        harness_path,
        required_run_ids,
        expected_digest,
    )
    if snapshot is None:
        return None
    runs, covered_run_ids, candidate_chains_valid = snapshot
    if not _backup_snapshot_matches_manifest(
        runs,
        covered_run_ids,
        candidate_chains_valid,
        harness_manifest,
        manifest,
        required_run_ids,
    ):
        return None
    return _backup_verification_result(
        bundle,
        age_seconds,
        expected_digest,
        runs,
        covered_run_ids,
        candidate_chains_valid,
    )


def _backup_verification_result(
    bundle: Path,
    age_seconds: int,
    expected_digest: str,
    runs: int,
    covered_run_ids: set[str],
    candidate_chains_valid: bool,
) -> dict[str, Any]:
    return {
        "verified": True,
        "bundle": bundle.name,
        "age_seconds": max(0, age_seconds),
        "sha256": expected_digest,
        "run_rows": runs,
        "covered_retention_candidates": len(covered_run_ids),
        "candidate_event_chains_valid": candidate_chains_valid,
        "_covered_run_ids": tuple(sorted(covered_run_ids)),
    }


def _backup_files_are_admissible(
    manifest_path: Path,
    harness_path: Path,
) -> bool:
    return (
        owner_only_regular_file(manifest_path)
        and owner_only_regular_file(harness_path)
        and manifest_path.stat().st_size <= MAX_BACKUP_MANIFEST_BYTES
    )


def _verified_backup_snapshot(
    harness_path: Path,
    required_run_ids: tuple[str, ...],
    expected_digest: str,
) -> tuple[int, set[str], bool] | None:
    if len(expected_digest) != 64 or sha256_file(harness_path) != expected_digest:
        return None
    return _inspect_backup_database(harness_path, required_run_ids)


def _backup_snapshot_matches_manifest(
    runs: int,
    covered_run_ids: set[str],
    candidate_chains_valid: bool,
    harness_manifest: dict,
    manifest: dict,
    required_run_ids: tuple[str, ...],
) -> bool:
    return (
        runs == int(harness_manifest.get("rows", -1))
        and runs == int(manifest.get("harness_runs", -1))
        and covered_run_ids == set(required_run_ids)
        and candidate_chains_valid
    )


def _load_backup_metadata(
    manifest_path: Path,
) -> tuple[dict[str, Any], dt.datetime | None, dict, dict] | None:
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        created = parse_timestamp(manifest.get("created_at"))
        harness_manifest = dict(
            dict(manifest.get("sqlite") or {}).get("investigation_harness") or {}
        )
        file_manifest = dict(
            dict(manifest.get("files") or {}).get(
                "investigation-harness.sqlite3"
            )
            or {}
        )
        return manifest, created, harness_manifest, file_manifest
    except (OSError, ValueError, TypeError):
        return None


def _backup_age_is_valid(
    created: dt.datetime | None,
    harness_manifest: dict,
    age_seconds: int,
    max_age_seconds: int,
) -> bool:
    return (
        created is not None
        and bool(harness_manifest.get("present"))
        and age_seconds >= -300
        and age_seconds <= max_age_seconds
    )


def _backup_age_seconds(
    now: dt.datetime,
    created: dt.datetime | None,
    max_age_seconds: int,
) -> int:
    return (
        int((now - created).total_seconds())
        if created is not None
        else max_age_seconds + 1
    )


def _inspect_backup_database(
    harness_path: Path,
    required_run_ids: tuple[str, ...],
) -> tuple[int, set[str], bool] | None:
    try:
        uri = f"{harness_path.resolve().as_uri()}?mode=ro&immutable=1"
        with closing(sqlite3.connect(uri, uri=True, timeout=5.0)) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA query_only = ON")
            if str(connection.execute("PRAGMA quick_check").fetchone()[0]) != "ok":
                return None
            if REQUIRED_TABLES.difference(table_names(connection)):
                return None
            runs = int(
                connection.execute("SELECT COUNT(*) FROM harness_runs").fetchone()[0]
            )
            covered_run_ids: set[str] = set()
            for offset in range(0, len(required_run_ids), 400):
                batch = required_run_ids[offset : offset + 400]
                placeholders = ",".join("?" for _ in batch)
                covered_run_ids.update(
                    str(row[0])
                    for row in connection.execute(
                        f"""
                        SELECT run_id FROM harness_runs
                        WHERE run_id IN ({placeholders})
                          AND status IN (?, ?, ?)
                        """,
                        (*batch, *TERMINAL_STATUSES),
                    ).fetchall()
                )
            return (
                runs,
                covered_run_ids,
                verify_event_chains(connection, required_run_ids),
            )
    except sqlite3.Error:
        return None
