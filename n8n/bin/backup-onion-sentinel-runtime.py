#!/usr/bin/env python3
"""Create an atomic, verified local disaster-recovery bundle."""

from __future__ import annotations

import argparse
from contextlib import closing
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tarfile

BIN_DIR = Path(__file__).resolve().parent
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))
from disk_capacity import require_runtime_capacity


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sqlite_tables(connection: sqlite3.Connection) -> set[str]:
    return {
        str(row[0])
        for row in connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
            """
        ).fetchall()
    }


def _validate_sqlite_connection(
    connection: sqlite3.Connection,
    *,
    required_tables: tuple[str, ...],
    count_table: str,
) -> tuple[str, int]:
    result = str(connection.execute("PRAGMA quick_check").fetchone()[0])
    if result != "ok":
        raise RuntimeError(f"SQLite backup failed quick_check: {result}")
    missing = sorted(set(required_tables).difference(_sqlite_tables(connection)))
    if missing:
        raise RuntimeError(
            "SQLite backup is missing required table(s): " + ", ".join(missing)
        )
    rows = int(
        connection.execute(f'SELECT COUNT(*) FROM "{count_table}"').fetchone()[0]
    )
    return result, rows


def _sqlite_sidecar_paths(database: Path) -> tuple[Path, Path]:
    return (
        Path(f"{database}-wal"),
        Path(f"{database}-shm"),
    )


def _canonicalize_sqlite_snapshot(
    connection: sqlite3.Connection,
    destination: Path,
) -> str:
    """Make a backup self-contained even when its source uses WAL.

    SQLite's online backup API copies the source database's persistent journal
    mode. Opening that copied database for validation can therefore create
    ``-wal`` and ``-shm`` files in the recovery bundle. A restore must not need
    those transient files, so switch the private snapshot to DELETE mode before
    validating or publishing it.
    """

    row = connection.execute("PRAGMA journal_mode = DELETE").fetchone()
    journal_mode = str(row[0] if row else "").strip().lower()
    if journal_mode != "delete":
        raise RuntimeError(
            "SQLite backup could not be canonicalized to DELETE journal mode"
        )
    connection.commit()
    for sidecar in _sqlite_sidecar_paths(destination):
        try:
            sidecar.unlink()
        except FileNotFoundError:
            pass
    return journal_mode


def __copy_sqlite_snapshot(source: Path, destination: Path) -> str:
    # sqlite3.Connection's context manager commits or rolls back but does not
    # close the handle. Explicit closing keeps repeated backup jobs bounded.
    with closing(sqlite3.connect(source)) as src, closing(
        sqlite3.connect(destination)
    ) as dst:
        with src, dst:
            src.backup(dst)
            return _canonicalize_sqlite_snapshot(dst, destination)


def __verify_sqlite_snapshot(
    destination: Path,
    *,
    required_tables: tuple[str, ...],
    count_table: str,
) -> tuple[str, int, int, str, int, int]:
    with closing(sqlite3.connect(destination)) as check:
        quick_check, rows = _validate_sqlite_connection(
            check,
            required_tables=required_tables,
            count_table=count_table,
        )
        foreign_key_errors = len(
            check.execute("PRAGMA foreign_key_check").fetchall()
        )
        if foreign_key_errors:
            raise RuntimeError(
                f"SQLite backup failed foreign_key_check: "
                f"{foreign_key_errors} row(s)"
            )
        with closing(sqlite3.connect(":memory:")) as restored:
            check.backup(restored)
            restore_check, restored_rows = _validate_sqlite_connection(
                restored,
                required_tables=required_tables,
                count_table=count_table,
            )
            restore_foreign_key_errors = len(
                restored.execute("PRAGMA foreign_key_check").fetchall()
            )
    return (
        quick_check,
        rows,
        foreign_key_errors,
        restore_check,
        restored_rows,
        restore_foreign_key_errors,
    )


def __validate_logical_restore(
    *,
    rows: int,
    restored_rows: int,
    restore_foreign_key_errors: int,
) -> None:
    if restore_foreign_key_errors:
        raise RuntimeError(
            "SQLite logical restore failed foreign_key_check: "
            f"{restore_foreign_key_errors} row(s)"
        )
    if restored_rows != rows:
        raise RuntimeError(
            "SQLite logical restore row count does not match snapshot"
        )


def __validate_no_sqlite_sidecars(destination: Path) -> None:
    unexpected_sidecars = [
        path.name
        for path in _sqlite_sidecar_paths(destination)
        if path.exists() or path.is_symlink()
    ]
    if unexpected_sidecars:
        raise RuntimeError(
            "canonical SQLite backup retained transient sidecar(s): "
            + ", ".join(unexpected_sidecars)
        )


def backup_sqlite_database(
    source: Path,
    destination: Path,
    *,
    required_tables: tuple[str, ...],
    count_table: str,
) -> dict[str, object]:
    """Create and logically restore one consistent SQLite snapshot.

    SQLite's online backup API includes committed WAL content. Restoring that
    snapshot into an independent in-memory database catches artifacts which
    are readable as files but cannot be restored through SQLite itself.
    """
    if source.is_symlink() or not source.is_file():
        raise RuntimeError(f"SQLite source is not a regular file: {source}")
    journal_mode = __copy_sqlite_snapshot(source, destination)
    (
        quick_check,
        rows,
        foreign_key_errors,
        restore_check,
        restored_rows,
        restore_foreign_key_errors,
    ) = __verify_sqlite_snapshot(
        destination,
        required_tables=required_tables,
        count_table=count_table,
    )
    __validate_logical_restore(
        rows=rows,
        restored_rows=restored_rows,
        restore_foreign_key_errors=restore_foreign_key_errors,
    )
    __validate_no_sqlite_sidecars(destination)
    return {
        "rows": rows,
        "quick_check": quick_check,
        "journal_mode": journal_mode,
        "foreign_key_check_rows": foreign_key_errors,
        "restore_drill": {
            "quick_check": restore_check,
            "foreign_key_check_rows": restore_foreign_key_errors,
            "rows": restored_rows,
        },
    }


def backup_sqlite(source: Path, destination: Path) -> int:
    """Backward-compatible alert-store backup helper."""
    result = backup_sqlite_database(
        source,
        destination,
        required_tables=("alerts",),
        count_table="alerts",
    )
    return int(result["rows"])


def postgres_dump_container(
    docker: str,
    destination: Path,
    container: str,
) -> None:
    command = [
        docker, "exec", container, "sh", "-ec",
        'PGPASSWORD="$POSTGRES_PASSWORD" exec pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc',
    ]
    with destination.open("wb") as stream:
        subprocess.run(command, stdout=stream, check=True, timeout=1800)
    if destination.stat().st_size == 0:
        raise RuntimeError("PostgreSQL dump is empty")
    with destination.open("rb") as stream:
        subprocess.run(
            [docker, "exec", "-i", container, "pg_restore", "--list"],
            stdin=stream,
            stdout=subprocess.DEVNULL,
            check=True,
            timeout=300,
        )


def postgres_dump(docker: str, destination: Path) -> None:
    """Backward-compatible n8n PostgreSQL dump helper."""
    postgres_dump_container(docker, destination, "n8n-postgres")


def env_flag(path: Path, name: str) -> bool:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return False
    prefix = f"{name}="
    for line in lines:
        if line.startswith(prefix):
            return line[len(prefix):].strip().strip("\"'") == "1"
    return False


def archive_runtime_secrets(stack_dir: Path, destination: Path) -> list[str]:
    candidates = [
        Path(".env"),
        Path("n8n_data/config"),
        Path("config"),
        Path("soc-alerts/agent-memory"),
        Path("asset-discovery"),
    ]
    included: list[str] = []
    with tarfile.open(destination, "w:gz") as archive:
        for relative in candidates:
            source = stack_dir / relative
            if source.exists():
                archive.add(source, arcname=str(relative), recursive=True)
                included.append(str(relative))
    return included


def __require_bundle_capacity(
    stack_dir: Path,
    backup_root: Path,
) -> tuple[Path, Path]:
    sqlite_source = stack_dir / "alert_store_data/alerts.sqlite3"
    harness_source = (
        stack_dir / "alert_store_data/investigation-harness.sqlite3"
    )
    if harness_source.is_symlink():
        raise RuntimeError("harness SQLite source must not be a symlink")
    sqlite_source_bytes = (
        sqlite_source.stat().st_size if sqlite_source.is_file() else 0
    )
    harness_source_bytes = (
        harness_source.stat().st_size
        if harness_source.exists() and not harness_source.is_symlink()
        else 0
    )
    estimated_bytes = max(
        2 * 1024**3,
        (sqlite_source_bytes + harness_source_bytes) * 2,
    )
    require_runtime_capacity(
        backup_root,
        estimated_bytes,
        label="runtime recovery backup",
    )
    return sqlite_source, harness_source


def __backup_optional_harness(
    harness_source: Path,
    staging: Path,
) -> dict[str, object]:
    if not harness_source.exists():
        return {"present": False}
    harness_result = backup_sqlite_database(
        harness_source,
        staging / "investigation-harness.sqlite3",
        required_tables=(
            "harness_metadata",
            "harness_runs",
            "harness_events",
            "harness_evidence",
            "harness_hypotheses",
            "harness_decisions",
            "harness_model_calls",
            "harness_tool_calls",
            "harness_budget_reservations",
        ),
        count_table="harness_runs",
    )
    return {"present": True, **harness_result}


def __dump_optional_alert_store_postgres(
    stack_dir: Path,
    staging: Path,
    docker: str,
) -> dict[str, object]:
    if not env_flag(
        stack_dir / ".env",
        "ALERT_STORE_POSTGRES_SHADOW_ENABLED",
    ):
        return {"present": False}
    container = "onion-sentinel-alert-store-postgres"
    postgres_dump_container(
        docker,
        staging / "alert-store-postgres.dump",
        container,
    )
    return {"present": True, "container": container}


def __bundle_file_inventory(
    staging: Path,
) -> dict[str, dict[str, object]]:
    files: dict[str, dict[str, object]] = {}
    for path in sorted(staging.iterdir()):
        if path.is_file():
            os.chmod(path, 0o600)
            files[path.name] = {
                "bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
    return files


def __bundle_manifest(
    *,
    alert_sqlite: dict[str, object],
    harness_sqlite: dict[str, object],
    alert_store_postgres: dict[str, object],
    included: list[str],
    files: dict[str, dict[str, object]],
) -> dict[str, object]:
    return {
        "created_at": dt.datetime.now()
        .astimezone()
        .replace(microsecond=0)
        .isoformat()
        .replace("T", "  "),
        "alert_rows": int(alert_sqlite["rows"]),
        "harness_runs": (
            int(harness_sqlite["rows"])
            if harness_sqlite["present"]
            else 0
        ),
        "sqlite": {
            "alerts": {"present": True, **alert_sqlite},
            "investigation_harness": harness_sqlite,
        },
        "postgres": {
            "n8n": {"present": True, "container": "n8n-postgres"},
            "alert_store_shadow": alert_store_postgres,
        },
        "runtime_paths": included,
        "files": files,
    }


def create_bundle(stack_dir: Path, backup_root: Path, docker: str) -> Path:
    sqlite_source, harness_source = __require_bundle_capacity(
        stack_dir,
        backup_root,
    )
    stamp = dt.datetime.now().astimezone().strftime("%Y%m%dT%H%M%S%z")
    staging = backup_root / f".staging-{stamp}"
    final = backup_root / stamp
    staging.mkdir(mode=0o700, parents=True)
    try:
        alert_sqlite = backup_sqlite_database(
            sqlite_source,
            staging / "alerts.sqlite3",
            required_tables=("alerts", "alert_group_summary"),
            count_table="alerts",
        )
        harness_sqlite = __backup_optional_harness(
            harness_source,
            staging,
        )
        postgres_dump(docker, staging / "n8n-postgres.dump")
        alert_store_postgres = __dump_optional_alert_store_postgres(
            stack_dir,
            staging,
            docker,
        )
        included = archive_runtime_secrets(stack_dir, staging / "runtime-secrets.tar.gz")
        files = __bundle_file_inventory(staging)
        manifest = __bundle_manifest(
            alert_sqlite=alert_sqlite,
            harness_sqlite=harness_sqlite,
            alert_store_postgres=alert_store_postgres,
            included=included,
            files=files,
        )
        (staging / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n"
        )
        os.chmod(staging / "manifest.json", 0o600)
        staging.rename(final)
        return final
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def prune(backup_root: Path, keep: int) -> None:
    bundles = sorted((path for path in backup_root.iterdir() if path.is_dir() and not path.name.startswith(".")), reverse=True)
    for path in bundles[keep:]:
        shutil.rmtree(path)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stack-dir", type=Path, default=Path.home() / "n8n-local")
    parser.add_argument("--backup-root", type=Path)
    parser.add_argument("--docker", default="/usr/local/bin/docker")
    parser.add_argument("--keep", type=int, default=7)
    args = parser.parse_args()
    backup_root = args.backup_root or args.stack_dir / "recovery_backups"
    backup_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(backup_root, 0o700)
    with (backup_root / ".backup.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        bundle = create_bundle(args.stack_dir, backup_root, args.docker)
        prune(backup_root, max(2, args.keep))
    print(f"backup_ok path={bundle}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
