#!/usr/bin/env python3
"""Read harness trace ledgers from one consistent read-only SQLite snapshot."""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote


@dataclass(frozen=True)
class TraceStoragePolicy:
    current_schema_version: int
    error: type[RuntimeError]


def connect_read_only(
    path: Path, policy: TraceStoragePolicy
) -> sqlite3.Connection:
    """Open an existing database without creating, migrating, or writing it."""
    try:
        resolved = path.expanduser().resolve(strict=True)
    except FileNotFoundError as exc:
        raise policy.error(f"harness database does not exist: {path}") from exc
    if not resolved.is_file():
        raise policy.error(
            f"harness database is not a regular file: {resolved}"
        )
    uri = f"file:{quote(str(resolved), safe='/')}?mode=ro"
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(uri, uri=True, timeout=10.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        connection.execute("PRAGMA busy_timeout = 10000")
        connection.execute("BEGIN")
        return connection
    except sqlite3.Error as exc:
        if connection is not None:
            connection.close()
        raise policy.error(
            f"cannot open harness database read-only: {exc}"
        ) from exc


def table_names(connection: sqlite3.Connection) -> set[str]:
    return {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        ).fetchall()
    }


def database_schema_version(
    connection: sqlite3.Connection,
    available_tables: set[str],
    policy: TraceStoragePolicy,
) -> int | None:
    if "harness_metadata" not in available_tables:
        return None
    try:
        row = connection.execute(
            "SELECT value FROM harness_metadata WHERE key = 'schema_version'"
        ).fetchone()
    except sqlite3.Error as exc:
        raise policy.error(
            f"cannot read harness database schema version: {exc}"
        ) from exc
    if row is None:
        return None
    try:
        version = int(row[0])
    except (TypeError, ValueError) as exc:
        raise policy.error("harness database schema version is invalid") from exc
    if version > policy.current_schema_version:
        raise policy.error("harness database was created by a newer runtime")
    return version


def selected_runs(
    connection: sqlite3.Connection,
    run_id: str | None,
    policy: TraceStoragePolicy,
) -> list[dict[str, Any]]:
    if run_id:
        rows = connection.execute(
            "SELECT * FROM harness_runs WHERE run_id = ?", (run_id,)
        ).fetchall()
        if not rows:
            raise policy.error(f"unknown harness run_id: {run_id}")
    else:
        rows = connection.execute(
            "SELECT * FROM harness_runs ORDER BY started_at, run_id"
        ).fetchall()
    return [dict(row) for row in rows]


def rows_for_run(
    connection: sqlite3.Connection,
    available_tables: set[str],
    table: str,
    run_id: str,
    order_by: str,
) -> list[dict[str, Any]]:
    if table not in available_tables:
        return []
    rows = connection.execute(
        f"SELECT * FROM {table} WHERE run_id = ? ORDER BY {order_by}",
        (run_id,),
    ).fetchall()
    return [dict(row) for row in rows]
