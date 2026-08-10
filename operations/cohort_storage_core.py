#!/usr/bin/env python3
"""Read-only SQLite admission, schema inspection, and alias resolution."""
from __future__ import annotations

import contextlib
from dataclasses import dataclass
from pathlib import Path
import sqlite3
from typing import Any, Callable, Iterable, Mapping
import urllib.parse


@dataclass(frozen=True)
class CohortStoragePolicy:
    error: type[RuntimeError]
    sha256_value: Callable[[Any], str]


def connect_read_only(
    database_path: Path,
    policy: CohortStoragePolicy,
) -> sqlite3.Connection:
    """Open an existing SQLite database with enforced query-only semantics."""
    path = database_path.expanduser()
    if not path.exists() or not path.is_file():
        raise policy.error(f"alert database not found: {path}")
    uri_path = urllib.parse.quote(str(path.resolve()), safe="/")
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(
            f"file:{uri_path}?mode=ro",
            uri=True,
            timeout=5.0,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        if int(connection.execute("PRAGMA query_only").fetchone()[0]) != 1:
            connection.close()
            raise policy.error("SQLite query_only could not be enabled")
        return connection
    except sqlite3.Error as exc:
        if connection is not None:
            with contextlib.suppress(sqlite3.Error):
                connection.close()
        raise policy.error(f"could not open alert database read-only: {exc}") from exc


def table_exists(connection: sqlite3.Connection, table: str) -> bool:
    row = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table,),
    ).fetchone()
    return row is not None


def table_columns(connection: sqlite3.Connection, table: str) -> set[str]:
    if not table_exists(connection, table):
        return set()
    return {
        str(row["name"])
        for row in connection.execute(f'PRAGMA table_info("{table}")').fetchall()
    }


def require_columns(
    connection: sqlite3.Connection,
    table: str,
    required: Iterable[str],
    policy: CohortStoragePolicy,
) -> set[str]:
    columns = table_columns(connection, table)
    missing = set(required) - columns
    if missing:
        raise policy.error(
            f"alert database schema is missing {table} columns: "
            + ", ".join(sorted(missing))
        )
    return columns


def schema_fingerprint(
    connection: sqlite3.Connection,
    policy: CohortStoragePolicy,
) -> str:
    rows = connection.execute(
        """
        SELECT type, name, tbl_name, COALESCE(sql, '') AS sql
        FROM sqlite_master
        WHERE type IN ('table', 'index')
          AND name IN (
            'alert_group_summary', 'alert_group_alias',
            'incident_response_cases', 'incident_reanalysis_runs',
            'incident_reanalysis_run_cases', 'durable_jobs',
            'ai_analysis_runs', 'ai_second_opinion_runs'
          )
        ORDER BY type, name
        """
    ).fetchall()
    return policy.sha256_value([dict(row) for row in rows])


def load_aliases(
    connection: sqlite3.Connection,
    policy: CohortStoragePolicy,
) -> dict[str, str]:
    require_columns(
        connection,
        "alert_group_alias",
        {"legacy_group_id", "stable_group_id"},
        policy,
    )
    aliases: dict[str, str] = {}
    for row in connection.execute(
        """
        SELECT legacy_group_id, stable_group_id
        FROM alert_group_alias
        ORDER BY legacy_group_id
        """
    ):
        legacy = str(row["legacy_group_id"] or "").strip().lower()
        stable = str(row["stable_group_id"] or "").strip().lower()
        if not legacy or not stable:
            raise policy.error("alert_group_alias contains a blank identity")
        aliases[legacy] = stable
    return aliases


def resolve_alias(
    identity: str,
    aliases: Mapping[str, str],
    policy: CohortStoragePolicy,
) -> str:
    current = str(identity or "").strip().lower()
    visited: set[str] = set()
    while current in aliases:
        if current in visited:
            raise policy.error(f"cycle detected in alert group aliases at {current}")
        visited.add(current)
        current = str(aliases[current] or "").strip().lower()
    return current
