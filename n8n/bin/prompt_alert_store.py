#!/usr/bin/env python3
"""Read-only SQLite and stable alert identity helpers for prompt building."""
from __future__ import annotations

import hashlib
import sqlite3
from typing import Any, Iterable


def query_rows(
    connection: sqlite3.Connection,
    sql: str,
    params: Iterable[object] = (),
) -> list[sqlite3.Row]:
    """Execute a read query and return all rows."""
    return connection.execute(sql, tuple(params)).fetchall()


def query_row(
    connection: sqlite3.Connection,
    sql: str,
    params: Iterable[object] = (),
) -> sqlite3.Row | None:
    """Execute a read query and return its first row."""
    return connection.execute(sql, tuple(params)).fetchone()


def build_test_alert_filter(
    patterns: Iterable[str],
    prefix: str = "alert_id",
) -> tuple[str, list[object]]:
    """Build the legacy parameterized exclusion predicate for test alerts."""
    clauses: list[str] = []
    params: list[object] = []
    for pattern in patterns:
        clauses.append(f"{prefix} NOT LIKE ?")
        params.append(pattern)
    return " AND ".join(clauses), params


def sqlite_row_value(
    row_value: Any,
    key: str,
    default: object = None,
) -> object:
    """Read a SQLite row field without failing when a legacy column is absent."""
    return row_value[key] if key in row_value.keys() else default


def derive_alert_group_key(row_value: Any) -> str:
    """Return the duplicate-group key shared by the UI and AI scheduler."""
    suppression_key = str(
        sqlite_row_value(row_value, "suppression_key") or ""
    ).strip()
    if suppression_key:
        return suppression_key
    return "|".join(
        [
            str(sqlite_row_value(row_value, "triage_level") or "unscored"),
            str(sqlite_row_value(row_value, "rule_name") or "unknown-rule"),
            str(sqlite_row_value(row_value, "source_ip") or "unknown-source"),
            str(
                sqlite_row_value(row_value, "destination_ip")
                or "unknown-destination"
            ),
            str(sqlite_row_value(row_value, "filter_status") or "accepted"),
        ]
    )


def stable_alert_group_id(group_key: str) -> str:
    """Return the legacy stable twelve-character group digest."""
    return hashlib.sha1(str(group_key or "").encode("utf-8")).hexdigest()[:12]


def read_table_columns(
    connection: sqlite3.Connection,
    table: str,
) -> set[str]:
    """Return SQLite table columns, failing soft for unavailable schemas."""
    try:
        return {
            str(item["name"])
            for item in query_rows(connection, f"PRAGMA table_info({table})")
        }
    except sqlite3.Error:
        return set()
