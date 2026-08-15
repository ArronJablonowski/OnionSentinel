"""Versioned, transactional SQLite schema owner for the alert Relay."""
from __future__ import annotations

import importlib.util
import sqlite3
import sys
from pathlib import Path

try:
    import alert_outbox
except ModuleNotFoundError:
    _outbox_spec = importlib.util.spec_from_file_location(
        "alert_outbox",
        Path(__file__).with_name("alert_outbox.py"),
    )
    if _outbox_spec is None or _outbox_spec.loader is None:
        raise
    alert_outbox = importlib.util.module_from_spec(_outbox_spec)
    sys.modules.setdefault("alert_outbox", alert_outbox)
    _outbox_spec.loader.exec_module(alert_outbox)


CURRENT_SCHEMA_VERSION = 1
SCHEMA_VERSION_KEY = "schema_version"


def _metadata_exists(conn: sqlite3.Connection) -> bool:
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='relay_metadata'"
    ).fetchone() is not None


def _read_schema_version(conn: sqlite3.Connection) -> int:
    if not _metadata_exists(conn):
        return 0
    rows = conn.execute(
        "SELECT value FROM relay_metadata WHERE key = ?",
        (SCHEMA_VERSION_KEY,),
    ).fetchall()
    if len(rows) != 1:
        raise RuntimeError("Relay database schema version is missing or ambiguous")
    raw_version = rows[0][0]
    try:
        version = int(raw_version)
    except (TypeError, ValueError):
        raise RuntimeError("Relay database schema version is invalid") from None
    if version < 0:
        raise RuntimeError("Relay database schema version is invalid")
    return version


def _require_supported_version(version: int) -> None:
    if version > CURRENT_SCHEMA_VERSION:
        raise RuntimeError(
            "Relay database schema version "
            f"{version} is newer than supported version {CURRENT_SCHEMA_VERSION}"
        )


def _install_metadata_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS relay_metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
        """
    )


def _install_seen_alerts_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS seen_alerts (
            alert_id TEXT PRIMARY KEY,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            seen_count INTEGER NOT NULL DEFAULT 1
        )
        """
    )


def _persist_schema_version(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        INSERT INTO relay_metadata(key, value) VALUES(?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value
        """,
        (SCHEMA_VERSION_KEY, str(CURRENT_SCHEMA_VERSION)),
    )


def initialize(conn: sqlite3.Connection) -> None:
    """Atomically admit, migrate, recover, and version one Relay database."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        existing_version = _read_schema_version(conn)
        _require_supported_version(existing_version)
        _install_metadata_schema(conn)
        _install_seen_alerts_schema(conn)
        alert_outbox.install_schema(conn)
        alert_outbox.recover_interrupted_claims(conn)
        _persist_schema_version(conn)
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
