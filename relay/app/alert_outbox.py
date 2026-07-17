"""Durable outbound delivery queue for the Raspberry Pi alert relay.

Security Onion's rolling lookback is not a delivery guarantee. Alerts enter
this SQLite outbox before any delivery attempt so a Mac Studio outage cannot make
an already-fetched alert disappear when it ages out of the next SSH poll.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Iterable


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def initialize(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS alert_delivery_outbox (
            alert_id TEXT PRIMARY KEY,
            payload_json TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending'
                CHECK(status IN ('pending', 'delivering', 'delivered')),
            attempt_count INTEGER NOT NULL DEFAULT 0,
            last_error TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            delivered_at TEXT
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_alert_delivery_outbox_status_created "
        "ON alert_delivery_outbox(status, created_at, alert_id)"
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS alert_delivery_dead_letter (
            alert_id TEXT PRIMARY KEY,
            payload_json TEXT NOT NULL,
            attempt_count INTEGER NOT NULL,
            last_error TEXT NOT NULL,
            created_at TEXT NOT NULL,
            failed_at TEXT NOT NULL
        )
        """
    )
    # A process killed between claim and delivery is safe to replay because
    # alert-store treats alert_id as an idempotency key.
    conn.execute(
        "UPDATE alert_delivery_outbox SET status = 'pending' WHERE status = 'delivering'"
    )
    conn.commit()


def enqueue(conn: sqlite3.Connection, alerts: Iterable[dict]) -> int:
    now = now_utc_iso()
    queued = 0
    for alert in alerts:
        alert_id = str(alert.get("alert_id") or "").strip()
        if not alert_id:
            continue
        result = conn.execute(
            """
            INSERT OR IGNORE INTO alert_delivery_outbox (
                alert_id, payload_json, status, attempt_count, created_at, updated_at
            ) VALUES (?, ?, 'pending', 0, ?, ?)
            """,
            (alert_id, json.dumps(alert, separators=(",", ":"), sort_keys=True), now, now),
        )
        queued += max(0, int(result.rowcount or 0))
    conn.commit()
    return queued


def pending(conn: sqlite3.Connection, limit: int = 1000) -> list[dict]:
    rows = conn.execute(
        """
        SELECT alert_id, payload_json, attempt_count
        FROM alert_delivery_outbox
        WHERE status = 'pending'
        ORDER BY created_at ASC, alert_id ASC
        LIMIT ?
        """,
        (max(1, min(int(limit), 10000)),),
    ).fetchall()
    results = []
    for alert_id, payload_json, attempt_count in rows:
        try:
            payload = json.loads(payload_json)
        except json.JSONDecodeError:
            move_to_dead_letter(conn, alert_id, "stored outbox payload is not valid JSON")
            continue
        results.append({"alert_id": alert_id, "payload": payload, "attempt_count": attempt_count})
    return results


def claim(conn: sqlite3.Connection, alert_id: str) -> bool:
    result = conn.execute(
        """
        UPDATE alert_delivery_outbox
        SET status = 'delivering', attempt_count = attempt_count + 1, updated_at = ?
        WHERE alert_id = ? AND status = 'pending'
        """,
        (now_utc_iso(), alert_id),
    )
    conn.commit()
    return result.rowcount == 1


def mark_delivered(conn: sqlite3.Connection, alert_id: str) -> None:
    now = now_utc_iso()
    conn.execute(
        """
        UPDATE alert_delivery_outbox
        SET status = 'delivered', last_error = NULL, delivered_at = ?, updated_at = ?
        WHERE alert_id = ?
        """,
        (now, now, alert_id),
    )
    conn.commit()


def mark_failure(conn: sqlite3.Connection, alert_id: str, error: str) -> None:
    conn.execute(
        """
        UPDATE alert_delivery_outbox
        SET status = 'pending', last_error = ?, updated_at = ?
        WHERE alert_id = ?
        """,
        (str(error)[:500], now_utc_iso(), alert_id),
    )
    conn.commit()


def move_to_dead_letter(conn: sqlite3.Connection, alert_id: str, error: str) -> bool:
    """Quarantine one permanent rejection without blocking newer alerts."""
    now = now_utc_iso()
    row = conn.execute(
        """
        SELECT alert_id, payload_json, attempt_count, created_at
        FROM alert_delivery_outbox WHERE alert_id = ?
        """,
        (alert_id,),
    ).fetchone()
    if row is None:
        return False
    conn.execute(
        """
        INSERT INTO alert_delivery_dead_letter (
            alert_id, payload_json, attempt_count, last_error, created_at, failed_at
        ) VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(alert_id) DO UPDATE SET
            payload_json = excluded.payload_json,
            attempt_count = excluded.attempt_count,
            last_error = excluded.last_error,
            failed_at = excluded.failed_at
        """,
        (row[0], row[1], int(row[2] or 0), str(error)[:500], row[3], now),
    )
    conn.execute("DELETE FROM alert_delivery_outbox WHERE alert_id = ?", (alert_id,))
    conn.commit()
    return True


def counts(conn: sqlite3.Connection) -> dict[str, int]:
    rows = conn.execute(
        "SELECT status, COUNT(*) FROM alert_delivery_outbox GROUP BY status"
    ).fetchall()
    result = {"pending": 0, "delivering": 0, "delivered": 0, "dead_letter": 0}
    result.update({str(status): int(count) for status, count in rows})
    dead_letter = conn.execute("SELECT COUNT(*) FROM alert_delivery_dead_letter").fetchone()
    result["dead_letter"] = int(dead_letter[0] if dead_letter else 0)
    return result


def prune_delivered(conn: sqlite3.Connection, retain_days: int = 30) -> int:
    result = conn.execute(
        """
        DELETE FROM alert_delivery_outbox
        WHERE status = 'delivered'
          AND datetime(replace(delivered_at, 'Z', '+00:00')) < datetime('now', ?)
        """,
        (f"-{max(1, int(retain_days))} days",),
    )
    conn.commit()
    return max(0, int(result.rowcount or 0))
