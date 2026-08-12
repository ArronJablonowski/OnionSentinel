#!/usr/bin/env python3
"""Read-only SQLite projections for the daily SOC rollup."""
from __future__ import annotations

import sqlite3
from typing import Iterable


TEST_PREFIXES = (
    "phase%",
    "config-%",
    "internal-test-%",
    "sqlite-%",
    "policy-%",
    "codex-e2e-%",
)


def where_clause(
    since: str, include_tests: bool
) -> tuple[str, list[object]]:
    clauses = [
        "substr(replace(last_seen, 'T', ' '), 1, 19) >= "
        "substr(replace(?, 'T', ' '), 1, 19)"
    ]
    params: list[object] = [since]
    if not include_tests:
        for pattern in TEST_PREFIXES:
            clauses.append("alert_id NOT LIKE ?")
            params.append(pattern)
    return "WHERE " + " AND ".join(clauses), params


def notification_where_clause(
    since: str, include_tests: bool
) -> tuple[str, list[object]]:
    clauses = [
        "replace(replace(notification_log.last_sent, 'T', ' '), 'Z', '') "
        ">= replace(replace(?, 'T', ' '), 'Z', '')"
    ]
    params: list[object] = [since]
    if not include_tests:
        for pattern in TEST_PREFIXES:
            clauses.append("notification_log.alert_id NOT LIKE ?")
            params.append(pattern)
    return "WHERE " + " AND ".join(clauses), params


def all_rows(
    conn: sqlite3.Connection,
    sql: str,
    params: Iterable[object] = (),
) -> list[sqlite3.Row]:
    return conn.execute(sql, tuple(params)).fetchall()


def one_row(
    conn: sqlite3.Connection,
    sql: str,
    params: Iterable[object] = (),
) -> sqlite3.Row:
    return conn.execute(sql, tuple(params)).fetchone()


def _summary(
    conn: sqlite3.Connection, where: str, params: list[object]
) -> sqlite3.Row:
    return one_row(
        conn,
        f"""
        SELECT
          COUNT(*) AS raw_alerts,
          COALESCE(SUM(seen_count), 0) AS total_seen,
          SUM(CASE WHEN triage_level IN ('critical', 'high') THEN 1 ELSE 0 END) AS urgent_rows,
          SUM(CASE WHEN filter_status = 'accepted' THEN 1 ELSE 0 END) AS accepted_rows,
          SUM(CASE WHEN filter_status = 'suppressed' THEN 1 ELSE 0 END) AS suppressed_rows,
          SUM(CASE WHEN filter_status = 'duplicate' THEN 1 ELSE 0 END) AS duplicate_rows,
          MIN(first_seen) AS first_seen,
          MAX(last_seen) AS last_seen
        FROM alerts
        {where}
        """,
        params,
    )


def _by_status(
    conn: sqlite3.Connection, where: str, params: list[object]
) -> list[sqlite3.Row]:
    return all_rows(
        conn,
        f"""
        SELECT COALESCE(filter_status, 'unknown') AS filter_status,
               COALESCE(triage_level, 'unscored') AS triage_level,
               COUNT(*) AS raw_alerts,
               COALESCE(SUM(seen_count), 0) AS total_seen,
               MAX(last_seen) AS last_seen
        FROM alerts
        {where}
        GROUP BY COALESCE(filter_status, 'unknown'), COALESCE(triage_level, 'unscored')
        ORDER BY raw_alerts DESC, total_seen DESC
        """,
        params,
    )


def _grouped(
    conn: sqlite3.Connection,
    where: str,
    params: list[object],
    limit: int,
) -> list[sqlite3.Row]:
    return all_rows(
        conn,
        f"""
        WITH grouped AS (
          SELECT
            COALESCE(
              suppression_key,
              COALESCE(triage_level, 'unscored') || '|' ||
              COALESCE(rule_name, 'unknown-rule') || '|' ||
              COALESCE(source_ip, 'unknown-source') || '|' ||
              COALESCE(destination_ip, 'unknown-destination') || '|' ||
              COALESCE(filter_status, 'accepted')
            ) AS alert_group_key,
            COALESCE(rule_name, 'unknown-rule') AS rule_name,
            COALESCE(source_ip, 'unknown-source') AS source_ip,
            COALESCE(destination_ip, 'unknown-destination') AS destination_ip,
            COALESCE(triage_level, 'unscored') AS triage_level,
            COALESCE(filter_status, 'unknown') AS filter_status,
            COUNT(*) AS raw_alerts,
            COALESCE(SUM(seen_count), 0) AS total_seen,
            MAX(triage_score) AS max_score,
            MIN(first_seen) AS first_seen,
            MAX(last_seen) AS last_seen
          FROM alerts
          {where}
          GROUP BY alert_group_key
        )
        SELECT *
        FROM grouped
        ORDER BY max_score DESC, total_seen DESC, raw_alerts DESC, last_seen DESC
        LIMIT ?
        """,
        [*params, limit],
    )


def _urgent(
    conn: sqlite3.Connection,
    where: str,
    params: list[object],
    limit: int,
) -> list[sqlite3.Row]:
    return all_rows(
        conn,
        f"""
        SELECT alert_id, triage_level, triage_score, filter_status, routing,
               rule_name, source_ip, destination_ip, seen_count, last_seen
        FROM alerts
        {where}
          AND triage_level IN ('critical', 'high')
        ORDER BY triage_score DESC, last_seen DESC
        LIMIT ?
        """,
        [*params, limit],
    )


def _suppressed(
    conn: sqlite3.Connection, since: str, limit: int
) -> list[sqlite3.Row]:
    return all_rows(
        conn,
        """
        SELECT suppression_key, rule_name, reason, seen_count, suppressed_count,
               escalated_count, ttl_seconds, last_seen
        FROM suppression_log
        WHERE replace(replace(last_seen, 'T', ' '), 'Z', '') >= replace(replace(?, 'T', ' '), 'Z', '')
        ORDER BY suppressed_count DESC, seen_count DESC, replace(replace(last_seen, 'T', ' '), 'Z', '') DESC
        LIMIT ?
        """,
        [since, limit],
    )


def _new_pairs(
    conn: sqlite3.Connection,
    where: str,
    params: list[object],
    since: str,
    limit: int,
) -> list[sqlite3.Row]:
    return all_rows(
        conn,
        f"""
        SELECT COALESCE(a.source_ip, 'unknown') AS source_ip,
               COALESCE(a.destination_ip, 'unknown') AS destination_ip,
               COUNT(*) AS raw_alerts,
               COALESCE(SUM(a.seen_count), 0) AS total_seen,
               MAX(a.triage_score) AS max_score,
               MAX(a.last_seen) AS last_seen
        FROM alerts a
        {where.replace('last_seen', 'a.last_seen')}
          AND NOT EXISTS (
            SELECT 1 FROM alerts older
            WHERE older.last_seen < ?
              AND COALESCE(older.source_ip, 'unknown') = COALESCE(a.source_ip, 'unknown')
              AND COALESCE(older.destination_ip, 'unknown') = COALESCE(a.destination_ip, 'unknown')
          )
        GROUP BY COALESCE(a.source_ip, 'unknown'), COALESCE(a.destination_ip, 'unknown')
        ORDER BY max_score DESC, raw_alerts DESC, last_seen DESC
        LIMIT ?
        """,
        [*params, since, limit],
    )


def _notifications(
    conn: sqlite3.Connection,
    where: str,
    params: list[object],
    limit: int,
) -> list[sqlite3.Row]:
    return all_rows(
        conn,
        f"""
        SELECT notification_log.channel, notification_log.triage_level,
               notification_log.rule_name, notification_log.source_ip,
               notification_log.destination_ip, notification_log.sent_count,
               notification_log.last_sent
        FROM notification_log
        {where}
        ORDER BY notification_log.last_sent DESC
        LIMIT ?
        """,
        [*params, limit],
    )


def collect_rollup_data(
    conn: sqlite3.Connection,
    *,
    since: str,
    limit: int,
    include_tests: bool,
) -> dict[str, object]:
    """Collect every bounded read-only projection used by one rollup."""
    where, params = where_clause(since, include_tests)
    notif_where, notif_params = notification_where_clause(
        since, include_tests
    )
    return {
        "summary": _summary(conn, where, params),
        "by_status": _by_status(conn, where, params),
        "grouped": _grouped(conn, where, params, limit),
        "urgent": _urgent(conn, where, params, limit),
        "suppressed": _suppressed(conn, since, limit),
        "new_pairs": _new_pairs(conn, where, params, since, limit),
        "notifications": _notifications(
            conn, notif_where, notif_params, limit
        ),
    }
