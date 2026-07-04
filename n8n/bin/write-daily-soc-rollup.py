#!/usr/bin/env python3
"""Write an Obsidian-friendly daily SOC rollup from alert-store SQLite.

This host-side script is intentionally read-only against alert-store SQLite and
writes one Markdown file into the SOC Alerts corpus. The local LLM can use these
rollups as compact daily memory without rereading every raw alert report.
"""
from __future__ import annotations

import argparse
import datetime as dt
import sqlite3
from pathlib import Path
from typing import Iterable


HOME = Path.home()
DEFAULT_DB = HOME / "n8n-local" / "alert_store_data" / "alerts.sqlite3"
DEFAULT_OUT = HOME / "n8n-local" / "soc-alerts" / "daily-rollups"
TEST_PREFIXES = (
    "phase%",
    "config-%",
    "internal-test-%",
    "sqlite-%",
    "policy-%",
    "codex-e2e-%",
)


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Write a daily SOC Markdown rollup")
    parser.add_argument("--db", type=Path, default=DEFAULT_DB, help="Path to alert-store SQLite DB")
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT, help="Directory for rollup Markdown files")
    parser.add_argument("--hours", type=int, default=24, help="Lookback window in hours")
    parser.add_argument("--date", help="Report date label, YYYY-MM-DD. Defaults to current UTC date")
    parser.add_argument("--limit", type=int, default=20, help="Maximum rows per detail table")
    parser.add_argument("--include-tests", action="store_true", help="Include validation/test alerts")
    args = parser.parse_args()
    if args.hours <= 0:
        parser.error("--hours must be positive")
    if args.limit <= 0:
        parser.error("--limit must be positive")
    return args


def iso(value: dt.datetime) -> str:
    return value.isoformat().replace("T", "  ").replace("+00:00", "Z")


def md(value: object) -> str:
    return str(value if value is not None else "").replace("|", "\\|").replace("\n", " ")


def table(headers: list[str], rows: Iterable[Iterable[object]]) -> str:
    rows = list(rows)
    if not rows:
        return "_No rows._\n"
    header = "| " + " | ".join(headers) + " |"
    divider = "| " + " | ".join("---" for _ in headers) + " |"
    body = ["| " + " | ".join(md(cell) for cell in row) + " |" for row in rows]
    return "\n".join([header, divider, *body]) + "\n"


def short_id(alert_id: object) -> str:
    value = str(alert_id or "")
    last = value.split(":")[-1] or value
    return f"{last[:18]}..." if len(last) > 18 else last


def where_clause(since: str, include_tests: bool) -> tuple[str, list[object]]:
    clauses = ["replace(replace(last_seen, 'T', ' '), 'Z', '') >= replace(replace(?, 'T', ' '), 'Z', '')"]
    params: list[object] = [since]
    if not include_tests:
        for pattern in TEST_PREFIXES:
            clauses.append("alert_id NOT LIKE ?")
            params.append(pattern)
    return "WHERE " + " AND ".join(clauses), params


def notification_where_clause(since: str, include_tests: bool) -> tuple[str, list[object]]:
    clauses = ["replace(replace(notification_log.last_sent, 'T', ' '), 'Z', '') >= replace(replace(?, 'T', ' '), 'Z', '')"]
    params: list[object] = [since]
    if not include_tests:
        for pattern in TEST_PREFIXES:
            clauses.append("notification_log.alert_id NOT LIKE ?")
            params.append(pattern)
    return "WHERE " + " AND ".join(clauses), params


def all_rows(conn: sqlite3.Connection, sql: str, params: Iterable[object] = ()) -> list[sqlite3.Row]:
    return conn.execute(sql, tuple(params)).fetchall()


def one_row(conn: sqlite3.Connection, sql: str, params: Iterable[object] = ()) -> sqlite3.Row:
    return conn.execute(sql, tuple(params)).fetchone()


def build_rollup(conn: sqlite3.Connection, *, since: str, generated_at: str, report_date: str, hours: int, limit: int, include_tests: bool) -> str:
    where, params = where_clause(since, include_tests)
    notif_where, notif_params = notification_where_clause(since, include_tests)

    summary = one_row(
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

    by_status = all_rows(
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

    grouped = all_rows(
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

    urgent = all_rows(
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

    suppressed = all_rows(
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

    new_pairs = all_rows(
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

    notifications = all_rows(
        conn,
        f"""
        SELECT notification_log.channel, notification_log.triage_level,
               notification_log.rule_name, notification_log.source_ip,
               notification_log.destination_ip, notification_log.sent_count,
               notification_log.last_sent
        FROM notification_log
        {notif_where}
        ORDER BY notification_log.last_sent DESC
        LIMIT ?
        """,
        [*notif_params, limit],
    )

    lines: list[str] = []
    lines.extend([
        "---",
        "type: soc-daily-rollup",
        f"date: {report_date}",
        f"generated_at: {generated_at}",
        f"lookback_hours: {hours}",
        "tags:",
        "  - security-onion",
        "  - soc-rollup",
        "  - ai-context",
        "---",
        "",
        f"# SOC Daily Rollup - {report_date}",
        "",
        f"Generated: {generated_at}",
        f"Window start: {since}",
        f"Include test alerts: {'yes' if include_tests else 'no'}",
        "",
        "## Executive Summary",
        "",
    ])

    raw_alerts = summary["raw_alerts"] or 0
    urgent_rows = summary["urgent_rows"] or 0
    suppressed_rows = summary["suppressed_rows"] or 0
    lines.append(
        f"- {raw_alerts} raw alert rows were recorded in the window, representing {summary['total_seen'] or 0} total seen events."
    )
    lines.append(f"- {urgent_rows} rows were critical/high and should be reviewed first.")
    lines.append(f"- {suppressed_rows} rows were suppressed by tuning rules and retained as evidence.")
    lines.append("- Use the grouped detections table for alert-volume reality; it mirrors the dashboard Count model.")
    lines.append("")

    lines.extend([
        "## Summary Metrics",
        "",
        table(
            ["Raw Rows", "Total Seen", "Urgent Rows", "Accepted", "Suppressed", "Duplicates", "First Seen", "Last Seen"],
            [[
                summary["raw_alerts"] or 0,
                summary["total_seen"] or 0,
                summary["urgent_rows"] or 0,
                summary["accepted_rows"] or 0,
                summary["suppressed_rows"] or 0,
                summary["duplicate_rows"] or 0,
                summary["first_seen"] or "none",
                summary["last_seen"] or "none",
            ]],
        ),
        "## By Filter Status And Level",
        "",
        table(
            ["Filter Status", "Level", "Raw Rows", "Total Seen", "Last Seen"],
            ([row["filter_status"], row["triage_level"], row["raw_alerts"], row["total_seen"], row["last_seen"]] for row in by_status),
        ),
        "## Top Grouped Detections",
        "",
        table(
            ["Count", "Raw Rows", "Level", "Status", "Max Score", "Rule", "Source", "Destination", "Last Seen"],
            (
                [
                    max(row["total_seen"] or 0, row["raw_alerts"] or 0),
                    row["raw_alerts"],
                    row["triage_level"],
                    row["filter_status"],
                    row["max_score"],
                    row["rule_name"],
                    row["source_ip"],
                    row["destination_ip"],
                    row["last_seen"],
                ]
                for row in grouped
            ),
        ),
        "## Urgent Alert Queue",
        "",
        table(
            ["Alert ID", "Level", "Score", "Status", "Routing", "Rule", "Source", "Destination", "Seen", "Last Seen"],
            (
                [
                    short_id(row["alert_id"]),
                    row["triage_level"],
                    row["triage_score"],
                    row["filter_status"],
                    row["routing"],
                    row["rule_name"],
                    row["source_ip"],
                    row["destination_ip"],
                    row["seen_count"],
                    row["last_seen"],
                ]
                for row in urgent
            ),
        ),
        "## Suppression Activity",
        "",
        table(
            ["Suppression Key", "Rule", "Reason", "Seen", "Suppressed", "Escalated", "TTL Seconds", "Last Seen"],
            (
                [
                    row["suppression_key"],
                    row["rule_name"],
                    row["reason"],
                    row["seen_count"],
                    row["suppressed_count"],
                    row["escalated_count"],
                    row["ttl_seconds"],
                    row["last_seen"],
                ]
                for row in suppressed
            ),
        ),
        "## New Source Destination Pairs",
        "",
        table(
            ["Source", "Destination", "Raw Rows", "Total Seen", "Max Score", "Last Seen"],
            ([row["source_ip"], row["destination_ip"], row["raw_alerts"], row["total_seen"], row["max_score"], row["last_seen"]] for row in new_pairs),
        ),
        "## Telegram Notifications",
        "",
        table(
            ["Channel", "Level", "Rule", "Source", "Destination", "Sent Count", "Last Sent"],
            (
                [
                    row["channel"],
                    row["triage_level"],
                    row["rule_name"],
                    row["source_ip"],
                    row["destination_ip"],
                    row["sent_count"],
                    row["last_sent"],
                ]
                for row in notifications
            ),
        ),
        "## Analyst Follow-Up",
        "",
        "- [ ] Review urgent alert queue and decide whether each item is benign, expected, suspicious, or needs escalation.",
        "- [ ] Review top grouped detections for noisy rules that need tuning.",
        "- [ ] Review suppressed activity for escalation thresholds that are too low or too high.",
        "- [ ] Capture any final dispositions in investigation notes or tuning docs.",
        "",
        "## AI Context Notes",
        "",
        "This rollup is safe context for the local AI analyst. It summarizes SQLite alert state and links alert volume to dashboard Count semantics without requiring the model to parse every raw report file.",
        "",
    ])

    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    if not args.db.exists():
        raise SystemExit(f"SQLite DB not found: {args.db}")
    now = utc_now()
    # Use the Mac's local calendar day for filenames. Keep generated_at/window
    # timestamps in UTC so they line up with Security Onion and SQLite rows.
    report_date = args.date or dt.datetime.now().astimezone().date().isoformat()
    since = iso(now - dt.timedelta(hours=args.hours))
    args.out_dir.mkdir(parents=True, exist_ok=True)
    output_path = args.out_dir / f"{report_date}-soc-daily-rollup.md"

    conn = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        content = build_rollup(
            conn,
            since=since,
            generated_at=iso(now),
            report_date=report_date,
            hours=args.hours,
            limit=args.limit,
            include_tests=args.include_tests,
        )
    finally:
        conn.close()

    output_path.write_text(content, encoding="utf-8")
    print(output_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
