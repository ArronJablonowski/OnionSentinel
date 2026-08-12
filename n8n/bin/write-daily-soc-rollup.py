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

from daily_soc_rollup_data import (
    TEST_PREFIXES,
    all_rows,
    collect_rollup_data,
    notification_where_clause,
    one_row,
    where_clause,
)
from daily_soc_rollup_markdown import md, render_rollup, short_id, table


HOME = Path.home()
DEFAULT_DB = HOME / "n8n-local" / "alert_store_data" / "alerts.sqlite3"
DEFAULT_OUT = HOME / "n8n-local" / "soc-alerts" / "daily-rollups"


def project_now() -> dt.datetime:
    return dt.datetime.now().astimezone().replace(microsecond=0)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Write a daily SOC Markdown rollup"
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=DEFAULT_DB,
        help="Path to alert-store SQLite DB",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=DEFAULT_OUT,
        help="Directory for rollup Markdown files",
    )
    parser.add_argument(
        "--hours", type=int, default=24, help="Lookback window in hours"
    )
    parser.add_argument(
        "--date",
        help="Report date label, YYYY-MM-DD. Defaults to current UTC date",
    )
    parser.add_argument(
        "--limit", type=int, default=20, help="Maximum rows per detail table"
    )
    parser.add_argument(
        "--include-tests",
        action="store_true",
        help="Include validation/test alerts",
    )
    args = parser.parse_args()
    if args.hours <= 0:
        parser.error("--hours must be positive")
    if args.limit <= 0:
        parser.error("--limit must be positive")
    return args


def iso(value: dt.datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=dt.timezone.utc)
    return value.astimezone().isoformat().replace("T", "  ")


def build_rollup(
    conn: sqlite3.Connection,
    *,
    since: str,
    generated_at: str,
    report_date: str,
    hours: int,
    limit: int,
    include_tests: bool,
) -> str:
    data = collect_rollup_data(
        conn,
        since=since,
        limit=limit,
        include_tests=include_tests,
    )
    return render_rollup(
        data,
        since=since,
        generated_at=generated_at,
        report_date=report_date,
        hours=hours,
        include_tests=include_tests,
    )


def main() -> int:
    args = parse_args()
    if not args.db.exists():
        raise SystemExit(f"SQLite DB not found: {args.db}")
    now = project_now()
    # Use the Mac's local calendar day and local-offset project timestamps.
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
