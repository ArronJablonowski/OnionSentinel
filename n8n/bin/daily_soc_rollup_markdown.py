#!/usr/bin/env python3
"""Deterministic Markdown composition for the daily SOC rollup."""
from __future__ import annotations

from typing import Iterable, Mapping


def md(value: object) -> str:
    return str(value if value is not None else "").replace(
        "|", "\\|"
    ).replace("\n", " ")


def table(headers: list[str], rows: Iterable[Iterable[object]]) -> str:
    materialized = list(rows)
    if not materialized:
        return "_No rows._\n"
    header = "| " + " | ".join(headers) + " |"
    divider = "| " + " | ".join("---" for _ in headers) + " |"
    body = [
        "| " + " | ".join(md(cell) for cell in row) + " |"
        for row in materialized
    ]
    return "\n".join([header, divider, *body]) + "\n"


def short_id(alert_id: object) -> str:
    value = str(alert_id or "")
    last = value.split(":")[-1] or value
    return f"{last[:18]}..." if len(last) > 18 else last


def _header(
    *,
    since: str,
    generated_at: str,
    report_date: str,
    hours: int,
    include_tests: bool,
) -> list[str]:
    return [
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
    ]


def _executive_summary(summary: Mapping[str, object]) -> list[str]:
    raw_alerts = summary["raw_alerts"] or 0
    urgent_rows = summary["urgent_rows"] or 0
    suppressed_rows = summary["suppressed_rows"] or 0
    return [
        f"- {raw_alerts} raw alert rows were recorded in the window, representing {summary['total_seen'] or 0} total seen events.",
        f"- {urgent_rows} rows were critical/high and should be reviewed first.",
        f"- {suppressed_rows} rows were suppressed by tuning rules and retained as evidence.",
        "- Use the grouped detections table for alert-volume reality; it mirrors the dashboard Count model.",
        "",
    ]


def _summary_tables(data: Mapping[str, object]) -> list[str]:
    summary = data["summary"]
    by_status = data["by_status"]
    return [
        "## Summary Metrics",
        "",
        table(
            [
                "Raw Rows",
                "Total Seen",
                "Urgent Rows",
                "Accepted",
                "Suppressed",
                "Duplicates",
                "First Seen",
                "Last Seen",
            ],
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
            [
                "Filter Status",
                "Level",
                "Raw Rows",
                "Total Seen",
                "Last Seen",
            ],
            (
                [
                    row["filter_status"],
                    row["triage_level"],
                    row["raw_alerts"],
                    row["total_seen"],
                    row["last_seen"],
                ]
                for row in by_status
            ),
        ),
    ]


def _grouped_detection_table(grouped: object) -> list[str]:
    return [
        "## Top Grouped Detections",
        "",
        table(
            [
                "Count",
                "Raw Rows",
                "Level",
                "Status",
                "Max Score",
                "Rule",
                "Source",
                "Destination",
                "Last Seen",
            ],
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
    ]


def _urgent_alert_table(urgent: object) -> list[str]:
    return [
        "## Urgent Alert Queue",
        "",
        table(
            [
                "Alert ID",
                "Level",
                "Score",
                "Status",
                "Routing",
                "Rule",
                "Source",
                "Destination",
                "Seen",
                "Last Seen",
            ],
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
    ]


def _suppression_table(suppressed: object) -> list[str]:
    return [
        "## Suppression Activity",
        "",
        table(
            [
                "Suppression Key",
                "Rule",
                "Reason",
                "Seen",
                "Suppressed",
                "Escalated",
                "TTL Seconds",
                "Last Seen",
            ],
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
    ]


def _new_pair_table(new_pairs: object) -> list[str]:
    return [
        "## New Source Destination Pairs",
        "",
        table(
            [
                "Source",
                "Destination",
                "Raw Rows",
                "Total Seen",
                "Max Score",
                "Last Seen",
            ],
            (
                [
                    row["source_ip"],
                    row["destination_ip"],
                    row["raw_alerts"],
                    row["total_seen"],
                    row["max_score"],
                    row["last_seen"],
                ]
                for row in new_pairs
            ),
        ),
    ]


def _notification_table(notifications: object) -> list[str]:
    return [
        "## Telegram Notifications",
        "",
        table(
            [
                "Channel",
                "Level",
                "Rule",
                "Source",
                "Destination",
                "Sent Count",
                "Last Sent",
            ],
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
    ]


def _analyst_tail() -> list[str]:
    return [
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
    ]


def render_rollup(
    data: Mapping[str, object],
    *,
    since: str,
    generated_at: str,
    report_date: str,
    hours: int,
    include_tests: bool,
) -> str:
    """Render one collected rollup without database or filesystem access."""
    lines = _header(
        since=since,
        generated_at=generated_at,
        report_date=report_date,
        hours=hours,
        include_tests=include_tests,
    )
    lines.extend(_executive_summary(data["summary"]))
    lines.extend(_summary_tables(data))
    lines.extend(_grouped_detection_table(data["grouped"]))
    lines.extend(_urgent_alert_table(data["urgent"]))
    lines.extend(_suppression_table(data["suppressed"]))
    lines.extend(_new_pair_table(data["new_pairs"]))
    lines.extend(_notification_table(data["notifications"]))
    lines.extend(_analyst_tail())
    return "\n".join(lines)
