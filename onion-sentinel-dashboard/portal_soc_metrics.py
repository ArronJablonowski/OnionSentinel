"""SOC alert metrics and analyst-status read-model policy."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


Row = object


@dataclass(frozen=True)
class SocMetricsQueryPlan:
    """Parameterized queries required for one metrics snapshot."""

    source: str
    args: tuple[object, ...]
    total_sql: str
    latest_sql: str
    grouped_sql: str
    filter_status_sql: str
    level_sql: str
    top_rules_sql: str
    suppression_sql: str


def metrics_query_plan(
    since: str,
    group_expr: str,
    summary_available: bool,
) -> SocMetricsQueryPlan:
    """Build the bounded summary or legacy metrics repository plan."""
    where_sql = " WHERE last_seen >= ?" if since else ""
    args: tuple[object, ...] = (since,) if since else ()
    if summary_available:
        source = "sqlite-summary"
        grouped_sql = f"""
            SELECT group_id, group_key, raw_alert_count, total_seen_count,
                   last_seen, filter_status
            FROM alert_group_summary
            {where_sql}
        """
    else:
        source = "sqlite"
        grouped_sql = f"""
            SELECT {group_expr} AS group_key,
                   COUNT(*) AS raw_alert_count,
                   COALESCE(SUM(MAX(1, COALESCE(seen_count, 1))), 0)
                     AS total_seen_count,
                   MAX(last_seen) AS last_seen,
                   COALESCE(NULLIF(filter_status, ''), 'accepted') AS filter_status
            FROM alerts
            {where_sql}
            GROUP BY group_key, filter_status
        """
    return SocMetricsQueryPlan(
        source=source,
        args=args,
        total_sql=f"SELECT COUNT(*) FROM alerts{where_sql}",
        latest_sql=f"SELECT MAX(last_seen) FROM alerts{where_sql}",
        grouped_sql=grouped_sql,
        filter_status_sql=(
            "SELECT COALESCE(filter_status, 'accepted'), COUNT(*) "
            f"FROM alerts{where_sql} GROUP BY COALESCE(filter_status, 'accepted')"
        ),
        level_sql=(
            "SELECT COALESCE(triage_level, severity_label, 'unknown'), COUNT(*) "
            f"FROM alerts{where_sql} "
            "GROUP BY COALESCE(triage_level, severity_label, 'unknown')"
        ),
        top_rules_sql=(
            "SELECT COALESCE(rule_name, 'unknown'), COUNT(*) AS rule_count "
            f"FROM alerts{where_sql} GROUP BY COALESCE(rule_name, 'unknown') "
            "ORDER BY rule_count DESC LIMIT 10"
        ),
        suppression_sql=(
            "SELECT COUNT(*), COALESCE(SUM(suppressed_count), 0), "
            "COALESCE(SUM(escalated_count), 0) FROM suppression_log"
        ),
    )


def exclude_group_rows(
    rows: list[Row],
    excluded_group_ids: set[str],
    group_id: Callable[[Row], str],
) -> list[Row]:
    """Remove manually escalated groups from the SOC dashboard snapshot."""
    return [row for row in rows if group_id(row) not in excluded_group_ids]


def grouped_observation_count(rows: list[Row]) -> int:
    """Count observations without undercounting legacy raw group rows."""
    total = 0
    for row in rows:
        total += max(
            int(row["raw_alert_count"] or 0),
            int(row["total_seen_count"] or 0),
        )
    return total


def compose_metrics_payload(
    *,
    source: str,
    since: str,
    total: int,
    latest_seen: object,
    grouped_rows: list[Row],
    pcap_ingest_size_bytes: int,
    by_filter_status: dict,
    by_analyst_status: dict,
    by_level: dict,
    top_rules: list[dict],
    suppression_totals: Row,
) -> dict:
    """Compose the stable public metrics response schema."""
    return {
        "ok": True,
        "source": source,
        "mode": "grouped",
        "since": since or None,
        "total": total,
        "grouped_total": len(grouped_rows),
        "grouped_observations": grouped_observation_count(grouped_rows),
        "pcap_ingest_size_bytes": pcap_ingest_size_bytes,
        "latest_seen": latest_seen,
        "by_filter_status": by_filter_status,
        "by_analyst_status": by_analyst_status,
        "by_level": by_level,
        "top_rules": top_rules,
        "suppression_log": {
            "windows": suppression_totals[0],
            "suppressed_count": suppression_totals[1],
            "escalated_count": suppression_totals[2],
        },
    }


def compose_status_payload(
    statuses: dict,
    *,
    group_counts: dict[str, int] | None = None,
    escalated_group_ids: set[str] | None = None,
    active_group_ids: set[str] | None = None,
) -> dict:
    """Compose grouped analyst state, preserving database-unavailable fallback."""
    acknowledged_all = {
        alert_id for alert_id, meta in statuses.items()
        if isinstance(meta, dict) and meta.get("status") == "acknowledged"
    }
    suppressed_all = {
        alert_id for alert_id, meta in statuses.items()
        if isinstance(meta, dict) and meta.get("status") == "suppressed"
    }
    acknowledged = acknowledged_all
    suppressed = suppressed_all
    counts = {
        "open": 0,
        "acknowledged": len(acknowledged),
        "suppressed": len(suppressed),
    }
    if group_counts is None or escalated_group_ids is None or active_group_ids is None:
        counts["total"] = len(statuses)
    else:
        acknowledged = acknowledged_all.difference(escalated_group_ids)
        suppressed = suppressed_all.difference(escalated_group_ids)
        counts.update({
            "open": len(active_group_ids),
            "acknowledged": len(acknowledged),
            "suppressed": len(suppressed),
            "escalated": len(set(group_counts).intersection(escalated_group_ids)),
            "total": len(set(group_counts).difference(escalated_group_ids)),
        })
    return {
        "ok": True,
        "mode": "grouped",
        "statuses": statuses,
        "acknowledged": sorted(acknowledged),
        "suppressed": sorted(suppressed),
        "counts": counts,
    }
