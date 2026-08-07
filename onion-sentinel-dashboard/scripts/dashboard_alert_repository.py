"""Read-only SQLite repository and grouped-row normalization for SOC alerts."""
from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path

from dashboard_alert_detail_enrichment import public_enrichment_has_content
from dashboard_alert_detail_values import nested_value
from dashboard_pcap_request_index import build_pcap_request_index
from dashboard_time_format import parse_iso_timestamp


GROUP_FALLBACK_VALUES = {
    "triage_level": "unscored",
    "rule_name": "unknown-rule",
    "source_ip": "unknown-source",
    "destination_ip": "unknown-destination",
    "filter_status": "accepted",
}


@dataclass(frozen=True)
class AlertRepositoryResult:
    """Normalized grouped alerts and request metadata from one DB snapshot."""

    rows: tuple[dict[str, object], ...]
    pcap_request_index: dict[str, object]


def row_item(row: object, key: str) -> object:
    """Read a required column from a SQLite-compatible row."""
    return row[key]  # type: ignore[index]


def safe_int(value: object) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def clean_endpoint_part(value: object | None) -> str:
    value = str(value or "").strip().strip("\"'")
    return "" if value.lower() in {"none", "null", "n/a", "unknown"} else value


def raw_alert_object(row: object) -> dict:
    """Decode the stored normalized alert object without raising on bad JSON."""
    try:
        value = json.loads(row_item(row, "alert_json") or "{}")
        return value if isinstance(value, dict) else {}
    except json.JSONDecodeError:
        return {}


def alert_group_key(row: object) -> str:
    """Return the stable grouped-detection key, excluding rotating source ports."""
    suppression_key = row_item(row, "suppression_key")
    if suppression_key:
        return str(suppression_key)
    return (
        f'{row_item(row, "triage_level") or GROUP_FALLBACK_VALUES["triage_level"]}|'
        f'{row_item(row, "rule_name") or GROUP_FALLBACK_VALUES["rule_name"]}|'
        f'{row_item(row, "source_ip") or GROUP_FALLBACK_VALUES["source_ip"]}|'
        f'{row_item(row, "destination_ip") or GROUP_FALLBACK_VALUES["destination_ip"]}|'
        f'{row_item(row, "filter_status") or GROUP_FALLBACK_VALUES["filter_status"]}'
    )


def select_alert_rows(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    """Read alert rows across supported alert-store schema versions."""
    columns = {row[1] for row in conn.execute("PRAGMA table_info(alerts)").fetchall()}
    expressions = {
        "total_seen_count": "total_seen_count" if "total_seen_count" in columns else "0",
        "source_port": "source_port" if "source_port" in columns else "NULL",
        "destination_port": "destination_port" if "destination_port" in columns else "NULL",
        "network_protocol": "network_protocol" if "network_protocol" in columns else "NULL",
        "transport_protocol": "transport_protocol" if "transport_protocol" in columns else "NULL",
    }
    return conn.execute(
        f"""
        SELECT alert_id, first_seen, last_seen, seen_count,
               {expressions['total_seen_count']} AS total_seen_count,
               timestamp, rule_name, event_dataset, severity, severity_label, source_ip, destination_ip,
               {expressions['source_port']} AS source_port,
               {expressions['destination_port']} AS destination_port,
               {expressions['network_protocol']} AS network_protocol,
               {expressions['transport_protocol']} AS transport_protocol,
               alert_json, traffic_direction, triage_score, triage_level, routing,
               filter_status, filter_reason, suppression_key, enrichment_json
        FROM alerts
        ORDER BY replace(replace(COALESCE(last_seen, timestamp, first_seen), 'T', ' '), 'Z', '') DESC,
                 alert_id DESC
        """
    ).fetchall()


def timeline_member(member: object) -> tuple[dict[str, object], int]:
    """Normalize one raw member into timeline evidence and its seen count."""
    seen_count = max(
        1,
        safe_int(row_item(member, "seen_count")),
        safe_int(row_item(member, "total_seen_count")),
    )
    first_seen = row_item(member, "first_seen")
    last_seen = row_item(member, "last_seen")
    raw = raw_alert_object(member)
    timeline = {
        "alert_id": row_item(member, "alert_id"),
        "timestamp": row_item(member, "timestamp") or last_seen or first_seen,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "seen_count": seen_count,
        "source_ip": row_item(member, "source_ip") or nested_value(raw, "source", "ip") or "n/a",
        "destination_ip": row_item(member, "destination_ip") or nested_value(raw, "destination", "ip") or "n/a",
        "destination_port": clean_endpoint_part(
            row_item(member, "destination_port") or nested_value(raw, "destination", "port")
        ),
    }
    return timeline, seen_count


def group_time_bounds(members: list[object]) -> tuple[object, object]:
    """Return the earliest first-seen and latest last-seen values in a group."""
    earliest = row_item(members[0], "first_seen")
    latest = row_item(members[0], "last_seen")
    earliest_ts = parse_iso_timestamp(earliest)  # type: ignore[arg-type]
    latest_ts = parse_iso_timestamp(latest)  # type: ignore[arg-type]
    for member in members[1:]:
        member_first = row_item(member, "first_seen")
        member_last = row_item(member, "last_seen")
        member_first_ts = parse_iso_timestamp(member_first)  # type: ignore[arg-type]
        member_last_ts = parse_iso_timestamp(member_last)  # type: ignore[arg-type]
        if earliest_ts is None or (member_first_ts is not None and member_first_ts < earliest_ts):
            earliest, earliest_ts = member_first, member_first_ts
        if latest_ts is None or (member_last_ts is not None and member_last_ts > latest_ts):
            latest, latest_ts = member_last, member_last_ts
    return earliest, latest


def carry_forward_enrichment(row: dict[str, object], members: list[object]) -> None:
    """Use the newest available public enrichment when the representative lacks it."""
    if public_enrichment_has_content(row.get("enrichment_json")):
        return
    enriched = next(
        (member for member in members if public_enrichment_has_content(row_item(member, "enrichment_json"))),
        None,
    )
    if enriched is not None:
        row["enrichment_json"] = row_item(enriched, "enrichment_json")


def aggregate_alert_group(key: str, members: list[object]) -> dict[str, object]:
    """Collapse one ordered group into its newest representative and timeline."""
    representative = members[0]
    earliest_first_seen, latest_last_seen = group_time_bounds(members)
    normalized = [timeline_member(member) for member in members]
    timeline = [item for item, _seen_count in normalized]
    total_seen = sum(seen_count for _item, seen_count in normalized)
    row = dict(representative)  # type: ignore[arg-type]
    carry_forward_enrichment(row, members)
    raw_count = len(members)
    row.update({
        "raw_alert_count": raw_count,
        "total_seen_count": total_seen,
        "repeat_count": max(raw_count, total_seen),
        "member_alert_ids": [row_item(member, "alert_id") for member in members],
        "member_timeline": timeline,
        "first_seen": earliest_first_seen or row_item(representative, "first_seen") or "n/a",
        "last_seen": latest_last_seen or row_item(representative, "last_seen") or "n/a",
        "alert_group_key": key,
    })
    return row


def aggregate_alert_rows(rows: list[sqlite3.Row]) -> tuple[dict[str, object], ...]:
    """Group ordered raw rows into stable dashboard detections."""
    grouped: dict[str, list[object]] = {}
    for row in rows:
        grouped.setdefault(alert_group_key(row), []).append(row)
    return tuple(aggregate_alert_group(key, members) for key, members in grouped.items())


def load_alert_repository(db_path: Path) -> AlertRepositoryResult:
    """Read one consistent alert-store snapshot without creating or mutating state."""
    with closing(sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=30)) as conn:
        conn.row_factory = sqlite3.Row
        rows = select_alert_rows(conn)
        pcap_requests = build_pcap_request_index(conn)
    return AlertRepositoryResult(
        rows=aggregate_alert_rows(rows),
        pcap_request_index=pcap_requests,
    )
