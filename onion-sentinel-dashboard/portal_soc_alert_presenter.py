"""Pure API projection for one SOC alert summary row."""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Callable, Union


JsonObject = dict[str, object]
Row = Union[sqlite3.Row, dict]


@dataclass(frozen=True)
class SocAlertPresentationDependencies:
    dashboard_group_id: Callable[[str], str]
    ai_status: Callable[[Row, str, object, object, str], JsonObject]
    enrichment_status: Callable[[object], JsonObject]
    pcap_status: Callable[[str, object, object, object], JsonObject]
    incident_defaults: Callable[[], JsonObject]
    review_defaults: Callable[[], JsonObject]


def _has(row: Row, key: str) -> bool:
    return key in row.keys()


def _optional(row: Row, key: str, default: object = "") -> object:
    return row[key] if _has(row, key) else default


def _local_status(statuses: object, group_id: str) -> dict:
    if not isinstance(statuses, dict):
        return {}
    value = statuses.get(group_id, {})
    return value if isinstance(value, dict) else {}


def _base_fields(row: Row, group_id: str, local_status: dict) -> JsonObject:
    repeat_count = max(
        int(row["raw_alert_count"] or 0),
        int(row["total_seen_count"] or 0),
        int(row["seen_count"] or 0),
    )
    return {
        "group_id": group_id,
        "group_key": row["group_key"],
        "representative_alert_id": row["alert_id"],
        "first_seen": row["group_first_seen"] or row["first_seen"],
        "last_seen": row["group_last_seen"] or row["last_seen"],
        "raw_alert_count": int(row["raw_alert_count"] or 0),
        "seen_count": repeat_count,
        "timestamp": row["timestamp"],
        "rule_name": row["rule_name"],
        "event_dataset": row["event_dataset"],
        "severity": row["severity"],
        "severity_label": row["severity_label"],
        "triage_score": row["triage_score"],
        "triage_level": row["triage_level"],
        "routing": row["routing"],
        "traffic_direction": row["traffic_direction"],
        "source_ip": row["source_ip"],
        "source_port": row["source_port"],
        "destination_ip": row["destination_ip"],
        "destination_port": row["destination_port"],
        "payload_size_bytes": int(_optional(row, "payload_size_bytes", 0) or 0),
        "transport_protocol": row["transport_protocol"],
        "filter_status": row["filter_status"] or "accepted",
        "filter_reason": row["filter_reason"],
        "suppression_key": row["suppression_key"],
        "analyst_status": local_status.get("status", "open"),
        "analyst_status_reason": local_status.get("reason", ""),
        "analyst_status_updated_at": local_status.get("updated_at"),
        "analyst_status_updated_by": local_status.get("updated_by", ""),
    }


def _evidence_fields(evidence_metadata: object, group_id: str,
                     deps: SocAlertPresentationDependencies) -> JsonObject:
    evidence = evidence_metadata if isinstance(evidence_metadata, dict) else {}
    record = evidence.get(group_id)
    if isinstance(record, dict):
        return record
    return {
        "pcap_size_bytes": 0,
        "detection_outcome": "",
        "detection_outcome_label": "n/a",
        **deps.incident_defaults(),
        **deps.review_defaults(),
    }


def compose_soc_alert_row(row: Row, statuses: object, ai_reports: object,
                          pcap_analysis: object, pcap_requests: object,
                          ai_artifacts: object, evidence_metadata: object,
                          analysis_min_severity: str,
                          dependencies: SocAlertPresentationDependencies) -> JsonObject:
    """Project one summary row plus precomputed page metadata into the public API."""
    group_id = dependencies.dashboard_group_id(str(row["group_key"] or ""))
    data = _base_fields(row, group_id, _local_status(statuses, group_id))
    data.update(dependencies.ai_status(
        row, group_id, ai_reports, ai_artifacts, analysis_min_severity,
    ))
    data.update(dependencies.enrichment_status(_optional(row, "enrichment_json")))
    data.update(dependencies.pcap_status(
        group_id, row["alert_id"], pcap_analysis or {}, pcap_requests or {},
    ))
    data.update(_evidence_fields(evidence_metadata, group_id, dependencies))
    return data
