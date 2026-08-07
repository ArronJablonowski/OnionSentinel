"""Shared SOC alert report view model and severity ordering."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


CRITICALITY_ORDER = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "informational": 1,
    "info": 1,
}


@dataclass
class AlertReport:
    """Static dashboard view of one grouped alert and its evidence state."""

    title: str
    source: Path
    rel_source: str
    mtime: float
    size: int
    digest: str
    rendered_html: str
    summary: str
    criticality: str
    criticality_rank: int
    alert_source: str
    filter_status: str
    source_ip: str
    source_port: str
    destination_ip: str
    destination_port: str
    source_endpoint: str
    destination_endpoint: str
    rule_id: str
    rule_name: str
    raw_alert_count: int
    total_seen_count: int
    repeat_count: int
    first_seen: str
    last_seen: str
    alert_group_key: str
    alert_ts: float
    ai_status_key: str
    ai_status_label: str
    ai_status_detail: str
    enrichment_status_key: str
    enrichment_status_label: str
    enrichment_status_detail: str
    enrichment_record_count: int
    enrichment_skip_count: int
    enrichment_error_count: int
    pcap_status_key: str
    pcap_status_label: str
    pcap_status_detail: str
    tuning_recommendation: str
    tuning_reason: str
    recommended_tuning_actions: list[str]
    ai_analysis: dict[str, object]
