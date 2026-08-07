"""Grouped SOC alert page orchestration and public response composition."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


JsonObject = dict[str, object]
Row = object


@dataclass(frozen=True)
class SocAlertQuerySnapshot:
    statuses: dict
    status_counts: dict[str, int]
    active_total: int
    active_severity_counts: dict[str, int]
    active_highest_severity: str
    severity_counts: dict[str, int]
    highest_severity: str
    top_endpoints: dict[str, str]
    filtered_rows: list[Row]
    page_rows: list[Row]
    total_matching: int
    total_pages: int
    current_page: int
    offset: int
    next_cursor: str | None


@dataclass(frozen=True)
class SocGroupQueryDependencies:
    db_path: str
    load_ai_reports: Callable[[], dict]
    load_ai_artifacts: Callable[[list[Row]], dict]
    load_analysis_min_severity: Callable[[], str]
    load_pcap_analysis: Callable[[], dict]
    load_page_evidence: Callable[[list[Row], dict, dict], tuple[dict, dict]]
    present_alert: Callable[..., JsonObject]


def _present_alerts(snapshot: SocAlertQuerySnapshot, dependencies: SocGroupQueryDependencies,
                    ai_reports: dict, ai_artifacts: dict, pcap_analysis: dict,
                    pcap_requests: dict, evidence_metadata: dict,
                    analysis_min_severity: str) -> list[JsonObject]:
    return [
        dependencies.present_alert(
            row, snapshot.statuses, ai_reports, pcap_analysis, pcap_requests,
            ai_artifacts, evidence_metadata, analysis_min_severity,
        )
        for row in snapshot.page_rows
    ]


def _response(source: str, snapshot: SocAlertQuerySnapshot, limit: int,
              sort_key: str, sort_direction: str, db_path: str,
              alerts: list[JsonObject]) -> JsonObject:
    return {
        "ok": True, "source": source, "mode": "grouped", "db_path": db_path,
        "count": len(snapshot.page_rows), "total_matching": snapshot.total_matching,
        "status_counts": snapshot.status_counts, "active_total": snapshot.active_total,
        "active_severity_counts": snapshot.active_severity_counts,
        "active_highest_severity": snapshot.active_highest_severity,
        "severity_counts": snapshot.severity_counts,
        "highest_severity": snapshot.highest_severity,
        "top_endpoints": snapshot.top_endpoints, "limit": limit,
        "page": snapshot.current_page, "page_size": limit,
        "total_pages": snapshot.total_pages, "sort": sort_key,
        "direction": sort_direction, "next_cursor": snapshot.next_cursor,
        "alerts": alerts,
    }


def compose_group_query_payload(
    *,
    source: str,
    snapshot: SocAlertQuerySnapshot,
    limit: int,
    sort_key: str,
    sort_direction: str,
    dependencies: SocGroupQueryDependencies,
) -> JsonObject:
    """Load page-scoped metadata once and compose the grouped public response."""
    ai_reports = dependencies.load_ai_reports()
    ai_artifacts = dependencies.load_ai_artifacts(snapshot.page_rows)
    analysis_min_severity = dependencies.load_analysis_min_severity()
    pcap_analysis = dependencies.load_pcap_analysis()
    pcap_requests, evidence_metadata = dependencies.load_page_evidence(
        snapshot.page_rows, ai_artifacts, pcap_analysis,
    )
    alerts = _present_alerts(
        snapshot, dependencies, ai_reports, ai_artifacts, pcap_analysis,
        pcap_requests, evidence_metadata, analysis_min_severity,
    )
    return _response(
        source, snapshot, limit, sort_key, sort_direction, dependencies.db_path, alerts,
    )
