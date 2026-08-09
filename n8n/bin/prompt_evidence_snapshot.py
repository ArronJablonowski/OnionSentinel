#!/usr/bin/env python3
"""Collect bounded read-only evidence snapshots for prompt preparation."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable


@dataclass(frozen=True)
class CoreEvidenceSnapshotRequest:
    """Inputs for evidence required before governed admission."""

    connection: Any
    selected: Any
    rollup_dir: Path
    rollup_bytes: int
    related_limit: int
    include_tests: bool
    pcap_analysis_dir: Path
    pcap_analysis_limit: int
    correlation_limit: int
    correlation_min_score: int


@dataclass(frozen=True)
class CoreEvidenceSnapshotSources:
    """Read-only collectors injected by the legacy composition root."""

    grouped_alert_context: Callable[[Any, Any, int, bool], dict]
    pcap_evidence_context: Callable[[Any, Any, Path, int], dict]
    public_enrichment_context: Callable[[Any, Any, int, bool], dict]
    authorized_activity_context: Callable[[Any, Any], dict]
    analyst_state_context: Callable[[Any, Any], dict]
    correlated_alert_context: Callable[[Any, Any, int, int], dict]
    compact_alert: Callable[[Any], dict]


@dataclass(frozen=True)
class CoreEvidenceSnapshot:
    """Bounded evidence needed for detection and admission preparation."""

    latest_daily_rollup: dict
    grouped_alert_context: dict
    pcap_evidence: dict
    public_enrichment: dict
    authorization_evidence: dict
    analyst_state: dict
    correlated_alert_context: dict
    alert: dict


@dataclass(frozen=True)
class HistoricalEvidenceSnapshotRequest:
    """Inputs for history loaded only after governed admission succeeds."""

    connection: Any
    selected: Any
    analysis_dir: Path
    related_limit: int
    include_tests: bool
    blind_reanalysis: bool


@dataclass(frozen=True)
class HistoricalEvidenceSnapshotSources:
    """Historical read projections injected by the composition root."""

    prior_analysis_context: Callable[[Any, Path, Any], Any]
    related_alerts: Callable[[Any, Any, int, bool], list[dict]]
    query_rows: Callable[[Any, str, list[Any]], list[Any]]


@dataclass(frozen=True)
class HistoricalEvidenceSnapshot:
    """Historical evidence admitted after current-evidence validation."""

    prior_analyses: Any
    related_alerts: list[dict]
    recent_notifications: list[dict]


def _latest_rollup(rollup_dir: Path, limit_bytes: int) -> dict:
    files = sorted(rollup_dir.glob("*-soc-daily-rollup.md"))
    if not files:
        return {"path": None, "content": ""}
    latest = files[-1]
    with latest.open("rb") as handle:
        data = handle.read(limit_bytes)
    return {"path": str(latest), "content": data.decode("utf-8", errors="replace")}


def _notification_context(
    sources: HistoricalEvidenceSnapshotSources,
    request: HistoricalEvidenceSnapshotRequest,
) -> list[dict]:
    found = sources.query_rows(
        request.connection,
        """
        SELECT channel, triage_level, rule_name, source_ip, destination_ip,
               sent_count, last_sent
        FROM notification_log
        WHERE rule_name = ?
           OR source_ip = ?
           OR destination_ip = ?
        ORDER BY last_sent DESC
        LIMIT 10
        """,
        [
            request.selected["rule_name"],
            request.selected["source_ip"],
            request.selected["destination_ip"],
        ],
    )
    return [dict(item) for item in found]


def collect_core_evidence_snapshot(
    sources: CoreEvidenceSnapshotSources,
    request: CoreEvidenceSnapshotRequest,
) -> CoreEvidenceSnapshot:
    """Collect current evidence in the established fail-fast order."""
    return CoreEvidenceSnapshot(
        latest_daily_rollup=_latest_rollup(
            request.rollup_dir,
            request.rollup_bytes,
        ),
        grouped_alert_context=sources.grouped_alert_context(
            request.connection,
            request.selected,
            request.related_limit,
            request.include_tests,
        ),
        pcap_evidence=sources.pcap_evidence_context(
            request.connection,
            request.selected,
            request.pcap_analysis_dir,
            request.pcap_analysis_limit,
        ),
        public_enrichment=sources.public_enrichment_context(
            request.connection,
            request.selected,
            request.related_limit,
            request.include_tests,
        ),
        authorization_evidence=sources.authorized_activity_context(
            request.connection,
            request.selected,
        ),
        analyst_state=sources.analyst_state_context(
            request.connection,
            request.selected,
        ),
        correlated_alert_context=sources.correlated_alert_context(
            request.connection,
            request.selected,
            request.correlation_limit,
            request.correlation_min_score,
        ),
        alert=sources.compact_alert(request.selected),
    )


def collect_historical_evidence_snapshot(
    sources: HistoricalEvidenceSnapshotSources,
    request: HistoricalEvidenceSnapshotRequest,
) -> HistoricalEvidenceSnapshot:
    """Collect prior, related, and notification evidence in package order."""
    prior_analyses = (
        []
        if request.blind_reanalysis
        else sources.prior_analysis_context(
            request.connection,
            request.analysis_dir,
            request.selected,
        )
    )
    return HistoricalEvidenceSnapshot(
        prior_analyses=prior_analyses,
        related_alerts=sources.related_alerts(
            request.connection,
            request.selected,
            request.related_limit,
            request.include_tests,
        ),
        recent_notifications=_notification_context(sources, request),
    )
