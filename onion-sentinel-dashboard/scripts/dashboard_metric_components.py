#!/usr/bin/env python3
"""Small HTML render helpers for SOC Alerts metric cards.

The dashboard builder is intentionally data-heavy: it reads SQLite, report
corpus metadata, AI state, and generated artifacts. Metric-card markup changes
are frequent UI polish work, so these helpers stay isolated from that larger
builder to make future edits easy to review and test.
"""
from __future__ import annotations

import html
from typing import Any


def _count(state: dict[str, Any], key: str) -> int:
    """Return an integer counter from the AI state without leaking bad input."""
    counts = state.get("counts") if isinstance(state.get("counts"), dict) else {}
    try:
        return int(counts.get(key, 0))
    except (TypeError, ValueError):
        return 0


def render_ai_activity_extra(state: dict[str, Any], fallback_model: str) -> str:
    """Render verbose AI queue state used when metric cards expand responsively."""
    model = str(state.get("model") or fallback_model)
    return (
        f'<span class="metric-detail-row"><b>Model</b><span>{html.escape(model)}</span></span>'
        f'<span class="metric-detail-row"><b>Active</b><span>{_count(state, "analyzing")}</span></span>'
        f'<span class="metric-detail-row"><b>Queued</b><span>{_count(state, "queued")}</span></span>'
        f'<span class="metric-detail-row"><b>Analyzed</b><span>{_count(state, "analyzed")}</span></span>'
        f'<span class="metric-detail-row"><b>Skipped</b><span>{_count(state, "not_queued")}</span></span>'
    )


def render_ai_activity_counts(state: dict[str, Any]) -> str:
    """Render the compact AI queue counts shown in the SOC metric card."""
    return (
        '<div class="ai-activity-counts" aria-label="AI analysis queue counts">'
        f'<span><b id="ai-analyzed-count">{_count(state, "analyzed")}</b> Analyzed</span>'
        f'<span><b id="ai-queued-count">{_count(state, "queued")}</b> Queued</span>'
        f'<span><b id="ai-skipped-count">{_count(state, "not_queued")}</b> Skipped</span>'
        '</div>'
    )


def render_active_alerts_metric(total_severity_html: str) -> str:
    """Render active alert counts by severity for groups needing analyst action."""
    return (
        '<div class="metric-card severity-summary-card">'
        '<span class="metric-icon"><img src="assets/metric-visible.png" alt="Active alert severity icon"></span>'
        '<div class="metric-main severity-summary-main">'
        '<strong>Active Alerts</strong>'
        f'<div id="visible-metric-extra" class="severity-breakdown severity-card-counts" aria-label="Active alert severity breakdown">{total_severity_html}</div>'
        '</div></div>'
    )


def render_alert_status_metric() -> str:
    """Render server-persisted analyst status totals for all grouped alerts."""
    return (
        '<div id="n8n-beacon-card" class="metric-card alert-status-card">'
        '<span class="metric-icon"><img src="assets/metric-total.png" alt="Alert status totals icon"></span>'
        '<div class="metric-main alert-status-main">'
        '<strong>Alert Status</strong>'
        '<div class="api-table-metrics alert-status-metrics" aria-label="SOC alert status totals">'
        '<span class="api-table-metric total"><b id="top-api-grouped-total">0</b> Total</span>'
        '<span class="api-table-metric"><b id="top-api-visible-total">0</b> Active</span>'
        '<span class="api-table-metric acknowledged"><b id="top-api-acknowledged-total">0</b> Acknowledged</span>'
        '<span class="api-table-metric suppressed"><b id="top-api-suppressed-total">0</b> Suppressed</span>'
        '</div></div></div>'
    )


def render_ai_activity_metric(state: dict[str, Any], fallback_model: str) -> str:
    """Render local AI alert triage status and queue counters."""
    ai_activity_class = " ai-activity-active" if bool(state.get("active")) else ""
    ai_activity_label = html.escape(str(state.get("label") or "AI Alert Triage"))
    ai_activity_detail = html.escape(str(state.get("detail") or f"Idle · Model: {fallback_model}"))
    return (
        f'<div id="ai-activity-card" class="metric-card ai-activity-card{ai_activity_class}" aria-live="polite">'
        '<div class="metric-main ai-activity-main">'
        f'<strong id="ai-activity-label">{ai_activity_label}</strong>'
        f'<span id="ai-activity-detail">{ai_activity_detail}</span>'
        f'{render_ai_activity_counts(state)}'
        '</div>'
        f'<div id="ai-activity-extra" class="metric-extra metric-detail">{render_ai_activity_extra(state, fallback_model)}</div>'
        '</div>'
    )


def render_latest_network_metric(latest_extra_html: str) -> str:
    """Render the most frequent source, destination, and destination port."""
    return (
        '<div id="latest-alert-card" class="metric-card latest-network-card">'
        '<span class="metric-icon"><img src="assets/metric-latest.png" alt="Latest alert icon"></span>'
        '<div class="metric-main latest-network-main">'
        '<strong>Frequent Indicators</strong>'
        '<div class="latest-network-metrics" aria-label="Top network indicators">'
        '<span class="latest-network-metric"><span>Top SRC:</span><b id="top-api-source-ip">n/a</b></span>'
        '<span class="latest-network-metric"><span>Top DST:</span><b id="top-api-destination-ip">n/a</b></span>'
        '<span class="latest-network-metric"><span>Top DST Port:</span><b id="top-api-destination-port">n/a</b></span>'
        '</div></div>'
        f'<div id="latest-alert-extra" class="metric-extra metric-detail">{latest_extra_html}</div>'
        '</div>'
    )


def render_size_metric(total_size_text: str, latest_alert_text: str, pcap_ingest_size_text: str = "0 B") -> str:
    """Render the compact System Health card shown in the SOC Alerts metrics row."""
    latest_alert_html = html.escape(latest_alert_text).replace("  ", "&nbsp;&nbsp;", 1)
    return (
        '<div class="metric-card system-health-metric-card">'
        '<strong class="system-health-metric-heading">System Health</strong>'
        '<div class="metric-main system-health-metric-main">'
        f'<span><b>SOC Reports:</b> {html.escape(total_size_text)}</span>'
        f'<span><b>PCAP Ingest:</b> <span id="pcap-ingest-size">{html.escape(pcap_ingest_size_text)}</span></span>'
        f'<span><b>Last Alert:</b> {latest_alert_html}</span>'
        '</div>'
        '</div>'
    )
