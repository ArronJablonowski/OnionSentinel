"""Pure Executive Home view models and chart/KPI renderers."""
from __future__ import annotations

from dataclasses import dataclass
import html


@dataclass(frozen=True)
class ExecutiveDonutRowViewModel:
    label: str
    value: int
    class_name: str


@dataclass(frozen=True)
class ExecutiveHourlyBucketViewModel:
    start_utc_iso: str
    fallback_label: str
    count: int
    current: bool


@dataclass(frozen=True)
class ExecutiveHourlyIntakeViewModel:
    buckets: tuple[ExecutiveHourlyBucketViewModel, ...]
    exact: bool


@dataclass(frozen=True)
class ExecutiveCacheViewModel:
    available: bool
    runtime_available: bool
    fresh_entries: int
    stale_entries: int
    api_calls_avoided: int
    hit_rate: str
    provider_loads: int
    stale_fallbacks: int
    payload_size: str


@dataclass(frozen=True)
class ExecutiveHomePageViewModel:
    latest_seen: str
    total_groups: int
    total_observations: int
    urgent_groups: int
    suppressed_groups: int
    analyzed_groups: int
    urgent_percent: int
    ai_percent: int
    suppression_percent: int
    cache_kpi_label: str
    cache_kpi_value: str
    cache_kpi_note: str
    severity_rows: tuple[ExecutiveDonutRowViewModel, ...]
    status_rows: tuple[ExecutiveDonutRowViewModel, ...]
    ai_rows: tuple[ExecutiveDonutRowViewModel, ...]
    top_rule_rows: tuple[tuple[str, int], ...]
    destination_rows: tuple[tuple[str, int], ...]
    source_ip_rows: tuple[tuple[str, int], ...]
    source_rows: tuple[tuple[str, int], ...]
    hourly: ExecutiveHourlyIntakeViewModel
    cache: ExecutiveCacheViewModel


def _percent(part: int | float, total: int | float) -> int:
    return round((part / total) * 100) if total else 0


def render_executive_donut(
    title: str, center: str, subtitle: str,
    rows: tuple[ExecutiveDonutRowViewModel, ...],
) -> str:
    total = sum(row.value for row in rows)
    if total <= 0:
        rows = (ExecutiveDonutRowViewModel('No data', 1, 'info'),)
        total = 1
    offset = 25.0
    segments, legend = [], []
    for row in rows:
        if row.value <= 0:
            continue
        dash = max(0.5, (row.value / total) * 100)
        segments.append(
            f'<circle class="donut-segment donut-{html.escape(row.class_name)}" cx="18" cy="18" r="15.915" '
            f'stroke-dasharray="{dash:.3f} {100 - dash:.3f}" stroke-dashoffset="{offset:.3f}"></circle>'
        )
        offset -= dash
        legend.append(
            f'<span><i class="legend-dot donut-bg-{html.escape(row.class_name)}"></i>'
            f'<b>{html.escape(str(row.value))}</b> {html.escape(row.label)}</span>'
        )
    return f'''
    <article class="exec-card chart-card">
      <div class="exec-card-title"><span>{html.escape(title)}</span><b>{html.escape(subtitle)}</b></div>
      <div class="donut-layout"><div class="donut-wrap">
        <svg class="donut-chart" viewBox="0 0 36 36" role="img" aria-label="{html.escape(title)}">
          <circle class="donut-track" cx="18" cy="18" r="15.915"></circle>{''.join(segments)}
        </svg><div class="donut-center">{html.escape(center)}</div>
      </div><div class="donut-legend">{''.join(legend)}</div></div>
    </article>'''


def render_executive_bar_card(
    title: str, subtitle: str, rows: tuple[tuple[str, int], ...], suffix: str = '',
) -> str:
    max_value = max((value for _label, value in rows), default=0)
    rows = rows or (('No data', 0),)
    bars = []
    for label, value in rows:
        width = _percent(value, max_value) if max_value else 0
        bars.append(
            f'<div class="exec-bar-row"><div class="exec-bar-label" title="{html.escape(label, quote=True)}">{html.escape(label)}</div>'
            f'<div class="exec-bar-track"><span style="width:{width}%"></span></div>'
            f'<div class="exec-bar-value">{html.escape(str(value))}{html.escape(suffix)}</div></div>'
        )
    return f'''
    <article class="exec-card bar-card">
      <div class="exec-card-title"><span>{html.escape(title)}</span><b>{html.escape(subtitle)}</b></div>
      <div class="exec-bars">{''.join(bars)}</div>
    </article>'''


def render_executive_hourly_intake(view: ExecutiveHourlyIntakeViewModel) -> str:
    max_value = max((bucket.count for bucket in view.buckets), default=0)
    total = sum(bucket.count for bucket in view.buckets)
    rows = []
    for bucket in view.buckets:
        width = _percent(bucket.count, max_value) if max_value else 0
        current = 'true' if bucket.current else 'false'
        rows.append(
            f'<div class="exec-bar-row"><div class="exec-bar-label exec-hour-label" '
            f'data-hour-start="{html.escape(bucket.start_utc_iso, quote=True)}" data-current-hour="{current}" '
            f'title="{html.escape(bucket.fallback_label, quote=True)}">{html.escape(bucket.fallback_label)}</div>'
            f'<div class="exec-bar-track"><span style="width:{width}%"></span></div>'
            f'<div class="exec-bar-value"><b>{bucket.count}</b><span> alerts</span></div></div>'
        )
    source_label = 'Exact committed intake' if view.exact else 'Telemetry unavailable'
    return f'''
    <article class="exec-card bar-card exec-hourly-card">
      <div class="exec-card-title"><span>Alert intake</span><b>Completed ingests by local hour</b></div>
      <div class="exec-bars">{''.join(rows)}</div>
      <div class="exec-card-note"><b>{total} alerts</b> ingested in this 12-hour window. {html.escape(source_label)}. The current hour is partial; bars scale to the busiest hour.</div>
    </article>'''


def render_executive_cache(view: ExecutiveCacheViewModel) -> str:
    runtime_value = lambda value: str(value) if view.runtime_available else 'n/a'
    durable_note = f'{view.payload_size} normalized cache payload' if view.available else 'Durable cache inventory unavailable'
    rows = (
        ('Reusable now', str(view.fresh_entries) if view.available else 'n/a', 'Fresh durable results'),
        ('Expired entries', str(view.stale_entries) if view.available else 'n/a', 'Outage fallback only'),
        ('API calls avoided', runtime_value(view.api_calls_avoided), 'Since alert-store restart'),
        ('Cache hit rate', view.hit_rate, 'Since alert-store restart'),
        ('Provider lookups', runtime_value(view.provider_loads), 'Since alert-store restart'),
        ('Stale fallbacks', runtime_value(view.stale_fallbacks), 'Used during provider errors'),
    )
    rendered = ''.join(
        f'<div class="exec-cache-row"><div><span>{html.escape(label)}</span><small>{html.escape(note)}</small></div>'
        f'<strong>{html.escape(value)}</strong></div>' for label, value, note in rows
    )
    return f'''
    <article class="exec-card exec-cache-card">
      <div class="exec-card-title"><span>Threat-intel cache</span><b>Quota protection</b></div>
      <div class="exec-cache-rows">{rendered}</div>
      <div class="exec-card-note">{html.escape(durable_note)}. Process counters reset when alert-store restarts.</div>
    </article>'''


def render_executive_home(view: ExecutiveHomePageViewModel) -> str:
    return f'''
    <section class="view-section active executive-home-view" aria-label="Executive SOC overview">
      <section class="exec-hero" aria-label="Executive SOC summary"><div>
        <span class="exec-kicker">Executive overview</span><h2>Security posture at a glance</h2>
        <p>Grouped detections, alert volume, AI analysis coverage, and noisy-repeat pressure from the Security Onion alert pipeline.</p>
      </div><div class="exec-hero-stamp"><span>Latest alert</span><strong>{html.escape(view.latest_seen)}</strong></div></section>
      <section class="exec-kpi-grid" aria-label="Executive SOC key metrics">
        <article class="exec-kpi"><span>Grouped detections</span><strong>{view.total_groups}</strong><em>Unique analyst-facing rows</em></article>
        <article class="exec-kpi"><span>Total observations</span><strong>{view.total_observations}</strong><em>Includes repeated detections</em></article>
        <article class="exec-kpi"><span>Urgent exposure</span><strong>{view.urgent_percent}%</strong><em>{view.urgent_groups} critical/high groups</em></article>
        <article class="exec-kpi"><span>AI coverage</span><strong>{view.ai_percent}%</strong><em>{view.analyzed_groups} analyzed groups</em></article>
        <article class="exec-kpi"><span>Suppression pressure</span><strong>{view.suppression_percent}%</strong><em>{view.suppressed_groups} noisy groups</em></article>
        <article class="exec-kpi"><span>{html.escape(view.cache_kpi_label)}</span><strong>{html.escape(view.cache_kpi_value)}</strong><em>{html.escape(view.cache_kpi_note)}</em></article>
      </section>
      <section class="exec-chart-grid" aria-label="Executive SOC charts">
        {render_executive_donut('Severity mix', f'{view.urgent_percent}%', 'Critical/high share', view.severity_rows)}
        {render_executive_donut('Workflow status', f'{view.suppression_percent}%', 'Suppressed share', view.status_rows)}
        {render_executive_donut('AI analysis coverage', f'{view.ai_percent}%', 'Analyzed share', view.ai_rows)}
        {render_executive_bar_card('Top detection families', 'By total observations', view.top_rule_rows)}
        {render_executive_bar_card('Top destination assets', 'By total observations', view.destination_rows)}
        {render_executive_bar_card('Top source assets', 'By total observations', view.source_ip_rows)}
        {render_executive_hourly_intake(view.hourly)}
        {render_executive_bar_card('Log source mix', 'Grouped detections', view.source_rows)}
        {render_executive_cache(view.cache)}
      </section>
    </section>'''
