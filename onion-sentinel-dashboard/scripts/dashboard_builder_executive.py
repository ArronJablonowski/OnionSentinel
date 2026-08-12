"""Executive dashboard page composition and view-model projection."""
from __future__ import annotations

from dashboard_builder_contract import *  # noqa: F403
from dashboard_builder_settings import *  # noqa: F403
from dashboard_builder_report_core import *  # noqa: F403
from dashboard_builder_reports import *  # noqa: F403


def pct(part: int | float, total: int | float) -> int:
    """Return a rounded percent while avoiding divide-by-zero noise."""
    if not total:
        return 0
    return round((part / total) * 100)


def counter_top(items: list[tuple[str, int]], limit: int = 6) -> list[tuple[str, int]]:
    """Aggregate label/value pairs and return the largest entries."""
    totals: dict[str, int] = {}
    for label, value in items:
        cleaned = str(label or 'n/a').strip() or 'n/a'
        totals[cleaned] = totals.get(cleaned, 0) + int(value or 0)
    return sorted(totals.items(), key=lambda item: (item[1], item[0].lower()), reverse=True)[:limit]


def _executive_donut_rows(rows: list[tuple[str, int, str]]) -> tuple[ExecutiveDonutRowViewModel, ...]:
    return tuple(ExecutiveDonutRowViewModel(label, value, class_name) for label, value, class_name in rows)


def _executive_hourly_view(metrics: HourlyIntakeMetrics) -> ExecutiveHourlyIntakeViewModel:
    buckets = tuple(ExecutiveHourlyBucketViewModel(
        start_utc_iso=bucket.start_utc.isoformat().replace('+00:00', 'Z'),
        fallback_label=bucket.start_utc.strftime('%H:00 UTC'),
        count=bucket.count, current=bucket.current,
    ) for bucket in metrics.buckets)
    return ExecutiveHourlyIntakeViewModel(buckets=buckets, exact=metrics.exact)


def _executive_cache_view(metrics: EnrichmentCacheMetrics) -> ExecutiveCacheViewModel:
    hit_rate = f'{metrics.hit_rate:g}%' if metrics.hit_rate is not None else 'n/a'
    return ExecutiveCacheViewModel(
        available=metrics.available, runtime_available=metrics.runtime_available,
        fresh_entries=metrics.fresh_entries, stale_entries=metrics.stale_entries,
        api_calls_avoided=metrics.api_calls_avoided, hit_rate=hit_rate,
        provider_loads=metrics.provider_loads, stale_fallbacks=metrics.stale_fallbacks,
        payload_size=human_size(metrics.payload_bytes),
    )


def _executive_cache_kpi(metrics: EnrichmentCacheMetrics) -> tuple[str, str, str]:
    if metrics.runtime_available and metrics.hit_rate is not None:
        return 'Cache hit rate', f'{metrics.hit_rate:g}%', f'{metrics.api_calls_avoided} API calls avoided since restart'
    value = str(metrics.fresh_entries) if metrics.available else 'n/a'
    return 'Reusable enrichments', value, 'Fresh durable cache results'


def _executive_severity_rows(reports: list[AlertReport]) -> tuple[ExecutiveDonutRowViewModel, ...]:
    order = (('Critical', 'critical'), ('High', 'high'), ('Medium', 'medium'), ('Low', 'low'), ('Info', 'informational'))
    counts = {level: sum(1 for report in reports if criticality_class(report.criticality) == level) for _label, level in order}
    return tuple(ExecutiveDonutRowViewModel(label, counts[level], level) for label, level in order)


def _executive_status_rows(reports: list[AlertReport]) -> tuple[ExecutiveDonutRowViewModel, ...]:
    order = (('Accepted', 'accepted'), ('Suppressed', 'suppressed'), ('Escalated', 'escalated'), ('Stored', 'stored'), ('Other', 'other'))
    counts = {key: 0 for _label, key in order}
    for report in reports:
        key = report.filter_status if report.filter_status in counts else 'other'
        counts[key] += 1
    return tuple(ExecutiveDonutRowViewModel(label, counts[key], key) for label, key in order)


def _executive_ai_rows(reports: list[AlertReport]) -> tuple[ExecutiveDonutRowViewModel, ...]:
    states = (('Analyzed', 'analyzed', 'cyan'), ('Queued', 'queued', 'amber'), ('Analyzing', 'analyzing', 'green'))
    rows = [ExecutiveDonutRowViewModel(label, sum(1 for report in reports if report.ai_status_key == key), css) for label, key, css in states]
    other = sum(1 for report in reports if report.ai_status_key not in {'analyzed', 'queued', 'analyzing'})
    return tuple(rows + [ExecutiveDonutRowViewModel('Other', other, 'info')])


def __executive_home_counts(
    reports: list[AlertReport],
) -> tuple[int, int, int, int, int, int]:
    total = len(reports)
    urgent = sum(
        1 for report in reports
        if criticality_class(report.criticality) in {'critical', 'high'}
    )
    suppressed = sum(
        1 for report in reports if report.filter_status == 'suppressed'
    )
    analyzed = sum(
        1 for report in reports if report.ai_status_key == 'analyzed'
    )
    latest = max((report.alert_ts for report in reports), default=0)
    observations = sum(
        max(1, int(report.repeat_count or 1)) for report in reports
    )
    return total, urgent, suppressed, analyzed, latest, observations


def __executive_home_rankings(
    reports: list[AlertReport],
) -> tuple[tuple[tuple[str, int], ...], ...]:
    return (
        tuple(counter_top([(r.rule_name, r.repeat_count) for r in reports], 7)),
        tuple(counter_top([(r.destination_ip, r.repeat_count) for r in reports], 7)),
        tuple(counter_top([(r.source_ip, r.repeat_count) for r in reports], 7)),
        tuple(counter_top([(r.alert_source, 1) for r in reports], 5)),
    )


def _executive_home_view(
    reports: list[AlertReport], hourly: HourlyIntakeMetrics, cache: EnrichmentCacheMetrics,
) -> ExecutiveHomePageViewModel:
    total, urgent, suppressed, analyzed, latest, observations = (
        __executive_home_counts(reports)
    )
    top_rules, destinations, source_ips, sources = (
        __executive_home_rankings(reports)
    )
    cache_label, cache_value, cache_note = _executive_cache_kpi(cache)
    return ExecutiveHomePageViewModel(
        latest_seen=human_time(latest) if latest else 'n/a', total_groups=total,
        total_observations=observations,
        urgent_groups=urgent, suppressed_groups=suppressed, analyzed_groups=analyzed,
        urgent_percent=pct(urgent, total), ai_percent=pct(analyzed, total),
        suppression_percent=pct(suppressed, total), cache_kpi_label=cache_label,
        cache_kpi_value=cache_value, cache_kpi_note=cache_note,
        severity_rows=_executive_severity_rows(reports), status_rows=_executive_status_rows(reports),
        ai_rows=_executive_ai_rows(reports),
        top_rule_rows=top_rules, destination_rows=destinations,
        source_ip_rows=source_ips, source_rows=sources,
        hourly=_executive_hourly_view(hourly), cache=_executive_cache_view(cache),
    )


def executive_donut(title: str, center: str, subtitle: str, rows: list[tuple[str, int, str]]) -> str:
    return render_executive_donut(title, center, subtitle, _executive_donut_rows(rows))


def executive_bar_card(title: str, subtitle: str, rows: list[tuple[str, int]], suffix: str = '') -> str:
    return render_executive_bar_card(title, subtitle, tuple(rows), suffix)


def executive_hourly_intake_card(metrics: HourlyIntakeMetrics) -> str:
    return render_executive_hourly_intake(_executive_hourly_view(metrics))


def executive_cache_card(metrics: EnrichmentCacheMetrics) -> str:
    return render_executive_cache(_executive_cache_view(metrics))


def executive_home_section(
    reports: list[AlertReport],
    hourly_metrics: HourlyIntakeMetrics | None = None,
    cache_metrics: EnrichmentCacheMetrics | None = None,
) -> str:
    hourly = hourly_metrics or load_hourly_alert_intake(DB_PATH)
    cache = cache_metrics or load_enrichment_cache_metrics(DB_PATH)
    return render_executive_home(_executive_home_view(reports, hourly, cache))
