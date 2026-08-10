"""Dashboard page view-model composition and Settings page orchestration."""
from __future__ import annotations

from dashboard_builder_contract import *  # noqa: F403
from dashboard_builder_contract import (  # noqa: F401
    _boolean_setting,
    _normalized_enabled_models,
    _normalized_hermes_model,
)
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


def _executive_home_view(
    reports: list[AlertReport], hourly: HourlyIntakeMetrics, cache: EnrichmentCacheMetrics,
) -> ExecutiveHomePageViewModel:
    total = len(reports)
    urgent = sum(1 for report in reports if criticality_class(report.criticality) in {'critical', 'high'})
    suppressed = sum(1 for report in reports if report.filter_status == 'suppressed')
    analyzed = sum(1 for report in reports if report.ai_status_key == 'analyzed')
    latest = max((report.alert_ts for report in reports), default=0)
    cache_label, cache_value, cache_note = _executive_cache_kpi(cache)
    return ExecutiveHomePageViewModel(
        latest_seen=human_time(latest) if latest else 'n/a', total_groups=total,
        total_observations=sum(max(1, int(report.repeat_count or 1)) for report in reports),
        urgent_groups=urgent, suppressed_groups=suppressed, analyzed_groups=analyzed,
        urgent_percent=pct(urgent, total), ai_percent=pct(analyzed, total),
        suppression_percent=pct(suppressed, total), cache_kpi_label=cache_label,
        cache_kpi_value=cache_value, cache_kpi_note=cache_note,
        severity_rows=_executive_severity_rows(reports), status_rows=_executive_status_rows(reports),
        ai_rows=_executive_ai_rows(reports),
        top_rule_rows=tuple(counter_top([(r.rule_name, r.repeat_count) for r in reports], 7)),
        destination_rows=tuple(counter_top([(r.destination_ip, r.repeat_count) for r in reports], 7)),
        source_ip_rows=tuple(counter_top([(r.source_ip, r.repeat_count) for r in reports], 7)),
        source_rows=tuple(counter_top([(r.alert_source, 1) for r in reports], 5)),
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


def _publication_paths() -> DashboardPublicationPaths:
    """Resolve mutable compatibility globals at the publication boundary."""
    return DashboardPublicationPaths(
        out_dir=OUT_DIR,
        detail_dir=DETAIL_DIR,
        status_json=STATUS_JSON,
        beacon_json=N8N_BEACON_JSON,
        beacon_history_json=N8N_BEACON_HISTORY_JSON,
        source_beacon_json=DB_BEACON_JSON,
        source_beacon_history_json=DB_BEACON_HISTORY_JSON,
        asset_source_dirs=tuple(ASSET_SOURCE_DIRS),
    )


def _publication_timestamp() -> str:
    return format_project_timestamp(
        dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    )



def write_status_json(reports: list[AlertReport]) -> Path:
    """Write the fast-changing status payload polled by the static WebUI."""
    return publish_status_json(
        reports, _publication_paths(), generated_at=_publication_timestamp(),
        ai_state=ai_activity_state(reports),
    )


def write_n8n_beacon_json(reports: list[AlertReport]) -> Path:
    """Seed the dynamic n8n webhook beacon file for static dashboard serving."""
    return publish_beacon_json(
        reports, _publication_paths(), generated_at=_publication_timestamp(),
        report_time=iso_local_time,
    )


def write_n8n_beacon_history_json() -> Path:
    """Mirror the rolling n8n beacon history into the generated dashboard output."""
    return publish_beacon_history_json(_publication_paths())



def write_detail_fragments(reports: list[AlertReport]) -> list[Path]:
    """Publish lazy-loaded detail fragments without an API-visible empty window.

    The dashboard API serves these files while this builder runs. Replacing the
    whole directory made every detail endpoint transiently return 404 during a
    rebuild, so each fragment is now written beside its destination and
    atomically renamed into place. Stale fragments are removed only after all
    current fragments are available.
    """
    return publish_detail_fragments(reports, _publication_paths())


def build_html(reports: list[AlertReport]) -> str:
    """Compose the generated shell from live report metrics and pure fragments."""
    now = dt.datetime.now().astimezone().replace(microsecond=0).isoformat().replace('T', '  ')
    latest = reports[0] if reports else None
    active_count = active_alert_count(reports)
    active_reports = active_alert_reports(reports)
    severity_levels = ('critical', 'high', 'medium', 'low', 'informational')
    severity_labels = {'critical': 'Crit', 'high': 'High', 'medium': 'Med', 'low': 'Low', 'informational': 'Info'}
    severity_counts = {level: 0 for level in severity_levels}
    for report in active_reports:
        level = criticality_class(report.criticality)
        severity_counts[level] = severity_counts.get(level, 0) + 1
    severity_html = ''.join(
        f'<span class="sev-chip sev-{level}{" sev-zero" if severity_counts[level] == 0 else ""}"><b>{severity_counts[level]}</b> {severity_labels[level]}</span>'
        for level in severity_levels
    )
    latest_extra_html = (
        f'<span class="metric-detail-row"><b>Source</b><span>{html.escape(latest.rel_source)}</span></span>'
        f'<span class="metric-detail-row"><b>Size</b><span>{human_size(latest.size)}</span></span>'
    ) if latest else '<span class="metric-detail-row"><b>Source</b><span>—</span></span>'
    latest_alert = max(reports, key=last_seen_ts_for) if reports else None
    latest_alert_text = compact_minute_timestamp(last_seen_iso_for(latest_alert)) if latest_alert else 'No alerts yet'
    total_bytes = sum(report.size for report in reports)
    pcap_ingest_bytes = directory_size_bytes(PCAP_ARTIFACT_DIR)
    metrics_html = ''.join((
        render_active_alerts_metric(severity_html),
        render_latest_network_metric(latest_extra_html),
        render_ai_activity_metric(ai_activity_state(reports)),
        render_alert_status_metric(),
        render_size_metric_card(human_size(total_bytes), latest_alert_text, human_size(pcap_ingest_bytes)),
    ))
    return render_dashboard_shell(DashboardShellViewModel(
        navigation_html=build_nav_html('home', active_count),
        overview_html=render_soc_overview(len(reports)),
        metrics_html=metrics_html,
        alert_table_html=render_alert_table_shell(),
        generated_at=html.escape(now),
        database_path=html.escape(str(DB_PATH).replace(str(HOME), '~')),
        source_directory=html.escape(str(SOURCE_DIR).replace(str(HOME), '~')),
        adjudication_modal_html=analyst_adjudication_modal_html(),
    ))

def _cyber_threat_intel_page_view(reports: list[AlertReport]) -> CyberThreatIntelPageViewModel:
    actionable = [
        report for report in reports
        if report.filter_status not in {'suppressed', 'acknowledged'}
    ]
    return CyberThreatIntelPageViewModel(
        urgent_local_signals=sum(
            1 for report in actionable
            if report.criticality_rank >= CRITICALITY_ORDER['high']
        ),
        repeated_local_signals=sum(
            1 for report in actionable if report.repeat_count >= 5
        ),
        model_label=agent_model_route_label(
            load_soc_ai_settings(), 'cyber-threat-intel'
        ),
    )


def cyber_threat_intel_page_section(reports: list[AlertReport]) -> str:
    return render_cyber_threat_intel_page(
        _cyber_threat_intel_page_view(reports)
    )











def siem_engineering_html_list(values: object, empty: str) -> str:
    return render_siem_engineering_html_list(values, empty)


def _siem_recommendation_view(report: AlertReport) -> SiemRecommendationViewModel:
    analysis = report.ai_analysis if isinstance(report.ai_analysis, dict) else {}
    response = analysis.get('response') if isinstance(analysis.get('response'), dict) else {}
    normalize = lambda value: normalize_iso_display_text(value)
    return SiemRecommendationViewModel(
        title=report.title, digest=report.digest, rel_source=report.rel_source,
        summary=normalize(report.summary), ai_summary=normalize(ai_summary_for(report)),
        criticality=report.criticality, criticality_rank=report.criticality_rank,
        alert_source=report.alert_source, source_ip=report.source_ip,
        destination_ip=report.destination_ip, destination_port=report.destination_port,
        source_endpoint=report.source_endpoint, destination_endpoint=report.destination_endpoint,
        rule_id=report.rule_id, rule_name=report.rule_name,
        raw_alert_count=report.raw_alert_count, total_seen_count=report.total_seen_count,
        repeat_count=report.repeat_count, first_seen=normalize(report.first_seen),
        last_seen=last_seen_iso_for(report), alert_group_key=report.alert_group_key,
        alert_ts=report.alert_ts, ai_status_key=report.ai_status_key,
        ai_status_label=report.ai_status_label, ai_status_detail=normalize(report.ai_status_detail),
        enrichment_status_label=report.enrichment_status_label,
        enrichment_status_detail=normalize(report.enrichment_status_detail),
        enrichment_record_count=report.enrichment_record_count,
        enrichment_skip_count=report.enrichment_skip_count,
        enrichment_error_count=report.enrichment_error_count,
        pcap_status_label=report.pcap_status_label,
        pcap_status_detail=normalize(report.pcap_status_detail),
        tuning_recommendation=report.tuning_recommendation,
        tuning_reason=normalize(report.tuning_reason),
        recommended_tuning_actions=tuple(normalize(action) for action in report.recommended_tuning_actions),
        generated_at=normalize(analysis.get('generated_at') or 'n/a'), response=response,
    )


def siem_engineering_detail_report(report: AlertReport, recommendation_kind: str) -> str:
    return render_siem_engineering_detail_report(
        _siem_recommendation_view(report), recommendation_kind
    )



def siem_engineering_tuning_row(report: AlertReport, index: int) -> str:
    return render_siem_engineering_tuning_row(_siem_recommendation_view(report), index)



def siem_engineering_detection_row(report: AlertReport, index: int) -> str:
    return render_siem_engineering_detection_row(_siem_recommendation_view(report), index)



def siem_engineering_roi_score(report: AlertReport) -> tuple[int, int, int, float]:
    return render_siem_engineering_roi_score(_siem_recommendation_view(report))



def siem_engineering_best_roi_section(reports: list[AlertReport]) -> str:
    views = tuple(_siem_recommendation_view(report) for report in reports)
    return render_siem_engineering_best_roi(views)



def siem_engineering_table(title: str, subtitle: str, rows: str, empty: str) -> str:
    return render_siem_engineering_table(title, rows, empty)



def siem_engineering_page_section(reports: list[AlertReport]) -> str:
    settings = load_soc_ai_settings()
    actionable = [
        report for report in reports
        if report.tuning_recommendation
        and report.tuning_recommendation not in {'none', 'n/a', 'needs_more_data'}
    ]
    repeated = sorted(
        [report for report in reports if report.repeat_count >= 3 and report not in actionable],
        key=lambda report: (report.repeat_count, report.criticality_rank), reverse=True,
    )[:4]
    view = SiemEngineeringPageViewModel(
        mode=str(settings.get('mode', 'ollama')),
        local_model=str(settings.get('ollama_model') or current_local_ai_model()),
        cloud_model=str(settings.get('cloud_model') or settings.get('cloud_provider') or 'not configured'),
        analyzed=sum(1 for report in reports if report.ai_status_key == 'analyzed'),
        total=len(reports),
        all_candidates=tuple(_siem_recommendation_view(report) for report in reports),
        actionable=tuple(_siem_recommendation_view(report) for report in actionable),
        repeated=tuple(_siem_recommendation_view(report) for report in repeated),
    )
    return render_siem_engineering_page(view)



def _threat_hunt_candidate(report: AlertReport) -> ThreatHuntCandidateViewModel:
    return ThreatHuntCandidateViewModel(
        digest=report.digest,
        rule_name=report.rule_name,
        title=report.title,
        source_ip=report.source_ip,
        destination_ip=report.destination_ip,
        destination_port=report.destination_port,
        alert_source=report.alert_source,
        criticality=report.criticality,
        criticality_rank=report.criticality_rank,
        repeat_count=report.repeat_count,
        first_seen=report.first_seen,
        last_seen=last_seen_iso_for(report),
        hypothesis=ai_summary_for(report),
    )


def threat_hunt_queries(report: AlertReport) -> tuple[str, str, str]:
    return render_threat_hunt_queries(_threat_hunt_candidate(report))


def threat_hunt_row(report: AlertReport, index: int) -> str:
    return render_threat_hunt_row(_threat_hunt_candidate(report), index)


def threat_hunter_page_section(reports: list[AlertReport]) -> str:
    candidates = sorted(
        [
            report for report in reports
            if report.filter_status in {'accepted', 'escalated', 'unknown', 'suppressed'}
        ],
        key=lambda report: (
            report.criticality_rank,
            report.repeat_count,
            last_seen_ts_for(report),
        ),
        reverse=True,
    )[:12]
    return render_threat_hunter_page(
        [_threat_hunt_candidate(report) for report in candidates]
    )




def _flow_page_view(reports: list[AlertReport]) -> FlowPageViewModel:
    assignment = current_soc_analysis_model()
    total_groups = len(reports)
    analyzed_groups = sum(1 for report in reports if report.ai_status_key == 'analyzed')
    telegram_counts = telegram_sent_counts()
    return FlowPageViewModel(
        analysis_provider=assignment['provider'],
        analysis_model=assignment['model_detail'],
        analysis_icon=(
            'assets/brand/ollama.svg'
            if assignment['provider_key'] == 'ollama'
            else 'assets/settings-ai-model-routing.png'
        ),
        total_groups=total_groups,
        total_observations=sum(max(1, int(report.repeat_count or 1)) for report in reports),
        ai_coverage=pct(analyzed_groups, total_groups),
        urgent_groups=sum(
            1 for report in reports
            if criticality_class(report.criticality) in {'critical', 'high'}
        ),
        ai_markdown_reports=count_ai_analysis_artifacts('.md'),
        ai_json_reports=count_ai_analysis_artifacts('.json'),
        telegram_critical=telegram_counts['critical'],
        telegram_high=telegram_counts['high'],
        enrichment_tiles_html=render_enrichment_service_tiles(ENRICHMENT_FLOW_SERVICES),
    )


def flow_page_section(reports: list[AlertReport]) -> str:
    return render_flow_page(_flow_page_view(reports))



SETTINGS_AGENT_LABELS = {
    'soc-analyst': 'SOC Analyst',
    'incident-responder': 'Incident Responder',
    'siem-engineer': 'SIEM Engineer',
    'cyber-threat-intel': 'Cyber Threat Intel Analyst',
    'threat-hunter': 'Threat Hunter',
}
SETTINGS_AGENT_API_NAMES = {'soc-analyst': 'analyst', **{role: role for role in CYBER_SECURITY_AGENT_ROLES if role != 'soc-analyst'}}
SETTINGS_AGENT_PROMPT_LOADERS = {
    'soc-analyst': load_soc_analyst_prompt,
    'incident-responder': load_incident_responder_prompt,
    'siem-engineer': load_siem_engineer_prompt,
    'cyber-threat-intel': load_cyber_threat_intel_prompt,
    'threat-hunter': load_threat_hunter_prompt,
}
SETTINGS_AGENT_PROMPT_FILES = {
    'soc-analyst': SOC_ANALYST_PROMPT_FILE,
    'incident-responder': INCIDENT_RESPONDER_PROMPT_FILE,
    'siem-engineer': SIEM_ENGINEER_PROMPT_FILE,
    'cyber-threat-intel': CYBER_THREAT_INTEL_PROMPT_FILE,
    'threat-hunter': THREAT_HUNTER_PROMPT_FILE,
}
SETTINGS_AGENT_REVIEW_FILES = {
    'soc-analyst': SOC_ANALYST_SECOND_OPINION_PROMPT_FILE,
    'incident-responder': INCIDENT_RESPONDER_SECOND_OPINION_PROMPT_FILE,
    'siem-engineer': SIEM_ENGINEER_SECOND_OPINION_PROMPT_FILE,
    'cyber-threat-intel': CYBER_THREAT_INTEL_SECOND_OPINION_PROMPT_FILE,
    'threat-hunter': THREAT_HUNTER_SECOND_OPINION_PROMPT_FILE,
}
SETTINGS_AGENT_MEMORY_FILES = {
    'soc-analyst': SOC_ANALYST_MEMORY_FILE,
    'incident-responder': INCIDENT_RESPONDER_MEMORY_FILE,
    'siem-engineer': SIEM_ENGINEER_MEMORY_FILE,
    'cyber-threat-intel': CYBER_THREAT_INTEL_MEMORY_FILE,
    'threat-hunter': THREAT_HUNTER_MEMORY_FILE,
}
SETTINGS_GENERIC_AGENT_COPY = {
    'incident-responder': ('Incident responder prompt', 'Incident Responder', 'Trigger: manual incident workflow now; external IR host collection is TODO.', 'This prompt guides senior incident response planning, evidence preservation, containment guidance, and future host artifact collection workflows.', 'assets/settings-incident-responder-prompt.png', 'TODO: connect the dedicated incident response host before allowing this agent to trigger external host artifact collection scripts. Until then, recommendations should mark those actions as pending integration.'),
    'siem-engineer': ('SIEM engineer prompt', 'SIEM Engineer System Prompt', 'Planned trigger: cron every 6 hours after all eligible alerts are analyzed.', 'This prompt guides the SIEM Engineering review that recommends scoped tuning and new detection work after all eligible alerts have finished AI analysis.', 'assets/settings-siem-engineer-prompt.png', 'Designed cadence: every 6 hours, only when the alert analysis backlog is clear. It should review alerts, enrichments, notes, acknowledgments, suppressions, and related detection context before recommending changes.'),
    'cyber-threat-intel': ('Cyber threat intel prompt', 'Cyber Threat Intel Analyst', 'Trigger: manual intel review from alerts, enrichments, hunts, and engineering context; scheduled briefs are future work.', 'This prompt guides intelligence briefs, indicator review, enrichment pivots, confidence scoring, and cross-agent context for SOC decisions.', 'assets/settings-cyber-threat-intel-prompt.png', ''),
    'threat-hunter': ('Threat hunter prompt', 'Threat Hunter System Prompt', 'Trigger: manual hunt review from alert patterns; automated hunts are future work.', 'This prompt guides senior threat-hunt recommendations, including Security Onion pivots and query-ready KQL, OQL, and OSQuery hunt plans.', 'assets/settings-threat-hunter-prompt.png', ''),
}


def _settings_prompt_data() -> dict[str, dict[str, str]]:
    data: dict[str, dict[str, str]] = {}
    for role in CYBER_SECURITY_AGENT_ROLES:
        api_name = SETTINGS_AGENT_API_NAMES[role]
        review_file = SETTINGS_AGENT_REVIEW_FILES[role]
        primary_id = f'{role}-prompt'
        reviewer_id = f'{role}-second-opinion-prompt'
        data[role] = {
            'prompt_path': display_path(SETTINGS_AGENT_PROMPT_FILES[role]),
            'reviewer_prompt_path': display_path(review_file),
            'memory_path': display_path(SETTINGS_AGENT_MEMORY_FILES[role]),
            'control_html': agent_prompt_editors(
                role_label=SETTINGS_AGENT_LABELS[role],
                primary_id=primary_id,
                primary_prompt=html.escape(SETTINGS_AGENT_PROMPT_LOADERS[role]()),
                primary_endpoint=f'/api/soc-settings/{api_name}-prompt',
                reviewer_id=reviewer_id,
                reviewer_prompt=html.escape(load_second_opinion_prompt(review_file)),
                reviewer_endpoint=f'/api/soc-settings/{api_name}-second-opinion-prompt',
            ),
        }
    return data


def _settings_model_data(ai_settings: dict[str, object]) -> dict[str, dict[str, str]]:
    return {
        role: {
            'label': agent_model_route_label(ai_settings, role),
            'reviewer_label': agent_second_opinion_model_route_label(ai_settings, role),
            'adjudicator_label': agent_adjudicator_model_route_label(ai_settings, role),
            'control_html': agent_model_control(ai_settings, role, SETTINGS_AGENT_LABELS[role]),
        }
        for role in CYBER_SECURITY_AGENT_ROLES
    }


def _settings_generic_agent_cards(prompt_data: dict[str, dict[str, str]], model_data: dict[str, dict[str, str]]) -> str:
    cards: list[str] = []
    shared_path = display_path(SHARED_AGENT_MEMORY_FILE)
    for role, copy in SETTINGS_GENERIC_AGENT_COPY.items():
        kicker, title, trigger, description, icon_path, note = copy
        prompt = prompt_data[role]
        model = model_data[role]
        cards.append(render_agent_settings_card(AgentSettingsCardViewModel(
            role=role, role_label=SETTINGS_AGENT_LABELS[role], kicker=kicker,
            title=title, trigger=trigger, description=description, icon_path=icon_path,
            prompt_path=prompt['prompt_path'], reviewer_prompt_path=prompt['reviewer_prompt_path'],
            memory_path=prompt['memory_path'], shared_memory_path=shared_path,
            model_label=model['label'], reviewer_model_label=model['reviewer_label'],
            adjudicator_model_label=model['adjudicator_label'], model_control_html=model['control_html'],
            prompt_control_html=prompt['control_html'], note=note,
        )))
    return ''.join(cards)


def _settings_soc_agent_card(ai_settings: dict[str, object], prompt: dict[str, str], model: dict[str, str]) -> str:
    analysis = str(ai_settings.get('soc_analyst_analysis_min_severity') or 'informational')
    pcap = str(ai_settings.get('soc_analyst_pcap_min_severity') or 'informational')
    incident = str(ai_settings.get('soc_analyst_incident_min_severity') or 'disabled')
    return render_soc_agent_settings_card(SocAgentSettingsCardViewModel(
        prompt_path=prompt['prompt_path'], reviewer_prompt_path=prompt['reviewer_prompt_path'],
        memory_path=prompt['memory_path'], shared_memory_path=display_path(SHARED_AGENT_MEMORY_FILE),
        model_label=model['label'], reviewer_model_label=model['reviewer_label'],
        adjudicator_model_label=model['adjudicator_label'],
        analysis_threshold_label=SOC_ANALYSIS_SEVERITY_LABELS[analysis],
        pcap_threshold_label=SOC_ANALYSIS_SEVERITY_LABELS[pcap],
        incident_threshold_label=SOC_ANALYSIS_SEVERITY_LABELS[incident],
        analysis_disabled=analysis == 'disabled', incident_disabled=incident == 'disabled',
        analysis_threshold_options_html=severity_threshold_options(analysis),
        pcap_threshold_options_html=severity_threshold_options(pcap),
        incident_threshold_options_html=severity_threshold_options(incident),
        model_control_html=model['control_html'], prompt_control_html=prompt['control_html'],
    ))


def _settings_hermes_model_options(ai_settings: dict[str, object]) -> str:
    selected = _normalized_hermes_model(ai_settings.get('hermes_agent_model'))
    return ''.join(
        f'<option value="{html.escape(model, quote=True)}"'
        f'{" selected" if model == selected else ""}>{html.escape(model)}</option>'
        for model in CODEX_CLI_MODEL_CATALOG
    )


def _settings_count_state(count: int) -> str:
    return f'{count} enabled' if count else 'Disabled'


def _settings_enabled_state(enabled: bool) -> str:
    return 'Enabled' if enabled else 'Disabled'


def _settings_provider_view(ai_settings: dict[str, object]) -> AiProviderSettingsViewModel:
    enabled_ollama = _normalized_enabled_models(ai_settings.get('enabled_ollama_models'))
    codex_models = list(ai_settings.get('codex_cli_models') or [])
    enabled_codex = [entry for entry in codex_models if entry.get('enabled') is True]
    hermes_enabled = _boolean_setting(ai_settings.get('hermes_agent_enabled'))
    openclaw_enabled = _boolean_setting(ai_settings.get('openclaw_enabled'))
    native_count = len(enabled_ollama) + len(enabled_codex)
    return AiProviderSettingsViewModel(
        ai_path=display_path(SOC_AI_SETTINGS_FILE),
        onion_sentinel_harness_state=_settings_count_state(native_count),
        ollama_state=_settings_count_state(len(enabled_ollama)),
        ollama_url=str(ai_settings['ollama_url']),
        ollama_model_rows_html=ollama_model_toggle_rows(list_ollama_models(), enabled_ollama),
        codex_state=_settings_count_state(len(enabled_codex)),
        codex_path=str(ai_settings.get('codex_cli_path') or 'codex'),
        codex_model_rows_html=codex_cli_model_rows(codex_models),
        skill_catalog_html=investigation_skill_catalog(load_dashboard_investigation_skills()),
        hermes_state=_settings_enabled_state(hermes_enabled), hermes_enabled=hermes_enabled,
        hermes_path=str(ai_settings.get('hermes_agent_path') or 'hermes'),
        hermes_model_options_html=_settings_hermes_model_options(ai_settings),
        hermes_effort_options_html='<option value="medium" selected>Medium (required)</option>',
        openclaw_state=_settings_enabled_state(openclaw_enabled), openclaw_enabled=openclaw_enabled,
        openclaw_path=str(ai_settings.get('openclaw_path') or 'openclaw'),
        openclaw_model=str(ai_settings.get('openclaw_model') or 'ollama/gemma4:26b-mlx'),
        openclaw_effort_options_html=reasoning_effort_options(str(ai_settings.get('openclaw_reasoning_effort') or 'medium')),
    )


def _settings_page_view(ai_settings: dict[str, object]) -> SettingsPageViewModel:
    prompt_data = _settings_prompt_data()
    model_data = _settings_model_data(ai_settings)
    return SettingsPageViewModel(
        providers=_settings_provider_view(ai_settings),
        maxmind=MaxMindSettingsViewModel(
            asn_path=str(ai_settings['maxmind_geoip_asn_db_path']),
            city_path=str(ai_settings['maxmind_geoip_city_db_path']),
            country_path=str(ai_settings['maxmind_geoip_country_db_path']),
        ),
        soc_agent_card_html=_settings_soc_agent_card(ai_settings, prompt_data['soc-analyst'], model_data['soc-analyst']),
        agent_cards_html=_settings_generic_agent_cards(prompt_data, model_data),
    )


def settings_page_section() -> str:
    return render_settings_page(_settings_page_view(load_soc_ai_settings()))
