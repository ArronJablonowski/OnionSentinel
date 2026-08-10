"""Alert report loading, detail composition, and status presentation."""
from __future__ import annotations

from dashboard_builder_contract import *  # noqa: F403
from dashboard_builder_settings import *  # noqa: F403
from dashboard_builder_settings import _report_repository_config  # noqa: F401


def remove_markdown_sections(text: str, section_titles: set[str]) -> str:
    # Existing n8n Markdown can already contain large raw JSON sections. The
    # dashboard regenerates these from SQLite at the bottom so analysts always
    # get current, collapsible evidence without duplicated middle-of-report JSON.
    kept: list[str] = []
    skipping = False
    skip_level = 0
    for line in text.splitlines():
        heading = normalized_heading_text(line)
        if heading:
            level, title = heading
            if skipping and level <= skip_level:
                skipping = False
                skip_level = 0
            if not skipping and title in section_titles:
                skipping = True
                skip_level = level
                continue
        if not skipping:
            kept.append(line)
    return '\n'.join(kept).strip()


def markdown_section_bounds(text: str, title: str) -> tuple[int, int] | None:
    heading_re = re.compile(rf'^##\s+{re.escape(title)}\s*$', re.IGNORECASE | re.MULTILINE)
    match = heading_re.search(text)
    if not match:
        return None
    next_match = re.search(r'^##\s+', text[match.end():], flags=re.MULTILINE)
    end = match.end() + next_match.start() if next_match else len(text)
    return match.start(), end


def markdown_section_bounds_by_normalized(text: str, normalized_title: str) -> tuple[int, int] | None:
    """Find a Markdown section by normalized heading text, regardless of heading level."""
    lines = text.splitlines(keepends=True)
    offset = 0
    start = None
    start_level = 0
    for line in lines:
        heading = normalized_heading_text(line)
        if heading:
            level, title = heading
            if start is None and title == normalized_title:
                start = offset
                start_level = level
            elif start is not None and level <= start_level:
                return start, offset
        offset += len(line)
    if start is None:
        return None
    return start, len(text)


def extract_markdown_section(text: str, normalized_title: str) -> tuple[str | None, str]:
    bounds = markdown_section_bounds_by_normalized(text, normalized_title)
    if not bounds:
        return None, text
    start, end = bounds
    section = text[start:end].strip()
    remaining = (text[:start].rstrip() + '\n\n' + text[end:].lstrip()).strip()
    return section, remaining


def move_ai_report_after_initial_context(text: str) -> str:
    """Keep every Detailed Alert Report on the same initial read path.

    Analysts should always see identity/triage context first, then the duplicate
    timeline, AI output, model metadata, and enrichment evidence. The timeline
    is HTML-injected later, so this function positions the AI/enrichment block
    immediately after Triage Reasons when that section exists, or before Alert
    Summary for DB-only reports.
    """
    sections: list[str] = []
    working = text
    for title in ('ai analysis output', 'ai model used', 'enriched alert details'):
        section, working = extract_markdown_section(working, title)
        if section:
            sections.append(section)
    if not sections:
        return text

    insert_bounds = markdown_section_bounds_by_normalized(working, 'triage reasons')
    insert_at = insert_bounds[1] if insert_bounds else None
    if insert_at is None:
        summary_bounds = markdown_section_bounds_by_normalized(working, 'alert summary')
        insert_at = summary_bounds[0] if summary_bounds else len(working)

    insert_text = '\n\n'.join(sections).strip()
    return (working[:insert_at].rstrip() + '\n\n' + insert_text + '\n\n' + working[insert_at:].lstrip()).strip()


def move_ai_output_before_model(text: str) -> str:
    output_bounds = markdown_section_bounds(text, 'AI Analysis Output')
    model_bounds = markdown_section_bounds(text, 'AI Model Used')
    if not output_bounds or not model_bounds or output_bounds[0] < model_bounds[0]:
        return text
    output_section = text[output_bounds[0]:output_bounds[1]].strip()
    model_section = text[model_bounds[0]:model_bounds[1]].strip()
    ranges = sorted([output_bounds, model_bounds], reverse=True)
    working = text
    for start, end in ranges:
        working = working[:start].rstrip() + '\n\n' + working[end:].lstrip()
    insert_at = min(output_bounds[0], model_bounds[0])
    return (working[:insert_at].rstrip() + '\n\n' + output_section + '\n\n' + model_section + '\n\n' + working[insert_at:].lstrip()).strip()


def insert_timeline_after_alert_identity(rendered_html: str, timeline_html: str) -> str:
    if not timeline_html or timeline_html in rendered_html:
        return rendered_html
    anchor_patterns = [
        r'<section\b[^>]*\bdetail-section-ai-analysis-output\b[^>]*>',
        r'<h[2-4]>AI Analysis Output</h[2-4]>',
        r'<details\b[^>]*\bdetail-section-alert-summary\b[^>]*>',
        r'<section\b[^>]*\bdetail-section-alert-summary\b[^>]*>',
        r'<h[2-4]>Alert Summary</h[2-4]>',
    ]
    for pattern in anchor_patterns:
        match = re.search(pattern, rendered_html)
        if match:
            return f'{rendered_html[:match.start()]}{timeline_html}{rendered_html[match.start():]}'
    return timeline_html + rendered_html


def passthrough_markdown_report_text(text: str) -> str:
    # Kept for compatibility with the existing render path. Full-fidelity mode
    # intentionally renders report text without redacting alert fields.
    return text


def validate_rendered_detail_layout(rendered_html: str) -> list[str]:
    """Verify the required rendered sections exist once and in fixed order."""
    markers = (
        ('alert identity', '<h2>['),
        ('triage reasons', 'detail-section-triage-reasons'),
        ('duplicate alert timeline', 'alert-timeline-section'),
        ('ai analysis output', 'detail-section-ai-analysis-output'),
        ('ai model used', 'detail-section-ai-model-used'),
        ('enriched alert details', 'detail-section-enriched-alert-details'),
        ('alert summary', 'detail-section-alert-summary'),
        ('analyst notes', 'detail-section-analyst-notes'),
        ('parsed pcap evidence', 'detail-section-parsed-pcap-evidence'),
        ('network and flow details', 'detail-section-network-and-flow-details'),
        ('protocol details', 'detail-section-protocol-details'),
        ('host and sensor details', 'detail-section-host-and-sensor-details'),
        ('threat context', 'detail-section-threat-context'),
        ('security onion detail fields', 'detail-section-security-onion-detail-fields'),
        ('raw logs', 'detail-section-raw-logs'),
    )
    issues: list[str] = []
    positions: list[int] = []
    for label, marker in markers:
        count = rendered_html.count(marker)
        if count != 1:
            issues.append(f'Rendered section "{label}" appeared {count} time(s); exactly one is required.')
        positions.append(rendered_html.find(marker))
    present_positions = [position for position in positions if position >= 0]
    if present_positions != sorted(present_positions):
        issues.append('Rendered report sections are out of canonical order.')
    return issues


def detail_layout_error_html(issues: tuple[str, ...] | list[str]) -> str:
    if not issues:
        return ''
    items = ''.join(f'<li>{html.escape(issue)}</li>' for issue in issues)
    return (
        f'<section class="detail-layout-error" role="alert" data-layout-version="{DETAIL_REPORT_LAYOUT_VERSION}">'
        '<strong>Detailed Alert Report layout error</strong>'
        f'<p>Legacy or malformed data could not be mapped cleanly to layout {DETAIL_REPORT_LAYOUT_VERSION}.</p>'
        f'<ul>{items}</ul></section>'
    )


def finalize_detail_report_html(
    rendered_html: str,
    timeline_html: str,
    source_issues: tuple[str, ...] | list[str] = (),
) -> str:
    """Insert the timeline, validate the DOM contract, and expose violations."""
    rendered = insert_timeline_after_alert_identity(rendered_html, timeline_html)
    issues = list(source_issues)
    issues.extend(validate_rendered_detail_layout(rendered))
    issues = list(dict.fromkeys(issues))
    valid = 'false' if issues else 'true'
    return (
        f'<div class="detail-layout-contract" data-layout-version="{DETAIL_REPORT_LAYOUT_VERSION}" '
        f'data-layout-valid="{valid}">{detail_layout_error_html(issues)}{rendered}</div>'
    )


def directory_size_bytes(path: Path) -> int:
    """Return total bytes for a runtime evidence directory without following symlinks."""
    if not path.exists():
        return 0
    total = 0
    for item in path.rglob('*'):
        try:
            if item.is_file() and not item.is_symlink():
                total += item.stat().st_size
        except OSError:
            continue
    return total


def pcap_analysis_index() -> dict[str, object]:
    """Index parsed PCAP evidence once per dashboard build for fast row lookups."""
    return resolve_pcap_analysis_index(PcapWorkflowConfig(DB_PATH, PCAP_ANALYSIS_DIR))


def pcap_request_status_for_row(
    row: sqlite3.Row | dict,
    index: dict[str, object] | None = None,
) -> dict:
    """Resolve broker state through the configured PCAP workflow boundary."""
    return resolve_pcap_request_status_for_row(
        row, PcapWorkflowConfig(DB_PATH, PCAP_ANALYSIS_DIR), index,
    )


def pcap_status_for_row(row: sqlite3.Row | dict, index: dict[str, object] | None = None) -> tuple[str, str, str]:
    """Return a compact PCAP analysis status for the alert table."""
    return resolve_pcap_status_for_row(
        row, PcapWorkflowConfig(DB_PATH, PCAP_ANALYSIS_DIR), index,
    )


def pcap_analysis_for_row(row: sqlite3.Row | dict, index: dict[str, object] | None = None) -> dict | None:
    """Return the newest parsed PCAP evidence artifact for this grouped alert."""
    return resolve_pcap_analysis_for_row(
        row, PcapWorkflowConfig(DB_PATH, PCAP_ANALYSIS_DIR), index,
    )




def report_from_sqlite_row(
    row: sqlite3.Row | dict,
    markdown_by_alert_id: dict[str, tuple[Path, str, os.stat_result]],
    ai_analysis_by_alert_id: dict[str, dict],
    ai_prompts_by_alert_id: dict[str, dict],
    running_ai_alert_ids: set[str],
    pcap_index: dict[str, set[str]] | None = None,
    ai_analysis_min_severity: str = 'informational',
) -> AlertReport:
    services = AlertReportFactoryServices(
        finalize_detail_report_html=finalize_detail_report_html,
    )
    return build_alert_report(
        row,
        markdown_by_alert_id,  # type: ignore[arg-type]
        ai_analysis_by_alert_id,
        ai_prompts_by_alert_id,
        running_ai_alert_ids,
        pcap_index,  # type: ignore[arg-type]
        ai_analysis_min_severity,
        AlertReportFactoryConfig(DB_PATH, MARKDOWN_SOURCES, PCAP_ANALYSIS_DIR),
        services,
    )


def load_markdown_only_reports() -> list[AlertReport]:
    """Build disaster-recovery reports through the read-only repository."""
    return load_markdown_fallback_reports(_report_repository_config())


def load_reports() -> list[AlertReport]:
    # SQLite is the normal source of truth for dashboard rows. Markdown is
    # supplementary detail/corpus content, not the table database.
    SOURCE_DIR.mkdir(parents=True, exist_ok=True)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    if not DB_PATH.exists():
        return load_markdown_only_reports()

    markdown_by_alert_id = load_markdown_reports_by_alert_id()
    repository = load_alert_repository(DB_PATH)
    ai_analysis_by_alert_id = load_ai_analysis_by_alert_id()
    ai_prompts_by_alert_id = load_ai_prompts_by_alert_id()
    running_ai_alert_ids = running_ai_prompt_alert_ids(ai_prompts_by_alert_id)
    pcap_index = pcap_analysis_index()
    pcap_index.update(repository.pcap_request_index)
    ai_analysis_min_severity = str(
        load_soc_ai_settings().get('soc_analyst_analysis_min_severity')
        or 'informational'
    )
    reports = [
        report_from_sqlite_row(
            row,
            markdown_by_alert_id,
            ai_analysis_by_alert_id,
            ai_prompts_by_alert_id,
            running_ai_alert_ids,
            pcap_index,
            ai_analysis_min_severity,
        )
        for row in repository.rows
    ]
    return sorted(reports, key=lambda r: (r.criticality_rank, r.mtime, r.title.lower()), reverse=True)

def human_size(num: int) -> str:
    n = float(num)
    for unit in ('B', 'KB', 'MB', 'GB'):
        if n < 1024 or unit == 'GB':
            return f'{n:.1f} {unit}' if unit != 'B' else f'{int(n)} B'
        n /= 1024
    return f'{n:.1f} GB'


def human_time(ts: float) -> str:
    return format_project_timestamp(dt.datetime.fromtimestamp(ts, tz=dt.timezone.utc).replace(microsecond=0))


def iso_local_time(ts: float) -> str:
    """Render alert timestamps in local ISO 8601 with the project separator."""
    value = dt.datetime.fromtimestamp(ts, tz=dt.timezone.utc)
    return format_project_timestamp(value)


def last_seen_ts_for(report: AlertReport) -> float:
    # `last_seen` is the grouped newest alert timestamp. `alert_ts` is the
    # representative-row fallback if older SQLite rows have sparse timestamps.
    return parse_iso_timestamp(report.last_seen) or report.alert_ts or report.mtime


def last_seen_iso_for(report: AlertReport) -> str:
    return iso_local_time(last_seen_ts_for(report))


def compact_minute_timestamp(value: str) -> str:
    """Render a timestamp as `YYYY-MM-DD  HH:MM-06:00` for compact metric cards."""
    parsed = parse_iso_datetime(value)
    text = format_project_timestamp(parsed) if parsed else str(value or '')
    match = re.search(r'(\d{4}-\d{2}-\d{2})(?:T|\s+)(\d{2}:\d{2})(?::\d{2}(?:\.\d+)?)?(Z|[+-]\d{2}:?\d{2})?', text)
    if not match:
        return text
    date, minute, offset = match.groups()
    return f'{date}  {minute}{offset or ""}'



def ai_summary_for(report: AlertReport) -> str:
    title = report.title.lower()
    if 'cins active threat' in title or 'poor reputation' in title:
        return 'IP reputation hit observed in threat intelligence feeds. Review related SSH or external connection activity.'
    if 'ssh scan outbound' in title:
        return 'Outbound SSH scanning activity detected. Multiple destination attempts may indicate reconnaissance or misconfiguration.'
    if 'potential ssh scan' in title:
        return 'SSH scanning behavior identified. Review source host, destination spread, and authentication telemetry.'
    if 'telegram api certificate' in title:
        return 'Telegram API certificate observed in traffic. Validate expected application use and possible exfiltration channel.'
    if 'curl user-agent' in title or 'dotted quad' in title:
        return 'Direct-IP curl-style traffic observed. Review process context and destination reputation.'
    if 'abused hosting domain' in title or 'azurewebsites' in title:
        return 'Potential abused hosting infrastructure observed. Review DNS/TLS context and related endpoint activity.'
    return report.summary[:170] + ('…' if len(report.summary) > 170 else '')


def risk_score_for(report: AlertReport) -> int:
    haystack = f'{report.title}\n{report.summary}'
    score_match = re.search(r'triage\s+score\s*[:=]\s*["\']?(\d{1,3})\b', haystack, flags=re.IGNORECASE)
    if score_match:
        return max(0, min(100, int(score_match.group(1))))
    return {5: 92, 4: 78, 3: 58, 2: 32, 1: 12}.get(report.criticality_rank, 12)


def ai_status_pill(report: AlertReport) -> str:
    return (
        f'<span class="ai-status-pill ai-status-{html.escape(report.ai_status_key)}" '
        f'title="{html.escape(report.ai_status_detail, quote=True)}">'
        f'{html.escape(report.ai_status_label)}</span>'
    )


def enrichment_status_pill(report: AlertReport) -> str:
    return (
        f'<span class="enrichment-status-pill enrichment-status-{html.escape(report.enrichment_status_key)}" '
        f'title="{html.escape(report.enrichment_status_detail, quote=True)}">'
        f'{html.escape(report.enrichment_status_label)}</span>'
    )


def pcap_status_pill(report: AlertReport) -> str:
    return (
        f'<span class="pcap-status-pill pcap-status-{html.escape(report.pcap_status_key)}" '
        f'title="{html.escape(report.pcap_status_detail, quote=True)}">'
        f'{html.escape(report.pcap_status_label)}</span>'
    )


def ai_activity_state(reports: list[AlertReport]) -> dict[str, object]:
    """Summarize AI queue state for both static rendering and live polling."""
    counts = {
        'analyzing': sum(1 for report in reports if report.ai_status_key == 'analyzing'),
        'queued': sum(1 for report in reports if report.ai_status_key == 'queued'),
        'analyzed': sum(1 for report in reports if report.ai_status_key == 'analyzed'),
        'not_queued': sum(1 for report in reports if report.ai_status_key == 'not-queued'),
        'total': len(reports),
    }
    active = counts['analyzing'] > 0
    assignment = current_soc_analysis_model()
    model = assignment['label']
    status_label = 'Analyzing' if active else 'Idle'
    return {
        'active': active,
        'label': 'AI Alert Triage',
        'detail': f'{status_label} · Assigned: {model}',
        'model': model,
        'provider': assignment['provider'],
        'route': assignment['route'],
        'counts': counts,
    }


def render_ai_activity_metric(state: dict[str, object]) -> str:
    return render_ai_activity_metric_card(
        state,
        current_soc_analysis_model()['label'],
    )
