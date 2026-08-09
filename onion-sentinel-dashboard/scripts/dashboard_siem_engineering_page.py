"""Pure SIEM Engineering recommendation view models and renderers."""
from __future__ import annotations

from dataclasses import dataclass
import html
import json
import re
from typing import Mapping, Sequence


@dataclass(frozen=True)
class SiemRecommendationViewModel:
    title: str
    digest: str
    rel_source: str
    summary: str
    ai_summary: str
    criticality: str
    criticality_rank: int
    alert_source: str
    source_ip: str
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
    enrichment_status_label: str
    enrichment_status_detail: str
    enrichment_record_count: int
    enrichment_skip_count: int
    enrichment_error_count: int
    pcap_status_label: str
    pcap_status_detail: str
    tuning_recommendation: str
    tuning_reason: str
    recommended_tuning_actions: tuple[str, ...]
    generated_at: str
    response: Mapping[str, object]


@dataclass(frozen=True)
class SiemEngineeringPageViewModel:
    mode: str
    local_model: str
    cloud_model: str
    analyzed: int
    total: int
    all_candidates: tuple[SiemRecommendationViewModel, ...]
    actionable: tuple[SiemRecommendationViewModel, ...]
    repeated: tuple[SiemRecommendationViewModel, ...]


def _criticality_class(label: str) -> str:
    return re.sub(r'[^a-z0-9]+', '-', label.lower()).strip('-') or 'informational'


def _compact(text: object, max_len: int) -> str:
    value = re.sub(r'\s+', ' ', str(text or '')).strip()
    if not value:
        return ''
    sentence = re.split(r'(?<=[.!?])\s+', value, maxsplit=1)[0].strip()
    clipped = sentence if sentence else value
    return (clipped[:max_len - 1].rstrip() + '…') if len(clipped) > max_len else clipped


def siem_engineering_html_list(values: object, empty: str) -> str:
    if isinstance(values, (list, tuple)):
        items = values
    elif values not in (None, ''):
        items = [values]
    else:
        items = []
    rendered = []
    for value in items:
        text = json.dumps(value, sort_keys=True, default=str) if isinstance(value, (dict, list)) else str(value)
        if text.strip():
            rendered.append(f'<li>{html.escape(text.strip())}</li>')
    return f'<ul>{"".join(rendered)}</ul>' if rendered else f'<p>{html.escape(empty)}</p>'


def _recommendation_plan(
    report: SiemRecommendationViewModel, recommendation_kind: str
) -> tuple[str, str, str, Sequence[str], Sequence[str], str]:
    response = report.response
    if recommendation_kind == 'current-rule':
        return (
            'Current rule tuning analysis', report.tuning_recommendation or 'review',
            report.tuning_reason or str(response.get('alert_frequency_assessment') or report.ai_summary),
            report.recommended_tuning_actions or ('Review this detection with the SIEM Engineer model before changing production rule behavior.',),
            (
                'Replay or query representative historical events and confirm the scoped condition matches only the intended traffic.',
                'Run the change in audit or count-only mode and compare alert volume, severity, and missed true-positive risk.',
                'Require analyst approval before enabling a suppression, drop, or score change in production.',
            ),
            'Restore the prior rule or scoring configuration and rerun the same validation window.',
        )
    route = f'{report.source_endpoint} > {report.destination_endpoint}'
    return (
        'New detection candidate analysis', 'create candidate',
        str(response.get('alert_frequency_assessment') or response.get('summary') or report.ai_summary),
        (
            f'Create a candidate detection for the repeated {report.rule_name or report.title} behavior.',
            f'Scope the first test to log source {report.alert_source}, route {route}, and the observed frequency before generalizing it.',
        ),
        (
            'Backtest the candidate against the full first-seen to last-seen window and record expected and unexpected matches.',
            'Deploy disabled or alert-only first, then compare precision and coverage with the source detection.',
            'Promote only after an analyst confirms the query does not encode environment-specific noise as malicious behavior.',
        ),
        'Disable the candidate detection and preserve its test results for later refinement.',
    )


def _context_html(report: SiemRecommendationViewModel, recommendation: str) -> str:
    route = f'{report.source_endpoint} > {report.destination_endpoint}'
    observations = max(report.repeat_count, report.raw_alert_count, report.total_seen_count, 1)
    rows = (
        ('Detection', report.rule_name or report.title), ('Severity', report.criticality),
        ('Recommendation type', recommendation), ('Log source', report.alert_source),
        ('Rule ID', report.rule_id or 'n/a'), ('Alert group', report.alert_group_key or 'n/a'),
        ('Observed route', route), ('First seen', report.first_seen), ('Last seen', report.last_seen),
        ('Grouped observations', observations), ('Raw alert rows', report.raw_alert_count),
        ('AI workflow', f'{report.ai_status_label}: {report.ai_status_detail}'),
        ('Public enrichment', f'{report.enrichment_status_label}: {report.enrichment_status_detail}'),
        ('Enrichment records', report.enrichment_record_count), ('Enrichment skips', report.enrichment_skip_count),
        ('Enrichment errors', report.enrichment_error_count),
        ('PCAP evidence', f'{report.pcap_status_label}: {report.pcap_status_detail}'),
        ('Source artifact', report.rel_source),
    )
    return ''.join(
        f'<div><dt>{html.escape(str(label))}</dt><dd>{html.escape(str(value or "n/a"))}</dd></div>'
        for label, value in rows
    )


def _assessment_html(response: Mapping[str, object]) -> str:
    fields = (
        ('Summary', 'summary'), ('Likely meaning', 'likely_meaning'),
        ('Severity reasoning', 'severity_reasoning'), ('Frequency assessment', 'alert_frequency_assessment'),
    )
    return ''.join(
        f'<div><dt>{label}</dt><dd>{html.escape(str(response.get(key) or "n/a"))}</dd></div>'
        for label, key in fields
    )


def _evidence_html(response: Mapping[str, object]) -> str:
    fields = (
        ('Public enrichment findings', 'public_enrichment_findings', 'No public enrichment findings were recorded.'),
        ('PCAP findings', 'pcap_analysis_findings', 'No parsed PCAP findings were recorded.'),
        ('False-positive considerations', 'false_positive_possibilities', 'No false-positive considerations were recorded.'),
        ('Evidence gaps', 'evidence_gaps', 'No additional evidence gaps were recorded.'),
        ('Evidence used', 'evidence_used', 'No evidence list was recorded.'),
        ('Recommended investigation', 'recommended_next_steps', 'No additional investigation steps were recorded.'),
    )
    return ''.join(
        f'<div><h4>{label}</h4>{siem_engineering_html_list(response.get(key), empty)}</div>'
        for label, key, empty in fields
    )


def render_siem_engineering_detail_report(report: SiemRecommendationViewModel, recommendation_kind: str) -> str:
    response = report.response
    report_title, recommendation, why, actions, validation, rollback = _recommendation_plan(report, recommendation_kind)
    outcome = str(response.get('detection_outcome') or 'Inconclusive')
    bluf = str(response.get('bluf') or response.get('summary') or 'No model BLUF is available yet.')
    complete_response = html.escape(json.dumps(response, indent=2, sort_keys=True, default=str))
    return f'''
    <section class="siem-analysis-report" aria-label="{html.escape(report_title)}">
      <header class="siem-analysis-header">
        <div><span class="settings-kicker">AI engineering report</span><h3>{html.escape(report_title)}</h3></div>
        <span class="siem-table-pill">{html.escape(recommendation)}</span>
      </header>
      <div class="siem-analysis-generated">Generated: {html.escape(report.generated_at)} · Model status: {html.escape(report.ai_status_label)}</div>
      <section class="siem-analysis-bluf"><h4>Bottom line</h4><p><b>{html.escape(outcome)}</b> · {html.escape(bluf)}</p></section>
      <div class="siem-analysis-lead">
        <section><h4>What should change</h4>{siem_engineering_html_list(actions, 'No safe change has been recommended yet.')}</section>
        <section><h4>Why</h4><p>{html.escape(why)}</p></section>
      </div>
      <section class="siem-analysis-section"><h4>Detection context</h4><dl class="siem-detection-context">{_context_html(report, recommendation)}</dl></section>
      <section class="siem-analysis-section"><h4>AI detection assessment</h4><dl class="siem-analysis-findings">{_assessment_html(response)}</dl></section>
      <section class="siem-analysis-evidence">{_evidence_html(response)}</section>
      <section class="siem-analysis-section"><h4>Validation and rollback</h4>{siem_engineering_html_list(validation, 'Validate before deployment.')}<p><b>Rollback:</b> {html.escape(rollback)}</p></section>
      <details class="siem-ai-json"><summary>Complete AI response JSON</summary><pre><code>{complete_response or '{}'}</code></pre></details>
    </section>'''


def render_siem_engineering_tuning_row(report: SiemRecommendationViewModel, index: int) -> str:
    action = report.recommended_tuning_actions[0] if report.recommended_tuning_actions else 'Review this detection after the SIEM Engineer model run completes.'
    route = f'{report.source_ip} > {report.destination_ip} : {report.destination_port}'
    detail_id = f'siem-current-detail-{index}-{report.digest}'
    return f'''
    <tr class="siem-recommendation-row" tabindex="0" aria-expanded="false" aria-controls="{html.escape(detail_id)}" data-siem-toggle>
      <td><span class="severity-label severity-text-{html.escape(_criticality_class(report.criticality))}">{html.escape(report.criticality)}</span></td>
      <td><strong><span class="siem-expand-indicator" aria-hidden="true">›</span>{html.escape(report.rule_name or report.title)}</strong><code>{html.escape(route)}</code></td>
      <td><span class="siem-table-pill">{html.escape(report.tuning_recommendation or 'review')}</span></td>
      <td class="siem-reason-cell"><p>{html.escape(_compact(report.tuning_reason or report.ai_summary, 135))}</p><em>{html.escape(_compact(action, 135))}</em></td>
      <td><b>{report.repeat_count}</b><span>{html.escape(report.ai_status_label)}</span></td>
    </tr>
    <tr id="{html.escape(detail_id)}" class="siem-recommendation-detail" hidden>
      <td colspan="5">{render_siem_engineering_detail_report(report, 'current-rule')}</td>
    </tr>'''


def render_siem_engineering_detection_row(report: SiemRecommendationViewModel, index: int) -> str:
    destination = f'{report.destination_ip}:{report.destination_port}'
    detail_id = f'siem-new-detail-{index}-{report.digest}'
    return f'''
    <tr class="siem-recommendation-row" tabindex="0" aria-expanded="false" aria-controls="{html.escape(detail_id)}" data-siem-toggle>
      <td><span class="severity-label severity-text-{html.escape(_criticality_class(report.criticality))}">{html.escape(report.criticality)}</span></td>
      <td><strong><span class="siem-expand-indicator" aria-hidden="true">›</span>{html.escape(report.rule_name or report.title)}</strong><code>{html.escape(report.alert_source)}</code></td>
      <td><span class="siem-table-pill">candidate</span></td>
      <td class="siem-reason-cell"><p>{html.escape(_compact(report.ai_summary, 135))}</p><em>Repeated target: {html.escape(destination)}</em></td>
      <td><b>{report.repeat_count}</b><span>{html.escape(report.last_seen)}</span></td>
    </tr>
    <tr id="{html.escape(detail_id)}" class="siem-recommendation-detail" hidden>
      <td colspan="5">{render_siem_engineering_detail_report(report, 'new-detection')}</td>
    </tr>'''


def siem_engineering_roi_score(report: SiemRecommendationViewModel) -> tuple[int, int, int, float]:
    model_tuning = int(bool(report.tuning_recommendation and report.tuning_recommendation not in {'none', 'n/a', 'needs_more_data'}))
    repeat_weight = max(report.repeat_count, report.raw_alert_count, report.total_seen_count, 1)
    return model_tuning, repeat_weight * max(report.criticality_rank, 1), repeat_weight, report.alert_ts


def _best_roi_candidate(reports: Sequence[SiemRecommendationViewModel]) -> SiemRecommendationViewModel | None:
    candidates = [r for r in reports if r.tuning_recommendation and r.tuning_recommendation not in {'none', 'n/a'}]
    candidates = candidates or [r for r in reports if r.repeat_count >= 2]
    return max(candidates, key=siem_engineering_roi_score) if candidates else None


def _roi_copy(best: SiemRecommendationViewModel, observations: int) -> tuple[str, str, str]:
    action = best.recommended_tuning_actions[0] if best.recommended_tuning_actions else (
        'Run SIEM Engineer review before changing rules; tune only with a scoped condition such as rule name, source, destination, destination port, direction, or time window.'
    )
    model_ready = best.tuning_recommendation not in {'none', 'n/a', 'needs_more_data'}
    if not model_ready:
        why = (
            f'This is the highest ROI review candidate because it has {observations} observations '
            f'and {best.criticality} severity, but the model has not provided a safe tuning action yet.'
        )
        return action, 'review', why
    why = best.tuning_reason or (
        f'This is the highest ROI tuning candidate because it combines {observations} observations, '
        f'{best.criticality} severity, and a model-backed {best.tuning_recommendation} recommendation.'
    )
    return action, best.tuning_recommendation, why


def render_siem_engineering_best_roi(reports: Sequence[SiemRecommendationViewModel]) -> str:
    best = _best_roi_candidate(reports)
    if best is None:
        return '''
      <section class="siem-roi-card" aria-label="Best ROI tuning candidate">
        <div class="siem-roi-head">
          <span class="settings-kicker">#1 ROI tune</span>
          <h3>No candidate yet</h3>
        </div>
        <table class="siem-roi-table"><tbody><tr><th>Why</th><td>No repeated or model-backed candidate.</td></tr><tr><th>Tune</th><td>Wait for analysis, then tune only scoped rule/source/destination/port evidence.</td></tr><tr><th>Activity</th><td>0 observations</td></tr></tbody></table>
      </section>'''
    observations = max(best.repeat_count, best.raw_alert_count, best.total_seen_count, 1)
    action, tuning_type, why = _roi_copy(best, observations)
    route = f'{best.source_ip} > {best.destination_ip} : {best.destination_port}'
    return f'''
      <section class="siem-roi-card" aria-label="Best ROI tuning candidate">
        <div class="siem-roi-head"><div><span class="settings-kicker">#1 ROI tune</span><h3>{html.escape(best.rule_name or best.title)}</h3><code>{html.escape(route)}</code></div>
          <div class="siem-roi-rank"><span>#1 ROI</span><strong class="severity-text-{html.escape(_criticality_class(best.criticality))}">{html.escape(best.criticality)}</strong></div></div>
        <table class="siem-roi-table"><tbody>
          <tr><th>Why</th><td>{html.escape(_compact(why, 180))}</td></tr>
          <tr><th>Tune</th><td>{html.escape(_compact(action, 180))}</td></tr>
          <tr><th>Activity</th><td>{html.escape(str(observations))} observations · {html.escape(tuning_type)} · {html.escape(best.ai_status_label)}</td></tr>
        </tbody></table>
      </section>'''


def render_siem_engineering_table(title: str, rows: str, empty: str) -> str:
    body = rows or f'<tr class="siem-empty-row"><td colspan="5">{html.escape(empty)}</td></tr>'
    return f'''
    <section class="siem-table-section" aria-label="{html.escape(title)}">
      <div class="siem-table-title"><h3>{html.escape(title)}</h3></div>
      <div class="siem-table-wrap"><table class="siem-engineering-table">
        <thead><tr><th>Severity</th><th>Detection</th><th>Type</th><th>Why / tune</th><th>Seen</th></tr></thead><tbody>{body}</tbody>
      </table></div>
    </section>'''


def render_siem_engineering_page(view: SiemEngineeringPageViewModel) -> str:
    ready = bool(view.total) and view.analyzed == view.total
    current_rows = ''.join(render_siem_engineering_tuning_row(r, i) for i, r in enumerate(view.actionable[:10], 1))
    new_rows = ''.join(render_siem_engineering_detection_row(r, i) for i, r in enumerate(view.repeated[:10], 1))
    return f'''
    <section class="view-section active siem-engineering-view" aria-label="SIEM Engineering recommendations">
      <section class="siem-eng-hero"><div><span class="settings-kicker">SIEM engineering</span><h2>SIEM Engineer</h2><p>Prioritized tuning and detection work.</p></div>
        <div class="siem-model-card"><span>Model route</span><strong>{html.escape(view.mode.title())}</strong><em>Local: {html.escape(view.local_model)} · Cloud: {html.escape(view.cloud_model)}</em></div></section>
      <section class="siem-eng-kpis" aria-label="SIEM engineering readiness">
        <article><span>Gate</span><strong>{'Ready' if ready else 'Waiting'}</strong><em>{view.analyzed}/{view.total} analyzed</em></article>
        <article><span>Cadence</span><strong>6h</strong><em>after backlog clears</em></article>
        <article><span>Tuning</span><strong>{len(view.actionable)}</strong><em>current-rule ideas</em></article>
        <article><span>Detections</span><strong>{len(view.repeated)}</strong><em>new-rule ideas</em></article>
      </section>
      {render_siem_engineering_best_roi(view.all_candidates)}
      {render_siem_engineering_table('Current rule tuning', current_rows, 'No model-backed tuning recommendations yet.')}
      {render_siem_engineering_table('New detections', new_rows, 'No repeated detection candidates yet.')}
    </section>'''
