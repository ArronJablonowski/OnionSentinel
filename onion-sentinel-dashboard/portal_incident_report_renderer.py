"""Composable HTML renderer for Incident Response investigation reports."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import html
import json


@dataclass(frozen=True)
class IncidentReportRenderCallbacks:
    html_text: Callable[[object, str], str]
    nonnegative_int: Callable[[object], int]
    linked_finding: Callable[[dict, object], str]
    html_list: Callable[[object, str], str]
    report_section: Callable[[str, str], str]
    investigation_audit: Callable[[dict, dict], tuple[str, int]]
    review_panel: Callable[..., str]


def _metadata(case: dict, analysis: dict, report: dict, callbacks) -> str:
    text = callbacks.html_text
    resolution = (
        f'<span><b>Resolution:</b> {text(case.get("resolution_reason"), "n/a")}</span>'
        f'<span><b>Resolved by:</b> {text(case.get("resolved_by"), "n/a")}</span>'
        f'<span><b>Resolved at:</b> {text(case.get("resolved_at"), "n/a")}</span>'
        if case.get("resolution_reason")
        else ""
    )
    return (
        '<div class="ir-analysis-meta">'
        f'<span><b>Case:</b> {text(case.get("case_id"), "n/a")}</span>'
        f'<span><b>Generated:</b> {text(analysis.get("generated_at"), "n/a")}</span>'
        f'<span><b>Model:</b> {text(analysis.get("model"), "n/a")}</span>'
        f'<span><b>Confidence:</b> '
        f'{text(report.get("confidence") or analysis.get("confidence"), "n/a")}</span>'
        f'{resolution}</div>'
    )


def _empty_report(case: dict, metadata: str) -> tuple[str, int]:
    state = str(case.get("agent_status") or "queued").replace("_", " ")
    error = str(case.get("latest_error") or "").strip()
    message = error if error else f"Incident Responder analysis is {state}."
    return (
        '<section class="ir-investigation-report">'
        '<h3>Incident Response Investigation</h3>'
        f'{metadata}<p class="ir-analysis-empty">{html.escape(message)}</p>'
        '</section>',
        0,
    )


def _timeline_html(report: dict, callbacks) -> str:
    text = callbacks.html_text
    timeline = report.get("factual_timeline")
    timeline = timeline if isinstance(timeline, list) else []
    rows = []
    for event in timeline[:200]:
        if not isinstance(event, dict):
            continue
        rows.append(
            '<tr>'
            f'<td>{text(event.get("timestamp"), "n/a")}</td>'
            f'<td>{text(event.get("event"), "n/a")}</td>'
            f'<td>{text(event.get("source_pack") or "supplied evidence", "n/a")}</td>'
            f'<td><code>{text(event.get("query_digest"), "n/a")}</code></td>'
            f'<td>{text(event.get("confidence") or "low", "n/a")}</td>'
            '</tr>'
        )
    if not rows:
        return '<p>No fact-grounded timeline entries were returned.</p>'
    return (
        '<div class="ir-timeline-wrap"><table class="ir-timeline-table">'
        '<thead><tr><th>Time</th><th>Observed event</th><th>Evidence source</th>'
        '<th>Query digest</th><th>Confidence</th></tr></thead>'
        f'<tbody>{"".join(rows)}</tbody></table></div>'
    )


def _report_sections(report: dict, callbacks) -> list[str]:
    text = callbacks.html_text
    section = callbacks.report_section
    html_list = callbacks.html_list
    sections = [
        section("Executive BLUF", f'<p>{text(report.get("executive_bluf"), "n/a")}</p>'),
        section(
            "Detection Outcome Reasoning",
            f'<p>{text(report.get("detection_outcome_reasoning"), "n/a")}</p>',
        ),
        section("Scope", f'<p>{text(report.get("scope"), "n/a")}</p>'),
        section(
            "Constraints",
            html_list(report.get("constraints"), "No explicit constraints were recorded."),
        ),
        section("Affected Systems", html_list(report.get("affected_systems"), "No findings were recorded.")),
        section("Methodology", html_list(report.get("methodology"), "No findings were recorded.")),
        section("Factual Timeline", _timeline_html(report, callbacks)),
    ]
    for title, key in (
        ("Security Onion Findings", "security_onion_findings"),
        ("OSquery Findings", "osquery_findings"),
        ("PCAP Findings", "pcap_findings"),
        ("Host Findings", "host_findings"),
        ("Correlation Findings", "correlation_findings"),
        ("Containment Recommendations", "containment_recommendations"),
        ("Eradication Recommendations", "eradication_recommendations"),
        ("Recovery Recommendations", "recovery_recommendations"),
        ("Follow-up Queries", "follow_up_queries"),
        ("Evidence Gaps", "evidence_gaps"),
    ):
        sections.append(section(title, html_list(report.get(key), "No findings were recorded.")))
    sections.append(section(
        "Conclusion",
        f'<p>{text(report.get("conclusion"), "n/a")}</p>'
        f'<p><b>Confidence:</b> {text(report.get("confidence") or "low", "n/a")}</p>',
    ))
    return sections


def _security_query_block(position: int, query: dict, report: dict, callbacks) -> str:
    text = callbacks.html_text
    count = callbacks.nonnegative_int
    window = query.get("window") if isinstance(query.get("window"), dict) else {}
    dsl = query.get("query_dsl") if isinstance(query.get("query_dsl"), dict) else {}
    dsl_text = html.escape(json.dumps(dsl, indent=2, sort_keys=True, default=str))
    finding = callbacks.linked_finding(report, query.get("query_digest"))
    return (
        f'<article class="ir-query-record" data-query-finding="{html.escape(finding, quote=True)}">'
        f'<h4>Query {position}: {text(query.get("pack") or "evidence pack", "n/a")}</h4>'
        '<div class="ir-query-meta">'
        f'<span><b>Status:</b> {text(query.get("status") or "unknown", "n/a")}</span>'
        f'<span><b>Digest:</b> <code>{text(query.get("query_digest"), "n/a")}</code></span>'
        f'<span><b>Window:</b> {text(window.get("start"), "n/a")} to '
        f'{text(window.get("end"), "n/a")}</span>'
        f'<span><b>Hits:</b> {count(query.get("total_hits"))} total / '
        f'{count(query.get("returned_hits"))} returned</span></div>'
        '<h5>KQL (analyst-readable equivalent)</h5>'
        f'<pre class="ir-query-code"><code>{text(query.get("kql_equivalent"), "n/a")}</code></pre>'
        '<h5>Elasticsearch Query DSL (exact executed request)</h5>'
        f'<pre class="ir-query-code"><code>{dsl_text}</code></pre></article>'
    )


def _security_audit(response: dict, report: dict, callbacks) -> tuple[str, int]:
    audit = response.get("_incident_query_audit")
    audit = audit if isinstance(audit, dict) else {}
    queries = audit.get("queries") if isinstance(audit.get("queries"), list) else []
    blocks = [
        _security_query_block(position, query, report, callbacks)
        for position, query in enumerate(queries[:100], 1)
        if isinstance(query, dict)
    ]
    text = callbacks.html_text
    body = "".join(blocks) if blocks else '<p>No restricted Security Onion queries were recorded.</p>'
    section = (
        '<section class="ir-query-audit"><h3>Security Onion Query Audit</h3>'
        '<div class="ir-analysis-meta">'
        f'<span><b>Source:</b> {text(audit.get("trusted_source"), "n/a")}</span>'
        f'<span><b>Read only:</b> {text(audit.get("read_only", True), "n/a")}</span>'
        f'<span><b>Complete:</b> {text(audit.get("complete", False), "n/a")}</span>'
        f'<span><b>Partial:</b> {text(audit.get("partial", True), "n/a")}</span>'
        f'</div>{body}</section>'
    )
    return section, len(blocks)


def _result_preview(query: dict, empty_message: str) -> str:
    rows = query.get("rows_preview") if isinstance(query.get("rows_preview"), list) else []
    if not rows:
        return f'<p>{html.escape(empty_message)}</p>'
    rows_text = html.escape(json.dumps(rows[:25], indent=2, sort_keys=True, default=str))
    return (
        '<h5>Bounded Result Preview</h5>'
        f'<pre class="ir-query-code"><code>{rows_text}</code></pre>'
    )


def _query_error(query: dict) -> str:
    error = str(query.get("error") or "").strip()
    return (
        f'<p class="ir-query-error"><b>Error:</b> {html.escape(error)}</p>'
        if error
        else ""
    )


def _appliance_query_block(position: int, query: dict, report: dict, callbacks) -> str:
    text = callbacks.html_text
    count = callbacks.nonnegative_int
    finding = callbacks.linked_finding(report, query.get("query_digest"))
    return (
        f'<article class="ir-query-record" data-query-finding="{html.escape(finding, quote=True)}">'
        f'<h4>OSquery {position}: {text(query.get("pack") or "reviewed pack", "n/a")}</h4>'
        '<div class="ir-query-meta">'
        f'<span><b>Target:</b> {text(query.get("target"), "n/a")}</span>'
        f'<span><b>Status:</b> {text(query.get("status") or "unknown", "n/a")}</span>'
        f'<span><b>Digest:</b> <code>{text(query.get("query_digest"), "n/a")}</code></span>'
        f'<span><b>Rows:</b> {count(query.get("total_rows"))} total / '
        f'{count(query.get("returned_rows"))} returned</span>'
        f'<span><b>Duration:</b> {count(query.get("duration_ms"))} ms</span>'
        f'<span><b>Truncated:</b> {text(query.get("truncated", False), "n/a")}</span></div>'
        '<h5>OSquery SQL (exact executed command)</h5>'
        f'<pre class="ir-query-code"><code>{text(query.get("query"), "n/a")}</code></pre>'
        f'{_result_preview(query, "No rows were returned by this reviewed pack.")}'
        f'{_query_error(query)}</article>'
    )


def _appliance_audit(response: dict, report: dict, callbacks) -> tuple[str, int]:
    audit = response.get("_incident_osquery_audit")
    audit = audit if isinstance(audit, dict) else {}
    queries = audit.get("queries") if isinstance(audit.get("queries"), list) else []
    blocks = [
        _appliance_query_block(position, query, report, callbacks)
        for position, query in enumerate(queries[:32], 1)
        if isinstance(query, dict)
    ]
    text = callbacks.html_text
    body = "".join(blocks) if blocks else '<p>No validated Security Onion appliance OSquery snapshots were recorded.</p>'
    return (
        '<section class="ir-query-audit"><h3>Security Onion Appliance OSQuery Snapshot Audit</h3>'
        '<div class="ir-analysis-meta">'
        f'<span><b>Source:</b> {text(audit.get("trusted_source"), "n/a")}</span>'
        f'<span><b>Read only:</b> {text(audit.get("read_only", True), "n/a")}</span>'
        f'<span><b>Contract:</b> {text(audit.get("query_contract"), "n/a")}</span>'
        f'</div>{body}</section>',
        len(blocks),
    )


def _live_query_block(position: int, query: dict, report: dict, callbacks) -> str:
    text = callbacks.html_text
    count = callbacks.nonnegative_int
    finding = callbacks.linked_finding(report, query.get("query_digest"))
    purpose = str(query.get("purpose") or "").strip()
    return (
        f'<article class="ir-query-record" data-query-purpose="{html.escape(purpose, quote=True)}" '
        f'data-query-finding="{html.escape(finding, quote=True)}">'
        f'<h4>Endpoint Query {position}: {text(query.get("target_alias") or "configured endpoint", "n/a")}</h4>'
        '<div class="ir-query-meta">'
        f'<span><b>Target:</b> {text(query.get("target_alias"), "n/a")}</span>'
        f'<span><b>Status:</b> {text(query.get("status") or "unknown", "n/a")}</span>'
        f'<span><b>Digest:</b> <code>{text(query.get("query_digest"), "n/a")}</code></span>'
        f'<span><b>Rows:</b> {count(query.get("total_rows"))} total / '
        f'{count(query.get("returned_rows"))} returned</span>'
        f'<span><b>Duration:</b> {count(query.get("duration_ms"))} ms</span>'
        f'<span><b>Truncated:</b> {text(query.get("truncated", False), "n/a")}</span></div>'
        '<h5>OSquery SQL (exact executed live query)</h5>'
        f'<pre class="ir-query-code"><code>{text(query.get("query"), "n/a")}</code></pre>'
        f'{_result_preview(query, "No rows were returned by this endpoint query.")}'
        f'{_query_error(query)}</article>'
    )


def _live_audit(response: dict, report: dict, callbacks) -> tuple[str, int]:
    audit = response.get("_incident_live_osquery_audit")
    audit = audit if isinstance(audit, dict) else {}
    queries = audit.get("queries") if isinstance(audit.get("queries"), list) else []
    blocks = [
        _live_query_block(position, query, report, callbacks)
        for position, query in enumerate(queries[:32], 1)
        if isinstance(query, dict)
    ]
    error = str(audit.get("error") or "").strip()
    error_html = (
        f'<p class="ir-query-error"><b>Collection note:</b> {html.escape(error)}</p>'
        if error
        else ""
    )
    text = callbacks.html_text
    body = "".join(blocks) if blocks else '<p>No endpoint live OSquery batch was executed for this investigation.</p>'
    return (
        '<section class="ir-query-audit"><h3>Endpoint Live OSQuery Audit</h3>'
        '<div class="ir-analysis-meta">'
        f'<span><b>Source:</b> {text(audit.get("trusted_source"), "n/a")}</span>'
        f'<span><b>Read only:</b> {text(audit.get("read_only", True), "n/a")}</span>'
        f'<span><b>Complete:</b> {text(audit.get("complete", False), "n/a")}</span>'
        f'<span><b>Contract:</b> {text(audit.get("query_contract"), "n/a")}</span>'
        f'</div>{error_html}{body}</section>',
        len(blocks),
    )


def render_incident_response_report(
    case: dict,
    response: dict,
    analysis: dict,
    review: dict | None,
    callbacks: IncidentReportRenderCallbacks,
) -> tuple[str, int]:
    """Render one escaped responder report and immutable query audit."""
    report = response.get("incident_response_report")
    report = report if isinstance(report, dict) else {}
    metadata = _metadata(case, analysis, report, callbacks)
    if not report:
        return _empty_report(case, metadata)
    security_html, security_count = _security_audit(response, report, callbacks)
    appliance_html, appliance_count = _appliance_audit(response, report, callbacks)
    live_html, live_count = _live_audit(response, report, callbacks)
    investigation_html, investigation_count = callbacks.investigation_audit(
        response, report
    )
    review_html = callbacks.review_panel(
        review,
        group_id=str(case.get("dashboard_group_id") or ""),
        case_id=str(case.get("case_id") or ""),
    )
    report_html = (
        '<section class="ir-investigation-report">'
        '<h3>Incident Response Investigation</h3>'
        f'{metadata}{"".join(_report_sections(report, callbacks))}</section>'
    )
    return (
        review_html + report_html + security_html + appliance_html
        + live_html + investigation_html,
        security_count + appliance_count + live_count + investigation_count,
    )
