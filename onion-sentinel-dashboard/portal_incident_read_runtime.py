"""Runtime composition for bounded Incident Response reads and rendering."""
from __future__ import annotations

from typing import Any


def soc_incidents_query_response(r: Any, query: dict[str, list[str]]) -> tuple[int, dict]:
    """Return one bounded page of durable Incident Response cases."""
    return r.incident_list_response(
        r.incident_read_service_sources(), query,
        max_per_page=r.SOC_ALERT_API_MAX_LIMIT,
    )


def soc_incident_review_state(
    r: Any, conn: Any, case: dict[str, object], analysis: dict[str, object],
    response: dict[str, object],
) -> dict[str, object]:
    records = r.load_incident_review_records(conn, case, analysis)
    return r.compose_incident_review_state(
        case, analysis, response, records.evidence_updated_at, records.reviewer,
        records.adjudication, r._soc_review_defaults(), r.INCIDENT_ROW_CALLBACKS,
    )


def incident_html_text(r: Any, value: object, fallback: str = "n/a") -> str:
    return r.html.escape(str(value or "").strip() or fallback)


def incident_nonnegative_int(r: Any, value: object) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError, OverflowError):
        return 0


def _bounded_finding(value: object) -> str:
    finding = str(value or "").strip()
    return finding if len(finding) <= 360 else f"{finding[:357].rstrip()}…"


def _timeline_linked_finding(report: dict[str, object], digest: str) -> str:
    timeline = report.get("factual_timeline")
    if not isinstance(timeline, list):
        return ""
    for event in timeline:
        if not isinstance(event, dict):
            continue
        if str(event.get("query_digest") or "").strip() != digest:
            continue
        finding = _bounded_finding(event.get("event"))
        if finding:
            return finding
    return ""


def _section_linked_finding(report: dict[str, object], digest: str) -> str:
    for key in (
        "security_onion_findings", "osquery_findings", "pcap_findings",
        "host_findings", "correlation_findings", "evidence_gaps",
    ):
        values = report.get(key)
        items = values if isinstance(values, list) else [values]
        for item in items:
            raw_finding = str(item or "").strip()
            if digest in raw_finding:
                return _bounded_finding(raw_finding)
    return ""


def incident_query_linked_finding(r: Any, report: dict[str, object], query_digest: object) -> str:
    _ = r
    digest = str(query_digest or "").strip()
    if not digest:
        return ""
    timeline_finding = _timeline_linked_finding(report, digest)
    if timeline_finding:
        return timeline_finding
    return _section_linked_finding(report, digest)


def incident_html_list(
    r: Any, values: object, fallback: str = "No findings were recorded."
) -> str:
    items = values if isinstance(values, list) else (
        [values] if values not in (None, "") else []
    )
    rendered = []
    for item in items[:100]:
        text = (
            r.json.dumps(item, sort_keys=True, default=str)
            if isinstance(item, (dict, list)) else str(item)
        )
        if text.strip():
            rendered.append(f"<li>{r.html.escape(text.strip())}</li>")
    if rendered:
        return f'<ul class="ir-report-list">{"".join(rendered)}</ul>'
    return f"<p>{r.html.escape(fallback)}</p>"


def incident_report_section(r: Any, title: str, body: str) -> str:
    return (
        '<section class="ir-report-subsection">'
        f"<h4>{r.html.escape(title)}</h4>"
        f'<div class="ir-report-subsection-body">{body}</div>'
        "</section>"
    )


def render_analyst_review_panel(
    r: Any, review: dict[str, object] | None, *, group_id: str, case_id: str = ""
) -> str:
    callbacks = r.ReviewPanelRenderCallbacks(
        html_text=r._incident_html_text,
        outcome_label=r.soc_alert_detection_outcome_label,
        review_defaults=r._soc_review_defaults,
    )
    return r.render_review_panel(
        review, group_id=group_id, case_id=case_id, callbacks=callbacks
    )


def render_investigation_query_audit_html(
    r: Any, response: dict[str, object], report: dict[str, object]
) -> tuple[str, int]:
    callbacks = r.InvestigationAuditRenderCallbacks(
        html_text=r._incident_html_text,
        nonnegative_int=r._incident_nonnegative_int,
        linked_finding=r._incident_query_linked_finding,
    )
    return r.render_investigation_query_audit(response, report, callbacks)


def render_incident_response_report_html(
    r: Any, case: dict[str, object], response: dict[str, object],
    analysis: dict[str, object], review: dict[str, object] | None = None,
) -> tuple[str, int]:
    callbacks = r.IncidentReportRenderCallbacks(
        html_text=r._incident_html_text,
        nonnegative_int=r._incident_nonnegative_int,
        linked_finding=r._incident_query_linked_finding,
        html_list=r._incident_html_list,
        report_section=r._incident_report_section,
        investigation_audit=r.render_investigation_query_audit_html,
        review_panel=r.render_analyst_review_panel,
    )
    return r.render_incident_response_report(
        case, response, analysis, review, callbacks
    )


def render_prior_soc_analysis_html(
    r: Any, response: dict[str, object], analysis: dict[str, object]
) -> str:
    text = r._incident_html_text
    section = r._incident_report_section
    html_list = r._incident_html_list
    sections = [
        section("BLUF", f"<p>{text(response.get('bluf') or analysis.get('bluf'))}</p>"),
        section("Assessment", f"<p>{text(response.get('summary') or analysis.get('summary'))}</p>"),
        section("Likely Meaning", f"<p>{text(response.get('likely_meaning'))}</p>"),
        section("Severity Reasoning", f"<p>{text(response.get('severity_reasoning'))}</p>"),
        section("Alert Frequency Assessment", f"<p>{text(response.get('alert_frequency_assessment'))}</p>"),
        section("Public Enrichment Findings", html_list(response.get("public_enrichment_findings"))),
        section("PCAP Analysis Findings", html_list(response.get("pcap_analysis_findings"))),
        section("False Positive Possibilities", html_list(response.get("false_positive_possibilities"))),
        section("Recommended Next Steps", html_list(response.get("recommended_next_steps"))),
        section("Evidence Used", html_list(response.get("evidence_used"))),
        section("Evidence Gaps", html_list(response.get("evidence_gaps"))),
        section("Recommended Tuning Actions", html_list(response.get("recommended_tuning_actions"))),
    ]
    return '<div class="ir-prior-analysis">' + "".join(sections) + "</div>"


def incident_read_service_sources(r: Any) -> Any:
    return r.IncidentReadServiceSources(
        connect=r.soc_alert_db_connect,
        api_error=r.soc_alert_api_error,
        parse_list_request=r.parse_incident_list_request,
        schema_ready=r.incident_schema_ready,
        empty_page=r.empty_incident_page,
        load_list_records=r.load_incident_list_records,
        load_inventory=r.load_asset_inventory_data,
        compose_list_rows=r.compose_incident_list_rows,
        load_detail_records=r.load_incident_detail_records,
        parse_analysis_response=r.parse_analysis_response,
        compose_review_state=r.compose_incident_review_state,
        review_defaults=r._soc_review_defaults,
        row_callbacks=r.INCIDENT_ROW_CALLBACKS,
        render_incident_report=r.render_incident_response_report_html,
        render_prior_analysis=r.render_prior_soc_analysis_html,
        compose_detail_payload=r.compose_incident_detail_payload,
    )


def soc_incident_detail_response(r: Any, case_id: str) -> tuple[int, dict]:
    return r.incident_detail_response(r.incident_read_service_sources(), case_id)
