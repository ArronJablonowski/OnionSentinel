"""Transform normalized alert rows into dashboard report view models."""
from __future__ import annotations

import datetime as dt
import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from dashboard_alert_detail_composer import canonical_detail_report_markdown
from dashboard_alert_detail_enrichment import public_enrichment_status
from dashboard_alert_detail_markdown import markdown_to_html
from dashboard_alert_detail_sections import severity_label_from_row
from dashboard_alert_detail_values import nested_value
from dashboard_alert_report_model import AlertReport, CRITICALITY_ORDER
from dashboard_alert_repository import alert_group_key, raw_alert_object, row_item, safe_int
from dashboard_pcap_components import render_pcap_evidence_markdown
from dashboard_time_format import normalize_iso_display_text, parse_iso_timestamp
from dashboard_timeline_components import alert_seen_timeline_html


StatusTuple = tuple[str, str, str]


@dataclass(frozen=True)
class AlertReportFactoryConfig:
    """Filesystem locations needed only to label attached report sources."""

    database_path: Path
    markdown_sources: tuple[Path, ...]


@dataclass(frozen=True)
class AlertReportFactoryServices:
    """Stateful status services kept outside the pure report transformation."""

    ai_analysis_for_row: Callable[[object, dict[str, dict]], dict | None]
    ai_workflow_status_for_row: Callable[
        [object, dict[str, dict], dict[str, dict], set[str], str], StatusTuple
    ]
    pcap_status_for_row: Callable[[object, dict[str, object] | None], StatusTuple]
    pcap_analysis_for_row: Callable[[object, dict[str, object] | None], dict | None]
    finalize_detail_report_html: Callable[[str, str, tuple[str, ...]], str]


@dataclass(frozen=True)
class ReportWorkflowEvidence:
    """Normalized AI, enrichment, and PCAP state for one report."""

    ai_analysis: dict | None
    ai_response: dict
    ai_status: StatusTuple
    enrichment_status: tuple[str, str, str, int, int, int]
    pcap_status: StatusTuple
    pcap_details: str


@dataclass(frozen=True)
class ReportNetworkIdentity:
    """Normalized network and detector identifiers for one alert."""

    source_ip: str
    source_port: str
    destination_ip: str
    destination_port: str
    alert_source: str
    rule_id: str


def first_value(*values: object, fallback: object = "") -> object:
    """Return the first non-empty value without truthy numeric coercion."""
    for value in values:
        if value not in (None, ""):
            return value
    return fallback


def clean_endpoint_part(value: object | None) -> str:
    """Normalize one report-facing endpoint value without inventing data."""
    normalized = str(value or "").strip().strip("\"'")
    return normalized or "—"


def endpoint_label(ip: str | None, port: str | None) -> str:
    """Render an endpoint with an explicit missing-port marker."""
    ip_label = clean_endpoint_part(ip)
    port_label = clean_endpoint_part(port)
    if ip_label != "—" and port_label != "—":
        return f"{ip_label}:{port_label}"
    if ip_label != "—":
        return f"{ip_label}:—"
    return "—"


def summarize_markdown(text: str, max_len: int = 220) -> str:
    """Return bounded prose from Markdown while excluding headings and code."""
    lines: list[str] = []
    in_code = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("```"):
            in_code = not in_code
            continue
        if in_code or not line or line.startswith("#") or re.match(r"^[-*_]{3,}$", line):
            continue
        line = re.sub(r"[`*_>#\[\]()]+", " ", line)
        line = normalize_iso_display_text(re.sub(r"\s+", " ", line).strip())
        if line:
            lines.append(line)
        if sum(len(item) for item in lines) > max_len:
            break
    summary = normalize_iso_display_text(" ".join(lines).strip())
    if len(summary) > max_len:
        return summary[: max_len - 1] + "…"
    return summary or "No summary text available yet."


def source_attachment(
    row: object,
    attachment: tuple[Path, str, object] | None,
    config: AlertReportFactoryConfig,
) -> tuple[Path, str, str, int]:
    """Resolve attached Markdown metadata or the SQLite fallback source."""
    if attachment is None:
        alert_json = str(row_item(row, "alert_json") or "")
        return config.database_path, "SQLite alert-store", "", len(alert_json)
    source, source_text, stat = attachment
    rel_source = source.name
    for source_dir in config.markdown_sources:
        if source_dir in source.parents or source == source_dir:
            rel_source = str(source.relative_to(source_dir))
            break
    return source, rel_source, source_text, int(getattr(stat, "st_size"))


def tuning_actions(ai_response: dict) -> list[str]:
    """Normalize the optional tuning action list without coercing other shapes."""
    raw_actions = ai_response.get("recommended_tuning_actions")
    if not isinstance(raw_actions, list):
        return []
    return [str(action).strip() for action in raw_actions if str(action).strip()]


def workflow_evidence(
    row: object,
    ai_analysis_by_alert_id: dict[str, dict],
    ai_prompts_by_alert_id: dict[str, dict],
    running_ai_alert_ids: set[str],
    pcap_index: dict[str, object] | None,
    ai_analysis_min_severity: str,
    services: AlertReportFactoryServices,
) -> ReportWorkflowEvidence:
    """Resolve all stateful workflow evidence through injected services."""
    analysis = services.ai_analysis_for_row(row, ai_analysis_by_alert_id)
    response = analysis.get("response") if isinstance(analysis, dict) else None
    ai_response = response if isinstance(response, dict) else {}
    ai_status = services.ai_workflow_status_for_row(
        row, ai_analysis_by_alert_id, ai_prompts_by_alert_id,
        running_ai_alert_ids, ai_analysis_min_severity,
    )
    enrichment_status = public_enrichment_status(row_item(row, "enrichment_json"))
    pcap_status = services.pcap_status_for_row(row, pcap_index)
    pcap_analysis = services.pcap_analysis_for_row(row, pcap_index)
    generated_at = (pcap_analysis or {}).get("generated_at") or ""
    pcap_details = render_pcap_evidence_markdown(
        pcap_status, pcap_analysis, normalize_iso_display_text(generated_at),
    )
    return ReportWorkflowEvidence(
        analysis, ai_response, ai_status, enrichment_status, pcap_status, pcap_details,
    )


def network_identity(row: object, raw: dict) -> ReportNetworkIdentity:
    """Resolve normalized network fields from columns before preserved JSON."""
    source_ip = clean_endpoint_part(first_value(row_item(row, "source_ip"), nested_value(raw, "source", "ip")))
    source_port = clean_endpoint_part(first_value(row_item(row, "source_port"), nested_value(raw, "source", "port")))
    destination_ip = clean_endpoint_part(first_value(row_item(row, "destination_ip"), nested_value(raw, "destination", "ip")))
    destination_port = clean_endpoint_part(first_value(row_item(row, "destination_port"), nested_value(raw, "destination", "port")))
    alert_source = clean_endpoint_part(first_value(
        row_item(row, "event_dataset"),
        nested_value(raw, "event", "dataset"),
        nested_value(raw, "security_onion", "event_dataset"),
    ))
    return ReportNetworkIdentity(
        source_ip, source_port, destination_ip, destination_port,
        alert_source, clean_endpoint_part(nested_value(raw, "rule_id")),
    )


def report_timestamp(row: object) -> float:
    """Use the newest stored event timestamp or an explicit build-time fallback."""
    for value in (row_item(row, "last_seen"), row_item(row, "timestamp")):
        parsed = parse_iso_timestamp(value)  # type: ignore[arg-type]
        if parsed is not None:
            return parsed
    return dt.datetime.now(dt.timezone.utc).timestamp()


def report_group_key(row: object) -> object:
    """Prefer the repository's materialized group key before recomputing it."""
    materialized = row_item(row, "alert_group_key")
    return materialized if materialized else alert_group_key(row)


def report_detail_html(
    source_text: str,
    row: object,
    raw: dict,
    ai_analysis: dict | None,
    pcap_details: str,
    repeat_count: int,
    services: AlertReportFactoryServices,
) -> tuple[str, str]:
    """Compose canonical Markdown and validated detail HTML."""
    layout_row = dict(row)  # type: ignore[arg-type]
    layout_row.update({
        "first_seen": row_item(row, "first_seen") or "n/a",
        "last_seen": row_item(row, "last_seen") or "n/a",
        "seen_count": repeat_count,
        "raw_alert_count": safe_int(row_item(row, "raw_alert_count")),
    })
    layout = canonical_detail_report_markdown(source_text, layout_row, raw, ai_analysis, pcap_details)
    text = normalize_iso_display_text(layout.markdown)
    rendered = markdown_to_html(text)
    timeline = alert_seen_timeline_html(row)
    return text, services.finalize_detail_report_html(rendered, timeline, layout.issues)


def build_alert_report(
    row: object,
    markdown_by_alert_id: dict[str, tuple[Path, str, object]],
    ai_analysis_by_alert_id: dict[str, dict],
    ai_prompts_by_alert_id: dict[str, dict],
    running_ai_alert_ids: set[str],
    pcap_index: dict[str, object] | None,
    ai_analysis_min_severity: str,
    config: AlertReportFactoryConfig,
    services: AlertReportFactoryServices,
) -> AlertReport:
    """Build one complete UI report from a normalized repository row."""
    raw = raw_alert_object(row)
    raw_alert_count = safe_int(row_item(row, "raw_alert_count"))
    total_seen_count = safe_int(row_item(row, "total_seen_count"))
    repeat_count = max(raw_alert_count, total_seen_count, safe_int(row_item(row, "seen_count")))
    alert_group = report_group_key(row)
    alert_id = str(first_value(row_item(row, "alert_id")))
    workflow = workflow_evidence(
        row, ai_analysis_by_alert_id, ai_prompts_by_alert_id, running_ai_alert_ids,
        pcap_index, ai_analysis_min_severity, services,
    )
    source, rel_source, source_text, size = source_attachment(
        row, markdown_by_alert_id.get(alert_id), config,
    )
    text, rendered_html = report_detail_html(
        source_text, row, raw, workflow.ai_analysis, workflow.pcap_details,
        repeat_count, services,
    )
    criticality = severity_label_from_row(row)
    status = str(first_value(row_item(row, "filter_status"), fallback="stored"))
    reason = str(first_value(row_item(row, "filter_reason"), fallback="no filter reason recorded"))
    network = network_identity(row, raw)
    alert_ts = report_timestamp(row)
    stored_rule_name = row_item(row, "rule_name")
    display_rule_name = str(first_value(stored_rule_name, fallback="Security Onion Alert"))
    title = f"[{criticality.upper()}] {display_rule_name}"
    report_rule_name = str(first_value(stored_rule_name, fallback=title))
    ai_status = workflow.ai_status
    enrichment_status = workflow.enrichment_status
    pcap_status = workflow.pcap_status
    return AlertReport(
        title=title, source=source, rel_source=rel_source, mtime=alert_ts, size=size,
        digest=hashlib.sha1(str(alert_group).encode("utf-8")).hexdigest()[:12],
        rendered_html=rendered_html,
        summary=f"{status}: {reason}. Seen {repeat_count} time(s). {summarize_markdown(text, 160)}",
        criticality=criticality,
        criticality_rank=CRITICALITY_ORDER.get(criticality.lower(), CRITICALITY_ORDER["informational"]),
        alert_source=network.alert_source or "n/a",
        filter_status=str(first_value(row_item(row, "filter_status"), fallback="accepted")),
        source_ip=network.source_ip, source_port=network.source_port,
        destination_ip=network.destination_ip, destination_port=network.destination_port,
        source_endpoint=endpoint_label(network.source_ip, network.source_port),
        destination_endpoint=endpoint_label(network.destination_ip, network.destination_port),
        rule_id=network.rule_id, rule_name=report_rule_name, raw_alert_count=raw_alert_count,
        total_seen_count=total_seen_count, repeat_count=repeat_count,
        first_seen=str(row_item(row, "first_seen") or "n/a"),
        last_seen=str(row_item(row, "last_seen") or "n/a"), alert_group_key=str(alert_group),
        alert_ts=alert_ts, ai_status_key=ai_status[0], ai_status_label=ai_status[1],
        ai_status_detail=ai_status[2], enrichment_status_key=enrichment_status[0],
        enrichment_status_label=enrichment_status[1], enrichment_status_detail=enrichment_status[2],
        enrichment_record_count=enrichment_status[3], enrichment_skip_count=enrichment_status[4],
        enrichment_error_count=enrichment_status[5], pcap_status_key=pcap_status[0],
        pcap_status_label=pcap_status[1], pcap_status_detail=pcap_status[2],
        tuning_recommendation=str(workflow.ai_response.get("tuning_recommendation") or "none").strip().lower(),
        tuning_reason=str(workflow.ai_response.get("tuning_reason") or "").strip(),
        recommended_tuning_actions=tuning_actions(workflow.ai_response),
        ai_analysis=workflow.ai_analysis if isinstance(workflow.ai_analysis, dict) else {},
    )
