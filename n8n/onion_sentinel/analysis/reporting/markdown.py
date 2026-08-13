"""Pure composition of the complete SOC and Incident Response Markdown report."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

from . import incident


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _review_context(response: dict[str, Any]) -> dict[str, Any]:
    second = _mapping(response.get("_second_opinion"))
    secondary = _mapping(second.get("response"))
    comparison = _mapping(second.get("comparison"))
    authorization = _mapping(second.get("automation_authorization"))
    adjudication = _mapping(response.get("_disagreement_adjudication"))
    adjudication_response = _mapping(adjudication.get("response"))
    disputed = [
        (
            f"{item.get('field', 'unknown')}: primary={item.get('primary', 'n/a')!s}; "
            f"reviewer={item.get('reviewer', 'n/a')!s}"
            + (" (material)" if item.get("material") else "")
        )
        for item in comparison.get("disputed_fields", [])
        if isinstance(item, dict)
    ]
    return {
        "second": second,
        "secondary": secondary,
        "comparison": comparison,
        "authorization": authorization,
        "adjudication": adjudication,
        "adjudication_response": adjudication_response,
        "disputed": disputed,
    }


def _context(
    prompt_package: dict[str, Any],
    response: dict[str, Any],
    generated_at: str,
    json_path: Path,
    *,
    normalize_correlation: Callable[[Any], dict[str, Any]],
    safe_filename: Callable[[Any], str],
) -> dict[str, Any]:
    alert = prompt_package.get("alert", {})
    grouped = _mapping(prompt_package.get("grouped_alert_context"))
    correlation = normalize_correlation(response.get("correlation_assessment"))
    review = _review_context(response)
    model_path = str(response.get("_analysis_model_path") or "")
    input_mode = str(response.get("_analysis_input_mode") or "")
    return {
        "alert": alert,
        "policy": prompt_package.get("analysis_policy", {}),
        "alert_id": alert.get("alert_id", ""),
        "rule_name": alert.get("rule_name", "Security Onion Alert"),
        "level": str(alert.get("triage_level", "unknown")).lower(),
        "score": alert.get("triage_score", ""),
        "source_ip": alert.get("source_ip", ""),
        "destination_ip": alert.get("destination_ip", ""),
        "total_observations": grouped.get(
            "total_observations", alert.get("seen_count", "")
        ),
        "raw_alert_rows": grouped.get("raw_alert_rows", 1),
        "first_seen": grouped.get("first_seen", alert.get("first_seen", "")),
        "last_seen": grouped.get("last_seen", alert.get("last_seen", "")),
        "correlation": correlation,
        **review,
        "input_mode": input_mode,
        "model_path": model_path,
        "model": str(response.get("_analysis_model") or ""),
        "analysis_tag": safe_filename(model_path or input_mode or "no-model-started"),
        "generated_at": generated_at,
        "json_name": json_path.name,
    }


def _header(context: dict[str, Any]) -> list[str]:
    return [
        "---",
        "type: soc-ai-analysis",
        f"analysis_input_mode: {json.dumps(context['input_mode'])}",
        f"analysis_model_path: {json.dumps(context['model_path'])}",
        f"analysis_model: {json.dumps(context['model'])}",
        f"generated_at: {json.dumps(context['generated_at'])}",
        f"alert_id: {json.dumps(context['alert_id'])}",
        f"triage_level: {json.dumps(context['level'])}",
        f"triage_score: {json.dumps(context['score'])}",
        f"source_ip: {json.dumps(context['source_ip'])}",
        f"destination_ip: {json.dumps(context['destination_ip'])}",
        "tags:",
        "  - security-onion",
        "  - soc-ai-analysis",
        f"  - {context['analysis_tag']}",
        "---",
        "",
        f"# Local AI Analysis - {context['rule_name']}",
        "",
        f"- **Generated:** {context['generated_at']}",
        f"- **Alert ID:** {context['alert_id']}",
        f"- **Triage:** {context['level']} / {context['score']}",
        f"- **Traffic:** {context['source_ip']} -> {context['destination_ip']}",
        f"- **Grouped observations:** {context['total_observations']} observation(s) across {context['raw_alert_rows']} alert row(s)",
        f"- **Grouped first/last seen:** {context['first_seen']} -> {context['last_seen']}",
        f"- **Hosted second opinion allowed:** {context['policy'].get('hosted_second_opinion_allowed')}",
        f"- **Machine JSON:** `{context['json_name']}`",
        "",
    ]


def _correlation_lines(correlation: dict[str, Any]) -> list[str]:
    groups = [
        f"{item['group_id']}: {item['reason'] or 'relationship requires analyst validation'}"
        for item in correlation["related_groups"]
    ]
    return [
        "## Correlation Assessment",
        "",
        f"- **Correlation found:** {correlation['correlation_found']}",
        f"- **Confidence:** {correlation['confidence']}",
        f"- **Attack-chain hypothesis:** {correlation['attack_chain_hypothesis'] or 'n/a'}",
        "",
        "### Related Alert Groups",
        "",
        incident.markdown_list(groups),
        "",
        "### Shared Evidence",
        "",
        incident.markdown_list(correlation["shared_evidence"]),
        "",
        "### Contradicting Evidence",
        "",
        incident.markdown_list(correlation["contradicting_evidence"]),
        "",
        "### Recommended Correlation Pivots",
        "",
        incident.markdown_list(correlation["recommended_pivots"]),
        "",
    ]


def _primary_lines(response: dict[str, Any]) -> list[str]:
    lines = [
        "## BLUF", "", f"- **Detection outcome:** {response['detection_outcome']}",
        f"- **Bottom line:** {response['bluf']}", "", "## Summary", "",
        response["summary"], "", "## Likely Meaning", "", response["likely_meaning"],
        "", "## Severity Reasoning", "", response["severity_reasoning"], "",
        "## Alert Frequency Assessment", "", response["alert_frequency_assessment"], "",
    ]
    lines.extend(_correlation_lines(response["_render_correlation"]))
    for title, key in (
        ("Public Enrichment Findings", "public_enrichment_findings"),
        ("PCAP Analysis Findings", "pcap_analysis_findings"),
        ("False Positive Possibilities", "false_positive_possibilities"),
        ("Recommended Next Steps", "recommended_next_steps"),
        ("Evidence Used", "evidence_used"),
        ("Evidence Gaps", "evidence_gaps"),
    ):
        lines.extend([f"## {title}", "", incident.markdown_list(response[key]), ""])
    lines.extend(
        [
            "## Tuning Recommendation", "",
            f"- **Recommendation:** {response['tuning_recommendation']}",
            f"- **Reason:** {response['tuning_reason']}", "",
            "### Recommended Tuning Actions", "",
            incident.markdown_list(response["recommended_tuning_actions"]), "",
            "## Escalation", "", f"- **Confidence:** {response['confidence']}",
            f"- **Escalation needed:** {response['escalation_needed']}",
            f"- **Hosted second opinion recommended:** {response['hosted_second_opinion_recommended']}",
            "",
        ]
    )
    return lines


def _review_lines(context: dict[str, Any]) -> list[str]:
    second = context["second"]
    secondary = context["secondary"]
    comparison = context["comparison"]
    authorization = context["authorization"]
    adjudication = context["adjudication"]
    adjudicated = context["adjudication_response"]
    return [
        "## Second Opinion", "",
        f"- **Status:** {second.get('status', 'not requested')}",
        f"- **Trigger:** {second.get('trigger', 'n/a')}",
        f"- **Model route:** {second.get('model_route', 'n/a') or 'n/a'}",
        f"- **Runtime:** {second.get('runtime_seconds', 'n/a')} second(s)",
        f"- **Agreement:** {comparison.get('agreement', 'n/a')}",
        f"- **Comparison:** {comparison.get('summary', 'n/a')}",
        f"- **Automation authorized by review:** {authorization.get('authorized', 'n/a')}",
        f"- **Automation authorization reason:** {authorization.get('reason', 'n/a')}",
        f"- **Detection outcome:** {secondary.get('detection_outcome', 'n/a')}",
        f"- **Confidence:** {secondary.get('confidence', 'n/a')}",
        f"- **BLUF:** {secondary.get('bluf', 'n/a')}",
        f"- **Summary:** {secondary.get('summary', second.get('error', 'n/a'))}",
        "", "### Disputed Fields", "", incident.markdown_list(context["disputed"]), "",
        "## Bounded Disagreement Adjudication", "",
        f"- **Status:** {adjudication.get('status', 'not required')}",
        f"- **Mode:** {adjudication.get('mode', 'shadow')}",
        f"- **Model route:** {adjudication.get('model_route', 'n/a') or 'n/a'}",
        f"- **Runtime:** {adjudication.get('runtime_seconds', 'n/a')} second(s)",
        f"- **Decision:** {adjudicated.get('decision', adjudication.get('decision', 'n/a'))}",
        f"- **Confidence:** {adjudicated.get('confidence', 'n/a')}",
        f"- **Confidence score:** {adjudicated.get('confidence_score', 'n/a')}",
        f"- **Rationale:** {adjudicated.get('rationale', adjudication.get('error', 'n/a'))}",
        f"- **Automation authorized:** {adjudication.get('automation_authorized', False)}",
        f"- **Human adjudication required:** {adjudication.get('human_adjudication_required', True)}",
        "", "### Remaining Disagreements", "",
        incident.markdown_list(adjudicated.get("remaining_disagreements", [])), "",
        "### Additional Evidence Needed", "",
        incident.markdown_list(adjudicated.get("additional_evidence_needed", [])), "",
    ]


def render(
    prompt_package: dict[str, Any],
    response: dict[str, Any],
    generated_at: str,
    json_path: Path,
    *,
    normalize_correlation: Callable[[Any], dict[str, Any]],
    safe_filename: Callable[[Any], str],
    bounded_text_list: Callable[[Any], list[str]],
) -> str:
    """Render one deterministic report without performing I/O."""
    context = _context(
        prompt_package,
        response,
        generated_at,
        json_path,
        normalize_correlation=normalize_correlation,
        safe_filename=safe_filename,
    )
    lines = _header(context)
    lines.extend(
        incident.render_incident_response(
            response,
            bounded_text_list=bounded_text_list,
        )
    )
    lines.extend(incident.render_security_onion_query_audit(response))
    lines.extend(incident.render_appliance_osquery_audit(response))
    lines.extend(incident.render_live_osquery_audit(response))
    rendering_response = dict(response)
    rendering_response["_render_correlation"] = context["correlation"]
    lines.extend(_primary_lines(rendering_response))
    lines.extend(_review_lines(context))
    return "\n".join(lines)
