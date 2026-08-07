"""Pure AI analysis report sections for detailed alert reports."""
from __future__ import annotations

import json

from dashboard_alert_detail_values import markdown_cell
from dashboard_time_format import normalize_iso_display_text


def truthy_or(value: object, fallback: object) -> object:
    """Match the existing report policy of replacing falsey display values."""
    return value if value else fallback


def dict_object(parent: dict, key: str) -> dict:
    """Return one nested dictionary or an empty object."""
    value = parent.get(key)
    return value if isinstance(value, dict) else {}


def field(parent: dict, key: str, fallback: object = "n/a") -> object:
    """Return a report field using the established falsey-value fallback."""
    return truthy_or(parent.get(key), fallback)


def explicit_field(parent: dict, key: str) -> object:
    """Distinguish a present false value from a missing report field."""
    return parent[key] if key in parent else "n/a"


def markdown_bullets(value: object) -> str:
    """Render a scalar or list as a non-empty Markdown bullet list."""
    if isinstance(value, list):
        items = [str(item).strip() for item in value if str(item).strip()]
        return "\n".join(f"- {item}" for item in items) if items else "- n/a"
    if value in (None, "", [], {}):
        return "- n/a"
    return f"- {value}"


def related_group_lines(correlation: dict) -> list[str]:
    """Normalize structured and legacy related-group values."""
    raw_groups = correlation.get("related_groups")
    groups = raw_groups if isinstance(raw_groups, list) else []
    related: list[str] = []
    for item in groups:
        if isinstance(item, dict):
            group_id = str(item.get("group_id") or "").strip()
            reason = str(item.get("reason") or "").strip()
        else:
            group_id = str(item or "").strip()
            reason = ""
        if group_id:
            related.append(f"{group_id}: {reason or 'relationship requires analyst validation'}")
    return related


def ai_model_used_markdown(analysis: dict | None) -> str:
    """Render model provenance for one completed or pending analysis."""
    if not analysis:
        return "\n".join([
            "## AI Model Used",
            "",
            "| Field | Value |",
            "| --- | --- |",
            "| Analysis status | Not analyzed yet |",
            "| Model path | n/a |",
            "| Model | n/a |",
        ])

    response = dict_object(analysis, "response")
    model = truthy_or(response.get("_analysis_model"), truthy_or(analysis.get("analysis_model"), "unknown"))
    analysis_type = str(truthy_or(analysis.get("analysis_type"), "")).strip().lower()
    model_path_labels = {
        "local-ai": "Ollama local",
        "ollama": "Ollama local",
        "frontier-cloud": "Frontier cloud CLI",
        "hybrid": "Hybrid local + cloud",
        "hybrid-local-only": "Hybrid local-only",
    }
    model_path = model_path_labels.get(analysis_type, field(analysis, "analysis_type", "unknown"))
    generated_at = normalize_iso_display_text(field(analysis, "generated_at", "unknown"))
    return "\n".join([
        "## AI Model Used",
        "",
        "| Field | Value |",
        "| --- | --- |",
        "| Analysis status | Complete |",
        f"| Model path | {markdown_cell(model_path)} |",
        f"| Model | {markdown_cell(model)} |",
        f"| Generated at | {markdown_cell(generated_at)} |",
        f"| Analysis artifact | {markdown_cell(field(analysis, '_analysis_filename'))} |",
        f"| Prompt package | {markdown_cell(field(analysis, 'prompt_package'))} |",
        f"| Artifact path | {markdown_cell(field(analysis, '_analysis_path'), 700)} |",
    ])


def ai_analysis_output_markdown(analysis: dict | None) -> str:
    """Render the analyst-facing AI narrative without changing its schema."""
    if not analysis:
        return "\n".join([
            "## AI Analysis Output",
            "",
            "**Generated:** n/a",
            "",
            "No AI analysis artifact was found for this alert yet.",
        ])

    response = dict_object(analysis, "response")
    correlation = dict_object(response, "correlation_assessment")
    generated_at = normalize_iso_display_text(field(analysis, "generated_at", "unknown"))
    lines = [
        "## AI Analysis Output", "", f"**Generated:** {generated_at}", "",
        "### BLUF", "", f"**Detection outcome:** {field(response, 'detection_outcome', 'Inconclusive')}", "",
        str(field(response, "bluf", "Inconclusive - Needs More Data: No BLUF classification was found in this analysis artifact.")), "",
        "### Assessment", "", str(field(response, "summary")), "",
        "### Likely Meaning", "", str(field(response, "likely_meaning")), "",
        "### Severity", "", str(field(response, "severity_reasoning")), "",
        "### Frequency", "", str(field(response, "alert_frequency_assessment")), "",
        "### Correlation Assessment", "",
        f"- **Correlation found:** {explicit_field(correlation, 'correlation_found')}",
        f"- **Confidence:** {field(correlation, 'confidence')}",
        f"- **Attack-chain hypothesis:** {field(correlation, 'attack_chain_hypothesis')}", "",
        "#### Related Alert Groups", "", markdown_bullets(related_group_lines(correlation)), "",
        "#### Shared Evidence", "", markdown_bullets(correlation.get("shared_evidence")), "",
        "#### Contradicting Evidence", "", markdown_bullets(correlation.get("contradicting_evidence")), "",
        "#### Recommended Correlation Pivots", "", markdown_bullets(correlation.get("recommended_pivots")), "",
        "### Public Enrichment Findings", "", markdown_bullets(response.get("public_enrichment_findings")), "",
        "### PCAP Findings", "", markdown_bullets(response.get("pcap_analysis_findings")), "",
        "### False Positive Checks", "", markdown_bullets(response.get("false_positive_possibilities")), "",
        "### Next Steps", "", markdown_bullets(response.get("recommended_next_steps")), "",
        "### Evidence Used", "", markdown_bullets(response.get("evidence_used")), "",
        "### Evidence Gaps", "", markdown_bullets(response.get("evidence_gaps")), "",
        "### SIEM Tuning", "",
        f"- **Recommendation:** {field(response, 'tuning_recommendation')}",
        f"- **Reason:** {field(response, 'tuning_reason')}", "",
        "#### Recommended Tuning Actions", "", markdown_bullets(response.get("recommended_tuning_actions")), "",
        "### Escalation", "",
        f"- **Confidence:** {field(response, 'confidence')}",
        f"- **Escalation needed:** {explicit_field(response, 'escalation_needed')}",
        f"- **Hosted second opinion recommended:** {explicit_field(response, 'hosted_second_opinion_recommended')}",
    ]
    return "\n".join(lines)


def ai_analysis_report_markdown(analysis: dict | None) -> str:
    """Render AI output followed by model provenance."""
    return "\n\n".join([
        ai_analysis_output_markdown(analysis),
        ai_model_used_markdown(analysis),
    ])


def complete_ai_response_json_markdown(analysis: dict | None) -> str:
    """Render the complete structured response for the Raw Logs section."""
    if not analysis:
        return ""
    response = dict_object(analysis, "response")
    if not response:
        return ""
    output_json = json.dumps(response, indent=2, sort_keys=True)
    return "\n".join([
        "### Complete AI Response JSON",
        "",
        "```json",
        output_json,
        "```",
    ])
