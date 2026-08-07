"""Canonical pure composer for detailed alert report Markdown."""
from __future__ import annotations

from dashboard_alert_detail_ai import ai_analysis_output_markdown, ai_model_used_markdown
from dashboard_alert_detail_enrichment import public_enrichment_markdown
from dashboard_alert_detail_evidence import standard_alert_detail_sections
from dashboard_alert_detail_layout import (
    DETAIL_REPORT_SECTION_ORDER,
    DETAIL_REPORT_SOURCE_ALIASES,
    DetailLayoutResult,
    normalized_heading_text,
    split_detail_source_sections,
)
from dashboard_alert_detail_sections import (
    alert_identity_markdown,
    alert_summary_markdown,
    analyst_notes_markdown,
    raw_logs_markdown,
    triage_reasons_markdown,
)
from dashboard_alert_detail_values import row_value


EMPTY_ENRICHMENT = "\n".join([
    "## Enriched Alert Details",
    "",
    "No public enrichment records were stored for this alert group.",
])
EMPTY_PCAP = "\n".join([
    "## Parsed PCAP Evidence",
    "",
    "No parsed Zeek/TShark PCAP summary is available for this alert group yet.",
])


def analysis_sections(
    ai_analysis: dict | None,
    source_sections: dict[str, str],
) -> tuple[str, str]:
    """Prefer current analysis, falling back to legacy sections when absent."""
    ai_output = ai_analysis_output_markdown(ai_analysis)
    ai_model = ai_model_used_markdown(ai_analysis)
    if not ai_analysis and source_sections.get("ai analysis output"):
        ai_output = source_sections["ai analysis output"]
    if not ai_analysis and source_sections.get("ai model used"):
        ai_model = source_sections["ai model used"]
    return ai_output, ai_model


def generated_section_order(markdown: str) -> tuple[str, ...]:
    """Return normalized H2 section order from generated Markdown."""
    actual: list[str] = []
    for line in markdown.splitlines():
        heading = normalized_heading_text(line)
        if heading and heading[0] == 2:
            actual.append(DETAIL_REPORT_SOURCE_ALIASES.get(heading[1], heading[1]))
    return tuple(actual)


def canonical_detail_report_markdown(
    source_text: str,
    row: object,
    raw: dict,
    ai_analysis: dict | None,
    pcap_details: str,
) -> DetailLayoutResult:
    """Compose every report from the versioned layout contract in one pass."""
    source_sections, legacy_sections, issues = split_detail_source_sections(source_text)
    ai_output, ai_model = analysis_sections(ai_analysis, source_sections)
    sections = {
        "triage reasons": triage_reasons_markdown(raw, source_sections),
        "ai analysis output": ai_output,
        "ai model used": ai_model,
        "enriched alert details": public_enrichment_markdown(
            raw,
            row_value(row, "enrichment_json"),
        ) or EMPTY_ENRICHMENT,
        "alert summary": alert_summary_markdown(row),
        "analyst notes": analyst_notes_markdown(source_sections),
        "parsed pcap evidence": pcap_details or EMPTY_PCAP,
        **standard_alert_detail_sections(raw),
        "raw logs": raw_logs_markdown(
            raw,
            row_value(row, "alert_json"),
            ai_analysis,
            legacy_sections=legacy_sections,
        ),
    }
    markdown = "\n\n".join([
        alert_identity_markdown(row, source_text),
        *(sections[title] for title in DETAIL_REPORT_SECTION_ORDER),
    ]).strip()
    actual_order = generated_section_order(markdown)
    if actual_order != DETAIL_REPORT_SECTION_ORDER:
        issues.append(
            "The generated section sequence did not match the canonical contract: "
            + ", ".join(actual_order or ("no H2 sections found",))
        )
    return DetailLayoutResult(markdown=markdown, issues=tuple(dict.fromkeys(issues)))
