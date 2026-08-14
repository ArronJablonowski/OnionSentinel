"""Core identity, summary, notes, and raw-log sections for alert reports."""
from __future__ import annotations

import json
import re

from dashboard_alert_detail_ai import complete_ai_response_json_markdown
from dashboard_alert_detail_values import markdown_cell, nested_object, row_value
from dashboard_time_format import normalize_iso_display_text


CRITICALITY_LABELS = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "informational": "Informational",
    "info": "Informational",
}


def severity_label_from_row(row: object) -> str:
    """Return deterministic triage severity with Security Onion fallback."""
    raw = str(row_value(row, "triage_level") or row_value(row, "severity_label") or "").strip().lower()
    if raw in CRITICALITY_LABELS:
        return CRITICALITY_LABELS[raw]
    severity = row_value(row, "severity")
    if severity == 1:
        return "Critical"
    if severity == 2:
        return "Medium"
    if severity == 3:
        return "Low"
    return "Informational"


def complete_alert_json_markdown(raw: dict) -> str:
    """Render the complete normalized alert object."""
    alert_json = json.dumps(raw or {}, indent=2, sort_keys=True)
    return "\n".join([
        "### Complete Alert JSON",
        "",
        "This block contains every alert field currently available to the dashboard from SQLite. Full-fidelity mode does not redact packet, payload, PCAP, or HTTP body fields.",
        "",
        "```json",
        alert_json,
        "```",
    ])


def raw_alert_markdown(raw: dict, fallback_json: str | None = None) -> str:
    """Render the raw alert with a stored JSON fallback."""
    alert_json = json.dumps(raw, indent=2, sort_keys=True) if raw else (fallback_json or "{}")
    return "\n".join(["### Raw Alert", "", "```json", alert_json, "```"])


def raw_logs_markdown(
    raw: dict,
    fallback_json: str | None = None,
    analysis: dict | None = None,
    legacy_sections: list[tuple[str, str]] | None = None,
) -> str:
    """Render complete raw evidence and safely relocated legacy sections."""
    sections = [complete_alert_json_markdown(raw), raw_alert_markdown(raw, fallback_json)]
    if legacy_sections:
        legacy_lines = [
            "### Legacy Source Content",
            "",
            "These sections came from an older report schema and were moved here so they cannot change the standard analyst layout.",
        ]
        for title, body in legacy_sections:
            legacy_lines.extend(["", f"#### {title}", "", body.strip() or "No content was recorded."])
        sections.insert(0, "\n".join(legacy_lines))
    ai_response_json = complete_ai_response_json_markdown(analysis)
    if ai_response_json:
        sections.append(ai_response_json)
    return "\n\n".join(["## Raw Logs", *sections]).strip()


def _summary_value(row: object, key: str, fallback: object) -> object:
    """Return one summary field with its established truthy fallback."""
    return row_value(row, key) or fallback


def _summary_nullable_value(row: object, key: str) -> object:
    """Preserve zero while retaining the legacy two-read non-None path."""
    return row_value(row, key) if row_value(row, key) is not None else "n/a"


def alert_summary_markdown(row: object) -> str:
    """Build the standard alert summary from authoritative group data."""
    return "\n".join([
        "## Alert Summary", "", "| Field | Value |", "| --- | --- |",
        f'| Rule name | {markdown_cell(_summary_value(row, "rule_name", "n/a"), 240)} |',
        f'| Event dataset | {markdown_cell(_summary_value(row, "event_dataset", "n/a"), 160)} |',
        f'| Severity | {markdown_cell(_summary_nullable_value(row, "severity"))} |',
        f'| Severity label | {markdown_cell(_summary_value(row, "severity_label", "n/a"))} |',
        f'| Triage level | {markdown_cell(_summary_value(row, "triage_level", "n/a"))} |',
        f'| First seen | {markdown_cell(normalize_iso_display_text(_summary_value(row, "first_seen", "n/a")))} |',
        f'| Last seen | {markdown_cell(normalize_iso_display_text(_summary_value(row, "last_seen", "n/a")))} |',
        f'| Seen count | {markdown_cell(_summary_nullable_value(row, "seen_count"))} |',
        f'| Grouped alert rows | {markdown_cell(row_value(row, "raw_alert_count", "n/a"))} |',
        f'| Source IP | {markdown_cell(_summary_value(row, "source_ip", "n/a"))} |',
        f'| Destination IP | {markdown_cell(_summary_value(row, "destination_ip", "n/a"))} |',
        f'| Destination port | {markdown_cell(_summary_value(row, "destination_port", "n/a"))} |',
        f'| Route | {markdown_cell(_summary_value(row, "routing", "n/a"))} |',
        f'| Filter status | {markdown_cell(_summary_value(row, "filter_status", "accepted"))} |',
    ])


def _identity_generated(row: object, source_text: str) -> object:
    """Resolve identity-card generation time from source text or group state."""
    generated_match = re.search(
        r"^(?:generated_at:\s*|[-*]\s+\*\*Generated:\*\*\s*)([^\n]+)",
        source_text or "",
        flags=re.IGNORECASE | re.MULTILINE,
    )
    return generated_match.group(1).strip().strip("\"'") if generated_match else (
        row_value(row, "timestamp") or row_value(row, "last_seen") or "n/a"
    )


def _identity_endpoints(row: object) -> tuple[str, str]:
    """Project source and destination after reading their paired fields."""
    source_ip = row_value(row, "source_ip") or "n/a"
    source_port = row_value(row, "source_port")
    destination_ip = row_value(row, "destination_ip") or "n/a"
    destination_port = row_value(row, "destination_port")
    source_endpoint = f"{source_ip}:{source_port}" if source_port not in (None, "", "n/a") else str(source_ip)
    destination_endpoint = f"{destination_ip}:{destination_port}" if destination_port not in (None, "", "n/a") else str(destination_ip)
    return source_endpoint, destination_endpoint


def alert_identity_markdown(row: object, source_text: str = "") -> str:
    """Generate the fixed identity card from authoritative group state."""
    generated = _identity_generated(row, source_text)
    source_endpoint, destination_endpoint = _identity_endpoints(row)
    status = row_value(row, "filter_status") or "accepted"
    return "\n".join([
        f'# [{severity_label_from_row(row).upper()}] {row_value(row, "rule_name") or "Security Onion Alert"}', "",
        f"- **Generated:** {normalize_iso_display_text(generated)}",
        f'- **Alert ID:** {row_value(row, "alert_id") or "n/a"}',
        f"- **Workflow status:** {status}", f"- **Filter status:** {status}",
        f'- **Route:** {row_value(row, "routing") or "n/a"}',
        f'- **Score:** {row_value(row, "triage_score", "n/a")}',
        f'- **Direction:** {row_value(row, "traffic_direction") or "unknown"}',
        f"- **Traffic:** {source_endpoint} -> {destination_endpoint}",
    ])


def triage_reasons_markdown(raw: dict, source_sections: dict[str, str]) -> str:
    """Use legacy triage text when present, otherwise render normalized reasons."""
    existing = source_sections.get("triage reasons")
    if existing:
        return existing
    triage = nested_object(raw, "triage")
    reasons = triage.get("reasons") if isinstance(triage, dict) and isinstance(triage.get("reasons"), list) else []
    if not reasons and isinstance(raw.get("triage_reasons"), list):
        reasons = raw.get("triage_reasons")
    cleaned = list(dict.fromkeys(str(reason).strip() for reason in reasons if str(reason).strip()))
    if not cleaned:
        cleaned = ["No scoring reasons were recorded for this alert."]
    return "\n".join(["## Triage Reasons", "", *(f"- [ ] {reason}" for reason in cleaned)])


def analyst_notes_markdown(source_sections: dict[str, str]) -> str:
    """Use recorded analyst notes or provide the standard investigation checklist."""
    existing = source_sections.get("analyst notes")
    if existing:
        return existing
    return "\n".join([
        "## Analyst Notes", "",
        "- [ ] Confirm whether the source and destination are expected for this asset or VLAN.",
        "- [ ] Record the investigation outcome, tuning decision, or escalation rationale.",
    ])
