"""Versioned layout contract and legacy-section normalization for alert details."""
from __future__ import annotations

import re
from dataclasses import dataclass


DETAIL_REPORT_LAYOUT_VERSION = "2026-07-15.1"
DETAIL_REPORT_SECTION_ORDER = (
    "triage reasons",
    "ai analysis output",
    "ai model used",
    "enriched alert details",
    "alert summary",
    "analyst notes",
    "parsed pcap evidence",
    "network and flow details",
    "protocol details",
    "host and sensor details",
    "threat context",
    "security onion detail fields",
    "raw logs",
)
DETAIL_REPORT_RENDER_ORDER = (
    "alert identity",
    "triage reasons",
    "duplicate alert timeline",
    *DETAIL_REPORT_SECTION_ORDER[1:],
)
DETAIL_REPORT_SECTION_LABELS = {
    "triage reasons": "Triage Reasons",
    "ai analysis output": "AI Analysis Output",
    "ai model used": "AI Model Used",
    "enriched alert details": "Enriched Alert Details",
    "alert summary": "Alert Summary",
    "analyst notes": "Analyst Notes",
    "parsed pcap evidence": "Parsed PCAP Evidence",
    "network and flow details": "Network And Flow Details",
    "protocol details": "Protocol Details",
    "host and sensor details": "Host And Sensor Details",
    "threat context": "Threat Context",
    "security onion detail fields": "Security Onion Detail Fields",
    "raw logs": "Raw Logs",
}
DETAIL_REPORT_SOURCE_ALIASES = {
    "public enrichment": "enriched alert details",
    "tshark corroboration": "tshark findings",
}
DETAIL_REPORT_REPLACED_SOURCE_SECTIONS = {
    "raw alert",
    "complete alert json",
    "complete ai response json",
}


@dataclass(frozen=True)
class DetailLayoutResult:
    """Canonical report Markdown plus legacy-data contract violations."""

    markdown: str
    issues: tuple[str, ...]


def normalized_heading_text(line: str) -> tuple[int, str] | None:
    """Return normalized heading level/text outside any parser state."""
    match = re.match(r"^(#{1,6})\s+(.+?)\s*$", line.strip())
    if not match:
        return None
    normalized = re.sub(
        r"[^a-z0-9]+",
        " ",
        re.sub(r"[`*_]+", "", match.group(2).lower()),
    ).strip()
    return len(match.group(1)), normalized


def demote_markdown_headings(text: str) -> str:
    """Keep relocated legacy content inside Raw Logs instead of creating peers."""
    output: list[str] = []
    in_code = False
    for line in (text or "").splitlines():
        if line.strip().startswith("```"):
            in_code = not in_code
            output.append(line)
            continue
        heading = re.match(r"^(#{1,6})(\s+.+)$", line) if not in_code else None
        if heading:
            level = min(6, len(heading.group(1)) + 2)
            output.append("#" * level + heading.group(2))
        else:
            output.append(line)
    return "\n".join(output)


def split_detail_source_sections(
    text: str,
) -> tuple[dict[str, str], list[tuple[str, str]], list[str]]:
    """Parse legacy H2 sections without allowing them to control UI structure."""
    issues: list[str] = []
    lines = (text or "").splitlines()
    if lines and lines[0].strip() == "---":
        closing = next(
            (index for index, line in enumerate(lines[1:], start=1) if line.strip() == "---"),
            None,
        )
        if closing is None:
            issues.append("Legacy Markdown front matter is not closed with a second `---` line.")
        else:
            lines = lines[closing + 1 :]

    sections: dict[str, str] = {}
    legacy_sections: list[tuple[str, str]] = []
    current_title = ""
    current_label = ""
    current_lines: list[str] = []
    in_code = False

    def flush() -> None:
        nonlocal current_title, current_label, current_lines
        if not current_title:
            current_lines = []
            return
        body = "\n".join(current_lines).strip()
        canonical = DETAIL_REPORT_SOURCE_ALIASES.get(current_title, current_title)
        known = canonical in DETAIL_REPORT_SECTION_ORDER or canonical in DETAIL_REPORT_REPLACED_SOURCE_SECTIONS
        if not known:
            legacy_sections.append((current_label or current_title.title(), demote_markdown_headings(body)))
            issues.append(
                f'Legacy top-level section "{current_label or current_title}" is not part of '
                f"Detailed Alert Report layout {DETAIL_REPORT_LAYOUT_VERSION}; it was moved to Raw Logs."
            )
        elif canonical in sections:
            legacy_sections.append(
                (f"Duplicate {current_label or current_title.title()}", demote_markdown_headings(body))
            )
            issues.append(
                f'Legacy data contains duplicate "{DETAIL_REPORT_SECTION_LABELS.get(canonical, current_label)}" '
                "sections; the first section was retained and the duplicate was moved to Raw Logs."
            )
        else:
            label = DETAIL_REPORT_SECTION_LABELS.get(canonical, current_label or canonical.title())
            sections[canonical] = f"## {label}\n\n{body}".rstrip()
        current_title = ""
        current_label = ""
        current_lines = []

    for line in lines:
        if line.strip().startswith("```"):
            in_code = not in_code
        heading = normalized_heading_text(line) if not in_code else None
        if heading and heading[0] == 2:
            flush()
            current_title = heading[1]
            current_label = re.sub(r"^##\s+", "", line.strip()).strip()
            continue
        if current_title:
            current_lines.append(line)
    flush()
    if in_code:
        issues.append("Legacy Markdown contains an unclosed fenced code block; affected content may be incomplete.")
    return sections, legacy_sections, issues
