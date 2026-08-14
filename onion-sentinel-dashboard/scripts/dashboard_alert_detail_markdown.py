"""Dependency-free Markdown renderer for Onion Sentinel alert details."""
from __future__ import annotations

import html
import re
from dataclasses import dataclass, field


COLLAPSIBLE_LABELS = {
    "raw alert": ("raw-alert-details", "raw-alert-body", "Raw Alert"),
    "complete alert json": ("raw-alert-details", "raw-alert-body", "Complete Alert JSON"),
    "complete ai response json": ("raw-alert-details", "raw-alert-body", "Complete AI Response JSON"),
    "raw logs": ("detail-report-section detail-collapsible-section detail-section-raw-logs", "detail-collapsible-body", "Raw Logs"),
    "ai model used": ("detail-report-section detail-collapsible-section detail-section-ai-model-used", "detail-collapsible-body", "AI Model Used"),
    "alert summary": ("detail-report-section detail-collapsible-section detail-section-alert-summary", "detail-collapsible-body", "Alert Summary"),
    "network and flow details": ("detail-report-section detail-collapsible-section detail-section-network-and-flow-details", "detail-collapsible-body", "Network And Flow Details"),
    "tshark findings": ("detail-report-section detail-collapsible-section detail-section-tshark-findings", "detail-collapsible-body", "TShark Findings"),
    "tshark corroboration": ("detail-report-section detail-collapsible-section detail-section-tshark-findings", "detail-collapsible-body", "TShark Findings"),
    "protocol details": ("detail-report-section detail-collapsible-section detail-section-protocol-details", "detail-collapsible-body", "Protocol Details"),
    "host and sensor details": ("detail-report-section detail-collapsible-section detail-section-host-and-sensor-details", "detail-collapsible-body", "Host And Sensor Details"),
    "threat context": ("detail-report-section detail-collapsible-section detail-section-threat-context", "detail-collapsible-body", "Threat Context"),
    "analyst notes": ("detail-report-section detail-collapsible-section detail-section-analyst-notes", "detail-collapsible-body", "Analyst Notes"),
    "parsed pcap evidence": ("detail-report-section detail-collapsible-section detail-section-parsed-pcap-evidence", "detail-collapsible-body", "Parsed PCAP Evidence"),
    "public enrichment": ("detail-report-section detail-collapsible-section detail-section-public-enrichment", "detail-collapsible-body", "Public Enrichment"),
    "enriched alert details": ("detail-report-section detail-collapsible-section detail-section-enriched-alert-details", "detail-collapsible-body", "Enriched Alert Details"),
    "security onion detail fields": ("detail-report-section detail-collapsible-section detail-section-security-onion-detail-fields", "detail-collapsible-body", "Security Onion Detail Fields"),
}


def inline_markdown(text: str) -> str:
    """Render the deliberately small inline Markdown subset used by reports."""
    escaped = html.escape(text)
    escaped = re.sub(r"`([^`]+)`", r"<code>\1</code>", escaped)
    escaped = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", escaped)
    escaped = re.sub(r"\*([^*]+)\*", r"<em>\1</em>", escaped)
    return re.sub(
        r"\[([^\]]+)\]\((https?://[^\s)]+)\)",
        lambda match: (
            f'<a href="{html.escape(match.group(2), quote=True)}" '
            f'target="_blank" rel="noopener">{match.group(1)}</a>'
        ),
        escaped,
    )


def is_table_separator(line: str) -> bool:
    cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
    return bool(cells) and all(re.fullmatch(r":?-{3,}:?", cell or "") for cell in cells)


def _table_presentation(normalized_header: list[str]) -> tuple[str, str]:
    table_classes = ["table-wrap"]
    colgroup_html = ""
    if normalized_header == ["source", "indicator", "type", "verdict", "confidence", "tags", "cached"]:
        table_classes.extend(("public-enrichment-table", "public-enrichment-records-table"))
        colgroup_html = (
            '<colgroup><col class="enrichment-col-source"><col class="enrichment-col-indicator">'
            '<col class="enrichment-col-type"><col class="enrichment-col-verdict">'
            '<col class="enrichment-col-confidence"><col class="enrichment-col-tags">'
            '<col class="enrichment-col-cached"></colgroup>'
        )
    elif normalized_header == ["source", "indicator", "reason", "limit_note"]:
        table_classes.extend(("public-enrichment-table", "public-enrichment-skipped-table"))
    return " ".join(table_classes), colgroup_html


def render_table(lines: list[str]) -> str:
    rows = [[cell.strip() for cell in line.strip().strip("|").split("|")] for line in lines]
    if len(rows) < 2:
        return ""
    header = rows[0]
    body = rows[2:] if len(rows) > 2 and is_table_separator(lines[1]) else rows[1:]
    head_html = "".join(f"<th>{inline_markdown(cell)}</th>" for cell in header)
    body_html = "".join(
        "<tr>" + "".join(f"<td>{inline_markdown(cell)}</td>" for cell in row) + "</tr>"
        for row in body
    )
    normalized_header = [re.sub(r"[^a-z0-9]+", "_", cell.lower()).strip("_") for cell in header]
    classes, colgroup_html = _table_presentation(normalized_header)
    return f'<div class="{classes}"><table>{colgroup_html}<thead><tr>{head_html}</tr></thead><tbody>{body_html}</tbody></table></div>'


def strip_markdown_front_matter(text: str) -> str:
    """Hide report metadata from the dashboard while preserving source files."""
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return text
    for index, line in enumerate(lines[1:], start=1):
        if line.strip() == "---":
            return "\n".join(lines[index + 1 :]).lstrip("\n")
    return text


@dataclass
class _MarkdownRenderState:
    blocks: list[str] = field(default_factory=list)
    paragraph: list[str] = field(default_factory=list)
    list_items: list[str] = field(default_factory=list)
    ordered_items: list[str] = field(default_factory=list)
    code_lines: list[str] = field(default_factory=list)
    table_lines: list[str] = field(default_factory=list)
    collapsible_section_levels: list[int] = field(default_factory=list)
    in_code: bool = False
    report_section_open: bool = False

    def flush_paragraph(self) -> None:
        if self.paragraph:
            self.blocks.append("<p>" + inline_markdown(" ".join(self.paragraph)) + "</p>")
            self.paragraph.clear()

    def flush_lists(self) -> None:
        if self.list_items:
            self.blocks.append("<ul>" + "".join(f"<li>{inline_markdown(item)}</li>" for item in self.list_items) + "</ul>")
            self.list_items.clear()
        if self.ordered_items:
            self.blocks.append("<ol>" + "".join(f"<li>{inline_markdown(item)}</li>" for item in self.ordered_items) + "</ol>")
            self.ordered_items.clear()

    def flush_table(self) -> None:
        if not self.table_lines:
            return
        rendered = render_table(self.table_lines)
        if rendered:
            self.blocks.append(rendered)
        else:
            self.blocks.extend("<p>" + inline_markdown(line) + "</p>" for line in self.table_lines)
        self.table_lines.clear()

    def flush_text(self) -> None:
        self.flush_paragraph()
        self.flush_lists()
        self.flush_table()

    def close_collapsible_sections(self, heading_level: int = 0) -> None:
        while self.collapsible_section_levels and (
            heading_level == 0 or heading_level <= self.collapsible_section_levels[-1]
        ):
            self.blocks.append("</div></details>")
            self.collapsible_section_levels.pop()

    def close_report_section(self) -> None:
        if self.report_section_open:
            self.blocks.append("</section>")
            self.report_section_open = False

    def handle_code_fence(self) -> None:
        self.flush_text()
        if self.in_code:
            self.blocks.append("<pre><code>" + html.escape("\n".join(self.code_lines)) + "</code></pre>")
            self.code_lines.clear()
        self.in_code = not self.in_code

    def handle_heading(self, heading: re.Match[str]) -> None:
        self.flush_paragraph()
        self.flush_lists()
        heading_level = len(heading.group(1))
        heading_text = heading.group(2).strip()
        self.close_collapsible_sections(heading_level)
        if self.report_section_open and heading_level <= 2:
            self.close_report_section()
        normalized = re.sub(r"[^a-z0-9]+", " ", re.sub(r"[`*_]+", "", heading_text.lower())).strip()
        collapsible = COLLAPSIBLE_LABELS.get(normalized)
        if collapsible:
            details_class, body_class, summary_label = collapsible
            self.collapsible_section_levels.append(heading_level)
            self.blocks.append(
                f'<details class="{details_class}"><summary>{summary_label}</summary>'
                f'<div class="{body_class}">'
            )
            return
        level = min(6, heading_level + 1)
        if heading_level <= 2:
            section_slug = re.sub(r"[^a-z0-9]+", "-", normalized).strip("-") or "section"
            self.report_section_open = True
            self.blocks.append(f'<section class="detail-report-section detail-section-{section_slug}">')
        self.blocks.append(f"<h{level}>{inline_markdown(heading_text)}</h{level}>")

    def handle_line(self, line: str) -> None:
        stripped = line.strip()
        if stripped.startswith("```"):
            self.handle_code_fence()
            return
        if self.in_code:
            self.code_lines.append(line)
            return
        if not stripped:
            self.flush_text()
            return
        if "|" in stripped and stripped.count("|") >= 2:
            self.flush_paragraph()
            self.flush_lists()
            self.table_lines.append(stripped)
            return
        self.flush_table()
        heading = re.match(r"^(#{1,6})\s+(.+)$", stripped)
        if heading:
            self.handle_heading(heading)
            return
        unordered = re.match(r"^[-*+]\s+(.+)$", stripped)
        if unordered:
            self.flush_paragraph()
            self.ordered_items.clear()
            self.list_items.append(unordered.group(1).strip())
            return
        ordered = re.match(r"^\d+[.)]\s+(.+)$", stripped)
        if ordered:
            self.flush_paragraph()
            self.list_items.clear()
            self.ordered_items.append(ordered.group(1).strip())
            return
        quote = re.match(r"^>\s*(.+)$", stripped)
        if quote:
            self.flush_paragraph()
            self.flush_lists()
            self.blocks.append(f"<blockquote>{inline_markdown(quote.group(1).strip())}</blockquote>")
            return
        self.paragraph.append(stripped)

    def finish(self) -> str:
        self.flush_text()
        if self.in_code and self.code_lines:
            self.blocks.append("<pre><code>" + html.escape("\n".join(self.code_lines)) + "</code></pre>")
        self.close_collapsible_sections()
        self.close_report_section()
        return "\n".join(self.blocks) or "<p>No markdown content available.</p>"


def markdown_to_html(text: str) -> str:
    """Render the bounded Markdown subset generated by Onion Sentinel."""
    state = _MarkdownRenderState()
    for raw in strip_markdown_front_matter(text).splitlines():
        state.handle_line(raw.rstrip("\n"))
    return state.finish()
