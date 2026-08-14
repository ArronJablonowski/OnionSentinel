#!/usr/bin/env python3
"""Render bounded PCAP evidence sections for SOC alert details.

Raw packet captures are runtime-only evidence. This module renders only parsed
Zeek/TShark summaries that are already bounded by the PCAP worker, keeping the
large dashboard builder focused on data loading and page assembly.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def has_parsed_pcap(record: dict[str, Any]) -> bool:
    """Return true only when a parser artifact contains real capture evidence."""
    pcap_files = record.get("pcap_files") if isinstance(record.get("pcap_files"), list) else []
    if not pcap_files:
        return False
    zeek = record.get("zeek") if isinstance(record.get("zeek"), dict) else {}
    tshark = record.get("tshark") if isinstance(record.get("tshark"), dict) else {}
    return bool(zeek.get("available") or tshark.get("available"))


def build_pcap_analysis_index(analysis_dir: Path) -> dict[str, object]:
    """Index valid parsed PCAP evidence once for fast dashboard row lookups."""
    index = {
        "request_ids": set(),
        "alert_ids": set(),
        "group_ids": set(),
        "records_by_request_id": {},
        "records_by_alert_id": {},
        "records_by_group_id": {},
    }
    if not analysis_dir.exists():
        return index
    for path in analysis_dir.glob("*-pcap-analysis.json"):
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(record, dict) or not has_parsed_pcap(record):
            continue
        record["_analysis_path"] = str(path)
        request = record.get("request") if isinstance(record.get("request"), dict) else {}
        for key, bucket, record_bucket in (
            ("request_id", "request_ids", "records_by_request_id"),
            ("alert_id", "alert_ids", "records_by_alert_id"),
            ("group_id", "group_ids", "records_by_group_id"),
        ):
            value = str(request.get(key) or "").strip()
            if value:
                index[bucket].add(value)
                index[record_bucket].setdefault(value, record)
    return index


def _cell(value: object, max_len: int = 420) -> str:
    """Return a compact Markdown table cell without allowing table breaks."""
    text = "n/a" if value is None else str(value)
    text = text.replace("|", "\\|").replace("\n", "<br>")
    if len(text) > max_len:
        text = text[: max_len - 1].rstrip() + "…"
    return text or "n/a"


def _bounded_block(value: object, language: str = "json", max_len: int = 1800) -> str:
    """Render a fenced block capped for detail-page readability."""
    text = json.dumps(value, indent=2, sort_keys=True) if not isinstance(value, str) else value
    text = text.strip()
    if len(text) > max_len:
        text = text[:max_len].rstrip() + "\n... truncated ..."
    return f"```{language}\n{text or 'n/a'}\n```"


def _zeek_summary_lines(zeek: dict[str, Any]) -> list[str]:
    """Project the bounded Zeek section without changing evidence order."""
    lines = ["### Zeek Summary", ""]
    if not zeek.get("available"):
        lines.append(f"- Zeek unavailable: {_cell(zeek.get('reason'))}")
        return lines

    record_counts = zeek.get("record_counts") if isinstance(zeek.get("record_counts"), dict) else {}
    lines.extend([f"- Record counts: `{json.dumps(record_counts, sort_keys=True)}`", ""])
    for title, key in (
        ("Top Connections", "top_connections"),
        ("DNS Queries", "dns_queries"),
        ("TLS SNI", "tls_sni"),
        ("HTTP Hosts", "http_hosts"),
        ("Notices", "notices"),
        ("Weird Activity", "weird"),
    ):
        values = zeek.get(key) if isinstance(zeek.get(key), list) else []
        lines.extend([f"#### {title}", "", _bounded_block(values[:10]), ""])
    return lines


def _tshark_corroboration_lines(tshark: dict[str, Any]) -> list[str]:
    """Project bounded TShark samples while preserving admission semantics."""
    lines = ["### TShark Corroboration", ""]
    if not tshark.get("available"):
        lines.append(f"- TShark unavailable: {_cell(tshark.get('reason'))}")
        return lines

    samples = tshark.get("samples") if isinstance(tshark.get("samples"), list) else []
    if not samples:
        lines.append("No bounded TShark samples were produced.")
    for sample in samples[:2]:
        if not isinstance(sample, dict):
            continue
        lines.extend(
            [
                f"#### {Path(str(sample.get('pcap') or 'capture')).name}",
                "",
                "**Protocol hierarchy**",
                "",
                _bounded_block(str(sample.get("protocol_hierarchy") or ""), "text"),
                "",
                "**Conversations**",
                "",
                _bounded_block(str(sample.get("conversations") or ""), "text"),
                "",
            ]
        )
    return lines


def render_pcap_evidence_markdown(
    pcap_status: tuple[str, str, str], pcap_analysis: dict[str, Any] | None, generated_at: str = ""
) -> str:
    """Render LLM-safe packet evidence for the Detailed Alert Report."""
    _status_key, status_label, status_detail = pcap_status
    if not pcap_analysis:
        return "\n".join(
            [
                "## Parsed PCAP Evidence",
                "",
                "| Field | Value |",
                "| --- | --- |",
                f"| Status | {_cell(status_label)} |",
                f"| Detail | {_cell(status_detail)} |",
                "",
                "No parsed Zeek/TShark PCAP summary is available for this alert group yet.",
            ]
        )

    request = pcap_analysis.get("request") if isinstance(pcap_analysis.get("request"), dict) else {}
    zeek = pcap_analysis.get("zeek") if isinstance(pcap_analysis.get("zeek"), dict) else {}
    tshark = pcap_analysis.get("tshark") if isinstance(pcap_analysis.get("tshark"), dict) else {}
    pcap_files = pcap_analysis.get("pcap_files") if isinstance(pcap_analysis.get("pcap_files"), list) else []
    generated = generated_at or str(pcap_analysis.get("generated_at") or "")
    lines = [
        "## Parsed PCAP Evidence",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| Status | {_cell(status_label)} |",
        f"| Detail | {_cell(status_detail)} |",
        f"| Request ID | {_cell(request.get('request_id'))} |",
        f"| Generated at | {_cell(generated)} |",
        f"| Artifact state | {_cell(pcap_analysis.get('artifact_state'))} |",
        f"| PCAP files parsed | {len(pcap_files)} |",
        f"| Analysis artifact | {_cell(Path(str(pcap_analysis.get('_analysis_path') or '')).name or 'n/a')} |",
        "",
    ]
    lines.extend(_zeek_summary_lines(zeek))
    lines.extend(_tshark_corroboration_lines(tshark))

    lines.extend(
        [
            "### Evidence Limits",
            "",
            "- Raw packet payloads are not displayed in the dashboard.",
            "- Zeek and TShark output is bounded before it is shown to analysts or sent to local AI.",
        ]
    )
    return "\n".join(lines)
