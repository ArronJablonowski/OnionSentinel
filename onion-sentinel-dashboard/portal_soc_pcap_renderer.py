"""Bounded escaped HTML rendering for parsed PCAP evidence."""
from __future__ import annotations

import html
import json
from pathlib import Path


def _mapping(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def _list(value: object) -> list:
    return value if isinstance(value, list) else []


def _escape(value: object) -> str:
    return html.escape("n/a" if value is None else str(value))


def _compact_json(value: object, limit: int = 2400) -> str:
    text = value if isinstance(value, str) else json.dumps(value, indent=2, sort_keys=True)
    text = text.strip() or "n/a"
    if len(text) > limit:
        text = text[:limit].rstrip() + "\n... truncated ..."
    return html.escape(text)


def _summary_table(record: dict, request: dict, files: list) -> str:
    analysis_name = Path(str(record.get("_analysis_path") or "")).name or "n/a"
    rows = (
        ("Status", "Parsed"), ("Request ID", request.get("request_id")),
        ("Generated", record.get("generated_at")), ("PCAP files parsed", len(files)),
        ("Analysis artifact", analysis_name),
    )
    body = "\n".join(
        f"<tr><th>{_escape(label)}</th><td>{_escape(value)}</td></tr>" for label, value in rows
    )
    return f'<table class="detail-kv-table"><tbody>{body}</tbody></table>'


def _zeek_parts(zeek: dict) -> list[str]:
    if not zeek.get("available"):
        return [f"<p>Zeek unavailable: {_escape(zeek.get('reason'))}</p>"]
    counts = _mapping(zeek.get("record_counts"))
    parts = [
        f"<p><strong>Record counts:</strong> <code>{_escape(json.dumps(counts, sort_keys=True))}</code></p>"
    ]
    for title, key in (
        ("Top Connections", "top_connections"), ("DNS Queries", "dns_queries"),
        ("TLS SNI", "tls_sni"), ("HTTP Hosts", "http_hosts"),
        ("Notices", "notices"), ("Weird Activity", "weird"),
    ):
        values = _list(zeek.get(key))
        if values:
            parts.extend([
                f"<h5>{_escape(title)}</h5>",
                f"<pre><code>{_compact_json(values[:10])}</code></pre>",
            ])
    return parts


def _tshark_parts(tshark: dict) -> list[str]:
    if not tshark.get("available"):
        return [f"<p>TShark unavailable: {_escape(tshark.get('reason'))}</p>"]
    samples = _list(tshark.get("samples"))
    if not samples:
        return ["<p>No bounded TShark samples were produced.</p>"]
    parts: list[str] = []
    for sample in samples[:2]:
        if not isinstance(sample, dict):
            continue
        parts.extend([
            "<h5>Protocol hierarchy</h5>",
            f"<pre><code>{_compact_json(sample.get('protocol_hierarchy'), 1800)}</code></pre>",
            "<h5>Conversations</h5>",
            f"<pre><code>{_compact_json(sample.get('conversations'), 1800)}</code></pre>",
        ])
    return parts


def render_pcap_summary(record: dict) -> str:
    """Render bounded summaries without exposing raw packet payloads."""
    request = _mapping(record.get("request"))
    zeek = _mapping(record.get("zeek"))
    tshark = _mapping(record.get("tshark"))
    files = _list(record.get("pcap_files"))
    parts = [
        '<section class="detail-section parsed-pcap-evidence">',
        "<h3>Parsed PCAP Evidence</h3>",
        "<p>Current Zeek/TShark packet evidence for this grouped detection. "
        "This section is generated from parsed summaries; raw packet payloads are not displayed.</p>",
        _summary_table(record, request, files),
        "<h4>Zeek Summary</h4>",
        *_zeek_parts(zeek),
        "<h4>TShark Corroboration</h4>",
        *_tshark_parts(tshark),
        "</section>",
    ]
    return "\n".join(parts)
