"""Pure Markdown sections for Incident Response and query audit evidence."""
from __future__ import annotations

import json
from typing import Any, Callable


def markdown_list(items: list[str]) -> str:
    """Render a stable Markdown list with an explicit empty marker."""
    if not items:
        return "- n/a"
    return "\n".join(f"- {item}" for item in items)


def _timeline_lines(report: dict[str, Any]) -> list[str]:
    timeline = report.get("factual_timeline")
    if not isinstance(timeline, list) or not timeline:
        return ["- n/a"]
    lines: list[str] = []
    for event in timeline:
        if not isinstance(event, dict):
            continue
        source = str(event.get("source_pack") or "supplied evidence")
        digest = str(event.get("query_digest") or "n/a")
        confidence = str(event.get("confidence") or "low")
        lines.append(
            f"- **{event.get('timestamp') or 'Time unavailable'}** - "
            f"{event.get('event') or 'n/a'} "
            f"(source: {source}; query: {digest}; confidence: {confidence})"
        )
    return lines


def _incident_list_sections(
    report: dict[str, Any],
    bounded_text_list: Callable[[Any], list[str]],
) -> list[str]:
    lines: list[str] = []
    for title, key in (
        ("Security Onion Findings", "security_onion_findings"),
        ("OSquery Findings", "osquery_findings"),
        ("PCAP Findings", "pcap_findings"),
        ("Host Findings", "host_findings"),
        ("Correlation Findings", "correlation_findings"),
        ("Containment Recommendations", "containment_recommendations"),
        ("Eradication Recommendations", "eradication_recommendations"),
        ("Recovery Recommendations", "recovery_recommendations"),
        ("Follow-up Queries", "follow_up_queries"),
        ("Evidence Gaps", "evidence_gaps"),
    ):
        lines.extend(
            [
                "",
                f"### {title}",
                "",
                markdown_list(bounded_text_list(report.get(key))),
            ]
        )
    return lines


def render_incident_response(
    response: dict[str, Any],
    *,
    bounded_text_list: Callable[[Any], list[str]],
) -> list[str]:
    """Render the evidence-backed Incident Response narrative section."""
    report = response.get("incident_response_report")
    if not isinstance(report, dict):
        return []
    lines = [
        "## Incident Response Investigation",
        "",
        "### Executive BLUF",
        "",
        str(report.get("executive_bluf") or "n/a"),
        "",
        "### Detection Outcome Reasoning",
        "",
        str(report.get("detection_outcome_reasoning") or "n/a"),
        "",
        "### Scope",
        "",
        str(report.get("scope") or "n/a"),
        "",
        "### Affected Systems",
        "",
        markdown_list(bounded_text_list(report.get("affected_systems"))),
        "",
        "### Methodology",
        "",
        markdown_list(bounded_text_list(report.get("methodology"))),
        "",
        "### Factual Timeline",
        "",
    ]
    lines.extend(_timeline_lines(report))
    lines.extend(_incident_list_sections(report, bounded_text_list))
    lines.extend(
        [
            "",
            "### Conclusion",
            "",
            str(report.get("conclusion") or "n/a"),
            "",
            f"- **Confidence:** {report.get('confidence') or 'low'}",
            "",
        ]
    )
    return lines


def render_security_onion_query_audit(response: dict[str, Any]) -> list[str]:
    """Render exact Security Onion query provenance and analyst equivalents."""
    audit = response.get("_incident_query_audit")
    if not isinstance(audit, dict):
        return []
    lines = [
        "## Security Onion Query Audit",
        "",
        f"- **Trusted source:** {audit.get('trusted_source', 'n/a')}",
        f"- **Read only:** {audit.get('read_only', True)}",
        f"- **Complete:** {audit.get('complete', False)}",
        f"- **Partial:** {audit.get('partial', True)}",
        "",
    ]
    queries = audit.get("queries") if isinstance(audit.get("queries"), list) else []
    if not queries:
        lines.append("No restricted Security Onion queries were recorded.")
        return lines
    for index, query in enumerate(queries, 1):
        if not isinstance(query, dict):
            continue
        lines.extend(
            [
                f"### Query {index}: {query.get('pack') or 'evidence pack'}",
                "",
                f"- **Status:** {query.get('status') or 'unknown'}",
                f"- **Digest:** `{query.get('query_digest') or 'n/a'}`",
                f"- **Window:** {query.get('window', {}).get('start', '')} to {query.get('window', {}).get('end', '')}",
                f"- **Hits:** {query.get('total_hits', 0)} total; {query.get('returned_hits', 0)} returned",
                "",
                "#### KQL (analyst-readable equivalent)",
                "",
                "```kql",
                str(query.get("kql_equivalent") or "n/a"),
                "```",
                "",
                "#### Elasticsearch Query DSL (exact executed request)",
                "",
                "```json",
                json.dumps(query.get("query_dsl") or {}, indent=2, sort_keys=True),
                "```",
                "",
            ]
        )
    return lines


def _render_osquery_rows(query: dict[str, Any]) -> list[str]:
    rows = query.get("rows_preview")
    if not isinstance(rows, list) or not rows:
        return []
    return [
        "#### Bounded Result Preview",
        "",
        "```json",
        json.dumps(rows, indent=2, sort_keys=True),
        "```",
        "",
    ]


def render_appliance_osquery_audit(response: dict[str, Any]) -> list[str]:
    """Render read-only appliance OSQuery snapshot provenance."""
    audit = response.get("_incident_osquery_audit")
    if not isinstance(audit, dict):
        return []
    lines = [
        "## Security Onion Appliance OSQuery Snapshot Audit",
        "",
        f"- **Trusted source:** {audit.get('trusted_source', 'n/a')}",
        f"- **Read only:** {audit.get('read_only', True)}",
        "",
    ]
    queries = audit.get("queries") if isinstance(audit.get("queries"), list) else []
    if not queries:
        lines.append(
            "No validated Security Onion appliance OSQuery snapshots were recorded."
        )
        return lines
    for index, query in enumerate(queries, 1):
        if not isinstance(query, dict):
            continue
        lines.extend(
            [
                f"### OSquery {index}: {query.get('pack') or 'reviewed pack'}",
                "",
                f"- **Target:** {query.get('target') or 'n/a'}",
                f"- **Status:** {query.get('status') or 'unknown'}",
                f"- **Digest:** `{query.get('query_digest') or 'n/a'}`",
                f"- **Rows:** {query.get('total_rows', 0)} total; {query.get('returned_rows', 0)} returned",
                f"- **Collector-owned alert bindings:** {query.get('support_binding_count', 0)}",
                f"- **Duration:** {query.get('duration_ms', 0)} ms",
                "",
                "#### OSquery SQL (exact executed command)",
                "",
                "```sql",
                str(query.get("query") or "n/a"),
                "```",
                "",
            ]
        )
        lines.extend(_render_osquery_rows(query))
        if query.get("error"):
            lines.extend([f"- **Error:** {query.get('error')}", ""])
    return lines


def render_live_osquery_audit(response: dict[str, Any]) -> list[str]:
    """Render endpoint live-query audit evidence and control-plane status."""
    audit = response.get("_incident_live_osquery_audit")
    if not isinstance(audit, dict):
        return []
    lines = [
        "## Endpoint Live OSQuery Audit",
        "",
        f"- **Trusted source:** {audit.get('trusted_source', 'n/a')}",
        f"- **Endpoint SQL read only:** {audit.get('endpoint_read_only', audit.get('read_only', True))}",
        f"- **Security Onion control-plane write status:** {audit.get('control_plane_write_status', 'confirmed' if audit.get('control_plane_writes', True) else 'none')}",
        f"- **Attempted batches:** {audit.get('batches', 0)}",
        f"- **Validated batches:** {audit.get('validated_batches', audit.get('batches', 0))}",
        f"- **Failed batches:** {audit.get('failed_batches', 0)}",
        f"- **Complete:** {audit.get('complete', False)}",
        "",
    ]
    if audit.get("preview_truncated"):
        lines.extend(
            [
                "- **Preview note:** Endpoint result previews were bounded to 100 rows and 256 KiB across the report.",
                "",
            ]
        )
    if audit.get("error"):
        lines.extend([f"- **Collection note:** {audit.get('error')}", ""])
    queries = audit.get("queries") if isinstance(audit.get("queries"), list) else []
    if not queries:
        lines.append("No endpoint live OSQuery batch was executed for this investigation.")
        return lines
    for index, query in enumerate(queries, 1):
        if isinstance(query, dict):
            lines.extend(_render_live_query(index, query))
    return lines


def _render_live_query(index: int, query: dict[str, Any]) -> list[str]:
    lines = [
        f"### Endpoint Query {index}: {query.get('target_alias') or 'configured endpoint'}",
        "",
        f"- **Purpose:** {query.get('purpose') or 'n/a'}",
        f"- **Status:** {query.get('status') or 'unknown'}",
        f"- **Digest:** `{query.get('query_digest') or 'n/a'}`",
        f"- **Rows:** {query.get('total_rows', 0)} total; {query.get('returned_rows', 0)} returned",
        f"- **Duration:** {query.get('duration_ms', 0)} ms",
        "",
        "#### OSQuery SQL (exact executed live query)",
        "",
        "```sql",
        str(query.get("query") or "n/a"),
        "```",
        "",
    ]
    lines.extend(_render_osquery_rows(query))
    if query.get("rows_preview_truncated"):
        lines.extend(
            [
                "Result preview truncated by the per-query or report-wide audit bound.",
                "",
            ]
        )
    if query.get("error"):
        lines.extend([f"- **Error:** {query.get('error')}", ""])
    return lines
