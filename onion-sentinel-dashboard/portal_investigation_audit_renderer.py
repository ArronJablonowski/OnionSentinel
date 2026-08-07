"""Pure HTML rendering for broker-owned interactive investigation pivots."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import html
import json


@dataclass(frozen=True)
class InvestigationAuditRenderCallbacks:
    """Shared portal presentation policies used by the audit renderer."""

    html_text: Callable[[object, str], str]
    nonnegative_int: Callable[[object], int]
    linked_finding: Callable[[dict, object], str]


def investigation_purpose_text(value: object) -> str:
    """Expand stable machine purposes without altering free-form purposes."""
    purpose = str(value or "").strip()
    labels = {
        "validate_detection": "Validate whether the observed event matches the triggering detection.",
        "establish_timeline": "Establish the order and timing of related activity.",
        "correlate_observable": "Correlate an exact trusted observable across reviewed telemetry.",
        "measure_prevalence": "Measure how often the exact activity appears in the authorized window.",
        "identify_related_activity": "Identify related activity that could expand or narrow incident scope.",
        "test_benign_hypothesis": "Test a specific benign explanation against the available telemetry.",
    }
    return labels.get(purpose, purpose)


def _query_backend(query: dict) -> str:
    return str(query.get("backend") or query.get("dialect") or "broker").strip().lower()


def _query_subject(query: dict) -> str:
    return str(
        query.get("pack")
        or query.get("operation")
        or query.get("target_alias")
        or query.get("query_id")
        or "reviewed pivot"
    ).strip()


def _query_digest(query: dict) -> str:
    return str(
        query.get("query_digest")
        or query.get("execution_digest")
        or query.get("request_digest")
        or ""
    ).strip()


def _count_meta(query: dict, callbacks: InvestigationAuditRenderCallbacks) -> list[str]:
    count = callbacks.nonnegative_int
    meta = []
    if query.get("total_hits") is not None or query.get("returned_hits") is not None:
        meta.append(
            f'<span><b>Hits:</b> {count(query.get("total_hits"))} total / '
            f'{count(query.get("returned_hits"))} returned</span>'
        )
    if query.get("total_rows") is not None or query.get("returned_rows") is not None:
        meta.append(
            f'<span><b>Rows:</b> {count(query.get("total_rows"))} total / '
            f'{count(query.get("returned_rows"))} returned</span>'
        )
    if query.get("candidate_records_scanned") is not None or query.get("records_returned") is not None:
        meta.append(
            f'<span><b>Records:</b> {count(query.get("candidate_records_scanned"))} '
            f'scanned / {count(query.get("records_returned"))} returned</span>'
        )
    return meta


def _query_meta(query: dict, digest: str, callbacks: InvestigationAuditRenderCallbacks) -> str:
    text = callbacks.html_text
    window = query.get("window") if isinstance(query.get("window"), dict) else {}
    meta = [
        f'<span><b>Status:</b> {text(query.get("status") or "unknown", "n/a")}</span>',
        f'<span><b>Digest:</b> <code>{text(digest, "n/a")}</code></span>',
    ]
    if window:
        meta.append(
            f'<span><b>Window:</b> {text(window.get("start"), "n/a")} '
            f'to {text(window.get("end"), "n/a")}</span>'
        )
    meta.extend(_count_meta(query, callbacks))
    semantics = query.get("semantics") or query.get("execution_semantics")
    if semantics:
        meta.append(f'<span><b>Semantics:</b> {text(semantics, "n/a")}</span>')
    if query.get("execution_backend"):
        meta.append(f'<span><b>Executor:</b> {text(query.get("execution_backend"), "n/a")}</span>')
    if any(bool(query.get(key)) for key in ("truncated", "result_truncated", "index_scan_truncated")):
        meta.append("<span><b>Truncated:</b> true</span>")
    return "".join(meta)


def _code_block(heading: str, value: object, *, json_value: bool = False) -> str:
    if value in (None, "", {}, []):
        return ""
    rendered = json.dumps(value, indent=2, sort_keys=True, default=str) if json_value else str(value)
    return (
        f"<h5>{html.escape(heading)}</h5>"
        f'<pre class="ir-query-code"><code>{html.escape(rendered)}</code></pre>'
    )


def _structured_request(query: dict) -> dict:
    return {
        key: query.get(key)
        for key in ("operation", "filters", "indicator", "limit")
        if query.get(key) not in (None, "", {}, [])
    }


def _query_code_blocks(query: dict, backend: str) -> str:
    blocks = [
        _code_block("OQL (analyst-readable equivalent)", query.get("oql_equivalent")),
        _code_block("KQL (analyst-readable equivalent)", query.get("kql_equivalent")),
        _code_block(
            "Elasticsearch Query DSL (exact executed request)",
            query.get("query_dsl"),
            json_value=True,
        ),
    ]
    if backend == "osquery":
        blocks.append(_code_block("OSquery SQL (exact executed live query)", query.get("query")))
    if backend in {"pcap", "zeek"}:
        blocks.append(
            _code_block(
                "Structured PCAP/Zeek request (exact broker input)",
                _structured_request(query),
                json_value=True,
            )
        )
    return "".join(blocks)


def _query_error(query: dict) -> str:
    error = str(query.get("error") or "").strip()
    return f'<p class="ir-query-error"><b>Error:</b> {html.escape(error)}</p>' if error else ""


def _render_query(
    query: dict,
    report: dict,
    position: int,
    round_number: int,
    callbacks: InvestigationAuditRenderCallbacks,
) -> str:
    backend = _query_backend(query)
    digest = _query_digest(query)
    purpose = investigation_purpose_text(query.get("purpose"))
    finding = callbacks.linked_finding(report, digest)
    title = f"Pivot {position} (round {round_number or 1}): {backend.upper()} · {_query_subject(query)}"
    return (
        '<article class="ir-query-record" '
        f'data-query-purpose="{html.escape(purpose, quote=True)}" '
        f'data-query-finding="{html.escape(finding, quote=True)}">'
        f"<h4>{html.escape(title)}</h4>"
        f'<div class="ir-query-meta">{_query_meta(query, digest, callbacks)}</div>'
        f'{_query_code_blocks(query, backend)}{_query_error(query)}'
        "</article>"
    )


def _query_blocks(
    rounds: list,
    report: dict,
    callbacks: InvestigationAuditRenderCallbacks,
) -> list[str]:
    blocks = []
    for round_record in rounds[:12]:
        if not isinstance(round_record, dict):
            continue
        round_number = callbacks.nonnegative_int(round_record.get("round"))
        queries = round_record.get("trusted_queries")
        queries = queries if isinstance(queries, list) else []
        for query in queries[:12]:
            if not isinstance(query, dict):
                continue
            blocks.append(
                _render_query(query, report, len(blocks) + 1, round_number, callbacks)
            )
    return blocks


def _audit_metadata(audit: dict, callbacks: InvestigationAuditRenderCallbacks) -> str:
    text = callbacks.html_text
    count = callbacks.nonnegative_int
    return (
        '<div class="ir-analysis-meta">'
        f'<span><b>Contract:</b> {text(audit.get("query_contract"), "n/a")}</span>'
        f'<span><b>Provider neutral:</b> {text(audit.get("provider_neutral", True), "n/a")}</span>'
        f'<span><b>Model route:</b> {text(audit.get("model_route"), "n/a")}</span>'
        f'<span><b>Rounds:</b> {count(audit.get("rounds_completed"))}</span>'
        f'<span><b>Admitted:</b> {count(audit.get("queries_admitted"))}</span>'
        f'<span><b>Rejected/over budget:</b> '
        f'{count(audit.get("requests_ignored_or_over_budget"))}</span></div>'
    )


def render_investigation_query_audit(
    response: dict,
    report: dict,
    callbacks: InvestigationAuditRenderCallbacks,
) -> tuple[str, int]:
    """Render bounded broker-owned pivot records, never model-authored queries."""
    audit = response.get("_investigation_query_audit")
    if not isinstance(audit, dict):
        return "", 0
    rounds = audit.get("rounds") if isinstance(audit.get("rounds"), list) else []
    blocks = _query_blocks(rounds, report, callbacks)
    body = (
        "".join(blocks)
        if blocks
        else "<p>No broker-authorized pivot produced a presentation-ready execution record.</p>"
    )
    section = (
        '<section class="ir-query-audit"><h3>Interactive Investigation Pivot Audit</h3>'
        f'{_audit_metadata(audit, callbacks)}{body}</section>'
    )
    return section, len(blocks)
