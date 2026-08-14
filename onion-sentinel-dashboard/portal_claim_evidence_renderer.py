"""Escaped HTML projection for validated claim-evidence graphs."""
from __future__ import annotations

from typing import Any


def _claim_html(claim: dict, position: int, callbacks: Any) -> str:
    text = callbacks.html_text
    html_list = callbacks.html_list
    correction = ""
    if claim.get("supersedes_claim_id"):
        correction = (
            f'<dt>Supersedes</dt><dd>{text(claim.get("supersedes_claim_id"), "n/a")}</dd>'
            f'<dt>Correction reason</dt><dd>{text(claim.get("correction_reason"), "n/a")}</dd>'
        )
    return (
        f'<article class="ir-claim-record"><h5>Claim {position}</h5><dl>'
        f'<dt>ID</dt><dd>{text(claim.get("id"), "n/a")}</dd>'
        f'<dt>Class</dt><dd>{text(claim.get("claim_kind"), "n/a")}</dd>'
        f'<dt>Scope</dt><dd>{text(claim.get("claim_scope"), "n/a")}</dd>'
        f'<dt>Material</dt><dd>{text(claim.get("material"), "n/a")}</dd>'
        f'<dt>Certainty</dt><dd>{text(claim.get("certainty"), "n/a")}</dd>'
        f'<dt>Claim</dt><dd>{text(claim.get("statement"), "n/a")}</dd>'
        f'{correction}</dl>'
        '<h6>Report fields</h6>'
        f'{html_list(claim.get("report_fields"), "No report fields were linked.")}'
        '<h6>Supporting evidence</h6>'
        f'{html_list(claim.get("supporting_evidence_refs"), "No supporting evidence was linked.")}'
        '<h6>Contradicting evidence</h6>'
        f'{html_list(claim.get("contradicting_evidence_refs"), "No contradicting evidence was linked.")}'
        '<h6>Decisive missing evidence</h6>'
        f'{html_list(claim.get("decisive_missing_evidence"), "No decisive gap was recorded.")}'
        '</article>'
    )


def _history_html(value: object, callbacks: Any) -> str:
    text = callbacks.html_text
    html_list = callbacks.html_list
    history = value if isinstance(value, list) else []
    blocks: list[str] = []
    for position, item in enumerate(history[:20], 1):
        if not isinstance(item, dict):
            continue
        original = [
            claim.get("id") for claim in item.get("original_claims", [])[:100]
            if isinstance(claim, dict)
        ] if isinstance(item.get("original_claims"), list) else []
        corrected = [
            claim.get("id") for claim in item.get("corrected_claims", [])[:100]
            if isinstance(claim, dict)
        ] if isinstance(item.get("corrected_claims"), list) else []
        blocks.append(
            f'<article class="ir-claim-review"><h5>Reviewer Correction {position}</h5>'
            f'<p><b>Evidence-based reason:</b> {text(item.get("correction_reason"), "n/a")}</p>'
            '<h6>Original claims retained</h6>'
            f'{html_list(original, "No original claims were retained.")}'
            '<h6>Corrected claims</h6>'
            f'{html_list(corrected, "No corrected claims were recorded.")}'
            '<h6>Adjudication evidence</h6>'
            f'{html_list(item.get("adjudication_evidence_refs"), "No adjudication evidence was recorded.")}'
            '</article>'
        )
    return "".join(blocks)


def render_claim_evidence(response: dict, callbacks: Any) -> str:
    """Render current claims plus immutable reviewer correction history."""
    graph = response.get("claim_evidence_graph")
    graph = graph if isinstance(graph, dict) else {}
    validation = graph.get("validation")
    validation = validation if isinstance(validation, dict) else {}
    claims = graph.get("claims")
    claims = claims if isinstance(claims, list) else []
    text = callbacks.html_text
    body = (
        '<div class="ir-analysis-meta">'
        f'<span><b>Schema:</b> {text(graph.get("schema"), "n/a")}</span>'
        f'<span><b>Valid:</b> {text(validation.get("valid"), "false")}</span>'
        f'<span><b>Material claims:</b> {text(validation.get("material_claim_count"), "0")}</span>'
        '</div>'
    )
    body += "".join(
        _claim_html(claim, position, callbacks)
        for position, claim in enumerate(claims[:100], 1)
        if isinstance(claim, dict)
    ) or '<p>No validated material claim bindings were recorded.</p>'
    body += _history_html(graph.get("review_history"), callbacks)
    return callbacks.report_section("Claim-Evidence Graph", body)
