"""Pure Markdown projection for validated claim-evidence graphs."""
from __future__ import annotations

from dashboard_untrusted_text import normalize_untrusted_text


def _text(value: object, fallback: str = "n/a") -> str:
    normalized = " ".join(str(value or "").split()).strip()
    return normalized or fallback


def _values(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [_text(item) for item in value if _text(item, "")]


def _joined(value: object) -> str:
    return ", ".join(_values(value)) or "n/a"


def _claim_lines(claim: dict, position: int) -> list[str]:
    lines = [
        f"#### Claim {position}", "",
        f"- **ID:** {_text(claim.get('id'))}",
        f"- **Class:** {_text(claim.get('claim_kind'))}",
        f"- **Scope:** {_text(claim.get('claim_scope'))}",
        f"- **Material:** {_text(claim.get('material'))}",
        f"- **Certainty:** {_text(claim.get('certainty'))}",
        f"- **Report fields:** {_joined(claim.get('report_fields'))}",
        f"- **Claim:** {_text(claim.get('statement'))}",
        f"- **Supporting evidence:** {_joined(claim.get('supporting_evidence_refs'))}",
        f"- **Contradicting evidence:** {_joined(claim.get('contradicting_evidence_refs'))}",
        f"- **Decisive missing evidence:** {_joined(claim.get('decisive_missing_evidence'))}",
    ]
    if claim.get("supersedes_claim_id"):
        lines.extend([
            f"- **Supersedes:** {_text(claim.get('supersedes_claim_id'))}",
            f"- **Correction reason:** {_text(claim.get('correction_reason'))}",
        ])
    lines.append("")
    return lines


def _claim_ids(value: object) -> list[str]:
    claims = value if isinstance(value, list) else []
    return [
        _text(claim.get("id")) for claim in claims[:100]
        if isinstance(claim, dict)
    ]


def _history_item_lines(item: dict, position: int) -> list[str]:
    original = _claim_ids(item.get("original_claims"))
    corrected = _claim_ids(item.get("corrected_claims"))
    return [
        f"#### Reviewer Correction {position}", "",
        f"- **Original claims retained:** {', '.join(original) or 'n/a'}",
        f"- **Corrected claims:** {', '.join(corrected) or 'n/a'}",
        f"- **Evidence-based reason:** {_text(item.get('correction_reason'))}",
        f"- **Adjudication evidence:** {_joined(item.get('adjudication_evidence_refs'))}",
        "",
    ]


def _history_lines(value: object) -> list[str]:
    history = value if isinstance(value, list) else []
    lines: list[str] = []
    for position, item in enumerate(history[:20], 1):
        if isinstance(item, dict):
            lines.extend(_history_item_lines(item, position))
    return lines


def claim_evidence_markdown(response: dict) -> str:
    """Render every current claim, missing discriminator, and review correction."""
    graph = response.get("claim_evidence_graph")
    graph = graph if isinstance(graph, dict) else {}
    validation = graph.get("validation")
    validation = validation if isinstance(validation, dict) else {}
    claims = graph.get("claims")
    claims = claims if isinstance(claims, list) else []
    lines = [
        "### Claim-Evidence Graph", "",
        f"- **Schema:** {_text(graph.get('schema'))}",
        f"- **Validation:** {_text(validation.get('valid'), 'False')}",
        f"- **Material claims:** {_text(validation.get('material_claim_count'), '0')}",
        "",
    ]
    for position, claim in enumerate(claims[:100], 1):
        if isinstance(claim, dict):
            lines.extend(_claim_lines(claim, position))
    if not claims:
        lines.extend(["No validated material claim bindings were recorded.", ""])
    lines.extend(_history_lines(graph.get("review_history")))
    return normalize_untrusted_text("\n".join(lines).rstrip())
