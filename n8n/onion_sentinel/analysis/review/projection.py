"""Analyst-facing projection of validated shadow adjudication decisions."""

from __future__ import annotations

import copy
from typing import Any


ANALYTICAL_FIELDS = (
    "event_status", "detection_validity", "activity_disposition", "handling",
    "duplicate_of", "detection_outcome", "escalation_needed",
)


def _completed_shadow_result(adjudication: Any) -> dict[str, Any] | None:
    if not isinstance(adjudication, dict):
        return None
    result = adjudication.get("response")
    if (
        adjudication.get("status") != "completed"
        or adjudication.get("mode") != "shadow"
        or adjudication.get("automation_authorized") is not False
        or not isinstance(result, dict)
    ):
        return None
    return result


def _validation_allows_projection(validation: Any) -> bool:
    return bool(
        isinstance(validation, dict)
        and validation.get("valid") is True
        and validation.get("automation_authorized") is False
    )


def _remaining_disagreements(result: dict[str, Any]) -> set[str]:
    remaining = result.get("remaining_disagreements")
    if not isinstance(remaining, list):
        return set()
    return {
        str(item or "").strip()
        for item in remaining
        if str(item or "").strip()
    }


def _validated_decision(adjudication: Any) -> tuple[str, dict[str, Any]] | None:
    result = _completed_shadow_result(adjudication)
    if result is None:
        return None
    validation = result.get("_adjudication_contract_validation")
    decision = str(result.get("decision") or "").strip().lower()
    if (
        not _validation_allows_projection(validation)
        or decision not in {"primary_supported", "reviewer_supported"}
        or _remaining_disagreements(result)
    ):
        return None
    return decision, result


def _validated_graph(response: dict[str, Any]) -> dict[str, Any] | None:
    graph = response.get("claim_evidence_graph")
    validation = graph.get("validation") if isinstance(graph, dict) else None
    if not isinstance(validation, dict) or validation.get("valid") is not True:
        return None
    claims = graph.get("claims")
    return graph if isinstance(claims, list) else None


def _material_claims(graph: dict[str, Any] | None) -> list[dict[str, Any]]:
    if graph is None:
        return []
    return [
        copy.deepcopy(item) for item in graph["claims"]
        if isinstance(item, dict) and item.get("material") is True
    ][:100]


def _review_history(
    primary: dict[str, Any], reviewer: dict[str, Any], result: dict[str, Any],
) -> dict[str, Any] | None:
    original = _material_claims(_validated_graph(primary))
    corrected = _material_claims(_validated_graph(reviewer))
    rationale = str(result.get("rationale") or "").strip()[:4000]
    evidence = result.get("evidence_used")
    evidence = [str(item)[:512] for item in evidence[:100]] if isinstance(evidence, list) else []
    if not original or not corrected or not rationale or not evidence:
        return None
    return {
        "schema": "onion-sentinel-claim-review-history-v1",
        "original_claims": original,
        "corrected_claims": corrected,
        "correction_reason": rationale,
        "adjudication_evidence_refs": evidence,
    }


def _project_reviewer_graph(
    primary: dict[str, Any], reviewer: dict[str, Any], result: dict[str, Any],
) -> dict[str, Any] | None:
    selected = _validated_graph(reviewer)
    history = _review_history(primary, reviewer, result)
    if selected is None or history is None:
        return None
    projected = copy.deepcopy(selected)
    prior = projected.get("review_history")
    review_history = list(prior) if isinstance(prior, list) else []
    review_history.append(history)
    projected["review_history"] = review_history[-20:]
    primary["claim_evidence_graph"] = projected
    primary["_claim_evidence_validation"] = copy.deepcopy(projected["validation"])
    primary_evidence = primary.get("evidence_used")
    reviewer_evidence = reviewer.get("evidence_used")
    merged = [
        str(item)[:512] for values in (primary_evidence, reviewer_evidence)
        if isinstance(values, list) for item in values
    ]
    primary["evidence_used"] = list(dict.fromkeys(merged))[:100]
    return history


def _claim_projection(
    primary: dict[str, Any], reviewer: dict[str, Any],
    decision: str, result: dict[str, Any],
) -> tuple[bool, dict[str, Any] | None]:
    advertised = "claim_evidence_graph" in primary or "claim_evidence_graph" in reviewer
    history = (
        _project_reviewer_graph(primary, reviewer, result)
        if decision == "reviewer_supported" else None
    )
    valid = not (decision == "reviewer_supported" and advertised and history is None)
    return valid, history


def _copy_analytical_fields(
    primary: dict[str, Any], chosen: dict[str, Any],
) -> None:
    for key in ANALYTICAL_FIELDS:
        primary[key] = chosen.get(key)
    if isinstance(chosen.get("scope_dispositions"), dict):
        primary["scope_dispositions"] = dict(chosen["scope_dispositions"])


def apply(
    primary_response: dict[str, Any], reviewer_response: dict[str, Any],
    adjudication: Any,
) -> bool:
    """Project one supported position without granting operational authority."""
    validated = _validated_decision(adjudication)
    if validated is None:
        return False
    decision, result = validated
    chosen = primary_response if decision == "primary_supported" else reviewer_response
    before = {key: primary_response.get(key) for key in ANALYTICAL_FIELDS}
    graph_valid, claim_history = _claim_projection(
        primary_response, reviewer_response, decision, result,
    )
    if not graph_valid:
        return False
    _copy_analytical_fields(primary_response, chosen)
    primary_response["_analytical_adjudication_projection"] = {
        "schema": "onion-sentinel-analytical-adjudication-projection-v1",
        "applied": True, "selected_position": decision,
        "resolved_fields": list(result.get("resolved_fields") or [])[:16],
        "remaining_disagreements": [], "before": before,
        "after": {key: primary_response.get(key) for key in ANALYTICAL_FIELDS},
        "claim_review_history": claim_history,
        "automation_authorized": False, "human_adjudication_required": True,
    }
    return True
