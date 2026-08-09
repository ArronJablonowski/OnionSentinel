#!/usr/bin/env python3
"""Project reviewer evidence and enforce its completion contract."""
from __future__ import annotations

import collections
import json
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping, Sequence


@dataclass(frozen=True)
class ReviewerEvaluationPolicy:
    reviewer_purpose: str
    reviewer_call_ids: Sequence[str]
    supplemental_purpose: str
    supplemental_call_id: str
    material_fields: Sequence[str]
    normalize_status: Callable[[object], str]
    nonnegative_int: Callable[[object], int]


def decision_payloads(
    decisions: Iterable[Mapping[str, Any]],
    malformed: collections.Counter[str],
) -> dict[str, dict[str, Any]]:
    output: dict[str, dict[str, Any]] = {}
    for row in decisions:
        decision_id = str(row.get("decision_id") or "")
        decision_type = str(row.get("decision_type") or "")
        payload = _decision_payload(row.get("payload_json"), malformed)
        output[decision_id or decision_type] = payload
        if decision_type:
            output.setdefault(decision_type, payload)
    return output


def _decision_payload(
    value: object, malformed: collections.Counter[str]
) -> dict[str, Any]:
    if not isinstance(value, str):
        malformed["decision.payload_json"] += 1
        return {}
    try:
        decoded = json.loads(value)
    except (TypeError, ValueError, json.JSONDecodeError):
        malformed["decision.payload_json"] += 1
        return {}
    if not isinstance(decoded, dict):
        malformed["decision.payload_json"] += 1
        return {}
    return decoded


def _review_calls(
    model_calls: Iterable[Mapping[str, Any]], policy: ReviewerEvaluationPolicy
) -> tuple[list[Mapping[str, Any]], list[Mapping[str, Any]]]:
    reviewer = [
        row
        for row in model_calls
        if _is_reviewer_call(row, policy)
    ]
    supplemental = [
        row
        for row in model_calls
        if _is_supplemental_call(row, policy)
    ]
    return reviewer, supplemental


def _is_reviewer_call(
    row: Mapping[str, Any], policy: ReviewerEvaluationPolicy
) -> bool:
    return bool(
        int(row.get("independent_review") or 0) == 1
        and str(row.get("purpose") or "") == policy.reviewer_purpose
        and str(row.get("call_id") or "") in policy.reviewer_call_ids
    )


def _is_supplemental_call(
    row: Mapping[str, Any], policy: ReviewerEvaluationPolicy
) -> bool:
    return bool(
        int(row.get("independent_review") or 0) == 1
        and str(row.get("purpose") or "") == policy.supplemental_purpose
        and str(row.get("call_id") or "") == policy.supplemental_call_id
    )


def _decision_count(
    decisions: Iterable[Mapping[str, Any]], decision_id: str, decision_type: str
) -> int:
    return sum(
        str(row.get("decision_id") or "") == decision_id
        and str(row.get("decision_type") or "") == decision_type
        for row in decisions
    )


def reviewer_result(
    model_calls: list[dict[str, Any]],
    decisions: list[dict[str, Any]],
    malformed: collections.Counter[str],
    policy: ReviewerEvaluationPolicy,
) -> dict[str, Any]:
    reviewer_calls, supplemental_calls = _review_calls(model_calls, policy)
    payloads = decision_payloads(decisions, malformed)
    primary = payloads.get("primary")
    reviewer = payloads.get("independent-review")
    comparable = isinstance(primary, dict) and isinstance(reviewer, dict)
    disputed = (
        [
            field
            for field in policy.material_fields
            if primary.get(field) != reviewer.get(field)
        ]
        if comparable
        else []
    )
    completed = lambda rows: sum(
        policy.normalize_status(row.get("status")) == "completed" for row in rows
    )
    return {
        "model_call_count": len(reviewer_calls) + len(supplemental_calls),
        "completed_model_call_count": completed(reviewer_calls + supplemental_calls),
        "supplemental_model_call_count": len(supplemental_calls),
        "supplemental_completed_model_call_count": completed(supplemental_calls),
        "primary_decision_count": _decision_count(
            decisions, "primary", "primary-analysis"
        ),
        "reviewer_decision_count": _decision_count(
            decisions, "independent-review", "independent-review"
        ),
        "has_primary_decision": isinstance(primary, dict),
        "has_reviewer_decision": isinstance(reviewer, dict),
        "comparison_basis": "primary_vs_independent-review" if comparable else "",
        "decision_comparable": comparable,
        "material_disagreement": bool(disputed),
        "disputed_fields": disputed,
        "missing_reviewer_decision": bool(reviewer_calls)
        and not isinstance(reviewer, dict),
    }


def _completion_checks(
    reviewer: Mapping[str, Any],
    call_count: int,
    exact_repair_count: int,
    supplemental_count: int,
    integer: Callable[[object], int],
) -> tuple[tuple[bool, str], ...]:
    return (
        (
            integer(reviewer.get("completed_model_call_count"))
            == 1 + supplemental_count,
            "completed-reviewer-call-count-invalid",
        ),
        (
            integer(reviewer.get("primary_decision_count")) == 1,
            "primary-decision-count-not-one",
        ),
        (
            integer(reviewer.get("reviewer_decision_count")) == 1,
            "reviewer-decision-count-not-one",
        ),
        (reviewer.get("has_primary_decision") is True, "primary-decision-missing"),
        (reviewer.get("has_reviewer_decision") is True, "reviewer-decision-missing"),
        (reviewer.get("decision_comparable") is True, "reviewer-decision-not-comparable"),
        (reviewer.get("missing_reviewer_decision") is False, "reviewer-decision-marked-missing"),
        (
            call_count == 1 + exact_repair_count + supplemental_count,
            "reviewer-call-count-does-not-match-repair",
        ),
        (
            supplemental_count in {0, 1},
            "supplemental-reviewer-call-count-invalid",
        ),
        (
            integer(reviewer.get("supplemental_completed_model_call_count"))
            == supplemental_count,
            "supplemental-reviewer-call-not-completed",
        ),
    )


def reviewer_completion_contract(
    reviewer: Mapping[str, Any],
    purpose_completion: Mapping[str, Any],
    policy: ReviewerEvaluationPolicy,
) -> dict[str, Any]:
    integer = policy.nonnegative_int
    call_count = integer(reviewer.get("model_call_count"))
    exact_repair = integer(purpose_completion.get("exact_reviewer_repair_count"))
    supplemental = integer(reviewer.get("supplemental_model_call_count"))
    required = call_count > 0
    failures = (
        [
            reason
            for valid, reason in _completion_checks(
                reviewer, call_count, exact_repair, supplemental, integer
            )
            if not valid
        ]
        if required
        else []
    )
    return {
        "completion_contract_required": required,
        "completion_contract_satisfied": not failures,
        "completion_contract_failure_reasons": failures,
    }
