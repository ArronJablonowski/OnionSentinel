#!/usr/bin/env python3
"""Classify bounded model-purpose completion and exact repair sequences."""
from __future__ import annotations

import collections
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence


@dataclass(frozen=True)
class ModelPurposePolicy:
    success_statuses: frozenset[str]
    validation_failed_status: str
    reviewer_purpose: str
    reviewer_ids: Sequence[str]
    supplemental_purpose: str
    supplemental_id: str
    adjudication_purpose: str
    adjudication_ids: Sequence[str]
    maximum_reported: int
    normalize_status: Callable[[object], str]


@dataclass(frozen=True)
class _GroupResult:
    summary: dict[str, Any]
    terminal_success: bool
    exact_reviewer_repair: bool
    exact_adjudication_repair: bool
    malformed: bool
    superseded_call_id: str


def _ordered_calls(
    model_calls: Sequence[Mapping[str, Any]],
) -> list[tuple[int, Mapping[str, Any]]]:
    return sorted(
        (
            (ordinal, row)
            for ordinal, row in enumerate(model_calls)
            if isinstance(row, dict)
        ),
        key=lambda item: (
            str(item[1].get("created_at") or ""),
            str(item[1].get("call_id") or ""),
            item[0],
        ),
    )


def _group_calls(
    ordered: Sequence[tuple[int, Mapping[str, Any]]],
    policy: ModelPurposePolicy,
) -> tuple[
    dict[tuple[bool, str, str], list[Mapping[str, Any]]], dict[str, str]
]:
    groups: dict[tuple[bool, str, str], list[Mapping[str, Any]]] = {}
    classifications: dict[str, str] = {}
    for ordinal, row in ordered:
        independent = int(row.get("independent_review") or 0) == 1
        purpose = str(row.get("purpose") or "")
        route = str(row.get("requested_route") or "")
        groups.setdefault((independent, purpose, route), []).append(row)
        call_id = str(row.get("call_id") or f"ordinal-{ordinal}")
        classifications[call_id] = (
            "successful"
            if policy.normalize_status(row.get("status")) in policy.success_statuses
            else "unexpected-unsuccessful"
        )
    return groups, classifications


def _group_shape(
    calls: Sequence[Mapping[str, Any]], policy: ModelPurposePolicy
) -> tuple[list[str], list[str], bool]:
    call_ids = [str(row.get("call_id") or "") for row in calls]
    statuses = [policy.normalize_status(row.get("status")) for row in calls]
    terminal = bool(statuses and statuses[-1] in policy.success_statuses)
    return call_ids, statuses, terminal


def _group_kinds(
    independent: bool,
    purpose: str,
    call_ids: Sequence[str],
    policy: ModelPurposePolicy,
) -> tuple[bool, bool]:
    adjudication = bool(
        purpose == policy.adjudication_purpose
        or any(call_id.startswith("disagreement-adjudication-") for call_id in call_ids)
    )
    reviewer = bool(
        (independent and not adjudication)
        or purpose == policy.reviewer_purpose
        or any(call_id.startswith("independent-review-") for call_id in call_ids)
    )
    return reviewer, adjudication


def _valid_single(
    independent: bool,
    purpose: str,
    route: str,
    call_ids: Sequence[str],
    terminal: bool,
    reviewer_like: bool,
    adjudication_like: bool,
    reviewer: Mapping[str, Any],
    policy: ModelPurposePolicy,
) -> bool:
    if len(call_ids) != 1 or not terminal or not purpose or not route:
        return False
    if not reviewer_like and not adjudication_like:
        return True
    return _valid_special_single(
        independent, purpose, call_ids[0], reviewer, policy
    )


def _valid_special_single(
    independent: bool,
    purpose: str,
    call_id: str,
    reviewer: Mapping[str, Any],
    policy: ModelPurposePolicy,
) -> bool:
    reviewer_single = bool(
        independent
        and purpose == policy.reviewer_purpose
        and call_id == policy.reviewer_ids[0]
        and reviewer.get("has_reviewer_decision") is True
    )
    adjudication_single = bool(
        independent
        and purpose == policy.adjudication_purpose
        and call_id == policy.adjudication_ids[0]
    )
    supplemental_single = bool(
        independent
        and purpose == policy.supplemental_purpose
        and call_id == policy.supplemental_id
    )
    return reviewer_single or adjudication_single or supplemental_single


def _exact_reviewer_repair(
    independent: bool,
    purpose: str,
    route: str,
    call_ids: Sequence[str],
    statuses: Sequence[str],
    reviewer_like: bool,
    reviewer: Mapping[str, Any],
    policy: ModelPurposePolicy,
) -> bool:
    return bool(
        reviewer_like
        and independent
        and purpose == policy.reviewer_purpose
        and route
        and call_ids == list(policy.reviewer_ids)
        and statuses[0] == policy.validation_failed_status
        and statuses[1] in policy.success_statuses
        and reviewer.get("has_reviewer_decision") is True
    )


def _exact_adjudication_repair(
    independent: bool,
    purpose: str,
    route: str,
    call_ids: Sequence[str],
    statuses: Sequence[str],
    adjudication_like: bool,
    policy: ModelPurposePolicy,
) -> bool:
    return bool(
        adjudication_like
        and independent
        and purpose == policy.adjudication_purpose
        and route
        and call_ids == list(policy.adjudication_ids)
        and statuses[0] == policy.validation_failed_status
        and statuses[1] in policy.success_statuses
    )


def _classify_group(
    key: tuple[bool, str, str],
    calls: Sequence[Mapping[str, Any]],
    reviewer: Mapping[str, Any],
    policy: ModelPurposePolicy,
) -> _GroupResult:
    independent, purpose, route = key
    call_ids, statuses, terminal = _group_shape(calls, policy)
    reviewer_like, adjudication_like = _group_kinds(
        independent, purpose, call_ids, policy
    )
    reviewer_repair = _exact_reviewer_repair(
        independent, purpose, route, call_ids, statuses,
        reviewer_like, reviewer, policy,
    )
    adjudication_repair = _exact_adjudication_repair(
        independent, purpose, route, call_ids, statuses,
        adjudication_like, policy,
    )
    valid_single = _valid_single(
        independent, purpose, route, call_ids, terminal,
        reviewer_like, adjudication_like, reviewer, policy,
    )
    if reviewer_repair:
        classification = "exact-reviewer-repair"
    elif adjudication_repair:
        classification = "exact-adjudication-repair"
    elif valid_single:
        classification = "single-success"
    else:
        classification = "malformed"
    return _GroupResult(
        summary={
            "independent_review": independent,
            "purpose": purpose[:160],
            "requested_route": route[:256],
            "call_ids": call_ids,
            "statuses": statuses,
            "terminally_successful": terminal,
            "sequence_classification": classification,
        },
        terminal_success=terminal,
        exact_reviewer_repair=reviewer_repair,
        exact_adjudication_repair=adjudication_repair,
        malformed=classification == "malformed",
        superseded_call_id=(
            call_ids[0] if reviewer_repair or adjudication_repair else ""
        ),
    )


def _classified_calls(
    ordered: Sequence[tuple[int, Mapping[str, Any]]],
    classifications: Mapping[str, str],
    policy: ModelPurposePolicy,
) -> list[dict[str, Any]]:
    return [
        {
            "call_id": str(row.get("call_id") or f"ordinal-{ordinal}"),
            "status": policy.normalize_status(row.get("status")),
            "classification": classifications[
                str(row.get("call_id") or f"ordinal-{ordinal}")
            ],
        }
        for ordinal, row in ordered
    ]


def model_purpose_completion(
    model_calls: Sequence[Mapping[str, Any]],
    reviewer: Mapping[str, Any],
    policy: ModelPurposePolicy,
) -> dict[str, Any]:
    ordered = _ordered_calls(model_calls)
    groups, classifications = _group_calls(ordered, policy)
    results = [
        _classify_group(key, calls, reviewer, policy)
        for key, calls in groups.items()
    ]
    for result in results:
        if result.superseded_call_id:
            classifications[result.superseded_call_id] = (
                "superseded-validation-failure"
            )
    classified = _classified_calls(ordered, classifications, policy)
    counts = collections.Counter(item["classification"] for item in classified)
    terminal = sum(result.terminal_success for result in results)
    reviewer_repairs = sum(result.exact_reviewer_repair for result in results)
    adjudication_repairs = sum(
        result.exact_adjudication_repair for result in results
    )
    return {
        "purpose_count": len(groups),
        "terminally_successful_purpose_count": terminal,
        "incomplete_purpose_count": len(groups) - terminal,
        "exact_reviewer_repair_count": reviewer_repairs,
        "exact_adjudication_repair_count": adjudication_repairs,
        "superseded_validation_failure_count": reviewer_repairs
        + adjudication_repairs,
        "unexpected_unsuccessful_call_count": counts.get(
            "unexpected-unsuccessful", 0
        ),
        "malformed_purpose_sequence_count": sum(
            result.malformed for result in results
        ),
        "call_status_classification_counts": dict(sorted(counts.items())),
        "call_status_classifications": classified[: policy.maximum_reported],
        "purpose_summaries": [result.summary for result in results][
            : policy.maximum_reported
        ],
    }
