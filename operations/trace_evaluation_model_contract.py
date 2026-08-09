#!/usr/bin/env python3
"""Build the canonical bounded model-call contract from trace ledger rows."""
from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Any, Callable, Mapping, Pattern, Sequence


@dataclass(frozen=True)
class ModelCallContractPolicy:
    schema: str
    maximum_calls: int
    primary_initial_id: str
    primary_initial_purpose: str
    query_planning_id: str
    query_planning_purpose: str
    query_planning_repair_id: str
    query_planning_repair_purpose: str
    followup_pattern: Pattern[str]
    reviewer_ids: Sequence[str]
    reviewer_purpose: str
    supplemental_id: str
    supplemental_purpose: str
    adjudication_ids: Sequence[str]
    adjudication_purpose: str
    validation_failed_status: str
    normalize_status: Callable[[object], str]
    digest_value: Callable[[Any], str]


@dataclass
class _State:
    facts: list[dict[str, Any]] = field(default_factory=list)
    violations: list[dict[str, Any]] = field(default_factory=list)
    followup_rounds: list[int] = field(default_factory=list)
    repair_rounds: list[int] = field(default_factory=list)
    primary_initial_count: int = 0
    query_planning_count: int = 0
    repair_count: int = 0
    next_primary_round: int = 1
    canonical_count: int = 0


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


def _fact(
    row: Mapping[str, Any], policy: ModelCallContractPolicy
) -> dict[str, Any]:
    return {
        "call_id": str(row.get("call_id") or ""),
        "purpose": str(row.get("purpose") or ""),
        "requested_route": str(row.get("requested_route") or ""),
        "independent_review": int(row.get("independent_review") or 0) == 1,
        "status": policy.normalize_status(row.get("status")),
    }


def _append_mismatch(
    reasons: list[str], valid: bool, reason: str
) -> None:
    if not valid:
        reasons.append(reason)


def _primary_reasons(
    fact: Mapping[str, Any], state: _State, policy: ModelCallContractPolicy
) -> list[str]:
    state.primary_initial_count += 1
    reasons: list[str] = []
    _append_mismatch(
        reasons,
        fact["purpose"] == policy.primary_initial_purpose,
        "primary-initial-purpose-mismatch",
    )
    _append_mismatch(
        reasons, not fact["independent_review"], "primary-initial-marked-reviewer"
    )
    _append_mismatch(
        reasons, fact["status"] == "completed", "primary-initial-status-not-completed"
    )
    return reasons


def _planning_reasons(
    fact: Mapping[str, Any], state: _State, policy: ModelCallContractPolicy
) -> list[str]:
    state.query_planning_count += 1
    reasons: list[str] = []
    _append_mismatch(
        reasons,
        fact["purpose"] == policy.query_planning_purpose,
        "query-planning-purpose-mismatch",
    )
    _append_mismatch(
        reasons, not fact["independent_review"], "query-planning-marked-reviewer"
    )
    _append_mismatch(
        reasons, fact["status"] == "completed", "query-planning-status-not-completed"
    )
    return reasons


def _planning_repair_reasons(
    fact: Mapping[str, Any], state: _State, policy: ModelCallContractPolicy
) -> list[str]:
    state.repair_count += 1
    state.repair_rounds.append(state.next_primary_round)
    state.next_primary_round += 1
    reasons: list[str] = []
    _append_mismatch(
        reasons,
        fact["purpose"] == policy.query_planning_repair_purpose,
        "query-planning-repair-purpose-mismatch",
    )
    _append_mismatch(
        reasons,
        not fact["independent_review"],
        "query-planning-repair-marked-reviewer",
    )
    _append_mismatch(
        reasons,
        fact["status"] == "completed",
        "query-planning-repair-status-not-completed",
    )
    return reasons


def _followup_reasons(
    fact: Mapping[str, Any],
    match: re.Match[str],
    state: _State,
) -> list[str]:
    round_number = int(match.group(1))
    state.followup_rounds.append(round_number)
    reasons: list[str] = []
    _append_mismatch(
        reasons,
        round_number == state.next_primary_round,
        "primary-followup-round-out-of-sequence",
    )
    state.next_primary_round += 1
    _append_mismatch(
        reasons,
        fact["purpose"] == f"primary investigation follow-up round {round_number}",
        "primary-followup-purpose-mismatch",
    )
    _append_mismatch(
        reasons, not fact["independent_review"], "primary-followup-marked-reviewer"
    )
    _append_mismatch(
        reasons, fact["status"] == "completed", "primary-followup-status-not-completed"
    )
    return reasons


def _independent_reasons(
    fact: Mapping[str, Any],
    ids: Sequence[str],
    purpose: str,
    reason_prefix: str,
    policy: ModelCallContractPolicy,
) -> list[str]:
    attempt = ids.index(str(fact["call_id"])) + 1
    allowed = (
        {"completed", policy.validation_failed_status}
        if attempt == 1
        else {"completed"}
    )
    reasons: list[str] = []
    _append_mismatch(
        reasons, fact["purpose"] == purpose, f"{reason_prefix}-purpose-mismatch"
    )
    _append_mismatch(
        reasons,
        bool(fact["independent_review"]),
        f"{reason_prefix}-call-not-marked-independent",
    )
    _append_mismatch(
        reasons, fact["status"] in allowed, f"{reason_prefix}-status-not-canonical"
    )
    return reasons


def _supplemental_reasons(
    fact: Mapping[str, Any], policy: ModelCallContractPolicy
) -> list[str]:
    reasons: list[str] = []
    _append_mismatch(
        reasons,
        fact["purpose"] == policy.supplemental_purpose,
        "supplemental-reviewer-purpose-mismatch",
    )
    _append_mismatch(
        reasons,
        bool(fact["independent_review"]),
        "supplemental-reviewer-call-not-independent",
    )
    _append_mismatch(
        reasons,
        fact["status"] == "completed",
        "supplemental-reviewer-status-not-completed",
    )
    return reasons


def _call_reasons(
    fact: Mapping[str, Any], state: _State, policy: ModelCallContractPolicy
) -> list[str]:
    call_id = str(fact["call_id"])
    followup = policy.followup_pattern.fullmatch(call_id)
    if call_id == policy.primary_initial_id:
        reasons = _primary_reasons(fact, state, policy)
    elif call_id == policy.query_planning_id:
        reasons = _planning_reasons(fact, state, policy)
    elif call_id == policy.query_planning_repair_id:
        reasons = _planning_repair_reasons(fact, state, policy)
    elif followup:
        reasons = _followup_reasons(fact, followup, state)
    elif call_id in policy.reviewer_ids:
        reasons = _independent_reasons(
            fact, policy.reviewer_ids, policy.reviewer_purpose, "reviewer", policy
        )
    elif call_id == policy.supplemental_id:
        reasons = _supplemental_reasons(fact, policy)
    elif call_id in policy.adjudication_ids:
        reasons = _independent_reasons(
            fact,
            policy.adjudication_ids,
            policy.adjudication_purpose,
            "adjudication",
            policy,
        )
    else:
        reasons = ["unknown-model-call-id"]
    if not fact["requested_route"]:
        reasons.append("requested-route-missing")
    return reasons


def _record_call(
    ordinal: int,
    row: Mapping[str, Any],
    state: _State,
    policy: ModelCallContractPolicy,
) -> None:
    fact = _fact(row, policy)
    reasons = _call_reasons(fact, state, policy)
    if len(state.facts) < policy.maximum_calls:
        state.facts.append(fact)
    if reasons:
        if len(state.violations) < policy.maximum_calls:
            state.violations.append(
                {"call_id": fact["call_id"] or f"ordinal-{ordinal}", "reasons": reasons}
            )
    else:
        state.canonical_count += 1


def _global_reasons(
    call_count: int, state: _State, policy: ModelCallContractPolicy
) -> list[str]:
    reasons: list[str] = []
    checks = (
        (call_count <= policy.maximum_calls, "model-call-budget-exceeded"),
        (state.primary_initial_count == 1, "primary-initial-count-not-one"),
        (state.query_planning_count in {0, 1}, "query-planning-count-invalid"),
        (state.repair_count in {0, 1}, "query-planning-repair-count-invalid"),
    )
    for valid, reason in checks:
        _append_mismatch(reasons, valid, reason)
    unique_followups = sorted(set(state.followup_rounds))
    _append_mismatch(
        reasons,
        len(unique_followups) == len(state.followup_rounds),
        "duplicate-primary-followup-round",
    )
    rounds = sorted(state.followup_rounds + state.repair_rounds)
    unique_rounds = sorted(set(rounds))
    _append_mismatch(
        reasons, len(unique_rounds) == len(rounds), "duplicate-primary-round-slot"
    )
    contiguous = not unique_rounds or unique_rounds == list(
        range(1, max(unique_rounds) + 1)
    )
    _append_mismatch(reasons, contiguous, "noncontiguous-primary-rounds")
    maximum_rounds = 2 if state.query_planning_count else 3
    _append_mismatch(
        reasons, len(unique_rounds) <= maximum_rounds, "too-many-primary-rounds"
    )
    return reasons


def canonical_model_call_contract(
    model_calls: Sequence[Mapping[str, Any]], policy: ModelCallContractPolicy
) -> dict[str, Any]:
    ordered = _ordered_calls(model_calls)
    state = _State()
    for ordinal, row in ordered:
        _record_call(ordinal, row, state, policy)
    global_reasons = _global_reasons(len(ordered), state, policy)
    reviewer_ids = set(policy.reviewer_ids) | {policy.supplemental_id}
    return {
        "schema": policy.schema,
        "valid": not state.violations and not global_reasons,
        "model_call_count": len(ordered),
        "canonical_model_call_count": state.canonical_count,
        "noncanonical_model_call_count": len(ordered) - state.canonical_count,
        "primary_initial_call_count": state.primary_initial_count,
        "query_planning_call_count": state.query_planning_count,
        "query_planning_repair_call_count": state.repair_count,
        "primary_followup_call_count": len(state.followup_rounds),
        "reviewer_model_call_count": sum(
            str(row.get("call_id") or "") in reviewer_ids for _ordinal, row in ordered
        ),
        "adjudicator_model_call_count": sum(
            str(row.get("call_id") or "") in policy.adjudication_ids
            for _ordinal, row in ordered
        ),
        "facts": state.facts,
        "facts_sha256": policy.digest_value(state.facts),
        "violation_count": len(state.violations) + len(global_reasons),
        "violations": state.violations,
        "global_reasons": global_reasons,
    }
