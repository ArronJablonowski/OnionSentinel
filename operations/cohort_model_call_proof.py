#!/usr/bin/env python3
"""Offline recomputation of bounded cohort model-call execution proofs."""
from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Any, Callable, Mapping


MODEL_CALL_CONTRACT_SCHEMA = "onion-sentinel-model-call-contract-v1"
MAX_RUNTIME_MODEL_CALLS = 6
SAFE_ROUTE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/+-]{2,255}")
MODEL_CALL_FACT_KEYS = frozenset(
    {"call_id", "purpose", "requested_route", "independent_review", "status"}
)
PRIMARY_MODEL_CALLS = {
    "primary-initial": "initial primary analysis",
    "primary-query-planning-retry-1": "evaluation query-planning retry 1 of 1",
}
QUERY_PLANNING_REPAIR_CALL_ID = "primary-query-planning-repair-1"
QUERY_PLANNING_REPAIR_PURPOSE = "primary query-planning repair 1 of 1"
FOLLOWUP_CALL_RE = re.compile(r"primary-followup-([1-3])")
REVIEWER_CALL_IDS = ("independent-review-1", "independent-review-2")
REVIEWER_PURPOSE = "independent second-opinion review"
SUPPLEMENTAL_REVIEW_CALL_ID = "independent-review-supplemental-1"
SUPPLEMENTAL_REVIEW_PURPOSE = (
    "independent reviewer supplemental reconciliation round 1"
)
ADJUDICATION_CALL_IDS = (
    "disagreement-adjudication-1",
    "disagreement-adjudication-2",
)
ADJUDICATION_PURPOSE = "bounded disagreement adjudication"


@dataclass
class FactLedger:
    primary_route: str
    reviewer_route: str
    call_ids: list[str] = field(default_factory=list)
    followup_rounds: list[int] = field(default_factory=list)
    planning_repair_rounds: list[int] = field(default_factory=list)
    reviewer_facts: list[Mapping[str, Any]] = field(default_factory=list)
    supplemental_facts: list[Mapping[str, Any]] = field(default_factory=list)
    adjudicator_facts: list[Mapping[str, Any]] = field(default_factory=list)
    purpose_keys: set[tuple[bool, str, str]] = field(default_factory=set)
    completed_count: int = 0
    completed_primary_count: int = 0
    planning_count: int = 0
    planning_repair_count: int = 0
    next_primary_round: int = 1

    def record(
        self,
        call_id: str,
        purpose: str,
        route: str,
        status: str,
        independent: bool,
    ) -> None:
        self.call_ids.append(call_id)
        self.purpose_keys.add((independent, purpose, route))
        if status == "completed":
            self.completed_count += 1
            if not independent:
                self.completed_primary_count += 1


def _integer(source: Mapping[str, Any], field: str) -> int:
    return int(source.get(field) or 0)


def _base_contract_valid(
    contract: Mapping[str, Any],
    facts: Any,
    sha256_value: Callable[[Any], str],
) -> bool:
    checks = (
        contract.get("schema") == MODEL_CALL_CONTRACT_SCHEMA,
        contract.get("valid") is True,
        isinstance(facts, list),
        isinstance(facts, list) and 1 <= len(facts) <= MAX_RUNTIME_MODEL_CALLS,
        str(contract.get("facts_sha256") or "") == sha256_value(facts),
        isinstance(facts, list) and _integer(contract, "model_call_count") == len(facts),
        isinstance(facts, list)
        and _integer(contract, "canonical_model_call_count") == len(facts),
        _integer(contract, "noncanonical_model_call_count") == 0,
        _integer(contract, "violation_count") == 0,
        contract.get("violations") == [],
        contract.get("global_reasons") == [],
    )
    return all(checks)


def _fact_fields(fact: Any) -> tuple[str, str, str, str, bool] | None:
    if not isinstance(fact, dict) or set(fact) != MODEL_CALL_FACT_KEYS:
        return None
    call_id = str(fact.get("call_id") or "")
    purpose = str(fact.get("purpose") or "")
    route = str(fact.get("requested_route") or "")
    status = str(fact.get("status") or "")
    independent = fact.get("independent_review")
    if not call_id or not SAFE_ROUTE_RE.fullmatch(route):
        return None
    if not isinstance(independent, bool):
        return None
    return call_id, purpose, route, status, independent


def _primary_valid(
    ledger: FactLedger,
    call_id: str,
    purpose: str,
    route: str,
    status: str,
    independent: bool,
) -> bool:
    if call_id == "primary-query-planning-retry-1":
        ledger.planning_count += 1
    checks = (
        independent is False,
        purpose == PRIMARY_MODEL_CALLS[call_id],
        status == "completed",
        route == ledger.primary_route,
    )
    return all(checks)


def _planning_repair_valid(
    ledger: FactLedger,
    purpose: str,
    route: str,
    status: str,
    independent: bool,
) -> bool:
    ledger.planning_repair_count += 1
    ledger.planning_repair_rounds.append(ledger.next_primary_round)
    ledger.next_primary_round += 1
    checks = (
        independent is False,
        purpose == QUERY_PLANNING_REPAIR_PURPOSE,
        status == "completed",
        route == ledger.primary_route,
    )
    return all(checks)


def _followup_valid(
    ledger: FactLedger,
    match: re.Match[str],
    purpose: str,
    route: str,
    status: str,
    independent: bool,
) -> bool:
    round_number = int(match.group(1))
    ledger.followup_rounds.append(round_number)
    checks = (
        round_number == ledger.next_primary_round,
        independent is False,
        purpose == f"primary investigation follow-up round {round_number}",
        status == "completed",
        route == ledger.primary_route,
    )
    ledger.next_primary_round += 1
    return all(checks)


def _supplemental_valid(
    ledger: FactLedger,
    fact: Mapping[str, Any],
    purpose: str,
    route: str,
    status: str,
    independent: bool,
) -> bool:
    ledger.supplemental_facts.append(fact)
    checks = (
        independent is True,
        purpose == SUPPLEMENTAL_REVIEW_PURPOSE,
        status == "completed",
        bool(ledger.reviewer_route),
        route == ledger.reviewer_route,
    )
    return all(checks)


def _independent_fact_valid(
    ledger: FactLedger,
    fact: Mapping[str, Any],
    call_id: str,
    purpose: str,
    route: str,
    status: str,
    independent: bool,
    *,
    adjudication: bool,
) -> bool:
    ids = ADJUDICATION_CALL_IDS if adjudication else REVIEWER_CALL_IDS
    expected_purpose = ADJUDICATION_PURPOSE if adjudication else REVIEWER_PURPOSE
    target = ledger.adjudicator_facts if adjudication else ledger.reviewer_facts
    target.append(fact)
    allowed = {"completed", "validation-failed"} if call_id == ids[0] else {"completed"}
    checks = (
        independent is True,
        purpose == expected_purpose,
        status in allowed,
        bool(ledger.reviewer_route),
        route == ledger.reviewer_route,
    )
    return all(checks)


def _classify_fact(ledger: FactLedger, fact: Any) -> bool:
    fields = _fact_fields(fact)
    if fields is None:
        return False
    call_id, purpose, route, status, independent = fields
    ledger.record(call_id, purpose, route, status, independent)
    if call_id in PRIMARY_MODEL_CALLS:
        return _primary_valid(ledger, *fields)
    if call_id == QUERY_PLANNING_REPAIR_CALL_ID:
        return _planning_repair_valid(ledger, purpose, route, status, independent)
    followup = FOLLOWUP_CALL_RE.fullmatch(call_id)
    if followup:
        return _followup_valid(ledger, followup, purpose, route, status, independent)
    if call_id == SUPPLEMENTAL_REVIEW_CALL_ID:
        return _supplemental_valid(ledger, fact, purpose, route, status, independent)
    if call_id in ADJUDICATION_CALL_IDS:
        return _independent_fact_valid(
            ledger, fact, *fields, adjudication=True
        )
    if call_id in REVIEWER_CALL_IDS:
        return _independent_fact_valid(
            ledger, fact, *fields, adjudication=False
        )
    return False


def _primary_sequence_valid(ledger: FactLedger) -> bool:
    unique_followups = sorted(set(ledger.followup_rounds))
    rounds = sorted(ledger.followup_rounds + ledger.planning_repair_rounds)
    unique_rounds = sorted(set(rounds))
    contiguous = not unique_rounds or unique_rounds == list(
        range(1, max(unique_rounds) + 1)
    )
    checks = (
        len(ledger.call_ids) == len(set(ledger.call_ids)),
        ledger.call_ids.count("primary-initial") == 1,
        ledger.planning_count in {0, 1},
        ledger.planning_repair_count in {0, 1},
        len(unique_followups) == len(ledger.followup_rounds),
        len(unique_rounds) == len(rounds),
        contiguous,
        len(unique_rounds) <= (2 if ledger.planning_count else 3),
    )
    return all(checks)


def _repair_count(
    facts: list[Mapping[str, Any]],
    ids: tuple[str, str],
) -> int | None:
    if not facts:
        return 0
    actual_ids = [str(fact["call_id"]) for fact in facts]
    statuses = [str(fact["status"]) for fact in facts]
    if actual_ids == [ids[0]] and statuses == ["completed"]:
        return 0
    if actual_ids == list(ids) and statuses == ["validation-failed", "completed"]:
        return 1
    return None


def _aggregate_counts_valid(
    harness: Mapping[str, Any],
    contract: Mapping[str, Any],
    ledger: FactLedger,
    facts: list[Any],
    reviewer_repair: int,
    adjudication_repair: int,
) -> bool:
    reviewer_count = len(ledger.reviewer_facts) + len(ledger.supplemental_facts)
    repairs = reviewer_repair + adjudication_repair
    checks = (
        _integer(contract, "primary_initial_call_count") == 1,
        _integer(contract, "query_planning_call_count") == ledger.planning_count,
        _integer(contract, "query_planning_repair_call_count") == ledger.planning_repair_count,
        _integer(contract, "primary_followup_call_count") == len(ledger.followup_rounds),
        _integer(contract, "reviewer_model_call_count") == reviewer_count,
        _integer(contract, "adjudicator_model_call_count") == len(ledger.adjudicator_facts),
        _integer(harness, "model_call_count") == len(facts),
        _integer(harness, "successful_model_call_count") == ledger.completed_count,
        _integer(harness, "successful_primary_model_call_count")
        == ledger.completed_primary_count,
        _integer(harness, "model_purpose_count") == len(ledger.purpose_keys),
        _integer(harness, "exact_reviewer_repair_count") == reviewer_repair,
        _integer(harness, "exact_adjudication_repair_count") == adjudication_repair,
        _integer(harness, "superseded_validation_failure_count") == repairs,
    )
    return all(checks)


def _reviewer_counts_valid(
    reviewer: Mapping[str, Any],
    ledger: FactLedger,
    reviewer_repair: int,
) -> bool:
    total = len(ledger.reviewer_facts) + len(ledger.supplemental_facts)
    supplemental = len(ledger.supplemental_facts)
    checks = (
        _integer(reviewer, "model_call_count") == total,
        _integer(reviewer, "completed_model_call_count") == total - reviewer_repair,
        _integer(reviewer, "supplemental_model_call_count") == supplemental,
        _integer(reviewer, "supplemental_completed_model_call_count") == supplemental,
    )
    return all(checks)


def _reviewer_completion_valid(
    reviewer: Mapping[str, Any],
    ledger: FactLedger,
    reviewer_repair: int,
) -> bool:
    calls = _integer(reviewer, "model_call_count")
    supplemental = len(ledger.supplemental_facts)
    if not calls:
        checks = (
            reviewer.get("completion_contract_required") is False,
            reviewer.get("completion_contract_satisfied") is True,
            reviewer.get("completion_contract_failure_reasons") == [],
            _integer(reviewer, "reviewer_decision_count") == 0,
            reviewer.get("has_reviewer_decision") is False,
            reviewer.get("missing_reviewer_decision") is False,
        )
        return all(checks)
    checks = (
        _integer(reviewer, "completed_model_call_count") == 1 + supplemental,
        _integer(reviewer, "primary_decision_count") == 1,
        _integer(reviewer, "reviewer_decision_count") == 1,
        reviewer.get("has_primary_decision") is True,
        reviewer.get("has_reviewer_decision") is True,
        reviewer.get("decision_comparable") is True,
        reviewer.get("missing_reviewer_decision") is False,
        reviewer.get("completion_contract_required") is True,
        reviewer.get("completion_contract_satisfied") is True,
        reviewer.get("completion_contract_failure_reasons") == [],
        calls == 1 + reviewer_repair + supplemental,
    )
    return all(checks)


def _classify_facts(ledger: FactLedger, facts: list[Any]) -> bool:
    return all(_classify_fact(ledger, fact) for fact in facts)


def _repair_counts(
    ledger: FactLedger,
) -> tuple[int, int] | None:
    reviewer = _repair_count(ledger.reviewer_facts, REVIEWER_CALL_IDS)
    adjudication = _repair_count(
        ledger.adjudicator_facts, ADJUDICATION_CALL_IDS
    )
    if reviewer is None or adjudication is None:
        return None
    if len(ledger.supplemental_facts) not in {0, 1}:
        return None
    return reviewer, adjudication


def _final_counts_valid(
    harness: Mapping[str, Any],
    contract: Mapping[str, Any],
    reviewer: Mapping[str, Any],
    ledger: FactLedger,
    facts: list[Any],
    repairs: tuple[int, int],
) -> bool:
    reviewer_repair, adjudication_repair = repairs
    checks = (
        _aggregate_counts_valid(
            harness,
            contract,
            ledger,
            facts,
            reviewer_repair,
            adjudication_repair,
        ),
        _reviewer_counts_valid(reviewer, ledger, reviewer_repair),
        _reviewer_completion_valid(reviewer, ledger, reviewer_repair),
    )
    return all(checks)


def bounded_model_call_proof_valid(
    harness: Mapping[str, Any],
    sha256_value: Callable[[Any], str],
) -> bool:
    contract = harness.get("model_call_contract")
    reviewer = harness.get("reviewer_completion")
    if not isinstance(contract, dict) or not isinstance(reviewer, dict):
        return False
    facts = contract.get("facts")
    if not _base_contract_valid(contract, facts, sha256_value):
        return False
    ledger = FactLedger(
        primary_route=str(harness.get("assigned_route") or ""),
        reviewer_route=str(harness.get("assigned_reviewer_route") or ""),
    )
    if not _classify_facts(ledger, facts):
        return False
    if not _primary_sequence_valid(ledger):
        return False
    repairs = _repair_counts(ledger)
    if repairs is None:
        return False
    return _final_counts_valid(
        harness, contract, reviewer, ledger, facts, repairs
    )
