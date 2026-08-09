#!/usr/bin/env python3
"""Model-call and reviewer execution evidence for cohort proof gates."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping


@dataclass(frozen=True)
class ModelExecutionPolicy:
    contract_schema: str
    maximum_model_calls: int
    sha256_value: Callable[[Any], str]


@dataclass(frozen=True)
class ModelExecutionEvidence:
    model_call_count: int
    successful_model_call_count: int
    model_purpose_count: int
    terminally_successful_model_purpose_count: int
    incomplete_model_purpose_count: int
    exact_reviewer_repair_count: int
    exact_adjudication_repair_count: int
    superseded_validation_failure_count: int
    unexpected_unsuccessful_model_call_count: int
    malformed_model_purpose_sequence_count: int
    reviewer_model_call_count: int
    reviewer_completed_model_call_count: int
    reviewer_supplemental_model_call_count: int
    reviewer_supplemental_completed_model_call_count: int
    reviewer_primary_decision_count: int
    reviewer_decision_count: int
    model_call_contract: dict[str, Any]
    reviewer_completion: dict[str, Any]
    failures: tuple[str, ...]


def _integer(source: Mapping[str, Any], field: str) -> int:
    return int(source.get(field) or 0)


def _model_counts(
    trace: Mapping[str, Any],
    models: Mapping[str, Any],
) -> dict[str, int]:
    counts = trace.get("counts")
    counts = counts if isinstance(counts, dict) else {}
    return {
        "model_call_count": _integer(counts, "model_calls"),
        "successful_model_call_count": _integer(models, "successful_call_count"),
        "model_purpose_count": _integer(models, "purpose_count"),
        "terminally_successful_model_purpose_count": _integer(
            models, "terminally_successful_purpose_count"
        ),
        "incomplete_model_purpose_count": _integer(
            models, "incomplete_purpose_count"
        ),
        "exact_reviewer_repair_count": _integer(
            models, "exact_reviewer_repair_count"
        ),
        "exact_adjudication_repair_count": _integer(
            models, "exact_adjudication_repair_count"
        ),
        "superseded_validation_failure_count": _integer(
            models, "superseded_validation_failure_count"
        ),
        "unexpected_unsuccessful_model_call_count": _integer(
            models, "unexpected_unsuccessful_call_count"
        ),
        "malformed_model_purpose_sequence_count": _integer(
            models, "malformed_purpose_sequence_count"
        ),
    }


def _reviewer_counts(reviewer: Mapping[str, Any]) -> dict[str, int]:
    return {
        "reviewer_model_call_count": _integer(reviewer, "model_call_count"),
        "reviewer_completed_model_call_count": _integer(
            reviewer, "completed_model_call_count"
        ),
        "reviewer_supplemental_model_call_count": _integer(
            reviewer, "supplemental_model_call_count"
        ),
        "reviewer_supplemental_completed_model_call_count": _integer(
            reviewer, "supplemental_completed_model_call_count"
        ),
        "reviewer_primary_decision_count": _integer(
            reviewer, "primary_decision_count"
        ),
        "reviewer_decision_count": _integer(reviewer, "reviewer_decision_count"),
    }


def _reviewer_with_calls_valid(
    reviewer: Mapping[str, Any],
    counts: Mapping[str, int],
) -> bool:
    calls = counts["reviewer_model_call_count"]
    supplemental = counts["reviewer_supplemental_model_call_count"]
    checks = (
        counts["reviewer_completed_model_call_count"] == 1 + supplemental,
        counts["reviewer_primary_decision_count"] == 1,
        counts["reviewer_decision_count"] == 1,
        reviewer.get("has_primary_decision") is True,
        reviewer.get("has_reviewer_decision") is True,
        reviewer.get("decision_comparable") is True,
        reviewer.get("missing_reviewer_decision") is False,
        calls == 1 + counts["exact_reviewer_repair_count"] + supplemental,
        supplemental in {0, 1},
        counts["reviewer_supplemental_completed_model_call_count"] == supplemental,
        reviewer.get("completion_contract_required") is True,
        reviewer.get("completion_contract_satisfied") is True,
        reviewer.get("completion_contract_failure_reasons") == [],
    )
    return all(checks)


def _reviewer_without_calls_valid(
    reviewer: Mapping[str, Any],
    counts: Mapping[str, int],
) -> bool:
    checks = (
        counts["reviewer_completed_model_call_count"] == 0,
        counts["reviewer_decision_count"] == 0,
        reviewer.get("has_reviewer_decision") is False,
        reviewer.get("missing_reviewer_decision") is False,
        reviewer.get("completion_contract_required") is False,
        reviewer.get("completion_contract_satisfied") is True,
        reviewer.get("completion_contract_failure_reasons") == [],
    )
    return all(checks)


def _model_call_contract_valid(
    contract: Mapping[str, Any],
    facts: Any,
    counts: Mapping[str, int],
    policy: ModelExecutionPolicy,
) -> bool:
    model_calls = counts["model_call_count"]
    checks = (
        contract.get("schema") == policy.contract_schema,
        contract.get("valid") is True,
        _integer(contract, "model_call_count") == model_calls,
        _integer(contract, "canonical_model_call_count") == model_calls,
        _integer(contract, "noncanonical_model_call_count") == 0,
        _integer(contract, "primary_initial_call_count") == 1,
        _integer(contract, "violation_count") == 0,
        contract.get("violations") == [],
        contract.get("global_reasons") == [],
        isinstance(facts, list),
        isinstance(facts, list) and len(facts) == model_calls,
        isinstance(facts, list) and len(facts) <= policy.maximum_model_calls,
        str(contract.get("facts_sha256") or "") == policy.sha256_value(facts),
        _integer(contract, "reviewer_model_call_count")
        == counts["reviewer_model_call_count"],
    )
    return all(checks)


def _model_purposes_valid(counts: Mapping[str, int]) -> bool:
    successful = counts["successful_model_call_count"]
    purposes = counts["model_purpose_count"]
    superseded = counts["superseded_validation_failure_count"]
    repairs = (
        counts["exact_reviewer_repair_count"]
        + counts["exact_adjudication_repair_count"]
    )
    checks = (
        purposes >= 1,
        counts["terminally_successful_model_purpose_count"] == purposes,
        counts["incomplete_model_purpose_count"] == 0,
        successful == purposes,
        counts["model_call_count"] == successful + superseded,
        repairs == superseded,
        counts["exact_reviewer_repair_count"] in {0, 1},
        counts["exact_adjudication_repair_count"] in {0, 1},
        counts["unexpected_unsuccessful_model_call_count"] == 0,
        counts["malformed_model_purpose_sequence_count"] == 0,
    )
    return all(checks)


def _contract_summary(
    contract: Mapping[str, Any],
    facts: Any,
) -> dict[str, Any]:
    fields = (
        "model_call_count",
        "canonical_model_call_count",
        "noncanonical_model_call_count",
        "primary_initial_call_count",
        "query_planning_call_count",
        "query_planning_repair_call_count",
        "primary_followup_call_count",
        "reviewer_model_call_count",
        "adjudicator_model_call_count",
        "violation_count",
    )
    summary = {field: _integer(contract, field) for field in fields}
    summary.update(
        {
            "schema": str(contract.get("schema") or ""),
            "valid": contract.get("valid") is True,
            "facts": list(facts or []),
            "facts_sha256": str(contract.get("facts_sha256") or ""),
            "violations": list(contract.get("violations") or []),
            "global_reasons": list(contract.get("global_reasons") or []),
        }
    )
    return summary


def _reviewer_summary(
    reviewer: Mapping[str, Any],
    counts: Mapping[str, int],
) -> dict[str, Any]:
    return {
        **{key.removeprefix("reviewer_"): value for key, value in counts.items()},
        "has_primary_decision": reviewer.get("has_primary_decision") is True,
        "has_reviewer_decision": reviewer.get("has_reviewer_decision") is True,
        "decision_comparable": reviewer.get("decision_comparable") is True,
        "missing_reviewer_decision": reviewer.get("missing_reviewer_decision") is True,
        "completion_contract_required": (
            reviewer.get("completion_contract_required") is True
        ),
        "completion_contract_satisfied": (
            reviewer.get("completion_contract_satisfied") is True
        ),
        "completion_contract_failure_reasons": list(
            reviewer.get("completion_contract_failure_reasons") or []
        ),
    }


def evaluate_model_execution(
    trace: Mapping[str, Any],
    models: Mapping[str, Any],
    reviewer: Mapping[str, Any],
    model_call_contract: Mapping[str, Any],
    *,
    reviewer_required: bool,
    policy: ModelExecutionPolicy,
) -> ModelExecutionEvidence:
    counts = {**_model_counts(trace, models), **_reviewer_counts(reviewer)}
    facts = model_call_contract.get("facts")
    failures: list[str] = []
    reviewer_calls = counts["reviewer_model_call_count"]
    if reviewer_required and reviewer_calls < 1:
        failures.append("harness-required-reviewer-call-missing")
    reviewer_valid = (
        _reviewer_with_calls_valid(reviewer, counts)
        if reviewer_calls > 0
        else _reviewer_without_calls_valid(reviewer, counts)
    )
    if not reviewer_valid:
        failures.append("harness-reviewer-completion-incomplete")
    if not _model_call_contract_valid(model_call_contract, facts, counts, policy):
        failures.append("harness-model-call-contract-noncanonical")
    if not _model_purposes_valid(counts):
        failures.append("harness-model-purpose-incomplete")
    return ModelExecutionEvidence(
        **counts,
        model_call_contract=_contract_summary(model_call_contract, facts),
        reviewer_completion=_reviewer_summary(reviewer, _reviewer_counts(reviewer)),
        failures=tuple(failures),
    )
