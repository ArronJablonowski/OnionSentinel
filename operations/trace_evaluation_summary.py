#!/usr/bin/env python3
"""Aggregate bounded per-run harness evaluations into the stable report schema."""
from __future__ import annotations

import collections
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping


DIMENSIONS = (
    "statuses", "roles", "task_kinds", "policy_modes", "model_names",
    "model_providers", "model_purposes", "model_statuses", "tool_backends",
    "tool_capabilities", "tool_statuses", "tool_coverage", "source_classes",
    "trust_tiers", "review_disputes", "budget_names", "memory_reasons",
    "coverage_reasons", "route_authorization_reasons", "model_identity_reasons",
)


@dataclass(frozen=True)
class TraceSummaryPolicy:
    report_schema: str
    terminal_statuses: frozenset[str]
    optional_tables: frozenset[str]
    maximum_reported: int


@dataclass(frozen=True)
class TraceSummaryServices:
    normalize_status: Callable[[object], str]
    counter_dict: Callable[[collections.Counter[str]], dict[str, int]]
    ratio: Callable[[int, int], float | None]
    utc_now: Callable[[], str]
    rows_for_run: Callable[..., list[dict[str, Any]]]


@dataclass
class _Aggregate:
    counters: dict[str, collections.Counter[str]] = field(
        default_factory=lambda: {
            name: collections.Counter() for name in DIMENSIONS
        }
    )
    metrics: collections.Counter[str] = field(default_factory=collections.Counter)
    ids: dict[str, list[str]] = field(
        default_factory=lambda: collections.defaultdict(list)
    )
    source_diversity: list[int] = field(default_factory=list)


def _counter(state: _Aggregate, name: str) -> collections.Counter[str]:
    return state.counters[name]


def _add(state: _Aggregate, name: str, value: object) -> None:
    state.metrics[name] += int(value or 0)


def _accumulate_skill(
    state: _Aggregate, run_id: str, result: Mapping[str, Any]
) -> None:
    skill = result["skill_selection_attestation"]
    _add(state, "skill_attestation_present", skill["present"])
    _add(state, "skill_attestation_valid", skill["valid"])
    _add(state, "skill_attestation_ready", skill["mandatory_ready"])
    _add(state, "skill_attestation_legacy", skill["legacy"])
    _add(state, "skill_attestation_unavailable", not skill["available"])
    if not skill["valid"]:
        state.ids["skill_attestation_invalid"].append(run_id)


def _accumulate_identity(
    state: _Aggregate,
    result: Mapping[str, Any],
    services: TraceSummaryServices,
) -> None:
    _counter(state, "statuses")[services.normalize_status(result["status"])] += 1
    _counter(state, "roles")[result["role"] or "unknown"] += 1
    _counter(state, "task_kinds")[result["task_kind"] or "unknown"] += 1
    _counter(state, "policy_modes")[result["policy_mode"] or "unknown"] += 1
    for source, target in (
        ("events", "total_events"), ("evidence", "total_evidence"),
        ("hypotheses", "total_hypotheses"), ("decisions", "total_decisions"),
        ("model_calls", "total_model_calls"), ("tool_calls", "total_tool_calls"),
    ):
        _add(state, target, result["counts"][source])


def _accumulate_models(state: _Aggregate, result: Mapping[str, Any]) -> None:
    models = result["models"]
    mappings = (
        ("duration_ms", "total_model_ms"),
        ("independent_review_calls", "independent_review_calls"),
        ("purpose_count", "model_purpose_count"),
        ("terminally_successful_purpose_count", "terminally_successful_model_purposes"),
        ("incomplete_purpose_count", "incomplete_model_purposes"),
        ("exact_reviewer_repair_count", "exact_reviewer_repairs"),
        ("superseded_validation_failure_count", "superseded_validation_failures"),
        ("unexpected_unsuccessful_call_count", "unexpected_unsuccessful_model_calls"),
        ("malformed_purpose_sequence_count", "malformed_model_purpose_sequences"),
    )
    for source, target in mappings:
        _add(state, target, models[source])
    contract = models["model_call_contract"]
    _add(state, "noncanonical_model_calls", contract["noncanonical_model_call_count"])
    _add(state, "invalid_model_call_contract_runs", contract["valid"] is not True)


def _accumulate_routes(
    state: _Aggregate, run_id: str, result: Mapping[str, Any]
) -> None:
    route = result["models"]["route_consistency"]
    mappings = (
        ("authorization_failure_count", "route_authorization_failures"),
        ("authorization_denied_event_count", "route_authorization_denials"),
        ("observation_denied_event_count", "model_observation_denials"),
        ("authorization_unverified_call_count", "route_authorization_unverified"),
        ("identity_mismatch_count", "model_identity_mismatches"),
        ("identity_unverified_call_count", "model_identity_unverified"),
    )
    for source, target in mappings:
        _add(state, target, route[source])
    if route["authorization_failure_count"]:
        state.ids["route_authorization_failure"].append(run_id)
    if route["identity_mismatch_count"]:
        state.ids["model_identity_failure"].append(run_id)
    for failure in route["authorization_failures"]:
        _counter(state, "route_authorization_reasons").update(failure["reasons"])
    for failure in route["identity_failures"]:
        _counter(state, "model_identity_reasons").update(failure["reasons"])


def _accumulate_tools_and_evidence(
    state: _Aggregate, run_id: str, result: Mapping[str, Any]
) -> None:
    tools = result["tools"]
    for source, target in (
        ("successful_call_count", "successful_tools"),
        ("read_only_call_count", "read_only_tools"),
        ("rejected_count", "rejected_tools"),
        ("failed_count", "failed_tools"),
        ("coverage_gap_count", "coverage_gap_tools"),
        ("truncated_count", "truncated_tools"),
        ("read_only_violation_count", "read_only_violations"),
    ):
        _add(state, target, tools[source])
    evidence = result["evidence"]
    _add(state, "corroborating_evidence", evidence["corroborating_count"])
    state.source_diversity.append(evidence["distinct_source_classes"])
    if not result["integrity"]["valid"]:
        state.ids["integrity_invalid"].append(run_id)
    if result["coverage_gap_reasons"]:
        state.ids["coverage_gap"].append(run_id)
        _counter(state, "coverage_reasons").update(result["coverage_gap_reasons"])


def _accumulate_reviewer(state: _Aggregate, result: Mapping[str, Any]) -> None:
    reviewer = result["reviewer"]
    _add(state, "reviewer_runs", bool(reviewer["model_call_count"]))
    _add(state, "comparable_reviews", reviewer["decision_comparable"])
    _add(state, "reviewer_disagreements", reviewer["material_disagreement"])
    if reviewer["material_disagreement"]:
        _counter(state, "review_disputes").update(reviewer["disputed_fields"])
    _add(state, "missing_reviewer_decisions", reviewer["missing_reviewer_decision"])
    _add(
        state,
        "reviewer_completion_failure_runs",
        reviewer["completion_contract_satisfied"] is not True,
    )


def _accumulate_budget_and_memory(
    state: _Aggregate, result: Mapping[str, Any]
) -> None:
    for name, count in result["budget_violations"].items():
        _counter(state, "budget_names")[name] += count
    _add(state, "budget_violation_runs", bool(result["budget_violations"]))
    _add(
        state,
        "budget_violation_operation_count",
        len(result["budget_violation_operations"]),
    )
    for promotion in result["memory_promotions"]:
        _add(state, "memory_decisions", 1)
        _add(state, "memory_candidates", promotion["candidate_count"])
        _add(state, "memory_allowed", promotion["allowed"])
        _add(state, "memory_blocked", not promotion["allowed"])
        _add(state, "memory_requires_approval", promotion["requires_approval"])
        _counter(state, "memory_reasons")[promotion["reason"] or "unspecified"] += 1


def _accumulate_raw_ledgers(
    state: _Aggregate,
    connection: Any,
    available_tables: set[str],
    run_id: str,
    services: TraceSummaryServices,
) -> None:
    _accumulate_model_rows(
        state,
        services.rows_for_run(
            connection, available_tables, "harness_model_calls", run_id,
            "created_at, call_id",
        ),
        services,
    )
    _accumulate_tool_rows(
        state,
        services.rows_for_run(
            connection, available_tables, "harness_tool_calls", run_id,
            "round_number, call_id",
        ),
        services,
    )
    _accumulate_evidence_rows(
        state,
        services.rows_for_run(
            connection, available_tables, "harness_evidence", run_id, "evidence_ref"
        ),
    )


def _accumulate_model_rows(
    state: _Aggregate,
    rows: list[dict[str, Any]],
    services: TraceSummaryServices,
) -> None:
    for row in rows:
        name = str(row.get("observed_model") or row.get("requested_route") or "unknown")
        _counter(state, "model_names")[name] += 1
        _counter(state, "model_providers")[str(row.get("observed_provider") or "unknown")] += 1
        _counter(state, "model_purposes")[str(row.get("purpose") or "unknown")] += 1
        status = services.normalize_status(row.get("status")) or "unknown"
        _counter(state, "model_statuses")[status] += 1


def _accumulate_tool_rows(
    state: _Aggregate,
    rows: list[dict[str, Any]],
    services: TraceSummaryServices,
) -> None:
    for row in rows:
        _counter(state, "tool_backends")[str(row.get("backend") or "unknown")] += 1
        _counter(state, "tool_capabilities")[str(row.get("capability") or "unknown")] += 1
        status = services.normalize_status(row.get("status")) or "unknown"
        coverage = services.normalize_status(row.get("coverage")) or "unknown"
        _counter(state, "tool_statuses")[status] += 1
        _counter(state, "tool_coverage")[coverage] += 1


def _accumulate_evidence_rows(
    state: _Aggregate, rows: list[dict[str, Any]]
) -> None:
    for row in rows:
        _counter(state, "source_classes")[str(row.get("source_class") or "unknown")] += 1
        _counter(state, "trust_tiers")[str(row.get("trust_tier") or "unknown")] += 1


def _accumulate_result(
    state: _Aggregate,
    connection: Any,
    available_tables: set[str],
    result: Mapping[str, Any],
    services: TraceSummaryServices,
) -> None:
    run_id = result["run_id"]
    _accumulate_skill(state, run_id, result)
    _accumulate_identity(state, result, services)
    _accumulate_models(state, result)
    _accumulate_routes(state, run_id, result)
    _accumulate_tools_and_evidence(state, run_id, result)
    _accumulate_reviewer(state, result)
    _accumulate_budget_and_memory(state, result)
    _accumulate_raw_ledgers(state, connection, available_tables, run_id, services)


def _completion(
    state: _Aggregate, run_count: int, policy: TraceSummaryPolicy,
    services: TraceSummaryServices,
) -> dict[str, Any]:
    statuses = _counter(state, "statuses")
    terminal = sum(count for status, count in statuses.items() if status in policy.terminal_statuses)
    succeeded = statuses.get("succeeded", 0)
    return {
        "status_counts": services.counter_dict(statuses),
        "terminal_runs": terminal,
        "terminal_rate": services.ratio(terminal, run_count),
        "succeeded_runs": succeeded,
        "success_rate": services.ratio(succeeded, run_count),
    }


def _integrity(state: _Aggregate, run_count: int, limit: int) -> dict[str, Any]:
    invalid = state.ids["integrity_invalid"]
    return {
        "all_chains_valid": not invalid and run_count > 0,
        "valid_run_count": run_count - len(invalid),
        "invalid_run_count": len(invalid),
        "invalid_run_ids": invalid[:limit],
        "event_count": state.metrics["total_events"],
    }


def _skill_summary(state: _Aggregate, limit: int) -> dict[str, Any]:
    invalid = state.ids["skill_attestation_invalid"]
    return {
        "present_run_count": state.metrics["skill_attestation_present"],
        "valid_run_count": state.metrics["skill_attestation_valid"],
        "mandatory_ready_run_count": state.metrics["skill_attestation_ready"],
        "legacy_run_count": state.metrics["skill_attestation_legacy"],
        "unavailable_run_count": state.metrics["skill_attestation_unavailable"],
        "invalid_run_count": len(invalid),
        "invalid_run_ids": invalid[:limit],
    }


def _models_summary(
    state: _Aggregate, run_count: int, limit: int, services: TraceSummaryServices
) -> dict[str, Any]:
    metrics = state.metrics
    calls = metrics["total_model_calls"]
    route_ids = state.ids["route_authorization_failure"]
    identity_ids = state.ids["model_identity_failure"]
    return {
        "call_count": calls,
        "calls_per_run": services.ratio(calls, run_count),
        "duration_ms": metrics["total_model_ms"],
        "average_duration_ms": round(metrics["total_model_ms"] / calls) if calls else None,
        "independent_review_call_count": metrics["independent_review_calls"],
        "purpose_count": metrics["model_purpose_count"],
        "terminally_successful_purpose_count": metrics["terminally_successful_model_purposes"],
        "incomplete_purpose_count": metrics["incomplete_model_purposes"],
        "exact_reviewer_repair_count": metrics["exact_reviewer_repairs"],
        "superseded_validation_failure_count": metrics["superseded_validation_failures"],
        "unexpected_unsuccessful_call_count": metrics["unexpected_unsuccessful_model_calls"],
        "malformed_purpose_sequence_count": metrics["malformed_model_purpose_sequences"],
        "noncanonical_call_count": metrics["noncanonical_model_calls"],
        "invalid_call_contract_run_count": metrics["invalid_model_call_contract_runs"],
        "by_model": services.counter_dict(_counter(state, "model_names")),
        "by_provider": services.counter_dict(_counter(state, "model_providers")),
        "by_purpose": services.counter_dict(_counter(state, "model_purposes")),
        "by_status": services.counter_dict(_counter(state, "model_statuses")),
        "route_authorization": _route_summary(state, route_ids, limit, services),
        "runtime_identity": _identity_summary(state, identity_ids, limit, services),
    }


def _route_summary(
    state: _Aggregate, ids: list[str], limit: int, services: TraceSummaryServices
) -> dict[str, Any]:
    return {
        "failure_count": state.metrics["route_authorization_failures"],
        "failure_run_count": len(ids),
        "failure_run_ids": ids[:limit],
        "denied_event_count": state.metrics["route_authorization_denials"],
        "observation_denied_event_count": state.metrics["model_observation_denials"],
        "unverified_call_count": state.metrics["route_authorization_unverified"],
        "reason_counts": services.counter_dict(_counter(state, "route_authorization_reasons")),
    }


def _identity_summary(
    state: _Aggregate, ids: list[str], limit: int, services: TraceSummaryServices
) -> dict[str, Any]:
    return {
        "mismatch_count": state.metrics["model_identity_mismatches"],
        "mismatch_run_count": len(ids),
        "mismatch_run_ids": ids[:limit],
        "unverified_call_count": state.metrics["model_identity_unverified"],
        "reason_counts": services.counter_dict(_counter(state, "model_identity_reasons")),
    }


def _tools_summary(
    state: _Aggregate, run_count: int, services: TraceSummaryServices
) -> dict[str, Any]:
    m = state.metrics
    calls = m["total_tool_calls"]
    return {
        "call_count": calls,
        "successful_call_count": m["successful_tools"],
        "read_only_call_count": m["read_only_tools"],
        "calls_per_run": services.ratio(calls, run_count),
        "rejected_count": m["rejected_tools"],
        "rejection_rate": services.ratio(m["rejected_tools"], calls),
        "failed_count": m["failed_tools"],
        "failure_rate": services.ratio(m["failed_tools"], calls),
        "coverage_gap_count": m["coverage_gap_tools"],
        "coverage_gap_rate": services.ratio(m["coverage_gap_tools"], calls),
        "truncated_count": m["truncated_tools"],
        "truncation_rate": services.ratio(m["truncated_tools"], calls),
        "read_only_violation_count": m["read_only_violations"],
        "by_backend": services.counter_dict(_counter(state, "tool_backends")),
        "by_capability": services.counter_dict(_counter(state, "tool_capabilities")),
        "by_status": services.counter_dict(_counter(state, "tool_statuses")),
        "by_coverage": services.counter_dict(_counter(state, "tool_coverage")),
    }


def _evidence_summary(state: _Aggregate, services: TraceSummaryServices) -> dict[str, Any]:
    values = state.source_diversity
    average = round(sum(values) / len(values), 3) if values else None
    return {
        "catalogued_count": state.metrics["total_evidence"],
        "corroborating_count": state.metrics["corroborating_evidence"],
        "hypothesis_count": state.metrics["total_hypotheses"],
        "decision_count": state.metrics["total_decisions"],
        "source_class_counts": services.counter_dict(_counter(state, "source_classes")),
        "trust_tier_counts": services.counter_dict(_counter(state, "trust_tiers")),
        "average_distinct_source_classes_per_run": average,
        "minimum_distinct_source_classes_per_run": min(values) if values else None,
        "runs_with_fewer_than_two_source_classes": sum(value < 2 for value in values),
    }


def _reviewer_summary(state: _Aggregate, services: TraceSummaryServices) -> dict[str, Any]:
    m = state.metrics
    return {
        "runs_with_reviewer_calls": m["reviewer_runs"],
        "comparable_decision_runs": m["comparable_reviews"],
        "material_disagreement_runs": m["reviewer_disagreements"],
        "material_disagreement_rate": services.ratio(m["reviewer_disagreements"], m["comparable_reviews"]),
        "missing_reviewer_decision_runs": m["missing_reviewer_decisions"],
        "completion_contract_failure_runs": m["reviewer_completion_failure_runs"],
        "disputed_field_counts": services.counter_dict(_counter(state, "review_disputes")),
    }


def _budget_memory_coverage(
    state: _Aggregate, run_count: int, limit: int, services: TraceSummaryServices
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    m = state.metrics
    gap_ids = state.ids["coverage_gap"]
    budgets = {
        "violation_runs": m["budget_violation_runs"],
        "violation_run_rate": services.ratio(m["budget_violation_runs"], run_count),
        "violation_operation_count": m["budget_violation_operation_count"],
        "violation_counts": services.counter_dict(_counter(state, "budget_names")),
    }
    memory = {
        "decision_count": m["memory_decisions"], "allowed_count": m["memory_allowed"],
        "blocked_count": m["memory_blocked"],
        "requires_approval_count": m["memory_requires_approval"],
        "candidate_count": m["memory_candidates"],
        "reason_counts": services.counter_dict(_counter(state, "memory_reasons")),
    }
    coverage = {
        "runs_with_gaps": len(gap_ids),
        "run_gap_rate": services.ratio(len(gap_ids), run_count),
        "run_ids": gap_ids[:limit],
        "reason_counts": services.counter_dict(_counter(state, "coverage_reasons")),
    }
    return budgets, memory, coverage


def summarize(
    connection: Any,
    db_path: Path,
    run_results: list[dict[str, Any]],
    available_tables: set[str],
    malformed: collections.Counter[str],
    selected_run_id: str | None,
    database_schema: int | None,
    policy: TraceSummaryPolicy,
    services: TraceSummaryServices,
) -> dict[str, Any]:
    """Aggregate selected immutable run evaluations into the report schema."""
    state = _Aggregate()
    for result in run_results:
        _accumulate_result(state, connection, available_tables, result, services)
    run_count = len(run_results)
    budgets, memory, coverage = _budget_memory_coverage(
        state, run_count, policy.maximum_reported, services
    )
    return {
        "schema": policy.report_schema,
        "generated_at": services.utc_now(),
        "database": str(db_path.expanduser()),
        "selected_run_id": selected_run_id,
        "run_count": run_count,
        "completion": _completion(state, run_count, policy, services),
        "integrity": _integrity(state, run_count, policy.maximum_reported),
        "workload": {
            "role_counts": services.counter_dict(_counter(state, "roles")),
            "task_kind_counts": services.counter_dict(_counter(state, "task_kinds")),
            "policy_mode_counts": services.counter_dict(_counter(state, "policy_modes")),
        },
        "skill_selection_attestation": _skill_summary(state, policy.maximum_reported),
        "models": _models_summary(state, run_count, policy.maximum_reported, services),
        "tools": _tools_summary(state, run_count, services),
        "evidence": _evidence_summary(state, services),
        "reviewer": _reviewer_summary(state, services),
        "budgets": budgets,
        "memory_promotion": memory,
        "coverage": coverage,
        "data_quality": {
            "database_schema_version": database_schema,
            "available_tables": sorted(available_tables),
            "missing_optional_tables": sorted(policy.optional_tables - available_tables),
            "malformed_json_counts": services.counter_dict(malformed),
        },
        "runs": run_results,
    }
