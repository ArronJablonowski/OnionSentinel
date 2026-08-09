#!/usr/bin/env python3
"""Compose one content-free investigation trace evaluation result."""
from __future__ import annotations

import collections
from dataclasses import dataclass
from typing import Any, Callable, Mapping


@dataclass(frozen=True)
class TraceRunPolicy:
    run_identity_columns: tuple[str, ...]
    trusted_source_tiers: frozenset[str]
    rejection_statuses: frozenset[str]
    failure_statuses: frozenset[str]
    success_statuses: frozenset[str]
    unresolved_hypothesis_statuses: frozenset[str]
    maximum_reported: int


@dataclass(frozen=True)
class TraceRunServices:
    rows_for_run: Callable[..., list[dict[str, Any]]]
    normalize_status: Callable[[object], str]
    safe_json: Callable[..., Any]
    nonnegative_int: Callable[[object], int]
    unresolved_tool_coverage_gaps: Callable[..., list[str]]
    budget_operation_id: Callable[..., str]
    reviewer_result: Callable[..., dict[str, Any]]
    model_purpose_completion: Callable[..., dict[str, Any]]
    reviewer_completion_contract: Callable[..., dict[str, Any]]
    canonical_model_call_contract: Callable[..., dict[str, Any]]
    model_route_consistency: Callable[..., dict[str, Any]]
    skill_selection_attestation_result: Callable[..., dict[str, Any]]
    terminal_execution_summary: Callable[..., dict[str, Any]]
    verify_chain: Callable[..., dict[str, Any]]
    digest_json: Callable[[object], str]


@dataclass(frozen=True)
class _Ledgers:
    events: list[dict[str, Any]]
    evidence: list[dict[str, Any]]
    hypotheses: list[dict[str, Any]]
    decisions: list[dict[str, Any]]
    model_calls: list[dict[str, Any]]
    tool_calls: list[dict[str, Any]]
    budget_reservations: list[dict[str, Any]]


@dataclass(frozen=True)
class _ToolProjection:
    rejected: list[str]
    failed: list[str]
    coverage_gaps: list[str]
    truncated: list[str]
    read_only_violations: list[str]
    successful: list[str]
    read_only: list[str]
    bindings: list[dict[str, Any]]


@dataclass(frozen=True)
class _EventProjection:
    type_counts: collections.Counter[str]
    stages: set[str]
    budget_violations: collections.Counter[str]
    budget_operations: list[dict[str, Any]]
    memory_promotions: list[dict[str, Any]]


def _load_ledgers(
    connection: Any,
    available_tables: set[str],
    run_id: str,
    services: TraceRunServices,
) -> _Ledgers:
    read = services.rows_for_run
    return _Ledgers(
        events=read(connection, available_tables, "harness_events", run_id, "sequence"),
        evidence=read(connection, available_tables, "harness_evidence", run_id, "evidence_ref"),
        hypotheses=read(connection, available_tables, "harness_hypotheses", run_id, "hypothesis_id"),
        decisions=read(connection, available_tables, "harness_decisions", run_id, "created_at, decision_id"),
        model_calls=read(connection, available_tables, "harness_model_calls", run_id, "created_at, call_id"),
        tool_calls=read(connection, available_tables, "harness_tool_calls", run_id, "round_number, call_id"),
        budget_reservations=read(
            connection,
            available_tables,
            "harness_budget_reservations",
            run_id,
            "reservation_type, reservation_id",
        ),
    )


def _integrity_ledgers(
    run: Mapping[str, Any],
    ledgers: _Ledgers,
    policy: TraceRunPolicy,
) -> dict[str, list[dict[str, Any]]]:
    return {
        "harness_run_identity": [
            {key: run[key] for key in policy.run_identity_columns if key in run}
        ],
        "harness_evidence": ledgers.evidence,
        "harness_hypotheses": ledgers.hypotheses,
        "harness_decisions": ledgers.decisions,
        "harness_model_calls": ledgers.model_calls,
        "harness_tool_calls": ledgers.tool_calls,
        "harness_budget_reservations": ledgers.budget_reservations,
    }


def _source_classes(
    evidence: list[dict[str, Any]],
    policy: TraceRunPolicy,
    services: TraceRunServices,
) -> list[str]:
    return sorted(
        {
            str(row.get("source_class") or "unknown")
            for row in evidence
            if str(row.get("source_class") or "")
            and int(row.get("corroborating") or 0) == 1
            and services.normalize_status(row.get("trust_tier"))
            in policy.trusted_source_tiers
        }
    )


def _call_ids_with_status(
    calls: list[dict[str, Any]],
    statuses: frozenset[str],
    services: TraceRunServices,
) -> list[str]:
    return [
        str(row.get("call_id") or "")
        for row in calls
        if services.normalize_status(row.get("status")) in statuses
    ]


def _call_ids_with_flag(
    calls: list[dict[str, Any]], key: str, expected: int
) -> list[str]:
    return [
        str(row.get("call_id") or "")
        for row in calls
        if int(row.get(key) or 0) == expected
    ]


def _call_ids_without_flag(
    calls: list[dict[str, Any]], key: str, expected: int
) -> list[str]:
    return [
        str(row.get("call_id") or "")
        for row in calls
        if int(row.get(key) or 0) != expected
    ]


def _read_only_bindings(
    tool_calls: list[dict[str, Any]],
    policy: TraceRunPolicy,
    services: TraceRunServices,
) -> list[dict[str, Any]]:
    bindings = [
        _tool_binding(row, services)
        for row in tool_calls
        if services.normalize_status(row.get("status")) in policy.success_statuses
        and int(row.get("read_only") or 0) == 1
    ]
    bindings.sort(key=lambda item: (int(item["round_number"]), str(item["call_id"])))
    return bindings


def _tool_binding(
    row: Mapping[str, Any], services: TraceRunServices
) -> dict[str, Any]:
    round_number = services.nonnegative_int(row.get("round_number"))
    call_id = str(row.get("call_id") or "")
    prefix = f"round-{round_number}-"
    query_id = call_id[len(prefix) :] if call_id.startswith(prefix) else ""
    return {
        "call_id": call_id,
        "round_number": round_number,
        "query_id": query_id,
        "backend": str(row.get("backend") or ""),
        "status": services.normalize_status(row.get("status")),
        "request_digest": str(row.get("request_digest") or ""),
        "result_digest": str(row.get("result_digest") or ""),
        "read_only": True,
    }


def _tool_projection(
    tool_calls: list[dict[str, Any]],
    policy: TraceRunPolicy,
    services: TraceRunServices,
) -> _ToolProjection:
    return _ToolProjection(
        rejected=_call_ids_with_status(tool_calls, policy.rejection_statuses, services),
        failed=_call_ids_with_status(tool_calls, policy.failure_statuses, services),
        coverage_gaps=services.unresolved_tool_coverage_gaps(tool_calls),
        truncated=_call_ids_with_flag(tool_calls, "truncated", 1),
        read_only_violations=_call_ids_without_flag(tool_calls, "read_only", 1),
        successful=_call_ids_with_status(tool_calls, policy.success_statuses, services),
        read_only=_call_ids_with_flag(tool_calls, "read_only", 1),
        bindings=_read_only_bindings(tool_calls, policy, services),
    )


def _event_projection(
    events: list[dict[str, Any]],
    malformed: collections.Counter[str],
    services: TraceRunServices,
) -> _EventProjection:
    type_counts: collections.Counter[str] = collections.Counter()
    stages: set[str] = set()
    violation_sources: dict[tuple[str, str], set[str]] = {}
    memory_promotions: list[dict[str, Any]] = []
    for event in events:
        event_type = str(event.get("event_type") or "")
        type_counts[event_type] += 1
        stages.add(str(event.get("stage") or ""))
        payload = services.safe_json(
            event.get("payload_json"), {}, malformed, "event.payload_json"
        )
        _record_policy_event(
            event, event_type, payload, violation_sources, memory_promotions, services
        )
    violations = collections.Counter(
        violation for _operation_id, violation in violation_sources
    )
    operations = [
        {"operation_id": operation_id, "violation": violation, "sources": sorted(sources)}
        for (operation_id, violation), sources in sorted(violation_sources.items())
    ]
    return _EventProjection(type_counts, stages, violations, operations, memory_promotions)


def _record_policy_event(
    event: Mapping[str, Any],
    event_type: str,
    payload: Mapping[str, Any],
    violation_sources: dict[tuple[str, str], set[str]],
    memory_promotions: list[dict[str, Any]],
    services: TraceRunServices,
) -> None:
    if event_type in {"policy.budget", "queries.completed"}:
        _record_budget_violations(
            event, event_type, payload, violation_sources, services
        )
    elif event_type == "policy.memory-promotion":
        memory_promotions.append(_memory_promotion(payload, services))


def _record_budget_violations(
    event: Mapping[str, Any],
    event_type: str,
    payload: Mapping[str, Any],
    violation_sources: dict[tuple[str, str], set[str]],
    services: TraceRunServices,
) -> None:
    key = "violations" if event_type == "policy.budget" else "budget_violations"
    values = payload.get(key)
    if not isinstance(values, list):
        return
    operation_id = services.budget_operation_id(event, payload)
    for value in values:
        violation = str(value or "").strip()
        if violation:
            violation_sources.setdefault((operation_id, violation), set()).add(event_type)


def _memory_promotion(
    payload: Mapping[str, Any], services: TraceRunServices
) -> dict[str, Any]:
    return {
        "allowed": bool(payload.get("allowed")),
        "requires_approval": bool(payload.get("requires_approval")),
        "candidate_count": services.nonnegative_int(payload.get("candidate_count")),
        "reason": str(payload.get("reason") or "")[:500],
    }


def _reviewer_and_models(
    ledgers: _Ledgers,
    malformed: collections.Counter[str],
    run: Mapping[str, Any],
    services: TraceRunServices,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    reviewer = services.reviewer_result(ledgers.model_calls, ledgers.decisions, malformed)
    completion = services.model_purpose_completion(ledgers.model_calls, reviewer)
    reviewer.update(services.reviewer_completion_contract(reviewer, completion))
    contract = services.canonical_model_call_contract(ledgers.model_calls)
    routes = services.model_route_consistency(
        run, ledgers.events, ledgers.model_calls, malformed
    )
    return reviewer, completion, contract, routes


def _coverage_reasons(
    ledgers: _Ledgers,
    tools: _ToolProjection,
    source_classes: list[str],
    reviewer: Mapping[str, Any],
    completion: Mapping[str, Any],
    contract: Mapping[str, Any],
    routes: Mapping[str, Any],
) -> list[str]:
    checks = (
        (not ledgers.evidence, "no-evidence-catalogue"),
        (not ledgers.model_calls, "no-model-call-ledger"),
        (not ledgers.tool_calls, "no-tool-call-ledger"),
        (bool(ledgers.tool_calls) and not tools.successful, "no-successful-tool-call-ledger"),
        (bool(tools.coverage_gaps), "tool-evidence-gap"),
        (bool(tools.truncated), "truncated-tool-results"),
        (len(source_classes) < 2, "fewer-than-two-evidence-source-classes"),
        (bool(tools.read_only_violations), "non-read-only-tool-call"),
        (bool(reviewer["missing_reviewer_decision"]), "reviewer-call-without-decision"),
        (reviewer["completion_contract_satisfied"] is not True, "reviewer-completion-contract-failed"),
        (contract["valid"] is not True, "noncanonical-model-call-contract"),
        (bool(completion["incomplete_purpose_count"]), "model-purpose-incomplete"),
        (bool(completion["malformed_purpose_sequence_count"]), "model-purpose-sequence-malformed"),
        (bool(completion["unexpected_unsuccessful_call_count"]), "unexpected-unsuccessful-model-call"),
        (bool(routes["authorization_failure_count"]), "model-route-authorization-failure"),
        (bool(routes["identity_mismatch_count"]), "model-runtime-identity-mismatch"),
    )
    return [reason for failed, reason in checks if failed]


def _identity_fields(run: Mapping[str, Any]) -> dict[str, str]:
    keys = (
        "run_id", "trace_id", "correlation_id", "case_id", "alert_id", "role",
        "task_kind", "status", "stage", "assigned_route", "assigned_reviewer_route",
        "policy_mode", "started_at", "completed_at",
    )
    return {key: str(run.get(key) or "") for key in keys}


def _counts(
    ledgers: _Ledgers,
    policy: TraceRunPolicy,
    services: TraceRunServices,
) -> dict[str, int]:
    unresolved = sum(
        services.normalize_status(row.get("status"))
        in policy.unresolved_hypothesis_statuses
        for row in ledgers.hypotheses
    )
    return {
        "events": len(ledgers.events),
        "evidence": len(ledgers.evidence),
        "hypotheses": len(ledgers.hypotheses),
        "unresolved_hypotheses": unresolved,
        "decisions": len(ledgers.decisions),
        "model_calls": len(ledgers.model_calls),
        "tool_calls": len(ledgers.tool_calls),
        "budget_reservations": len(ledgers.budget_reservations),
    }


def _model_summary(
    model_calls: list[dict[str, Any]],
    reviewer: Mapping[str, Any],
    completion: Mapping[str, Any],
    contract: Mapping[str, Any],
    routes: Mapping[str, Any],
    policy: TraceRunPolicy,
    services: TraceRunServices,
) -> dict[str, Any]:
    successful, successful_primary = _successful_model_counts(
        model_calls, policy, services
    )
    return {
        "observed": sorted(
            {
                str(row.get("observed_model") or row.get("requested_route") or "")
                for row in model_calls
                if str(row.get("observed_model") or row.get("requested_route") or "")
            }
        ),
        "independent_review_calls": reviewer["model_call_count"],
        "successful_call_count": successful,
        "successful_primary_call_count": successful_primary,
        **completion,
        "model_call_contract": contract,
        "duration_ms": sum(services.nonnegative_int(row.get("duration_ms")) for row in model_calls),
        "route_consistency": routes,
    }


def _successful_model_counts(
    model_calls: list[dict[str, Any]],
    policy: TraceRunPolicy,
    services: TraceRunServices,
) -> tuple[int, int]:
    successful = [
        row
        for row in model_calls
        if services.normalize_status(row.get("status")) in policy.success_statuses
    ]
    primary = sum(
        int(row.get("independent_review") or 0) == 0 for row in successful
    )
    return len(successful), primary


def _integrity_result(
    run_id: str,
    run: Mapping[str, Any],
    ledgers: _Ledgers,
    integrity_ledgers: Mapping[str, list[dict[str, Any]]],
    services: TraceRunServices,
    require_ledger_manifest: bool,
) -> dict[str, Any]:
    return services.verify_chain(
        run_id,
        ledgers.events,
        ledgers.hypotheses,
        run_status=str(run.get("status") or ""),
        ledgers=integrity_ledgers,
        require_ledger_manifest=require_ledger_manifest,
    )


def _tools_summary(
    tool_calls: list[dict[str, Any]],
    tools: _ToolProjection,
    policy: TraceRunPolicy,
    services: TraceRunServices,
) -> dict[str, Any]:
    limit = policy.maximum_reported
    return {
        "backends": sorted(
            {str(row.get("backend") or "unknown") for row in tool_calls if str(row.get("backend") or "")}
        ),
        "rejected_call_ids": tools.rejected[:limit],
        "rejected_count": len(tools.rejected),
        "failed_call_ids": tools.failed[:limit],
        "failed_count": len(tools.failed),
        "coverage_gap_call_ids": tools.coverage_gaps[:limit],
        "coverage_gap_count": len(tools.coverage_gaps),
        "truncated_call_ids": tools.truncated[:limit],
        "truncated_count": len(tools.truncated),
        "read_only_violation_call_ids": tools.read_only_violations[:limit],
        "read_only_violation_count": len(tools.read_only_violations),
        "successful_call_count": len(tools.successful),
        "read_only_call_count": len(tools.read_only),
        "successful_read_only_call_bindings": tools.bindings,
        "successful_read_only_call_bindings_sha256": services.digest_json(tools.bindings),
    }


def _evidence_summary(
    evidence: list[dict[str, Any]], source_classes: list[str]
) -> dict[str, Any]:
    return {
        "source_classes": source_classes,
        "distinct_source_classes": len(source_classes),
        "corroborating_count": sum(
            int(row.get("corroborating") or 0) == 1 for row in evidence
        ),
    }


def evaluate_run(
    connection: Any,
    available_tables: set[str],
    run: Mapping[str, Any],
    malformed: collections.Counter[str],
    policy: TraceRunPolicy,
    services: TraceRunServices,
    *,
    require_ledger_manifest: bool = False,
) -> dict[str, Any]:
    """Evaluate one run using bounded, read-only, injected trace services."""
    run_id = str(run.get("run_id") or "")
    ledgers = _load_ledgers(connection, available_tables, run_id, services)
    integrity_ledgers = _integrity_ledgers(run, ledgers, policy)
    sources = _source_classes(ledgers.evidence, policy, services)
    tools = _tool_projection(ledgers.tool_calls, policy, services)
    event = _event_projection(ledgers.events, malformed, services)
    reviewer, completion, contract, routes = _reviewer_and_models(
        ledgers, malformed, run, services
    )
    skills = services.skill_selection_attestation_result(run, ledgers.events, malformed)
    return {
        **_identity_fields(run),
        "terminal_execution_summary": services.terminal_execution_summary(
            ledgers.events, run.get("status"), malformed
        ),
        "skill_selection_attestation": skills,
        "integrity": _integrity_result(
            run_id, run, ledgers, integrity_ledgers, services,
            require_ledger_manifest,
        ),
        "counts": _counts(ledgers, policy, services),
        "event_type_counts": dict(sorted(event.type_counts.items())),
        "stage_count": len({stage for stage in event.stages if stage}),
        "models": _model_summary(
            ledgers.model_calls, reviewer, completion, contract, routes, policy, services
        ),
        "tools": _tools_summary(ledgers.tool_calls, tools, policy, services),
        "evidence": _evidence_summary(ledgers.evidence, sources),
        "reviewer": reviewer,
        "budget_violations": dict(sorted(event.budget_violations.items())),
        "budget_violation_operations": event.budget_operations,
        "memory_promotions": event.memory_promotions,
        "coverage_gap_reasons": _coverage_reasons(
            ledgers, tools, sources, reviewer, completion, contract, routes
        ),
    }
