"""Durable final audit assembly for a governed investigation-query run."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Sequence


@dataclass(frozen=True)
class Policy:
    query_contract: str
    route: str
    evaluation_required: bool
    max_queries_per_round: int
    configured_max_rounds: int
    configured_max_queries: int
    max_prompt_evidence_bytes: int
    max_prompt_evidence_rows: int


@dataclass(frozen=True)
class Planning:
    retry_attempted: bool
    retry_produced_requests: bool
    deterministic_requests: tuple[dict[str, Any], ...]
    model_initial_requests: int


@dataclass(frozen=True)
class Repair:
    produced_requests: bool
    admitted_requests: int
    rejected_requests: int
    candidates: tuple[dict[str, Any], ...]
    not_attempted_reason: str


@dataclass(frozen=True)
class Dependencies:
    pop_requests: Callable[[dict[str, Any]], list[Any]]
    ignore_terminal: Callable[[Any, int], Any]
    outcome_summary: Callable[..., dict[str, Any]]
    round_audit: Callable[[dict[str, Any]], dict[str, Any]]
    binding_summary: Callable[..., dict[str, Any]]
    canonical_digest: Callable[[Any], str]
    append_gaps: Callable[[dict[str, Any], list[str]], None]


@dataclass(frozen=True)
class Result:
    response: dict[str, Any]
    state: Any
    outcomes: dict[str, Any] | None


def _planning_audit(planning: Planning, dependencies: Dependencies) -> dict[str, Any]:
    deterministic = list(planning.deterministic_requests)
    return {
        "planning_retry_attempted": planning.retry_attempted,
        "planning_retry_produced_requests": planning.retry_produced_requests,
        "query_planning_retry": {
            "attempted": planning.retry_attempted,
            "attempts": 1 if planning.retry_attempted else 0,
            "maximum_attempts": 1,
            "evaluation_only": planning.retry_attempted,
        },
        "deterministic_protocol_plan": {
            "enabled": bool(deterministic),
            "requests": len(deterministic),
            "query_ids": [item["query_id"] for item in deterministic],
            "plan_digest": (
                dependencies.canonical_digest(deterministic)
                if deterministic else ""
            ),
            "model_initial_requests": planning.model_initial_requests,
            "read_only_fixed_packs_only": True,
            "query_text_model_supplied": False,
        },
    }


def _repair_audit(state: Any, repair: Repair) -> dict[str, Any]:
    attempted = bool(state.repair_attempted)
    candidates = list(repair.candidates)
    return {
        "planning_repair_attempted": attempted,
        "planning_repair_produced_requests": repair.produced_requests,
        "query_planning_repair": {
            "attempted": attempted,
            "attempts": 1 if attempted else 0,
            "maximum_attempts": 1,
            "used_existing_follow_up_call": False,
            "deterministic_scope_execution": attempted,
            "scope_widening_allowed": False,
            "candidate_count": len(candidates),
            "candidates": candidates,
            "produced_requests": repair.produced_requests,
            "admitted_repair_requests": repair.admitted_requests,
            "rejected_repair_requests": repair.rejected_requests,
            "not_attempted_reason": repair.not_attempted_reason,
        },
    }


def _limits_audit(state: Any, policy: Policy) -> dict[str, int]:
    return {
        "max_rounds": state.limits.rounds,
        "max_queries_total": state.limits.queries,
        "max_queries_per_round": policy.max_queries_per_round,
        "configured_max_rounds": policy.configured_max_rounds,
        "configured_max_queries_total": policy.configured_max_queries,
        "max_prompt_evidence_bytes": policy.max_prompt_evidence_bytes,
        "max_prompt_evidence_rows": policy.max_prompt_evidence_rows,
    }


def _execution_audit(
    rounds: Sequence[dict[str, Any]],
    state: Any,
    policy: Policy,
    dependencies: Dependencies,
) -> tuple[dict[str, Any], dict[str, Any]]:
    outcomes = dependencies.outcome_summary(
        list(rounds), queries_admitted=state.queries_admitted
    )
    round_audits = [dependencies.round_audit(item) for item in rounds]
    bindings = [
        binding
        for item in round_audits
        for binding in item["tool_call_bindings"]
    ]
    summary = dependencies.binding_summary(
        bindings, queries_admitted=state.queries_admitted
    )
    audit = {
        "query_contract": policy.query_contract,
        "provider_neutral": True,
        "model_route": policy.route,
        "rounds_completed": len(rounds),
        "queries_admitted": state.queries_admitted,
        "requests_ignored_or_over_budget": state.requests_ignored,
        "terminal_requests_ignored": state.terminal_requests_ignored,
        "limits": _limits_audit(state, policy),
        "read_only": summary["read_only"],
        "all_tool_call_bindings_read_only": summary[
            "all_tool_call_bindings_read_only"
        ],
        "successful_read_only_queries": summary["successful_read_only_queries"],
        "complete": summary["complete"],
        "evaluation_requirement_satisfied": summary[
            "evaluation_requirement_satisfied"
        ],
        "evaluation_query_guarantee": {
            "required": policy.evaluation_required, **summary
        },
        "outcomes": outcomes,
        "tool_call_bindings": bindings,
        "rounds": round_audits,
    }
    return audit, outcomes


def finalize(
    response: dict[str, Any],
    rounds: Sequence[dict[str, Any]],
    *,
    state: Any,
    policy: Policy,
    planning: Planning,
    repair: Repair,
    dependencies: Dependencies,
    error_type: type[Exception],
) -> Result:
    """Consume terminal requests and publish one evidence-bound audit record."""
    finalized = dict(response)
    repeated = dependencies.pop_requests(finalized)
    updated_state = dependencies.ignore_terminal(state, len(repeated))
    if not rounds and not updated_state.requests_ignored:
        return Result(finalized, updated_state, None)
    execution, outcomes = _execution_audit(
        rounds, updated_state, policy, dependencies
    )
    execution.update(_planning_audit(planning, dependencies))
    execution.update(_repair_audit(updated_state, repair))
    finalized["_investigation_query_audit"] = execution
    dependencies.append_gaps(finalized, outcomes["evidence_gaps"])
    if (
        policy.evaluation_required
        and not execution["evaluation_requirement_satisfied"]
    ):
        raise error_type(
            "controlled harness evaluation requires at least one successful "
            "read-only dynamic pivot and an all-read-only bound tool ledger"
        )
    return Result(finalized, updated_state, outcomes)
