"""Provider-neutral coordinator for the governed investigation query pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from . import (
    engine, finalization, observables, planning_retry, repair_stage,
    round_admission, round_result, state, synthesis,
)


PLANNING_RETRY_INSTRUCTION = (
    "The initial primary response did not request a dynamic investigation pivot. "
    "Return at least one narrow, material, read-only investigation_query_requests "
    "entry using only the advertised schema, backends, observables, time envelope, "
    "and budgets. Do not invent direct tool access or widen authorization."
)


@dataclass(frozen=True)
class Policy:
    route: str
    state_policy: state.Policy
    rounds_override: int | None
    queries_override: int | None
    evaluation_required: bool
    include_deterministic_requests: bool
    maximum_prompt_bytes: int
    hosted_route: bool
    query_round_offset: int
    model_call_id_prefix: str
    model_call_purpose_prefix: str
    model_call_independent_review: bool
    query_result_schema: str
    query_contract: str
    max_discovered_observables: int
    max_prompt_evidence_bytes: int
    max_prompt_evidence_rows: int


@dataclass(frozen=True)
class Ports:
    pop_requests: Callable[[dict[str, Any]], list[Any]]
    deterministic_requests: Callable[[dict[str, Any]], list[dict[str, Any]]]
    model_safe_copy: Callable[[Any, bool], Any]
    planning_execute: Callable[[dict[str, Any]], Any]
    planning_phase: Callable[[str], None]
    planning_preflight: Callable[[dict[str, Any]], None]
    planning_record: Callable[[dict[str, Any], float, str], None]
    normalize_request: Callable[..., dict[str, Any]]
    validate_repair: Callable[[dict[str, Any], dict[str, Any]], None]
    backend_available: Callable[[str], bool]
    semantic_digest: Callable[[dict[str, Any]], str]
    authorize: Callable[[int, dict[str, Any]], round_admission.Authorization]
    repair_scope: Callable[..., dict[str, Any] | None]
    query_text: Callable[[Any, int], str]
    valid_query_id: Callable[[str], bool]
    query_execute: Callable[[int, list[dict[str, Any]]], Any]
    repair_failures: Callable[[dict[str, Any]], dict[str, str]]
    now: Callable[[], str]
    observe_round: Callable[[dict[str, Any]], None]
    validate_observables: Callable[..., list[dict[str, Any]]]
    canonical_digest: Callable[[Any], str]
    error_digest: Callable[[Any], str]
    repair_prompt_entry: Callable[..., dict[str, Any]]
    request_from_scope: Callable[[dict[str, Any]], dict[str, Any]]
    admit_prompt: Callable[[dict[str, Any], list[dict[str, Any]]], None]
    build_model_input: Callable[[dict[str, Any], int], Any]
    synthesis_catalogue: Callable[[Any], None]
    synthesis_preflight: Callable[[str, Any, str], None]
    synthesis_execute: Callable[[Any], Any]
    synthesis_record: Callable[[str, str, Any, Any, float, str], None]
    synthesis_phase: Callable[[str], None]
    outcome_summary: Callable[..., dict[str, Any]]
    round_audit: Callable[[dict[str, Any]], dict[str, Any]]
    binding_summary: Callable[..., dict[str, Any]]
    append_gaps: Callable[[dict[str, Any], list[str]], None]
    monotonic: Callable[[], float]


@dataclass
class _Run:
    response: dict[str, Any]
    limits: state.Limits
    engine_state: engine.InvestigationState
    rounds: list[dict[str, Any]] = field(default_factory=list)
    initial_requests: list[Any] = field(default_factory=list)
    model_initial_requests: list[Any] = field(default_factory=list)
    deterministic_requests: list[dict[str, Any]] = field(default_factory=list)
    seen_semantic: set[str] = field(default_factory=set)
    pending_repair_scopes: dict[str, dict[str, Any]] = field(default_factory=dict)
    followup_call_number: int = 0
    planning_retry_attempted: bool = False
    repair_produced_requests: bool = False
    repair_admitted_requests: int = 0
    repair_rejected_requests: int = 0
    repair_candidates: list[dict[str, Any]] = field(default_factory=list)
    repair_not_attempted_reason: str = ""


class Coordinator:
    def __init__(self, policy: Policy, ports: Ports, error_type: type[Exception]):
        self.policy = policy
        self.ports = ports
        self.error_type = error_type

    def _new_run(self, primary_response: dict[str, Any]) -> _Run:
        limits = state.resolve(
            self.policy.state_policy,
            rounds_override=self.policy.rounds_override,
            queries_override=self.policy.queries_override,
        )
        return _Run(primary_response, limits, engine.begin(limits))

    def _prepare(self, run: _Run, prompt_package: dict[str, Any]) -> None:
        run.model_initial_requests = self.ports.pop_requests(run.response)
        run.deterministic_requests = (
            self.ports.deterministic_requests(prompt_package)
            if self.policy.include_deterministic_requests else []
        )
        run.initial_requests = (
            run.deterministic_requests + run.model_initial_requests
        )
        if not self.policy.evaluation_required or run.initial_requests:
            return
        run.planning_retry_attempted = True
        run.limits = run.limits.evaluation_retry(self.policy.state_policy)
        run.engine_state = engine.begin(run.limits)
        result = planning_retry.run(
            prompt_package,
            route=self.policy.route,
            limits=run.limits,
            maximum_prompt_bytes=self.policy.maximum_prompt_bytes,
            hosted=self.policy.hosted_route,
            policy=planning_retry.Policy(
                maximum_queries_per_round=self.policy.state_policy.maximum_queries_per_round,
                instruction=PLANNING_RETRY_INSTRUCTION,
            ),
            dependencies=planning_retry.Dependencies(
                model_safe_copy=self.ports.model_safe_copy,
                execute_model=self.ports.planning_execute,
                pop_requests=self.ports.pop_requests,
                phase=lambda: self.ports.planning_phase(
                    "evaluation retry 1 of 1 after initial response omitted pivots"
                ),
                preflight=self.ports.planning_preflight,
                record=self.ports.planning_record,
                monotonic=self.ports.monotonic,
            ),
            error_type=self.error_type,
        )
        run.response = result.response
        run.initial_requests = list(result.requests)

    def _admit(
        self, run: _Run, raw_requests: list[Any], *, round_number: int,
        harness_round: int, repair_round: bool, prompt_package: dict[str, Any],
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any], Any]:
        transition = engine.admit_round(
            run.engine_state, raw_requests, round_number=round_number
        )
        if transition.action == "stop_empty":
            return [], [], {}, transition
        run.engine_state = transition.state
        self.ports.planning_phase(f"round {harness_round}")
        context = prompt_package.get("_local_investigation_query_context")
        envelope = context.get("time_envelope") if isinstance(context, dict) else None
        admitted = round_admission.run(
            list(transition.admitted_requests),
            state=run.engine_state,
            round_number=harness_round,
            repair_round=repair_round,
            pending_repair_scopes=run.pending_repair_scopes,
            seen_semantic_digests=run.seen_semantic,
            time_envelope=envelope,
            authorization_context=context,
            dependencies=round_admission.Dependencies(
                normalize=self.ports.normalize_request,
                validate_repair=self.ports.validate_repair,
                backend_available=self.ports.backend_available,
                semantic_digest=self.ports.semantic_digest,
                ignore_semantic_repeat=lambda current: engine.ignore(current, 1),
                authorize=lambda request: self.ports.authorize(harness_round, request),
                repair_scope=self.ports.repair_scope,
                query_text=self.ports.query_text,
                valid_query_id=self.ports.valid_query_id,
            ),
            error_type=self.error_type,
        )
        run.engine_state = admitted.state
        run.seen_semantic = set(admitted.seen_semantic_digests)
        return (
            list(admitted.normalized), list(admitted.rejected),
            dict(admitted.repair_scopes), transition,
        )

    def _execute(
        self, normalized: list[dict[str, Any]], rejected: list[dict[str, Any]],
        *, harness_round: int,
    ) -> round_result.Result:
        return round_result.run(
            normalized, rejected, round_number=harness_round,
            policy=round_result.Policy(schema=self.policy.query_result_schema),
            dependencies=round_result.Dependencies(
                execute=lambda requests: self.ports.query_execute(
                    harness_round, requests
                ),
                repair_failures=self.ports.repair_failures,
                now=self.ports.now,
            ),
        )

    def _broker_repairs(
        self, normalized: list[dict[str, Any]], failures: dict[str, str],
        scopes: dict[str, dict[str, Any]], *, harness_round: int,
        prompt_package: dict[str, Any], repair_round: bool,
    ) -> None:
        if repair_round:
            return
        by_id = {request["query_id"]: request for request in normalized}
        context = prompt_package.get("_local_investigation_query_context")
        envelope = context.get("time_envelope") if isinstance(context, dict) else None
        for query_id, reason in failures.items():
            request = by_id.get(query_id)
            if request is None:
                continue
            scope = self.ports.repair_scope(
                request, round_number=harness_round, position=1,
                time_envelope=envelope, authorization_context=context,
            )
            if scope is not None:
                scopes[query_id] = {
                    "scope": scope, "reason": reason,
                    "trigger": "broker_rejection_or_invalid_response",
                }

    def _record_round(
        self, run: _Run, result: round_result.Result,
        normalized: list[dict[str, Any]], rejected: list[dict[str, Any]],
        *, repair_round: bool, prompt_package: dict[str, Any],
    ) -> None:
        run.rounds.append(result.envelope)
        self.ports.observe_round(result.envelope)
        if repair_round:
            run.repair_admitted_requests += len(normalized)
            run.repair_rejected_requests += len(rejected) + len(result.repair_failures)
            run.pending_repair_scopes = {}
        context = prompt_package.get("_local_investigation_query_context")
        if not isinstance(context, dict):
            return
        promoted = observables.promote(
            context.get("discovered_observables"),
            result.envelope.get("results"),
            limit=self.policy.max_discovered_observables,
            validate=self.ports.validate_observables,
        )
        context["discovered_observables"] = list(promoted.observables)

    def _repair(
        self, run: _Run, scopes: dict[str, dict[str, Any]],
        *, round_number: int, repair_round: bool,
    ) -> tuple[repair_stage.Result, state.Remaining]:
        remaining = engine.remaining(
            run.engine_state, round_number, repair_round=repair_round
        )
        transition = engine.plan_repair(
            run.engine_state, list(scopes.values()),
            round_number=round_number, repair_round=repair_round,
        )
        run.engine_state = transition.state
        stage = repair_stage.build(
            transition.repair,
            remaining_queries=remaining.queries,
            dependencies=repair_stage.Dependencies(
                canonical_digest=self.ports.canonical_digest,
                error_digest=self.ports.error_digest,
                prompt_entry=self.ports.repair_prompt_entry,
                request_from_scope=self.ports.request_from_scope,
            ),
        )
        if stage.audit_candidates:
            run.repair_candidates = list(stage.audit_candidates)
        if stage.not_attempted_reason:
            run.repair_not_attempted_reason = stage.not_attempted_reason
        return stage, remaining

    def _synthesize(
        self, run: _Run, prompt_package: dict[str, Any],
        *, round_number: int, harness_round: int, remaining: state.Remaining,
    ) -> bool:
        prompt_package["investigation_follow_up"] = synthesis.follow_up(
            round_number=round_number,
            remaining_rounds=remaining.rounds,
            remaining_queries=remaining.queries,
        )
        self.ports.admit_prompt(prompt_package, run.rounds)
        result = synthesis.run(
            prompt_package,
            state=run.engine_state,
            prior_call_number=run.followup_call_number,
            remaining_rounds=remaining.rounds,
            remaining_queries=remaining.queries,
            harness_round_number=harness_round,
            policy=synthesis.Policy(
                route=self.policy.route,
                call_id_prefix=self.policy.model_call_id_prefix,
                call_purpose_prefix=self.policy.model_call_purpose_prefix,
                independent_review=self.policy.model_call_independent_review,
                attest_route=self.policy.evaluation_required,
            ),
            dependencies=synthesis.Dependencies(
                build_input=self.ports.build_model_input,
                catalogue=self.ports.synthesis_catalogue,
                preflight=self.ports.synthesis_preflight,
                execute=self.ports.synthesis_execute,
                record=self.ports.synthesis_record,
                phase=self.ports.synthesis_phase,
                after_follow_up=state.after_follow_up,
                pop_requests=self.ports.pop_requests,
                ignore_terminal=lambda current, count: engine.ignore(
                    current, count, terminal=True
                ),
                monotonic=self.ports.monotonic,
            ),
            error_type=self.error_type,
        )
        run.response = result.response
        run.engine_state = result.state
        run.followup_call_number = result.call_number
        return result.stop

    def _round(
        self, run: _Run, prompt_package: dict[str, Any], round_number: int,
    ) -> bool:
        harness_round = self.policy.query_round_offset + round_number
        raw = (
            run.initial_requests if round_number == 1
            else self.ports.pop_requests(run.response)
        )
        repair_round = bool(run.pending_repair_scopes)
        if repair_round:
            run.repair_produced_requests = bool(raw)
        normalized, rejected, scopes, transition = self._admit(
            run, raw, round_number=round_number, harness_round=harness_round,
            repair_round=repair_round, prompt_package=prompt_package,
        )
        if transition.action == "stop_empty":
            return True
        executed = self._execute(normalized, rejected, harness_round=harness_round)
        self._broker_repairs(
            normalized, executed.repair_failures, scopes,
            harness_round=harness_round, prompt_package=prompt_package,
            repair_round=repair_round,
        )
        self._record_round(
            run, executed, normalized, rejected,
            repair_round=repair_round, prompt_package=prompt_package,
        )
        stage, remaining = self._repair(
            run, scopes, round_number=round_number, repair_round=repair_round
        )
        if stage.scheduled:
            run.pending_repair_scopes = dict(stage.pending_scopes)
            prompt_package["investigation_query_planning_repair"] = stage.prompt
            run.response = {"investigation_query_requests": list(stage.requests)}
            prompt_package.pop("investigation_query_planning_repair", None)
            return False
        return self._synthesize(
            run, prompt_package, round_number=round_number,
            harness_round=harness_round, remaining=remaining,
        )

    def _finalize(self, run: _Run) -> finalization.Result:
        return finalization.finalize(
            run.response, run.rounds, state=run.engine_state,
            policy=finalization.Policy(
                query_contract=self.policy.query_contract,
                route=self.policy.route,
                evaluation_required=self.policy.evaluation_required,
                max_queries_per_round=self.policy.state_policy.maximum_queries_per_round,
                configured_max_rounds=self.policy.state_policy.maximum_rounds,
                configured_max_queries=self.policy.state_policy.maximum_queries,
                max_prompt_evidence_bytes=self.policy.max_prompt_evidence_bytes,
                max_prompt_evidence_rows=self.policy.max_prompt_evidence_rows,
            ),
            planning=finalization.Planning(
                retry_attempted=run.planning_retry_attempted,
                retry_produced_requests=bool(
                    run.planning_retry_attempted and run.initial_requests
                ),
                deterministic_requests=tuple(run.deterministic_requests),
                model_initial_requests=len(run.model_initial_requests),
            ),
            repair=finalization.Repair(
                produced_requests=run.repair_produced_requests,
                admitted_requests=run.repair_admitted_requests,
                rejected_requests=run.repair_rejected_requests,
                candidates=tuple(run.repair_candidates),
                not_attempted_reason=run.repair_not_attempted_reason,
            ),
            dependencies=finalization.Dependencies(
                pop_requests=self.ports.pop_requests,
                ignore_terminal=lambda current, count: engine.ignore(
                    current, count, terminal=True
                ),
                outcome_summary=self.ports.outcome_summary,
                round_audit=self.ports.round_audit,
                binding_summary=self.ports.binding_summary,
                canonical_digest=self.ports.canonical_digest,
                append_gaps=self.ports.append_gaps,
            ),
            error_type=self.error_type,
        )

    def run(
        self, prompt_package: dict[str, Any], primary_response: dict[str, Any],
    ) -> dict[str, Any]:
        run = self._new_run(primary_response)
        self._prepare(run, prompt_package)
        for round_number in range(1, run.limits.rounds + 1):
            if self._round(run, prompt_package, round_number):
                break
        result = self._finalize(run)
        if (
            result.outcomes is not None
            and isinstance(prompt_package.get("investigation_query_results"), dict)
        ):
            prompt_package["investigation_query_results"]["outcomes"] = result.outcomes
        return result.response


def run(
    prompt_package: dict[str, Any], primary_response: dict[str, Any],
    *, policy: Policy, ports: Ports, error_type: type[Exception],
) -> dict[str, Any]:
    """Run the stable provider-neutral query pipeline interface."""
    return Coordinator(policy, ports, error_type).run(
        prompt_package, primary_response
    )
