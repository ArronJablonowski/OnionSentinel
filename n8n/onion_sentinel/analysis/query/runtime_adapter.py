"""Concrete runtime-port adapter for the governed investigation query loop.

The provider-neutral coordinator owns query-loop policy.  This module binds it
to one analysis invocation without importing the legacy executable wrapper or
granting any additional query authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from . import coordinator, round_admission, state


@dataclass(frozen=True)
class Policy:
    route: str
    evaluation_required: bool
    maximum_prompt_bytes: int
    hosted_route: bool
    maximum_rounds: int
    maximum_queries: int
    maximum_queries_per_round: int
    rounds_override: int | None
    queries_override: int | None
    include_deterministic_requests: bool
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
class Invocation:
    prompt_package: dict[str, Any]
    primary_response: dict[str, Any]
    args: Any
    settings: dict[str, Any]
    harness_runtime: Any
    model_executor: Callable[..., Any]
    query_executor: Callable[..., Any]
    configured_query_executor: bool
    live_osquery_config: dict[str, Any] | None
    enrichment_config: dict[str, Any] | None
    security_onion_config_path: Any
    investigation_pivot_dir: Any
    model_input_builder: Callable[[dict[str, Any], int], Any] | None


@dataclass(frozen=True)
class Dependencies:
    pop_requests: Callable[[dict[str, Any]], list[Any]]
    deterministic_requests: Callable[[dict[str, Any]], list[dict[str, Any]]]
    model_safe_copy: Callable[..., Any]
    normalize_request: Callable[..., dict[str, Any]]
    validate_repair: Callable[[dict[str, Any], dict[str, Any]], None]
    backend_available: Callable[..., bool]
    semantic_digest: Callable[[dict[str, Any]], str]
    harness_operator_approved: Callable[..., bool]
    backend_is_approval_gated: Callable[[str], bool]
    decision_is_effective: Callable[[str, Any], bool]
    backend_capability: Callable[[str], str]
    repair_scope: Callable[..., dict[str, Any] | None]
    query_text: Callable[[Any, int], str]
    valid_query_id: Callable[[str], bool]
    repair_failures: Callable[[Any], dict[str, str]]
    now: Callable[[], str]
    validate_observables: Callable[..., list[dict[str, Any]]]
    canonical_digest: Callable[[Any], str]
    error_digest: Callable[[Any], str]
    repair_prompt_entry: Callable[..., dict[str, Any]]
    request_from_scope: Callable[[dict[str, Any]], dict[str, Any]]
    admit_prompt: Callable[..., None]
    outcome_summary: Callable[..., dict[str, Any]]
    round_audit: Callable[[dict[str, Any]], dict[str, Any]]
    binding_summary: Callable[..., dict[str, Any]]
    append_gaps: Callable[[dict[str, Any], list[str]], None]
    monotonic: Callable[[], float]
    warn: Callable[[str], None]


class Runtime:
    """Bind one invocation to coordinator ports and harness observations."""

    def __init__(
        self, policy: Policy, invocation: Invocation, dependencies: Dependencies,
    ) -> None:
        self.policy = policy
        self.invocation = invocation
        self.dependencies = dependencies

    def observe(self, call: Callable[[], Any]) -> Any:
        runtime = self.invocation.harness_runtime
        if runtime is None:
            return None
        try:
            return call()
        except Exception as exc:
            if runtime.policy.mode == "enforce" or self.policy.evaluation_required:
                raise
            self.dependencies.warn(
                "Onion Sentinel harness shadow query observation failed: "
                f"{type(exc).__name__}: {exc}"
            )
            return None

    def planning_phase(self, note: str) -> None:
        runtime = self.invocation.harness_runtime
        self.observe(
            lambda: runtime.phase("investigation_query_planning", self.policy.route, note)
            if runtime is not None else None
        )

    def planning_preflight(self, package: dict[str, Any]) -> None:
        runtime = self.invocation.harness_runtime
        self.observe(
            lambda: runtime.preflight_model_call(
                call_id="primary-query-planning-retry-1",
                input_value=package,
                requested_route=self.policy.route,
                purpose="evaluation query-planning retry 1 of 1",
            ) if runtime is not None else None
        )

    def planning_record(
        self, response: dict[str, Any], duration: float, status: str,
    ) -> None:
        runtime = self.invocation.harness_runtime
        kwargs = {"status": status} if status else {}
        self.observe(
            lambda: runtime.model_call(
                call_id="primary-query-planning-retry-1",
                purpose="evaluation query-planning retry 1 of 1",
                requested_route=self.policy.route,
                response=response,
                input_value=self.invocation.prompt_package,
                duration_seconds=duration,
                **kwargs,
            ) if runtime is not None else None
        )

    def authorize(self, round_number: int, request: dict[str, Any]) -> Any:
        runtime = self.invocation.harness_runtime
        deps = self.dependencies
        decision = self.observe(
            lambda: runtime.authorize_tool(
                round_number=round_number,
                query_id=request["query_id"],
                backend=request["backend"],
                approved=(
                    request["backend"] == "osquery"
                    and deps.harness_operator_approved(
                        self.invocation.live_osquery_config,
                        request["parameters"].get("target_alias"),
                    )
                ),
            ) if runtime is not None else None
        )
        return round_admission.resolve_authorization(
            runtime_present=runtime is not None,
            approval_gated=deps.backend_is_approval_gated(request["backend"]),
            policy_mode=runtime.policy.mode if runtime is not None else "off",
            decision=decision,
            decision_effective=deps.decision_is_effective,
            fallback_capability=deps.backend_capability(request["backend"]),
        )

    def backend_available(self, backend: str) -> bool:
        return self.dependencies.backend_available(
            self.invocation.prompt_package,
            backend,
            live_osquery_config=self.invocation.live_osquery_config,
        )

    def query_execute(
        self, round_number: int, requests: list[dict[str, Any]],
    ) -> Any:
        runtime = self.invocation.harness_runtime
        self.observe(
            lambda: runtime.preflight_query_batch(
                round_number=round_number, request_count=len(requests)
            ) if runtime is not None else None
        )
        self.observe(
            lambda: runtime.phase(
                "investigation_query_execution", self.policy.route,
                f"round {round_number}; {len(requests)} admitted request(s)",
            ) if runtime is not None else None
        )
        kwargs = {
            "round_number": round_number,
            "live_osquery_config": self.invocation.live_osquery_config,
        }
        if self.invocation.configured_query_executor:
            kwargs.update({
                "security_onion_config_path": self.invocation.security_onion_config_path,
                "investigation_pivot_dir": self.invocation.investigation_pivot_dir,
            })
        if self.invocation.enrichment_config is not None:
            kwargs["enrichment_config"] = self.invocation.enrichment_config
        return self.invocation.query_executor(
            self.invocation.prompt_package, requests, **kwargs
        )

    def observe_round(self, result: dict[str, Any]) -> None:
        runtime = self.invocation.harness_runtime
        self.observe(lambda: runtime.query_round(result) if runtime is not None else None)

    def admit_prompt(
        self, package: dict[str, Any], rounds: list[dict[str, Any]],
    ) -> None:
        self.dependencies.admit_prompt(
            package,
            rounds,
            maximum_prompt_bytes=self.policy.maximum_prompt_bytes,
            hosted=self.policy.hosted_route,
        )

    def build_model_input(self, package: dict[str, Any], number: int) -> Any:
        builder = self.invocation.model_input_builder
        return builder(package, number) if builder is not None else package

    def synthesis_preflight(
        self, call_id: str, model_input: Any, purpose: str,
    ) -> None:
        runtime = self.invocation.harness_runtime
        self.observe(
            lambda: runtime.preflight_model_call(
                call_id=call_id,
                input_value=model_input,
                requested_route=self.policy.route,
                purpose=purpose,
                independent_review=self.policy.model_call_independent_review,
            ) if runtime is not None else None
        )

    def synthesis_record(
        self, call_id: str, purpose: str, response: Any, model_input: Any,
        duration: float, status: str,
    ) -> None:
        runtime = self.invocation.harness_runtime
        kwargs = {"status": status} if status else {}
        self.observe(
            lambda: runtime.model_call(
                call_id=call_id,
                purpose=purpose,
                requested_route=self.policy.route,
                response=response,
                input_value=model_input,
                duration_seconds=duration,
                independent_review=self.policy.model_call_independent_review,
                **kwargs,
            ) if runtime is not None else None
        )

    def planning_execute(self, package: dict[str, Any]) -> Any:
        return self.invocation.model_executor(
            self.policy.route, package, self.invocation.args, self.invocation.settings
        )

    def synthesis_catalogue(self, value: Any) -> None:
        runtime = self.invocation.harness_runtime
        self.observe(
            lambda: runtime.catalogue_prompt_evidence(value)
            if runtime is not None else None
        )

    def synthesis_execute(self, model_input: Any) -> Any:
        return self.invocation.model_executor(
            self.policy.route,
            model_input,
            self.invocation.args,
            self.invocation.settings,
        )

    def synthesis_phase(self, note: str) -> None:
        runtime = self.invocation.harness_runtime
        self.observe(
            lambda: runtime.phase("evidence_synthesis", self.policy.route, note)
            if runtime is not None else None
        )

    def ports(self) -> coordinator.Ports:
        deps = self.dependencies
        return coordinator.Ports(
            pop_requests=deps.pop_requests,
            deterministic_requests=deps.deterministic_requests,
            model_safe_copy=lambda value, hosted: deps.model_safe_copy(
                value, hosted=hosted
            ),
            planning_execute=self.planning_execute,
            planning_phase=self.planning_phase,
            planning_preflight=self.planning_preflight,
            planning_record=self.planning_record,
            normalize_request=deps.normalize_request,
            validate_repair=deps.validate_repair,
            backend_available=self.backend_available,
            semantic_digest=deps.semantic_digest,
            authorize=self.authorize,
            repair_scope=deps.repair_scope,
            query_text=deps.query_text,
            valid_query_id=deps.valid_query_id,
            query_execute=self.query_execute,
            repair_failures=deps.repair_failures,
            now=deps.now,
            observe_round=self.observe_round,
            validate_observables=deps.validate_observables,
            canonical_digest=deps.canonical_digest,
            error_digest=deps.error_digest,
            repair_prompt_entry=deps.repair_prompt_entry,
            request_from_scope=deps.request_from_scope,
            admit_prompt=self.admit_prompt,
            build_model_input=self.build_model_input,
            synthesis_catalogue=self.synthesis_catalogue,
            synthesis_preflight=self.synthesis_preflight,
            synthesis_execute=self.synthesis_execute,
            synthesis_record=self.synthesis_record,
            synthesis_phase=self.synthesis_phase,
            outcome_summary=deps.outcome_summary,
            round_audit=deps.round_audit,
            binding_summary=deps.binding_summary,
            append_gaps=deps.append_gaps,
            monotonic=deps.monotonic,
        )


def run(
    invocation: Invocation,
    policy: Policy,
    dependencies: Dependencies,
    *,
    error_type: type[Exception],
) -> dict[str, Any]:
    """Run the package coordinator through explicit legacy runtime ports."""
    runtime = Runtime(policy, invocation, dependencies)
    return coordinator.run(
        invocation.prompt_package,
        invocation.primary_response,
        policy=coordinator.Policy(
            route=policy.route,
            state_policy=state.Policy(
                maximum_rounds=policy.maximum_rounds,
                maximum_queries=policy.maximum_queries,
                maximum_queries_per_round=policy.maximum_queries_per_round,
            ),
            rounds_override=policy.rounds_override,
            queries_override=policy.queries_override,
            evaluation_required=policy.evaluation_required,
            include_deterministic_requests=policy.include_deterministic_requests,
            maximum_prompt_bytes=policy.maximum_prompt_bytes,
            hosted_route=policy.hosted_route,
            query_round_offset=policy.query_round_offset,
            model_call_id_prefix=policy.model_call_id_prefix,
            model_call_purpose_prefix=policy.model_call_purpose_prefix,
            model_call_independent_review=policy.model_call_independent_review,
            query_result_schema=policy.query_result_schema,
            query_contract=policy.query_contract,
            max_discovered_observables=policy.max_discovered_observables,
            max_prompt_evidence_bytes=policy.max_prompt_evidence_bytes,
            max_prompt_evidence_rows=policy.max_prompt_evidence_rows,
        ),
        ports=runtime.ports(),
        error_type=error_type,
    )
