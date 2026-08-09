"""Legacy invocation construction for the package-owned query coordinator."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping

from . import runtime_adapter


@dataclass(frozen=True)
class Options:
    live_osquery_config: dict[str, Any] | None = None
    enrichment_config: dict[str, Any] | None = None
    security_onion_config_path: Any = None
    investigation_pivot_dir: Any = None
    harness_runtime: Any = None
    model_executor: Callable[..., Any] | None = None
    query_executor: Callable[..., Any] | None = None
    route_override: str = ""
    max_rounds_override: int | None = None
    max_queries_total_override: int | None = None
    include_deterministic_requests: bool = True
    model_input_builder: Callable[[dict[str, Any], int], Any] | None = None
    model_call_id_prefix: str = "primary-followup"
    model_call_purpose_prefix: str = "primary investigation follow-up round"
    model_call_independent_review: bool = False
    query_round_offset: int = 0


def _route(
    b: Mapping[str, Any], args: Any, settings: dict[str, Any], agent_role: str,
    options: Options,
) -> tuple[str, bool, int]:
    route = b["canonical_model_route"](
        options.route_override
        or (settings.get("agent_models") or {}).get(agent_role))
    evaluation_required = bool(
        options.harness_runtime is not None
        and b["boolean_setting"](
            b["os"].environ.get(b["EVALUATION_FREEZE_MEMORY_ENV"]))
        and not options.model_call_independent_review)
    maximum = int(
        getattr(args, "max_prompt_bytes", b["DEFAULT_MAX_PROMPT_BYTES"])
        or b["DEFAULT_MAX_PROMPT_BYTES"])
    if b["canonical_model_route"](
        route, b["enabled_agent_model_routes"](settings)
    ).startswith("codex-cli:"):
        maximum = min(maximum, b["CODEX_CLI_MAX_PROMPT_PACKAGE_BYTES"])
    return route, evaluation_required, maximum


def _policy(
    b: Mapping[str, Any], args: Any, settings: dict[str, Any], agent_role: str,
    options: Options,
) -> runtime_adapter.Policy:
    route, evaluation_required, maximum = _route(
        b, args, settings, agent_role, options)
    return runtime_adapter.Policy(
        route=route, evaluation_required=evaluation_required,
        maximum_prompt_bytes=maximum,
        hosted_route=b["model_route_is_hosted"](route, settings),
        maximum_rounds=b["MAX_INVESTIGATION_QUERY_ROUNDS"],
        maximum_queries=b["MAX_INVESTIGATION_QUERIES_TOTAL"],
        maximum_queries_per_round=b["MAX_INVESTIGATION_QUERIES_PER_ROUND"],
        rounds_override=options.max_rounds_override,
        queries_override=options.max_queries_total_override,
        include_deterministic_requests=options.include_deterministic_requests,
        query_round_offset=options.query_round_offset,
        model_call_id_prefix=options.model_call_id_prefix,
        model_call_purpose_prefix=options.model_call_purpose_prefix,
        model_call_independent_review=options.model_call_independent_review,
        query_result_schema=b["INVESTIGATION_QUERY_RESULT_SCHEMA"],
        query_contract=b["INVESTIGATION_QUERY_CONTRACT"],
        max_discovered_observables=b["MAX_DISCOVERED_OBSERVABLES"],
        max_prompt_evidence_bytes=b["MAX_INVESTIGATION_PROMPT_EVIDENCE_BYTES"],
        max_prompt_evidence_rows=b["MAX_INVESTIGATION_PROMPT_EVIDENCE_ROWS"],
    )


def run(
    b: Mapping[str, Any], prompt_package: dict[str, Any],
    primary_response: dict[str, Any], args: Any, settings: dict[str, Any],
    agent_role: str, options: Options,
) -> dict[str, Any]:
    """Construct one legacy invocation and run the package coordinator."""
    query_executor = options.query_executor or b["execute_investigation_query_batch"]
    invocation = runtime_adapter.Invocation(
        prompt_package=prompt_package, primary_response=primary_response,
        args=args, settings=settings, harness_runtime=options.harness_runtime,
        model_executor=options.model_executor or b["analyze_model_route"],
        query_executor=query_executor,
        configured_query_executor=options.query_executor is None,
        live_osquery_config=options.live_osquery_config,
        enrichment_config=options.enrichment_config,
        security_onion_config_path=options.security_onion_config_path,
        investigation_pivot_dir=options.investigation_pivot_dir,
        model_input_builder=options.model_input_builder,
    )
    return runtime_adapter.run(
        invocation, _policy(b, args, settings, agent_role, options),
        runtime_adapter.legacy_dependencies(b, runtime_adapter),
        error_type=b["InvestigationQueryError"],
    )
