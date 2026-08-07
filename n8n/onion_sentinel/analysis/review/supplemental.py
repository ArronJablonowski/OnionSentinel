"""Bounded supplemental evidence reconciliation for independent reviewers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


@dataclass(frozen=True)
class Dependencies:
    pop_query_requests: Callable[[dict[str, Any]], list[Any]]
    canonical_digest: Callable[[Any], str]
    independent_package: Callable[..., dict[str, Any]]
    route_is_hosted: Callable[[str, dict[str, Any]], bool]
    analyze_route: Callable[..., dict[str, Any]]
    validate_reviewer: Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]]
    validate_response: Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]]
    apply_query_loop: Callable[..., dict[str, Any]]
    max_queries_per_round: int


def pivot_reason(reviewer_response: dict[str, Any]) -> str:
    """Return the bounded unresolved discriminator that permits one pivot."""
    requests = reviewer_response.get("investigation_query_requests")
    if not isinstance(requests, list) or not requests:
        return ""
    return _first_text(reviewer_response.get("evidence_gaps")) or _first_hypothesis(
        reviewer_response.get("hypotheses")
    )


def _first_text(values: Any) -> str:
    if not isinstance(values, list):
        return ""
    for value in values:
        text = str(value or "").strip()
        if text:
            return text[:500]
    return ""


def _first_hypothesis(values: Any) -> str:
    if not isinstance(values, list):
        return ""
    for item in values:
        if not isinstance(item, dict):
            continue
        text = str(item.get("next_discriminator") or "").strip()
        if text:
            return text[:500]
    return ""


def _audit(requests: list[Any], deps: Dependencies) -> dict[str, Any]:
    return {
        "schema": "onion-sentinel-reviewer-supplemental-pivot-v1",
        "requested": bool(requests),
        "executed": False,
        "maximum_rounds": 1,
        "maximum_queries": deps.max_queries_per_round,
        "request_count": len(requests),
        "reason": "",
    }


def _admission_reason(
    requests: list[Any],
    discriminator: str,
    harness_runtime: Any,
) -> str:
    if not requests:
        return "reviewer requested no supplemental pivot"
    if not discriminator:
        return "supplemental requests lacked a material unresolved discriminator"
    if harness_runtime is None:
        return "Onion Sentinel harness is not active"
    if harness_runtime.remaining_model_calls() < 1:
        return "no model-call budget remains for reconciliation"
    if harness_runtime.remaining_query_rounds() < 1:
        return "no query-round budget remains for reconciliation"
    if harness_runtime.remaining_queries() < 1:
        return "no query budget remains for reconciliation"
    return ""


def _input_builder(route: str, settings: dict[str, Any], deps: Dependencies) -> Callable[..., dict[str, Any]]:
    def build(package: dict[str, Any], _call_number: int) -> dict[str, Any]:
        return deps.independent_package(
            package, hosted=deps.route_is_hosted(route, settings)
        )
    return build


def _model_executor(reviewer_prompt: Any, deps: Dependencies) -> Callable[..., dict[str, Any]]:
    def execute_review(
        requested_route: str,
        review_package: dict[str, Any],
        model_args: Any,
        model_settings: dict[str, Any],
    ) -> dict[str, Any]:
        candidate = deps.analyze_route(
            requested_route, review_package, model_args, model_settings,
            system_prompt_file=reviewer_prompt, independent_review=True,
        )
        validated = deps.validate_reviewer(candidate, review_package)
        validated = deps.validate_response(validated, review_package)
        validated["second_opinion_recommended"] = False
        validated["hosted_second_opinion_recommended"] = False
        return validated
    return execute_review


def _run_query_loop(
    prompt_package: dict[str, Any],
    requests: list[Any],
    args: Any,
    settings: dict[str, Any],
    agent_role: str,
    route: str,
    reviewer_prompt: Any,
    *,
    live_osquery_config: dict[str, Any] | None,
    enrichment_config: dict[str, Any] | None,
    security_onion_config_path: Any,
    investigation_pivot_dir: Any,
    harness_runtime: Any,
    remaining_queries: int,
    query_round_offset: int,
    deps: Dependencies,
) -> dict[str, Any]:
    return deps.apply_query_loop(
        prompt_package, {"investigation_query_requests": requests}, args,
        settings, agent_role, live_osquery_config=live_osquery_config,
        enrichment_config=enrichment_config,
        security_onion_config_path=security_onion_config_path,
        investigation_pivot_dir=investigation_pivot_dir,
        harness_runtime=harness_runtime,
        model_executor=_model_executor(reviewer_prompt, deps),
        route_override=route, max_rounds_override=1,
        max_queries_total_override=min(deps.max_queries_per_round, remaining_queries),
        include_deterministic_requests=False,
        model_input_builder=_input_builder(route, settings, deps),
        model_call_id_prefix="independent-review-supplemental",
        model_call_purpose_prefix="independent reviewer supplemental reconciliation round",
        model_call_independent_review=True,
        query_round_offset=query_round_offset,
    )


def _install_context(
    prompt_package: dict[str, Any],
    reviewer_response: dict[str, Any],
    discriminator: str,
    harness_runtime: Any,
    deps: Dependencies,
) -> tuple[int, int, str]:
    remaining = harness_runtime.remaining_queries()
    offset = harness_runtime.query_rounds_used()
    initial_sha256 = deps.canonical_digest(reviewer_response)
    prompt_package["reviewer_supplemental_context"] = {
        "schema": "onion-sentinel-reviewer-supplemental-context-v1",
        "initial_review_sha256": initial_sha256,
        "material_discriminator": discriminator,
    }
    return remaining, offset, initial_sha256


def _complete_audit(
    final_response: dict[str, Any],
    audit: dict[str, Any],
    discriminator: str,
    initial_sha256: str,
    deps: Dependencies,
) -> None:
    ignored = deps.pop_query_requests(final_response)
    query_audit = final_response.get("_investigation_query_audit")
    terminal_ignored = int(query_audit.get("terminal_requests_ignored") or 0) if isinstance(
        query_audit, dict
    ) else 0
    audit.update({
        "executed": True,
        "reason": discriminator,
        "initial_review_sha256": initial_sha256,
        "final_review_sha256": deps.canonical_digest(final_response),
        "query_audit": query_audit,
        "recursive_requests_ignored": len(ignored) + terminal_ignored,
    })


def execute(
    prompt_package: dict[str, Any],
    reviewer_response: dict[str, Any],
    args: Any,
    settings: dict[str, Any],
    agent_role: str,
    route: str,
    reviewer_prompt: Any,
    *,
    live_osquery_config: dict[str, Any] | None,
    enrichment_config: dict[str, Any] | None,
    security_onion_config_path: Any,
    investigation_pivot_dir: Any,
    harness_runtime: Any,
    deps: Dependencies,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Execute at most one reviewer-requested read-only pivot round."""
    requests = deps.pop_query_requests(reviewer_response)
    audit = _audit(requests, deps)
    discriminator = pivot_reason({
        **reviewer_response,
        "investigation_query_requests": requests,
    })
    blocked = _admission_reason(requests, discriminator, harness_runtime)
    if blocked:
        audit["reason"] = blocked
        return reviewer_response, audit

    remaining_queries, query_round_offset, initial_sha256 = _install_context(
        prompt_package, reviewer_response, discriminator, harness_runtime, deps
    )

    final_response = _run_query_loop(
        prompt_package, requests, args, settings, agent_role, route,
        reviewer_prompt,
        live_osquery_config=live_osquery_config,
        enrichment_config=enrichment_config,
        security_onion_config_path=security_onion_config_path,
        investigation_pivot_dir=investigation_pivot_dir,
        harness_runtime=harness_runtime,
        remaining_queries=remaining_queries,
        query_round_offset=query_round_offset,
        deps=deps,
    )
    _complete_audit(
        final_response, audit, discriminator, initial_sha256, deps
    )
    return final_response, audit
