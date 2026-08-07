"""Bounded evaluation-only query-planning retry orchestration."""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Callable

from .state import Limits


CALL_ID = "primary-query-planning-retry-1"
PURPOSE = "evaluation query-planning retry 1 of 1"


@dataclass(frozen=True)
class Policy:
    maximum_queries_per_round: int
    instruction: str


@dataclass(frozen=True)
class Dependencies:
    model_safe_copy: Callable[[Any, bool], Any]
    execute_model: Callable[[dict[str, Any]], Any]
    pop_requests: Callable[[dict[str, Any]], list[dict[str, Any]]]
    phase: Callable[[], None]
    preflight: Callable[[dict[str, Any]], None]
    record: Callable[[dict[str, Any], float, str], None]
    monotonic: Callable[[], float]


@dataclass(frozen=True)
class Result:
    response: dict[str, Any]
    requests: tuple[dict[str, Any], ...]


def _encoded_size(value: Any) -> int:
    return len(json.dumps(
        value, sort_keys=True, separators=(",", ":"), default=str
    ).encode("utf-8"))


def _instruction(limits: Limits, policy: Policy) -> dict[str, Any]:
    return {
        "evaluation_only": True,
        "attempt": 1,
        "maximum_attempts": 1,
        "remaining_query_rounds": limits.rounds,
        "remaining_queries": limits.queries,
        "maximum_queries_this_round": policy.maximum_queries_per_round,
        "instruction": policy.instruction,
    }


def run(
    prompt_package: dict[str, Any],
    *,
    route: str,
    limits: Limits,
    maximum_prompt_bytes: int,
    hosted: bool,
    policy: Policy,
    dependencies: Dependencies,
    error_type: type[Exception],
) -> Result:
    """Execute the sole evaluation retry without granting query authority."""
    prompt_package["investigation_query_planning_retry"] = _instruction(
        limits, policy
    )
    safe_prompt = dependencies.model_safe_copy(prompt_package, hosted)
    if _encoded_size(safe_prompt) > maximum_prompt_bytes:
        raise error_type(
            "evaluation query-planning retry prompt exceeds max_prompt_bytes"
        )
    dependencies.phase()
    dependencies.preflight(prompt_package)
    started = dependencies.monotonic()
    try:
        response = dependencies.execute_model(prompt_package)
    except (Exception, SystemExit) as exc:
        dependencies.record(
            {}, dependencies.monotonic() - started, f"failed:{type(exc).__name__}"
        )
        raise
    if not isinstance(response, dict):
        dependencies.record(
            {}, dependencies.monotonic() - started, "failed:InvalidResponse"
        )
        raise error_type(
            "evaluation query-planning retry returned a non-object response"
        )
    dependencies.record(response, dependencies.monotonic() - started, "")
    prompt_package.pop("investigation_query_planning_retry", None)
    observed_route = str(response.get("_analysis_model_route") or "").strip()
    if observed_route != route:
        raise error_type(
            "evaluation query-planning retry did not preserve the assigned model route"
        )
    requests = dependencies.pop_requests(response)
    if not requests:
        raise error_type(
            "evaluation query-planning retry produced no investigation_query_requests"
        )
    return Result(response=response, requests=tuple(requests))
