"""Evidence-synthesis model-call boundary for governed query rounds."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


FOLLOW_UP_INSTRUCTION = (
    "Use the newly collected, audited evidence to update hypotheses and the "
    "final conclusion. Request another narrow investigation_query_requests "
    "batch only if a material discriminator remains and both budgets are positive."
)


@dataclass(frozen=True)
class Policy:
    route: str
    call_id_prefix: str
    call_purpose_prefix: str
    independent_review: bool
    attest_route: bool


@dataclass(frozen=True)
class Dependencies:
    build_input: Callable[[dict[str, Any], int], Any]
    catalogue: Callable[[Any], None]
    preflight: Callable[[str, Any, str], None]
    execute: Callable[[Any], Any]
    record: Callable[[str, str, Any, Any, float, str], None]
    phase: Callable[[str], None]
    after_follow_up: Callable[[int, int], Any]
    pop_requests: Callable[[dict[str, Any]], list[Any]]
    ignore_terminal: Callable[[Any, int], Any]
    monotonic: Callable[[], float]


@dataclass(frozen=True)
class Result:
    response: dict[str, Any]
    state: Any
    stop: bool
    call_number: int
    call_id: str


def follow_up(
    *, round_number: int, remaining_rounds: int, remaining_queries: int,
) -> dict[str, Any]:
    return {
        "round": round_number,
        "remaining_rounds": remaining_rounds,
        "remaining_queries": remaining_queries,
        "instruction": FOLLOW_UP_INSTRUCTION,
    }


def _invoke(
    model_input: Any,
    *,
    call_id: str,
    purpose: str,
    policy: Policy,
    dependencies: Dependencies,
) -> dict[str, Any]:
    dependencies.catalogue(model_input)
    dependencies.preflight(call_id, model_input, purpose)
    started = dependencies.monotonic()
    try:
        response = dependencies.execute(model_input)
    except (Exception, SystemExit) as exc:
        dependencies.record(
            call_id, purpose, {}, model_input,
            dependencies.monotonic() - started,
            f"failed:{type(exc).__name__}",
        )
        raise
    dependencies.record(
        call_id, purpose, response, model_input,
        dependencies.monotonic() - started, "",
    )
    return response


def run(
    prompt_package: dict[str, Any],
    *,
    state: Any,
    prior_call_number: int,
    remaining_rounds: int,
    remaining_queries: int,
    harness_round_number: int,
    policy: Policy,
    dependencies: Dependencies,
    error_type: type[Exception],
) -> Result:
    """Execute one evidence-synthesis call and apply terminal budget policy."""
    call_number = prior_call_number + 1
    call_id = f"{policy.call_id_prefix}-{call_number}"
    purpose = f"{policy.call_purpose_prefix} {call_number}"
    model_input = dependencies.build_input(prompt_package, call_number)
    response = _invoke(
        model_input, call_id=call_id, purpose=purpose,
        policy=policy, dependencies=dependencies,
    )
    if not isinstance(response, dict):
        raise error_type("investigation evidence synthesis returned a non-object response")
    observed_route = str(response.get("_analysis_model_route") or "").strip()
    if policy.attest_route and observed_route != policy.route:
        raise error_type(
            "evaluation investigation follow-up did not preserve the assigned model route"
        )
    dependencies.phase(
        f"round {harness_round_number} evidence assimilated"
    )
    stop = dependencies.after_follow_up(remaining_rounds, remaining_queries)
    updated_state = state
    if stop.stop:
        updated_state = dependencies.ignore_terminal(
            state, len(dependencies.pop_requests(response))
        )
    return Result(response, updated_state, stop.stop, call_number, call_id)
