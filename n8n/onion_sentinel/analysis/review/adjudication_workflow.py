"""Bounded runtime orchestration for independent disagreement adjudication."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Type


@dataclass(frozen=True)
class Policy:
    default_prompt_file: Path
    maximum_attempts: int = 2
    purpose: str = "bounded disagreement adjudication"


@dataclass(frozen=True)
class Context:
    prompt_package: dict[str, Any]
    primary_response: dict[str, Any]
    reviewer_response: dict[str, Any]
    comparison: dict[str, Any]
    args: Any
    settings: dict[str, Any]
    agent_role: str
    phase_callback: Callable[[str, str, str], None] | None
    harness_runtime: Any


@dataclass(frozen=True)
class Dependencies:
    route_identity: Callable[[Any, dict[str, Any]], str]
    notify_phase: Callable[..., None]
    build_package: Callable[..., dict[str, Any]]
    route_is_hosted: Callable[[str, dict[str, Any]], bool]
    analyze_route: Callable[..., dict[str, Any]]
    validate: Callable[[Any, dict[str, Any]], dict[str, Any]]
    reconcile_endpoint_gaps: Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]]
    monotonic: Callable[[], float]
    validation_error: Type[Exception]


@dataclass
class AttemptState:
    response: dict[str, Any] | None = None
    failures: list[dict[str, Any]] = field(default_factory=list)
    attempts: int = 0


def _route(context: Context) -> tuple[str, str, bool]:
    configured = str(
        (context.settings.get("agent_adjudicator_models") or {}).get(
            context.agent_role
        ) or ""
    ).strip()
    frozen = str(
        context.harness_runtime.envelope.assigned_reviewer_route
        if context.harness_runtime is not None else ""
    ).strip()
    return (
        frozen or configured,
        "frozen_reviewer_route" if frozen else "configured_adjudicator_route",
        bool(frozen),
    )


def _not_configured() -> dict[str, Any]:
    return {
        "status": "not_configured",
        "mode": "shadow",
        "automation_authorized": False,
        "error": "No independent disagreement adjudicator is configured.",
    }


def _not_independent(route: str) -> dict[str, Any]:
    return {
        "status": "not_independent",
        "mode": "shadow",
        "model_route": route,
        "automation_authorized": False,
        "error": (
            "The configured adjudicator resolves to a primary or reviewer "
            "provider/model identity."
        ),
    }


def _independent(
    context: Context,
    route: str,
    frozen: bool,
    dependencies: Dependencies,
) -> bool:
    settings = context.settings
    primary = dependencies.route_identity(
        (settings.get("agent_models") or {}).get(context.agent_role), settings
    )
    reviewer = dependencies.route_identity(
        (settings.get("agent_second_opinion_models") or {}).get(
            context.agent_role
        ),
        settings,
    )
    selected = dependencies.route_identity(route, settings)
    return selected != primary and (selected != reviewer or frozen)


def _prompt_file(context: Context, policy: Policy) -> Path:
    return Path(getattr(
        context.args,
        "disagreement_adjudicator_prompt_file",
        policy.default_prompt_file,
    ))


def _preflight(
    context: Context,
    package: dict[str, Any],
    route: str,
    call_id: str,
    policy: Policy,
) -> None:
    if context.harness_runtime is not None:
        context.harness_runtime.preflight_model_call(
            call_id=call_id,
            input_value=package,
            requested_route=route,
            purpose=policy.purpose,
            independent_review=True,
        )


def _record_call(
    context: Context,
    package: dict[str, Any],
    route: str,
    call_id: str,
    candidate: dict[str, Any],
    started: float,
    policy: Policy,
    dependencies: Dependencies,
    *,
    status: str = "",
) -> None:
    if context.harness_runtime is None:
        return
    kwargs = {
        "call_id": call_id,
        "purpose": policy.purpose,
        "requested_route": route,
        "response": candidate,
        "input_value": package,
        "duration_seconds": dependencies.monotonic() - started,
        "independent_review": True,
    }
    if status:
        kwargs["status"] = status
    context.harness_runtime.model_call(**kwargs)


def _repair(package: dict[str, Any], error: Exception) -> None:
    package["adjudication_contract_repair"] = {
        "attempt": 1,
        "instruction": (
            "Return one fresh complete object matching response_schema. "
            "Use only exact contract field names and evidence refs."
        ),
        "validation_error": str(error)[:1000],
    }


def _attempt(
    context: Context,
    package: dict[str, Any],
    route: str,
    prompt_file: Path,
    attempt: int,
    state: AttemptState,
    policy: Policy,
    dependencies: Dependencies,
) -> bool:
    call_id = f"disagreement-adjudication-{attempt}"
    _preflight(context, package, route, call_id, policy)
    started = dependencies.monotonic()
    candidate = dependencies.analyze_route(
        route,
        package,
        context.args,
        context.settings,
        system_prompt_file=prompt_file,
        independent_review=True,
    )
    try:
        validated = dependencies.validate(candidate, package)
    except dependencies.validation_error as exc:
        _record_call(
            context, package, route, call_id, candidate, started, policy,
            dependencies, status="validation-failed",
        )
        state.failures.append({"attempt": attempt, "error": str(exc)[:2000]})
        if attempt >= policy.maximum_attempts:
            raise
        _repair(package, exc)
        return False
    state.response = dependencies.reconcile_endpoint_gaps(validated, package)
    _record_call(
        context, package, route, call_id, candidate, started, policy, dependencies
    )
    return True


def _run_attempts(
    context: Context,
    package: dict[str, Any],
    route: str,
    prompt_file: Path,
    state: AttemptState,
    policy: Policy,
    dependencies: Dependencies,
) -> AttemptState:
    for attempt in range(1, policy.maximum_attempts + 1):
        state.attempts = attempt
        if _attempt(
            context, package, route, prompt_file, attempt, state, policy,
            dependencies,
        ):
            break
    if state.response is None:
        raise dependencies.validation_error(
            "adjudicator produced no validated response"
        )
    return state


def _completed(
    route: str,
    route_source: str,
    prompt_file: Path,
    started: float,
    state: AttemptState,
    dependencies: Dependencies,
) -> dict[str, Any]:
    assert state.response is not None
    return {
        "status": "completed",
        "mode": "shadow",
        "model_route": route,
        "route_source": route_source,
        "system_prompt_file": str(prompt_file),
        "runtime_seconds": round(dependencies.monotonic() - started, 3),
        "attempts": state.attempts,
        "validation_failures": state.failures,
        "response": state.response,
        "decision": state.response["decision"],
        "automation_authorized": False,
        "human_adjudication_required": True,
    }


def _failed(
    route: str,
    route_source: str,
    prompt_file: Path,
    started: float,
    state: AttemptState,
    error: Exception,
    dependencies: Dependencies,
) -> dict[str, Any]:
    return {
        "status": "failed",
        "mode": "shadow",
        "model_route": route,
        "route_source": route_source,
        "system_prompt_file": str(prompt_file),
        "runtime_seconds": round(dependencies.monotonic() - started, 3),
        "attempts": state.attempts,
        "validation_failures": state.failures,
        "automation_authorized": False,
        "human_adjudication_required": True,
        "error": f"{type(error).__name__}: {error}"[:2000],
    }


def run(
    context: Context,
    *,
    policy: Policy,
    dependencies: Dependencies,
) -> dict[str, Any]:
    """Run the closed shadow adjudication contract with one bounded repair."""
    route, route_source, frozen = _route(context)
    if not route:
        return _not_configured()
    if not _independent(context, route, frozen, dependencies):
        return _not_independent(route)
    dependencies.notify_phase(
        context.phase_callback,
        "disagreement_adjudication",
        route,
        "Material primary/reviewer disagreement requires bounded adjudication.",
    )
    package = dependencies.build_package(
        context.prompt_package,
        context.primary_response,
        context.reviewer_response,
        context.comparison,
        hosted=dependencies.route_is_hosted(route, context.settings),
    )
    prompt_file = _prompt_file(context, policy)
    started = dependencies.monotonic()
    state = AttemptState()
    try:
        state = _run_attempts(
            context, package, route, prompt_file, state, policy, dependencies
        )
        return _completed(
            route, route_source, prompt_file, started, state, dependencies
        )
    except Exception as exc:
        return _failed(
            route, route_source, prompt_file, started, state, exc, dependencies
        )
