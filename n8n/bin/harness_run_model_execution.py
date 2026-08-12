"""Durable model-call observation, budget, and ledger execution."""
from __future__ import annotations

import json
from typing import Any, Callable, Mapping

from harness_policy import (
    HarnessPolicyError,
    Stage,
    _model_route,
    _valid_identifier,
    digest_json,
)


def record_model_call(
    run: Any,
    *,
    call_id: str,
    purpose: str,
    requested_route: str,
    response: Mapping[str, Any],
    input_value: Any,
    duration_seconds: float,
    independent_review: bool,
    status: str,
    connect: Callable[[Any], Any],
) -> None:
    call_id = _valid_identifier(call_id, "model call_id", 128)
    requested_route = _model_route(
        requested_route,
        "completed model route",
    )
    authorization = _model_authorization(
        run,
        call_id,
        connect=connect,
    )
    observation = _model_observation(
        run,
        call_id=call_id,
        requested_route=requested_route,
        response=response,
        independent_review=independent_review,
        authorization=authorization,
    )
    _append_model_observation(run, observation)
    if not observation["allowed"] and run.policy.mode == "enforce":
        raise HarnessPolicyError(str(observation["reason"]))
    reservation = _reserve_model_call(run, call_id)
    _enforce_model_budget(
        run,
        call_id,
        independent_review=independent_review,
        reservation=reservation,
    )
    run.store.record_model_call(
        run.run_id,
        call_id=call_id,
        purpose=purpose,
        requested_route=requested_route,
        response=response,
        independent_review=independent_review,
        input_digest=digest_json(input_value),
        duration_ms=max(0, round(float(duration_seconds) * 1_000)),
        status=status,
    )
    run._model_calls = max(
        run._model_calls,
        int(reservation["total"]),
    )


def _model_authorization(
    run: Any,
    call_id: str,
    *,
    connect: Callable[[Any], Any],
) -> dict[str, Any]:
    with connect(run.store.path) as connection:
        authorization_row = connection.execute(
            """
            SELECT payload_json
            FROM harness_events
            WHERE run_id = ? AND idempotency_key = ?
            """,
            (
                run.run_id,
                f"policy.model-route:{call_id}",
            ),
        ).fetchone()
    return (
        json.loads(str(authorization_row["payload_json"]))
        if authorization_row is not None
        else {}
    )


def _model_observation(
    run: Any,
    *,
    call_id: str,
    requested_route: str,
    response: Mapping[str, Any],
    independent_review: bool,
    authorization: Mapping[str, Any],
) -> dict[str, Any]:
    observed_route = str(
        response.get("_analysis_model_route") or ""
    ).strip()
    route_authorized = bool(
        authorization.get("allowed") is True
        and authorization.get("requested_route") == requested_route
        and bool(authorization.get("independent_review"))
        is bool(independent_review)
    )
    observed_matches = (
        not response
        or (
            bool(observed_route)
            and observed_route == requested_route
        )
    )
    allowed = route_authorized and observed_matches
    return {
        "call_id": call_id,
        "requested_route": requested_route,
        "observed_route": observed_route,
        "independent_review": independent_review,
        "response_present": bool(response),
        "allowed": allowed,
        "reason": _model_observation_reason(
            allowed=allowed,
            response_present=bool(response),
            route_authorized=route_authorized,
        ),
        "policy_mode": run.policy.mode,
    }


def _model_observation_reason(
    *,
    allowed: bool,
    response_present: bool,
    route_authorized: bool,
) -> str:
    if allowed and response_present:
        return "authorized route and collector-observed route agree"
    if allowed:
        return "authorized failed invocation has no model response"
    if not route_authorized:
        return "model call has no matching allowed preflight"
    return "collector-observed route differs from the authorized route"


def _append_model_observation(
    run: Any,
    observation: Mapping[str, Any],
) -> None:
    stage = (
        Stage.INDEPENDENT_REVIEW.value
        if observation["independent_review"]
        else Stage.PRIMARY_ANALYSIS.value
    )
    run.store.append_event(
        run.run_id,
        "policy.model-observation",
        stage,
        dict(observation),
        idempotency_key=(
            f'policy.model-observation:{observation["call_id"]}'
        ),
    )


def _reserve_model_call(run: Any, call_id: str) -> dict[str, Any]:
    return run.store.reserve_budget_operation(
        run.run_id,
        reservation_type="model-call",
        reservation_id=call_id,
        amount=1,
        max_total=run.policy.budgets["max_model_calls"],
        max_operations=run.policy.budgets["max_model_calls"],
        enforce=run.policy.mode == "enforce",
    )


def _enforce_model_budget(
    run: Any,
    call_id: str,
    *,
    independent_review: bool,
    reservation: Mapping[str, Any],
) -> None:
    if not reservation["violations"] or run.policy.mode != "enforce":
        return
    run._enforce_budget(
        operation_id=f"model:{call_id}",
        operation="model call",
        stage=(
            Stage.INDEPENDENT_REVIEW.value
            if independent_review
            else Stage.PRIMARY_ANALYSIS.value
        ),
        observed={
            "call_id": call_id,
            "next_model_call": reservation["operation_count"],
            "reserved": False,
        },
        violations=reservation["violations"],
    )
