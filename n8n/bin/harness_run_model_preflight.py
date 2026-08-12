"""Model-route admission and atomic pre-execution budget reservation."""
from __future__ import annotations

from typing import Any, Callable, Mapping

from harness_policy import HarnessPolicyError, Stage


def preflight_model_call(
    run: Any,
    *,
    call_id: str,
    input_value: Any,
    requested_route: str,
    purpose: str,
    independent_review: bool,
    valid_identifier: Callable[[Any, str, int], str],
    model_route: Callable[[Any, str], str],
    redacted_string: Callable[[Any, int], str],
    canonical_json: Callable[[Any], str],
    approximate_evidence_rows: Callable[[Any], int],
) -> None:
    """Authorize one immutable route and reserve its model-call budget."""
    call_id = valid_identifier(call_id, "model call_id", 128)
    requested_route = model_route(
        requested_route,
        "requested model route",
    )
    decision = _route_decision(
        run,
        requested_route=requested_route,
        independent_review=independent_review,
    )
    _append_route_decision(
        run,
        call_id=call_id,
        purpose=purpose,
        requested_route=requested_route,
        independent_review=independent_review,
        decision=decision,
        redacted_string=redacted_string,
    )
    if not decision["allowed"] and run.policy.mode == "enforce":
        raise HarnessPolicyError(str(decision["reason"]))

    measurements = _prompt_measurements(
        run,
        input_value,
        canonical_json=canonical_json,
        approximate_evidence_rows=approximate_evidence_rows,
    )
    reservation = _reserve_model_call(
        run,
        call_id=call_id,
        violations=_measurement_violations(run, measurements),
    )
    if reservation["reserved"]:
        run._model_calls = max(
            run._model_calls,
            int(reservation["total"]),
        )
    _enforce_model_budget(
        run,
        call_id=call_id,
        purpose=purpose,
        requested_route=requested_route,
        independent_review=independent_review,
        decision=decision,
        measurements=measurements,
        reservation=reservation,
        redacted_string=redacted_string,
    )


def _route_decision(
    run: Any,
    *,
    requested_route: str,
    independent_review: bool,
) -> dict[str, Any]:
    expected_route = (
        run.envelope.assigned_reviewer_route
        if independent_review
        else run.envelope.assigned_route
    )
    allowed = bool(expected_route) and requested_route == expected_route
    if allowed and independent_review:
        reason = "requested route matches the immutable reviewer assignment"
    elif allowed:
        reason = "requested route matches the immutable primary assignment"
    elif independent_review and not expected_route:
        reason = "no reviewer route was assigned to this run"
    elif not expected_route:
        reason = "no primary route was assigned to this run"
    else:
        reason = "requested route does not match the immutable run assignment"
    return {
        "expected_route": expected_route,
        "allowed": allowed,
        "reason": reason,
        "stage": (
            Stage.INDEPENDENT_REVIEW.value
            if independent_review
            else Stage.PRIMARY_ANALYSIS.value
        ),
    }


def _append_route_decision(
    run: Any,
    *,
    call_id: str,
    purpose: str,
    requested_route: str,
    independent_review: bool,
    decision: Mapping[str, Any],
    redacted_string: Callable[[Any, int], str],
) -> None:
    run.store.append_event(
        run.run_id,
        "policy.model-route",
        str(decision["stage"]),
        {
            "call_id": call_id,
            "purpose": redacted_string(purpose, 160),
            "requested_route": requested_route,
            "expected_route": decision["expected_route"],
            "independent_review": independent_review,
            "allowed": decision["allowed"],
            "reason": decision["reason"],
            "policy_mode": run.policy.mode,
        },
        idempotency_key=f"policy.model-route:{call_id}",
    )


def _prompt_measurements(
    run: Any,
    input_value: Any,
    *,
    canonical_json: Callable[[Any], str],
    approximate_evidence_rows: Callable[[Any], int],
) -> dict[str, Any]:
    return {
        "prompt_bytes": len(canonical_json(input_value).encode("utf-8")),
        "approximate_evidence_rows": approximate_evidence_rows(input_value),
        "elapsed_seconds": run._elapsed_seconds(),
    }


def _measurement_violations(
    run: Any,
    measurements: Mapping[str, Any],
) -> list[str]:
    violations: list[str] = []
    if (
        measurements["prompt_bytes"]
        > run.policy.budgets["max_prompt_evidence_bytes"]
    ):
        violations.append("max_prompt_evidence_bytes")
    if (
        measurements["approximate_evidence_rows"]
        > run.policy.budgets["max_prompt_evidence_rows"]
    ):
        violations.append("max_prompt_evidence_rows")
    if measurements["elapsed_seconds"] > run.policy.budgets["max_run_seconds"]:
        violations.append("max_run_seconds")
    return violations


def _reserve_model_call(
    run: Any,
    *,
    call_id: str,
    violations: list[str],
) -> dict[str, Any]:
    return run.store.reserve_budget_operation(
        run.run_id,
        reservation_type="model-call",
        reservation_id=call_id,
        amount=1,
        max_total=run.policy.budgets["max_model_calls"],
        max_operations=run.policy.budgets["max_model_calls"],
        enforce=run.policy.mode == "enforce",
        preexisting_violations=violations,
    )


def _enforce_model_budget(
    run: Any,
    *,
    call_id: str,
    purpose: str,
    requested_route: str,
    independent_review: bool,
    decision: Mapping[str, Any],
    measurements: Mapping[str, Any],
    reservation: Mapping[str, Any],
    redacted_string: Callable[[Any, int], str],
) -> None:
    run._enforce_budget(
        operation_id=f"model:{call_id}",
        operation="model call",
        stage=str(decision["stage"]),
        observed={
            "call_id": call_id,
            "purpose": redacted_string(purpose, 160),
            "requested_route": requested_route,
            "expected_route": decision["expected_route"],
            "route_allowed": decision["allowed"],
            "independent_review": independent_review,
            "next_model_call": int(reservation["operation_count"]),
            "prompt_bytes": measurements["prompt_bytes"],
            "approximate_evidence_rows": measurements[
                "approximate_evidence_rows"
            ],
            "reserved": bool(reservation["reserved"]),
        },
        violations=list(reservation["violations"]),
    )
