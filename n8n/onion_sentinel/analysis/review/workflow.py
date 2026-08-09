"""Independent-review workflow orchestration with injected runtime ports."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable


@dataclass(frozen=True)
class Policy:
    """Immutable review limits and fallback prompt policy."""

    default_prompt_file: Path
    maximum_attempts: int = 2
    purpose: str = "independent second-opinion review"


@dataclass(frozen=True)
class Dependencies:
    """Runtime ports required by the review workflow."""

    trigger: Callable[[dict[str, Any], dict[str, Any]], str]
    notify_phase: Callable[..., None]
    route_identity: Callable[[str, dict[str, Any]], Any]
    role_prompt_file: Callable[[Path, str], Path]
    route_is_hosted: Callable[[str, dict[str, Any]], bool]
    independent_package: Callable[..., dict[str, Any]]
    monotonic: Callable[[], float]
    warning: Callable[[str], None]
    analyze_route: Callable[..., dict[str, Any]]
    validate_reviewer: Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]]
    reviewer_validation_error: type[Exception]
    validation_failure: Callable[..., dict[str, Any]]
    repair_error_category: Callable[[Any], str]
    repair_guidance: Callable[[Any], Any]
    validate_response: Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]]
    supplemental_pivot: Callable[..., tuple[dict[str, Any], dict[str, Any]]]
    compare: Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]]
    automation_authorization: Callable[..., dict[str, Any]]
    adjudicate: Callable[..., dict[str, Any]]
    apply_adjudication_projection: Callable[..., bool]
    reconcile_report: Callable[[dict[str, Any], dict[str, Any]], Any]
    apply_disagreement_gate: Callable[..., Any]
    apply_completed_gate: Callable[..., Any]
    apply_required_gate: Callable[..., Any]
    apply_tuning_guard: Callable[[dict[str, Any], dict[str, Any]], Any]


@dataclass
class Context:
    """Inputs and runtime handles for one independent-review decision."""

    prompt_package: dict[str, Any]
    primary_response: dict[str, Any]
    args: Any
    settings: dict[str, Any]
    agent_role: str
    phase_callback: Any = None
    harness_runtime: Any = None
    force_review_reason: str = ""
    live_osquery_config: dict[str, Any] | None = None
    enrichment_config: dict[str, Any] | None = None
    security_onion_config_path: Any = None
    investigation_pivot_dir: Any = None
    strict_harness_observation: bool = False


@dataclass(frozen=True)
class Admission:
    trigger: str
    route: str
    reviewer_prompt: Path


@dataclass
class AttemptResult:
    response: dict[str, Any]
    attempts: int = 0
    failures: list[dict[str, Any]] = field(default_factory=list)


class HarnessObserver:
    """Apply the workflow's fail-closed/shadow harness observation policy."""

    def __init__(self, runtime: Any, *, strict: bool, warning: Callable[[str], None]):
        self.runtime = runtime
        self.strict = strict
        self.warning = warning

    def observe(self, call: Callable[[], Any]) -> Any:
        if self.runtime is None:
            return None
        try:
            return call()
        except Exception as exc:
            enforce = getattr(getattr(self.runtime, "policy", None), "mode", "") == "enforce"
            if enforce or self.strict:
                raise
            self.warning(
                "warning: Onion Sentinel harness shadow reviewer observation "
                f"failed: {type(exc).__name__}: {exc}"
            )
            return None


def execute(context: Context, policy: Policy, deps: Dependencies) -> dict[str, Any]:
    """Run one bounded independent review without replacing primary evidence."""
    response = context.primary_response
    response.pop("_second_opinion", None)
    response.pop("_disagreement_adjudication", None)
    admission = _admit(context, policy, deps)
    if admission is None:
        return response
    started = deps.monotonic()
    package = deps.independent_package(
        context.prompt_package,
        hosted=deps.route_is_hosted(admission.route, context.settings),
    )
    observer = HarnessObserver(
        context.harness_runtime,
        strict=context.strict_harness_observation,
        warning=deps.warning,
    )
    attempts = AttemptResult({})
    try:
        _review_attempts(
            context, admission, package, observer, policy, deps, attempts
        )
        _complete_review(context, admission, package, attempts, started, deps)
    except SystemExit as exc:
        _record_failure(context, admission, started, attempts, exc, deps)
    except Exception as exc:
        _record_failure(context, admission, started, attempts, exc, deps)
    finally:
        _finalize(context, admission.trigger, deps)
    return response


def _admit(context: Context, policy: Policy, deps: Dependencies) -> Admission | None:
    trigger = deps.trigger(context.primary_response, context.prompt_package)
    trigger = trigger or str(context.force_review_reason or "").strip()
    if not trigger:
        context.primary_response["final_disposition_status"] = "primary_not_reviewed"
        deps.notify_phase(context.phase_callback, "post_processing")
        return None
    route = _assigned_route(context.settings, context.agent_role, second_opinion=True)
    if not route:
        _reject_configuration(context, trigger, "not_configured", "", deps)
        return None
    primary_route = _assigned_route(context.settings, context.agent_role)
    if deps.route_identity(primary_route, context.settings) == deps.route_identity(
        route, context.settings
    ):
        _reject_configuration(context, trigger, "not_independent", route, deps)
        return None
    prompt = _reviewer_prompt(context, policy, deps)
    deps.notify_phase(context.phase_callback, "second_opinion", route, trigger)
    return Admission(trigger=trigger, route=route, reviewer_prompt=prompt)


def _assigned_route(settings: dict[str, Any], role: str, *, second_opinion: bool = False) -> str:
    key = "agent_second_opinion_models" if second_opinion else "agent_models"
    routes = settings.get(key)
    return str((routes if isinstance(routes, dict) else {}).get(role) or "").strip()


def _reject_configuration(
    context: Context,
    trigger: str,
    status: str,
    route: str,
    deps: Dependencies,
) -> None:
    independent = status == "not_independent"
    reason = (
        "the reviewer resolves to the same provider/model identity as the primary"
        if independent else "no independent reviewer model is configured"
    )
    deps.apply_required_gate(
        context.primary_response,
        status=f"review_required_{status}",
        reason=reason,
    )
    record = {"status": status, "trigger": trigger, "model_route": route}
    if independent:
        record["error"] = (
            "The configured reviewer resolves to the same provider/model identity "
            "as the primary."
        )
    context.primary_response["_second_opinion"] = record
    deps.notify_phase(
        context.phase_callback,
        "post_processing",
        trigger_reason=trigger,
    )


def _reviewer_prompt(context: Context, policy: Policy, deps: Dependencies) -> Path:
    settings_path = getattr(context.args, "ai_settings_file", None)
    if settings_path:
        return deps.role_prompt_file(Path(settings_path).parent, context.agent_role)
    configured = context.prompt_package.get("second_opinion_system_prompt_file")
    fallback = getattr(context.args, "second_opinion_prompt_file", policy.default_prompt_file)
    return Path(str(configured or fallback))


def _review_attempts(
    context: Context,
    admission: Admission,
    package: dict[str, Any],
    observer: HarnessObserver,
    policy: Policy,
    deps: Dependencies,
    state: AttemptResult,
) -> None:
    for attempt in range(1, policy.maximum_attempts + 1):
        state.attempts = attempt
        call_id = f"independent-review-{attempt}"
        _observe_preflight(context, admission, package, observer, call_id, policy)
        started = deps.monotonic()
        candidate = _invoke_candidate(
            context, admission, package, observer, call_id, started, policy, deps
        )
        try:
            validated = deps.validate_reviewer(candidate, package)
        except deps.reviewer_validation_error as exc:
            _observe_call(
                context, admission, package, candidate, observer, call_id,
                started, policy, deps, status="validation-failed",
            )
            state.failures.append(deps.validation_failure(
                attempt=attempt, call_id=call_id, error=exc,
                input_value=package, response=candidate,
            ))
            if attempt >= policy.maximum_attempts:
                raise
            _install_repair(package, state.failures[-1], deps)
            continue
        _observe_call(
            context, admission, package, candidate, observer, call_id,
            started, policy, deps,
        )
        state.response = validated
        return
    raise deps.reviewer_validation_error("reviewer produced no validated response")


def _observe_preflight(
    context: Context,
    admission: Admission,
    package: dict[str, Any],
    observer: HarnessObserver,
    call_id: str,
    policy: Policy,
) -> None:
    observer.observe(lambda: context.harness_runtime.preflight_model_call(
        call_id=call_id,
        input_value=package,
        requested_route=admission.route,
        purpose=policy.purpose,
        independent_review=True,
    ) if context.harness_runtime is not None else None)


def _invoke_candidate(
    context: Context,
    admission: Admission,
    package: dict[str, Any],
    observer: HarnessObserver,
    call_id: str,
    started: float,
    policy: Policy,
    deps: Dependencies,
) -> dict[str, Any]:
    try:
        return deps.analyze_route(
            admission.route, package, context.args, context.settings,
            system_prompt_file=admission.reviewer_prompt,
            independent_review=True,
        )
    except (Exception, SystemExit) as exc:
        _observe_call(
            context, admission, package, {}, observer, call_id, started,
            policy, deps, status=f"failed:{type(exc).__name__}",
        )
        raise


def _observe_call(
    context: Context,
    admission: Admission,
    package: dict[str, Any],
    response: dict[str, Any],
    observer: HarnessObserver,
    call_id: str,
    started: float,
    policy: Policy,
    deps: Dependencies,
    *,
    status: str = "",
) -> None:
    kwargs = {
        "call_id": call_id,
        "purpose": policy.purpose,
        "requested_route": admission.route,
        "response": response,
        "input_value": package,
        "duration_seconds": deps.monotonic() - started,
        "independent_review": True,
    }
    if status:
        kwargs["status"] = status
    observer.observe(lambda: context.harness_runtime.model_call(**kwargs)
                     if context.harness_runtime is not None else None)


def _install_repair(
    package: dict[str, Any],
    failure: dict[str, Any],
    deps: Dependencies,
) -> None:
    message = failure["message"]
    package["review_contract_repair"] = {
        "attempt": 1,
        "instruction": (
            "The first response failed deterministic validation. Return one fresh "
            "complete object matching response_schema; do not copy or discuss the "
            "invalid response."
        ),
        "validation_errors": deps.repair_error_category(message),
        "field_guidance": deps.repair_guidance(message),
    }


def _complete_review(
    context: Context,
    admission: Admission,
    package: dict[str, Any],
    attempts: AttemptResult,
    started: float,
    deps: Dependencies,
) -> None:
    secondary = deps.validate_response(attempts.response, package)
    secondary["second_opinion_recommended"] = False
    secondary["hosted_second_opinion_recommended"] = False
    secondary, supplemental = _supplemental(
        context, admission, secondary, deps
    )
    comparison = deps.compare(context.primary_response, secondary)
    authorization = deps.automation_authorization(
        context.primary_response, secondary, comparison
    )
    context.primary_response["_second_opinion"] = _completed_record(
        admission, secondary, supplemental, comparison, authorization,
        attempts, deps.monotonic() - started,
    )
    _apply_disposition(context, secondary, comparison, authorization, deps)
    _apply_memory_gate(context.primary_response, authorization)


def _supplemental(
    context: Context,
    admission: Admission,
    secondary: dict[str, Any],
    deps: Dependencies,
) -> tuple[dict[str, Any], dict[str, Any]]:
    return deps.supplemental_pivot(
        context.prompt_package, secondary, context.args, context.settings,
        context.agent_role, admission.route, admission.reviewer_prompt,
        live_osquery_config=context.live_osquery_config,
        enrichment_config=context.enrichment_config,
        security_onion_config_path=context.security_onion_config_path,
        investigation_pivot_dir=context.investigation_pivot_dir,
        harness_runtime=context.harness_runtime,
    )


def _completed_record(
    admission: Admission,
    secondary: dict[str, Any],
    supplemental: dict[str, Any],
    comparison: dict[str, Any],
    authorization: dict[str, Any],
    attempts: AttemptResult,
    elapsed: float,
) -> dict[str, Any]:
    return {
        "status": "completed",
        "trigger": admission.trigger,
        "model_route": admission.route,
        "system_prompt_file": str(admission.reviewer_prompt),
        "runtime_seconds": round(elapsed, 3),
        "attempts": attempts.attempts,
        "validation_failures": attempts.failures,
        "supplemental_pivot": supplemental,
        "comparison": comparison,
        "response": secondary,
        "automation_authorization": authorization,
    }


def _apply_disposition(
    context: Context,
    secondary: dict[str, Any],
    comparison: dict[str, Any],
    authorization: dict[str, Any],
    deps: Dependencies,
) -> None:
    if comparison["material_disagreement"]:
        _apply_material_disagreement(context, secondary, comparison, deps)
    elif not authorization["authorized"]:
        deps.apply_completed_gate(
            context.primary_response, reason=authorization["reason"]
        )
    elif comparison["agreement"] == "agreement":
        context.primary_response["final_disposition_status"] = "corroborated"
    else:
        context.primary_response["final_disposition_status"] = (
            "primary_with_advisory_disagreement"
        )


def _apply_material_disagreement(
    context: Context,
    secondary: dict[str, Any],
    comparison: dict[str, Any],
    deps: Dependencies,
) -> None:
    response = context.primary_response
    adjudication = deps.adjudicate(
        context.prompt_package, response, secondary, comparison,
        context.args, context.settings, context.agent_role,
        context.phase_callback, context.harness_runtime,
    )
    response["_disagreement_adjudication"] = adjudication
    projected = deps.apply_adjudication_projection(response, secondary, adjudication)
    if projected:
        deps.reconcile_report(response, context.prompt_package)
        response["final_disposition_status"] = "adjudicated_analytical_pending_human"
    else:
        deps.apply_disagreement_gate(response, secondary, comparison)
        response["final_disposition_status"] = "disputed_pending_human"
    _block_disputed_automation(response, projected)


def _block_disputed_automation(response: dict[str, Any], projected: bool) -> None:
    response["tuning_recommendation"] = "needs_more_data"
    response["tuning_reason"] = (
        "Automatic tuning is blocked because the primary and independent reviewer "
        "materially disagree."
    )
    response["recommended_tuning_actions"] = []
    response["memory_candidates"] = []
    response["_automation_controls"] = {
        "automatic_closure_blocked": True,
        "containment_blocked": True,
        "tuning_blocked": True,
        "memory_writeback_blocked": True,
        "requires_human_review": True,
        "reason": (
            "shadow adjudication resolved the analytical display but cannot authorize automation"
            if projected else "material second-opinion disagreement"
        ),
    }


def _apply_memory_gate(response: dict[str, Any], authorization: dict[str, Any]) -> None:
    if authorization["memory_writeback_authorized"]:
        return
    controls = dict(response.get("_automation_controls") or {})
    reason = (
        "Primary memory writeback requires full high-confidence agreement from "
        "the independent reviewer."
    )
    controls["memory_writeback_blocked"] = True
    controls["memory_writeback_reason"] = reason
    if not str(controls.get("reason") or "").strip():
        controls["reason"] = reason
    response["_automation_controls"] = controls


def _record_failure(
    context: Context,
    admission: Admission,
    started: float,
    attempts: AttemptResult,
    error: BaseException,
    deps: Dependencies,
) -> None:
    validation = isinstance(error, deps.reviewer_validation_error) or isinstance(
        error, SystemExit
    )
    detail = str(error) if validation else f"{type(error).__name__}: {error}"
    deps.apply_required_gate(
        context.primary_response,
        status="review_required_failed",
        reason=detail[:500] or "reviewer validation failed",
    )
    context.primary_response["_second_opinion"] = {
        "status": "failed",
        "trigger": admission.trigger,
        "model_route": admission.route,
        "system_prompt_file": str(admission.reviewer_prompt),
        "runtime_seconds": round(deps.monotonic() - started, 3),
        "attempts": attempts.attempts,
        "validation_failures": attempts.failures,
        "error": detail[:1000],
    }


def _finalize(context: Context, trigger: str, deps: Dependencies) -> None:
    deps.apply_tuning_guard(context.primary_response, context.prompt_package)
    deps.reconcile_report(context.primary_response, context.prompt_package)
    deps.notify_phase(
        context.phase_callback,
        "post_processing",
        trigger_reason=trigger,
    )
