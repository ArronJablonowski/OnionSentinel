"""Assigned-route primary model execution with harness observation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


@dataclass(frozen=True)
class Policy:
    agent_roles: frozenset[str]
    evaluation_harness_run: bool
    call_id: str = "primary-initial"
    purpose: str = "initial primary analysis"


@dataclass(frozen=True)
class Dependencies:
    attach_evidence_contract: Callable[[dict[str, Any]], Any]
    canonical_route: Callable[[Any], str]
    notify_phase: Callable[[Any, str, str], None]
    analyze_route: Callable[[str, dict[str, Any], Any, dict[str, Any]], dict[str, Any]]
    monotonic: Callable[[], float]
    warning: Callable[[str], None]
    route_error: type[Exception]


def execute(
    prompt_package: dict[str, Any], args: Any, settings: dict[str, Any],
    agent_role: str, *, phase_callback: Any, harness_runtime: Any,
    policy: Policy, dependencies: Dependencies,
) -> dict[str, Any]:
    """Execute exactly one assigned primary route and record its provenance."""
    _attach_contract(prompt_package, dependencies)
    route = _assigned_route(settings, agent_role, policy, dependencies)
    dependencies.notify_phase(phase_callback, "primary_analysis", route)
    observer = _HarnessObserver(harness_runtime, policy, dependencies)
    observer.preflight(prompt_package, route)
    started = dependencies.monotonic()
    try:
        response = dependencies.analyze_route(route, prompt_package, args, settings)
    except (Exception, SystemExit) as exc:
        observer.record(prompt_package, route, {}, started, f"failed:{type(exc).__name__}")
        raise
    observer.record(prompt_package, route, response, started, "")
    _validate_route(response, route, policy, dependencies)
    return response


def _attach_contract(
    prompt_package: dict[str, Any], dependencies: Dependencies,
) -> None:
    fields = ("response_schema", "alert", "incident_response_evidence")
    if any(isinstance(prompt_package.get(field), dict) for field in fields):
        dependencies.attach_evidence_contract(prompt_package)


def _assigned_route(
    settings: dict[str, Any], agent_role: str, policy: Policy,
    dependencies: Dependencies,
) -> str:
    if agent_role not in policy.agent_roles:
        raise SystemExit(f"Unknown cyber-security agent role: {agent_role}")
    routes = settings.get("agent_models") or {}
    route = dependencies.canonical_route(routes.get(agent_role))
    if not route:
        raise SystemExit(f"Agent {agent_role} has no enabled analysis model assignment")
    return route


def _validate_route(
    response: dict[str, Any], route: str, policy: Policy,
    dependencies: Dependencies,
) -> None:
    observed = str(response.get("_analysis_model_route") or "").strip()
    if policy.evaluation_harness_run and observed != route:
        raise dependencies.route_error(
            "controlled harness evaluation initial response did not preserve "
            "the assigned model route"
        )


class _HarnessObserver:
    def __init__(self, runtime: Any, policy: Policy, dependencies: Dependencies):
        self.runtime = runtime
        self.policy = policy
        self.dependencies = dependencies

    def _observe(self, call: Callable[[], Any]) -> None:
        if self.runtime is None:
            return
        try:
            call()
        except Exception as exc:
            if self.runtime.policy.mode == "enforce" or self.policy.evaluation_harness_run:
                raise
            self.dependencies.warning(
                "warning: Onion Sentinel harness shadow model observation "
                f"failed: {type(exc).__name__}: {exc}"
            )

    def preflight(self, prompt_package: dict[str, Any], route: str) -> None:
        self._observe(lambda: self.runtime.preflight_model_call(
            call_id=self.policy.call_id, input_value=prompt_package,
            requested_route=route, purpose=self.policy.purpose,
        ))

    def record(
        self, prompt_package: dict[str, Any], route: str,
        response: dict[str, Any], started: float, status: str,
    ) -> None:
        kwargs = {"status": status} if status else {}
        self._observe(lambda: self.runtime.model_call(
            call_id=self.policy.call_id, purpose=self.policy.purpose,
            requested_route=route, response=response, input_value=prompt_package,
            duration_seconds=self.dependencies.monotonic() - started, **kwargs,
        ))
