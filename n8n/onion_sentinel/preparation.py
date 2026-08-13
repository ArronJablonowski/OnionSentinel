"""Harness and telemetry preparation for the AI analysis pipeline."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping

from .pipeline import RuntimeContext, Stage


@dataclass(frozen=True)
class PreparationInputs:
    run_id: str
    prompt_package: Mapping[str, Any]
    settings: Mapping[str, Any]
    agent_role: str
    memory_frozen: bool
    reanalysis_attempt_id: str
    policy_path: Any
    database_path: Any
    query_contract: Mapping[str, Any]
    max_query_rounds: int
    max_queries_total: int
    max_queries_per_round: int
    max_prompt_bytes: int
    max_response_bytes: int


@dataclass(frozen=True)
class HarnessStartRequest:
    run_id: str
    prompt_package: Mapping[str, Any]
    role: str
    assigned_route: str
    configuration: Mapping[str, Any]
    reanalysis_attempt_id: str
    policy_path: Any
    database_path: Any


@dataclass(frozen=True)
class PreparationPorts:
    enabled_routes: Callable[[Mapping[str, Any]], list[str]]
    canonical_route: Callable[[Any, list[str]], str]
    load_harness_policy: Callable[[Any], Any]
    harness_activation: Callable[[bool, str, str], tuple[bool, str]]
    start_harness: Callable[[HarnessStartRequest, Any], Any]
    build_running_record: Callable[[], dict[str, Any]]
    write_running_record: Callable[[dict[str, Any]], None]
    publish_phase: Callable[[dict[str, Any], str, str, str], dict[str, Any]]
    start_monitor: Callable[[], None]
    process_id: Callable[[], int]
    warn: Callable[[str], None]


@dataclass
class PreparedRuntime:
    harness: Any
    running_record: dict[str, Any]
    monitor_started: bool
    memory_frozen: bool
    warn: Callable[[str], None]
    publish_phase: Callable[[dict[str, Any], str, str, str], dict[str, Any]]

    def observe(self, call: Callable[[], Any]) -> Any:
        if self.harness is None:
            return None
        try:
            return call()
        except Exception as exc:
            if self.harness.policy.mode == "enforce" or self.memory_frozen:
                raise
            self.warn(
                "Onion Sentinel harness shadow observation failed: "
                f"{type(exc).__name__}: {exc}"
            )
            return None

    def update_phase(
        self,
        phase: str,
        model_route: str = "",
        trigger_reason: str = "",
    ) -> None:
        self.running_record = self.publish_phase(
            self.running_record, phase, model_route, trigger_reason
        )
        self.observe(
            lambda: self.harness.phase(phase, model_route, trigger_reason)
            if self.harness is not None else None
        )


def prepare(
    context: RuntimeContext,
    inputs: PreparationInputs,
    ports: PreparationPorts,
) -> PreparedRuntime:
    """Resolve routes and prepare harness, telemetry, and resource monitoring."""
    assigned_route, reviewer_route, configuration = _routes_and_configuration(
        inputs, ports
    )
    harness = _start_harness(
        inputs, ports, assigned_route, reviewer_route, configuration
    )
    return _finalize_preparation(context, inputs, ports, harness)


def _routes_and_configuration(
    inputs: PreparationInputs,
    ports: PreparationPorts,
) -> tuple[str, str, dict[str, Any]]:
    enabled = ports.enabled_routes(inputs.settings)
    agent_models = inputs.settings.get("agent_models") or {}
    reviewer_models = inputs.settings.get("agent_second_opinion_models") or {}
    assigned_route = ports.canonical_route(agent_models.get(inputs.agent_role), enabled)
    reviewer_route = ports.canonical_route(
        reviewer_models.get(inputs.agent_role), enabled
    )
    configuration = {
        "query_contract": inputs.query_contract,
        "agent_role": inputs.agent_role,
        "assigned_route": assigned_route,
        "reviewer_route": reviewer_route,
        "evaluation_memory_frozen": inputs.memory_frozen,
        "limits": {
            "max_query_rounds": inputs.max_query_rounds,
            "max_queries_total": inputs.max_queries_total,
            "max_queries_per_round": inputs.max_queries_per_round,
            "max_prompt_bytes": inputs.max_prompt_bytes,
            "max_response_bytes": inputs.max_response_bytes,
        },
    }
    return assigned_route, reviewer_route, configuration


def _start_harness(
    inputs: PreparationInputs,
    ports: PreparationPorts,
    assigned_route: str,
    reviewer_route: str,
    configuration: Mapping[str, Any],
) -> Any:
    harness_policy = ports.load_harness_policy(inputs.policy_path)
    allowed, reason = ports.harness_activation(
        bool(harness_policy.enabled), assigned_route, reviewer_route
    )
    harness = None
    if allowed:
        request = HarnessStartRequest(
            inputs.run_id,
            inputs.prompt_package,
            inputs.agent_role,
            assigned_route,
            configuration,
            inputs.reanalysis_attempt_id,
            inputs.policy_path,
            inputs.database_path,
        )
        try:
            harness = ports.start_harness(request, harness_policy)
        except Exception as exc:
            if harness_policy.mode == "enforce" or inputs.memory_frozen:
                raise
            ports.warn(
                "Onion Sentinel harness shadow initialization failed: "
                f"{type(exc).__name__}: {exc}"
            )
    elif inputs.memory_frozen:
        raise RuntimeError(
            "controlled harness evaluation cannot bypass the Onion Sentinel "
            f"harness: {reason}"
        )
    elif harness_policy.enabled:
        ports.warn(f"Onion Sentinel investigation harness bypassed: {reason}.")
    return harness


def _finalize_preparation(
    context: RuntimeContext,
    inputs: PreparationInputs,
    ports: PreparationPorts,
    harness: Any,
) -> PreparedRuntime:
    record = ports.build_running_record()
    record["runner_pid"] = ports.process_id()
    ports.write_running_record(record)
    prepared = PreparedRuntime(
        harness, record, False, inputs.memory_frozen, ports.warn, ports.publish_phase
    )
    ports.start_monitor()
    prepared.monitor_started = True
    context.advance(
        Stage.PREPARE,
        "runtime contexts, harness, telemetry, and monitor prepared",
    )
    return prepared
