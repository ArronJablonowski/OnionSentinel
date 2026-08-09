"""Pure projection of one analysis run into the operational log schema."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


@dataclass(frozen=True)
class Policy:
    observable_active_phases: frozenset[str] = frozenset({
        "primary_analysis", "live_follow_up", "second_opinion",
    })


@dataclass(frozen=True)
class Resources:
    gpu_celsius: float | None
    gpu_percent: float | None
    cpu_celsius: float | None
    soc_celsius: float | None
    memory_percent: float | None
    power_watts: float | None
    cpu_percent: float | None
    note: str


@dataclass(frozen=True)
class Inputs:
    run_id: str
    status: str
    started_at: str
    finished_at: str | None
    runtime_seconds: float | None
    prompt_path: Any
    prompt_package: dict[str, Any]
    settings: dict[str, Any]
    response: dict[str, Any] | None
    json_path: Any
    markdown_path: Any
    resources: Resources
    error: str = ""
    runtime_observation: dict[str, Any] | None = None


@dataclass(frozen=True)
class Dependencies:
    alert_summary: Callable[[dict[str, Any]], dict[str, Any]]
    enabled_routes: Callable[[dict[str, Any]], Any]
    canonical_route: Callable[[Any, Any], str]
    assigned_metadata: Callable[
        [dict[str, Any], str], tuple[str, str, str]
    ]
    pcap_size: Callable[[dict[str, Any]], int]
    alert_context_size: Callable[[dict[str, Any]], int]


def _text(value: Any) -> str:
    return str(value or "").strip()


def _assigned_route(
    inputs: Inputs,
    agent_role: str,
    dependencies: Dependencies,
) -> tuple[str, str, str, str]:
    routes = dependencies.enabled_routes(inputs.settings)
    assigned = (inputs.settings.get("agent_models") or {}).get(agent_role)
    route = dependencies.canonical_route(assigned, routes)
    model, path, mode = dependencies.assigned_metadata(
        inputs.settings, agent_role
    )
    return route, model, path, mode


def _observed_execution(
    inputs: Inputs,
    assigned_route: str,
    policy: Policy,
) -> tuple[str, str, str]:
    response = inputs.response or {}
    model_path = _text(response.get("_analysis_model_path"))
    model = _text(response.get("_analysis_model"))
    observed_route = assigned_route if model and model_path else ""
    observed = (
        inputs.runtime_observation
        if isinstance(inputs.runtime_observation, dict)
        else {}
    )
    if model or inputs.status == "running":
        return model, model_path, observed_route
    active_phase = _text(observed.get("active_phase")).lower()
    active_model = _text(observed.get("active_model"))
    if active_phase not in policy.observable_active_phases or not active_model:
        return model, model_path, observed_route
    return (
        active_model,
        _text(observed.get("active_model_path")),
        _text(observed.get("active_model_route")),
    )


def _mode(model_path: str, provider: str) -> str:
    return {
        "frontier-codex-cli": "codex-cli",
        "hermes-agent": "hermes-agent",
        "openclaw": "openclaw",
        "ollama": "ollama",
    }.get(model_path, provider)


def _running_fields(started_at: str) -> dict[str, Any]:
    return {
        "active_phase": "preparing",
        "active_phase_started_at": started_at,
        "active_model": "",
        "active_model_path": "",
        "active_model_route": "",
        "active_provider": "",
        "second_opinion_trigger": "",
    }


def _execution_fields(
    inputs: Inputs,
    *,
    agent_role: str,
    assigned_route: str,
    assigned_model: str,
    assigned_path: str,
    assigned_mode: str,
    policy: Policy,
) -> dict[str, Any]:
    model, model_path, observed_route = _observed_execution(
        inputs, assigned_route, policy
    )
    response = inputs.response or {}
    provider = _text(response.get("_analysis_provider"))
    return {
        "mode": _mode(model_path, provider),
        "model": model,
        "model_path": model_path,
        "provider": provider,
        "harness": _text(response.get("_analysis_harness")),
        "agent_role": agent_role,
        "model_route": observed_route,
        "model_started": bool(model and (model_path or observed_route)),
        "input_mode": _text(response.get("_analysis_input_mode")),
        "assigned_model": assigned_model,
        "assigned_model_path": assigned_path,
        "assigned_mode": assigned_mode,
        "assigned_model_route": assigned_route,
    }


def _artifact_resource_fields(
    inputs: Inputs,
    dependencies: Dependencies,
) -> dict[str, Any]:
    package = inputs.prompt_package
    resources = inputs.resources
    return {
        "prompt_package": str(inputs.prompt_path) if inputs.prompt_path else "",
        "analysis_json": str(inputs.json_path) if inputs.json_path else "",
        "analysis_markdown": (
            str(inputs.markdown_path) if inputs.markdown_path else ""
        ),
        "gpu_temperature_celsius_max": resources.gpu_celsius,
        "gpu_utilization_percent_max": resources.gpu_percent,
        "cpu_temperature_celsius_max": resources.cpu_celsius,
        "soc_temperature_celsius_max": resources.soc_celsius,
        "memory_used_percent_max": resources.memory_percent,
        "power_watts_max": resources.power_watts,
        "cpu_used_percent_max": resources.cpu_percent,
        "system_metrics_note": resources.note,
        "gpu_temperature_note": resources.note,
        "pcap_total_size_bytes": dependencies.pcap_size(package) if package else 0,
        "alert_context_size_bytes": (
            dependencies.alert_context_size(package) if package else 0
        ),
    }


def build(
    inputs: Inputs,
    *,
    policy: Policy,
    dependencies: Dependencies,
) -> dict[str, Any]:
    """Build one bounded operational record without performing I/O."""
    package = inputs.prompt_package
    alert = dependencies.alert_summary(package) if package else {}
    agent_role = str(package.get("agent_role") or "soc-analyst")
    assigned_route, assigned_model, assigned_path, assigned_mode = (
        _assigned_route(inputs, agent_role, dependencies)
    )
    record = {
        "log_id": inputs.run_id,
        "status": inputs.status,
        "success": inputs.status == "success",
        "started_at": inputs.started_at,
        "finished_at": inputs.finished_at,
        "runtime_seconds": (
            round(inputs.runtime_seconds, 3)
            if inputs.runtime_seconds is not None else None
        ),
        "error": inputs.error,
        "alert": alert,
    }
    record.update(_execution_fields(
        inputs,
        agent_role=agent_role,
        assigned_route=assigned_route,
        assigned_model=assigned_model,
        assigned_path=assigned_path,
        assigned_mode=assigned_mode,
        policy=policy,
    ))
    record.update(_artifact_resource_fields(inputs, dependencies))
    if inputs.status == "running":
        record.update(_running_fields(inputs.started_at))
    return record
