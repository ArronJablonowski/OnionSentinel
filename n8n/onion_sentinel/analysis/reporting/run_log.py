"""Pure projection of one analysis run into the operational log schema."""

from __future__ import annotations

from dataclasses import dataclass
import json
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
    enabled_routes: Callable[[dict[str, Any]], Any]
    canonical_route: Callable[[Any, Any], str]
    assigned_metadata: Callable[
        [dict[str, Any], str], tuple[str, str, str]
    ]


def _text(value: Any) -> str:
    return str(value or "").strip()


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _first_truthy(*values: Any) -> Any:
    for value in values:
        if value:
            return value
    return values[-1] if values else None


def _timeline_ids(grouped: dict[str, Any]) -> tuple[list[str], int]:
    timeline_value = grouped.get("timeline")
    timeline = timeline_value if isinstance(timeline_value, list) else []
    identifiers = [
        str(item.get("alert_id"))
        for item in timeline[:25]
        if isinstance(item, dict) and item.get("alert_id")
    ]
    return identifiers, len(timeline)


def _alert_count(value: Any) -> int:
    try:
        return max(1, int(value))
    except (TypeError, ValueError):
        return 1


def alert_summary(prompt_package: dict[str, Any]) -> dict[str, Any]:
    """Return bounded alert metadata for an operational analysis record."""
    alert = _mapping(prompt_package.get("alert"))
    grouped = _mapping(prompt_package.get("grouped_alert_context"))
    alert_ids, timeline_count = _timeline_ids(grouped)
    primary_alert_id = _text(alert.get("alert_id"))
    if primary_alert_id and primary_alert_id not in alert_ids:
        alert_ids.insert(0, primary_alert_id)
    count_value = _first_truthy(
        grouped.get("raw_alert_rows"),
        grouped.get("total_observations"),
        alert.get("seen_count"),
        len(alert_ids),
        1,
    )
    return {
        "primary_alert_id": primary_alert_id,
        "alert_ids": alert_ids,
        "alert_ids_truncated": max(0, timeline_count - len(alert_ids)),
        "alert_count": _alert_count(count_value),
        "rule_name": str(_first_truthy(
            alert.get("rule_name"), "Security Onion Alert",
        )),
        "triage_level": str(_first_truthy(
            alert.get("triage_level"), "unknown",
        )),
        "triage_score": alert.get("triage_score"),
        "source_ip": str(_first_truthy(alert.get("source_ip"), "")),
        "destination_ip": str(_first_truthy(alert.get("destination_ip"), "")),
        "destination_port": str(_first_truthy(
            alert.get("destination_port"), "",
        )),
        "first_seen": str(_first_truthy(
            grouped.get("first_seen"), alert.get("first_seen"), "",
        )),
        "last_seen": str(_first_truthy(
            grouped.get("last_seen"), alert.get("last_seen"), "",
        )),
        "total_observations": grouped.get(
            "total_observations", alert.get("seen_count")
        ),
    }


def _pcap_file_records(
    prompt_package: dict[str, Any],
):
    evidence = _mapping(prompt_package.get("pcap_evidence"))
    parsed_value = evidence.get("parsed_evidence")
    parsed = parsed_value if isinstance(parsed_value, list) else []
    for record in parsed:
        if not isinstance(record, dict):
            continue
        files_value = record.get("pcap_files")
        files = files_value if isinstance(files_value, list) else []
        for item in files:
            if isinstance(item, dict):
                yield str(record.get("request_id") or ""), item


def pcap_size_bytes(prompt_package: dict[str, Any]) -> int:
    """Sum unique, nonnegative collector-reported PCAP artifact sizes."""
    total = 0
    seen: set[tuple[str, str]] = set()
    for request_id, item in _pcap_file_records(prompt_package):
        identity = (request_id, str(item.get("sha256") or item.get("name") or ""))
        if identity in seen:
            continue
        seen.add(identity)
        try:
            total += max(0, int(item.get("size_bytes") or 0))
        except (TypeError, ValueError):
            continue
    return total


def alert_context_size_bytes(prompt_package: dict[str, Any]) -> int:
    """Measure the exact bounded alert context projected into run telemetry."""
    context = {
        key: prompt_package.get(key)
        for key in (
            "alert",
            "grouped_alert_context",
            "public_enrichment",
            "analyst_state",
            "pcap_evidence",
        )
    }
    return len(json.dumps(
        context,
        sort_keys=True,
        default=str,
    ).encode("utf-8"))


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
        "pcap_total_size_bytes": pcap_size_bytes(package) if package else 0,
        "alert_context_size_bytes": (
            alert_context_size_bytes(package) if package else 0
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
    alert = alert_summary(package) if package else {}
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
