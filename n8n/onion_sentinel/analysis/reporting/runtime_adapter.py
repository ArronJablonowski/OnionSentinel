"""Concrete telemetry, phase, and audit runtime bindings."""
from __future__ import annotations

from typing import Any, Callable, Mapping


def build_log_record(
    b: Mapping[str, Any], *, run_id: str, status: str, started_at: str,
    finished_at: str | None, runtime_seconds: float | None, prompt_path: Any,
    prompt_package: dict[str, Any], settings: dict[str, Any],
    response: dict[str, Any] | None, json_path: Any, markdown_path: Any,
    resource_monitor: Any, error: str = "",
    runtime_observation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    module = b["_reporting_run_log"]()
    resources = module.Resources(
        gpu_celsius=resource_monitor.max_gpu_celsius,
        gpu_percent=resource_monitor.max_gpu_percent,
        cpu_celsius=resource_monitor.max_cpu_celsius,
        soc_celsius=resource_monitor.max_soc_celsius,
        memory_percent=resource_monitor.max_memory_percent,
        power_watts=resource_monitor.max_power_watts,
        cpu_percent=resource_monitor.max_cpu_percent,
        note=resource_monitor.note,
    )
    return module.build(
        module.Inputs(
            run_id=run_id, status=status, started_at=started_at,
            finished_at=finished_at, runtime_seconds=runtime_seconds,
            prompt_path=prompt_path, prompt_package=prompt_package,
            settings=settings, response=response, json_path=json_path,
            markdown_path=markdown_path, resources=resources, error=error,
            runtime_observation=runtime_observation,
        ),
        policy=module.Policy(),
        dependencies=b["_reporting_run_log_dependencies"](),
    )


def phase_record(
    b: Mapping[str, Any], current_record: dict[str, Any],
    settings: dict[str, Any], *, phase: str, model_route: str = "",
    trigger_reason: str = "",
) -> dict[str, Any]:
    updated = dict(current_record)
    updated["active_phase"] = phase
    updated["active_phase_started_at"] = b["project_now"]()
    updated["second_opinion_trigger"] = trigger_reason
    if model_route:
        canonical, model, model_path, provider = b["model_route_metadata"](
            settings, model_route)
        updated.update({
            "active_model": model, "active_model_path": model_path,
            "active_model_route": canonical, "active_provider": provider,
        })
    else:
        updated.update({
            "active_model": "", "active_model_path": "",
            "active_model_route": "", "active_provider": "",
        })
    return updated


def publish_phase(
    b: Mapping[str, Any], current_record: dict[str, Any],
    settings: dict[str, Any], *, phase: str, model_route: str = "",
    trigger_reason: str = "", active_record_path: Any = None,
) -> dict[str, Any]:
    updated = b["current_analysis_phase_record"](
        current_record, settings, phase=phase, model_route=model_route,
        trigger_reason=trigger_reason)
    target = active_record_path or b["active_analysis_record_path"](
        updated.get("log_id"))
    b["atomic_write_json"](target, updated)
    return updated


def notify_phase(
    callback: Callable[[str, str, str], None] | None, phase: str,
    model_route: str = "", trigger_reason: str = "",
) -> None:
    if callback is None:
        return
    try:
        callback(phase, model_route, trigger_reason)
    except Exception:
        return


def security_onion_audit(
    b: Mapping[str, Any], prompt_package: dict[str, Any],
) -> dict[str, Any]:
    return b["_reporting_evidence_audits"]().security_onion(
        prompt_package, policy=b["_reporting_evidence_audit_policy"](),
        dependencies=b["_reporting_evidence_audit_dependencies"]())


def appliance_osquery_audit(
    b: Mapping[str, Any], prompt_package: dict[str, Any],
) -> dict[str, Any]:
    return b["_reporting_evidence_audits"]().appliance_osquery(
        prompt_package, policy=b["_reporting_evidence_audit_policy"](),
        dependencies=b["_reporting_evidence_audit_dependencies"]())


def live_osquery_audit(
    b: Mapping[str, Any], prompt_package: dict[str, Any],
) -> dict[str, Any]:
    return b["_reporting_live_osquery"]().audit(
        prompt_package, policy=b["_reporting_live_osquery_policy"](),
        dependencies=b["_reporting_live_osquery_dependencies"]())


def prepare_live_osquery(
    b: Mapping[str, Any], prompt_package: dict[str, Any], agent_role: str,
    config_path: Any,
) -> dict[str, Any] | None:
    if agent_role not in {"soc-analyst", "incident-responder"}:
        return None
    candidate = config_path.expanduser()
    config = (
        b["load_live_osquery_config"](candidate)
        if candidate.is_file()
        else {
            "enabled": False,
            "allowed_target_aliases": [],
            "allowed_agent_roles": ["incident-responder"],
        }
    )
    return b["_query_live_workflow"]().prepare_capability(
        prompt_package, agent_role, config,
        policy=b["_query_live_workflow_policy"](),
        dependencies=b["_query_live_workflow_dependencies"]())


def live_osquery_case_id(
    b: Mapping[str, Any], prompt_package: dict[str, Any],
) -> str:
    return b["_query_live_workflow"]().case_id(prompt_package)


def markdown_list(b: Mapping[str, Any], items: list[str]) -> str:
    return b["_reporting_incident"]().markdown_list(items)
