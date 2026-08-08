"""Pure LLM agent activity, provenance, and dashboard projection policy."""
from __future__ import annotations

from collections.abc import Callable

from portal_llm_runtime_state import llm_runtime_model_state


AGENT_EXECUTION_LABELS = {
    "soc-analyst": ("SOC Analyst", "ai_analysis", "SOC alert triage"),
    "incident-responder": (
        "Incident Responder",
        "incident_response_analysis",
        "Incident response investigation",
    ),
    "siem-engineer": (
        "SIEM Engineer",
        "siem_engineering",
        "Detection engineering analysis",
    ),
    "cyber-threat-intel": (
        "Cyber Threat Intel",
        "cyber_threat_intel",
        "Threat-intelligence analysis",
    ),
    "threat-hunter": (
        "Threat Hunter",
        "threat_hunt",
        "Threat-hunting analysis",
    ),
}


def llm_agent_execution_state(record: object) -> dict:
    """Describe the persisted agent/job owner for one observed execution."""
    current = record if isinstance(record, dict) else {}
    role = str(current.get("agent_role") or "").strip().lower().replace("_", "-")
    agent_label, job_type, job_label = AGENT_EXECUTION_LABELS.get(
        role,
        ("Unknown agent", "unknown", "Unknown analysis job"),
    )
    return {
        "agent_role": role or "unknown",
        "agent_label": agent_label,
        "job_type": job_type,
        "job_label": job_label,
    }


def decorate_llm_analysis_record(record: object, *, live: bool) -> dict:
    """Add display provenance while retaining immutable raw audit fields."""
    decorated = dict(record) if isinstance(record, dict) else {}
    for key, value in llm_agent_execution_state(decorated).items():
        decorated.setdefault(key, value)
    if live:
        runtime = llm_runtime_model_state(decorated)
        if runtime.get("running"):
            decorated.update(
                {
                    "runtime_model_label": runtime.get("label") or "Unknown model",
                    "phase_label": runtime.get("phase_label") or "Analysis",
                }
            )
        else:
            decorated.update(
                {"runtime_model_label": "No model running", "phase_label": "Idle"}
            )
        return decorated
    historical = dict(decorated)
    historical["status"] = "running"
    historical.pop("active_phase", None)
    runtime = llm_runtime_model_state(historical)
    model_observed = bool(
        str(decorated.get("model") or "").strip()
        or str(decorated.get("model_route") or "").strip()
    )
    model_label = (
        runtime.get("label") or "Unknown model"
        if model_observed
        else "No model started"
    )
    decorated.update(
        {"runtime_model_label": model_label, "phase_label": "Completed run"}
    )
    return decorated


def _joined_field(
    records: list[dict], key: str, separator: str, *, unique: bool = False
) -> str:
    values = [str(record.get(key) or "") for record in records if record.get(key)]
    if unique:
        values = list(dict.fromkeys(values))
    return separator.join(values)


def _concurrent_values(records: list[dict]) -> dict:
    runtimes = [llm_runtime_model_state(record) for record in records]
    return {
        "active_phase": "concurrent",
        "active_model": _joined_field(runtimes, "label", " + "),
        "active_provider": _joined_field(
            runtimes, "provider", " + ", unique=True
        ),
        "active_model_route": _joined_field(runtimes, "route", " | "),
        "runtime_model_label": _joined_field(runtimes, "label", " + "),
        "phase_label": "Concurrent analyses",
        "agent_label": _joined_field(records, "agent_label", " + ", unique=True),
        "job_label": _joined_field(records, "job_label", " + ", unique=True),
    }


def _active_analysis(queue_size: int, active_runs: list[dict]) -> dict:
    decorated = [
        decorate_llm_analysis_record(record, live=True) for record in active_runs
    ]
    data = dict(decorated[0])
    data.update(
        {
            "ok": True,
            "status": "running",
            "queue_size": queue_size,
            "active_count": len(decorated),
            "active_runs": decorated,
        }
    )
    if len(decorated) > 1:
        data.update(_concurrent_values(decorated))
    return data


def compose_current_llm_analysis(
    queue_size: int,
    active_runs: list[dict],
    current_record: object,
    process_active: Callable[[str], bool],
) -> dict:
    """Project live runs or a bounded current record into one activity state."""
    if active_runs:
        return _active_analysis(queue_size, active_runs)
    if not isinstance(current_record, dict) or not current_record:
        return decorate_llm_analysis_record(
            {
                "ok": True,
                "status": "idle",
                "alert": {},
                "model": "n/a",
                "queue_size": queue_size,
            },
            live=True,
        )
    data = dict(current_record)
    data["ok"] = True
    data["queue_size"] = queue_size
    prompt = str(data.get("prompt_package") or "")
    if data.get("status") == "running" and not process_active(prompt):
        data["status"] = "idle"
        data["stale_running_record"] = True
    return decorate_llm_analysis_record(data, live=True)


def _runtime_records(current: object) -> list[dict]:
    if not isinstance(current, dict):
        return []
    active_runs = current.get("active_runs")
    if isinstance(active_runs, list):
        return [record for record in active_runs if isinstance(record, dict)]
    return [current]


def _merged_runtime_values(runtimes: list[dict]) -> dict:
    if len(runtimes) == 1:
        runtime = runtimes[0]
        return {
            "detail": runtime["detail"],
            "model": runtime["label"],
            "provider": runtime["provider"],
            "route": runtime["route"],
            "phase": runtime["phase"],
        }
    return {
        "detail": f"{len(runtimes)} analyses running · "
        + " | ".join(
            f"{runtime['phase_label']}: {runtime['label']}"
            for runtime in runtimes
        ),
        "model": " + ".join(str(runtime["label"]) for runtime in runtimes),
        "provider": " + ".join(
            dict.fromkeys(
                str(runtime["provider"])
                for runtime in runtimes
                if runtime["provider"]
            )
        ),
        "route": " | ".join(
            str(runtime["route"]) for runtime in runtimes if runtime["route"]
        ),
        "phase": "concurrent",
    }


def merge_live_llm_activity(static_ai: object, current: object) -> dict:
    """Overlay current execution on the slower generated queue summary."""
    merged = dict(static_ai) if isinstance(static_ai, dict) else {}
    runtimes = [
        runtime
        for record in _runtime_records(current)
        if (runtime := llm_runtime_model_state(record)).get("running")
    ]
    if not runtimes:
        return merged
    counts = (
        dict(merged.get("counts") or {})
        if isinstance(merged.get("counts"), dict)
        else {}
    )
    try:
        analyzing_count = int(counts.get("analyzing") or 0)
    except (TypeError, ValueError, OverflowError):
        analyzing_count = 0
    counts["analyzing"] = max(len(runtimes), analyzing_count)
    merged.update(
        {
            "active": True,
            "label": str(merged.get("label") or "AI Alert Triage"),
            **_merged_runtime_values(runtimes),
            "counts": counts,
        }
    )
    return merged
