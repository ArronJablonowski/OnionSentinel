"""Transport-neutral dispatch for SOC and Incident Responder read APIs."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Union


Query = dict[str, list[str]]
Payload = Union[dict, bytes]
ReadPair = tuple[int, Payload]


@dataclass(frozen=True)
class SocReadResult:
    status: int
    payload: Payload
    encoded: bool = False


@dataclass(frozen=True)
class SocReadCallbacks:
    llm_current: Callable[[], dict]
    llm_logs: Callable[[Query], dict]
    alert_status: Callable[[], dict]
    settings_prompt: Callable[[str], dict]
    agent_memory: Callable[[str], ReadPair]
    ai_settings: Callable[[], dict]
    ollama_models: Callable[[bool], dict]
    alerts: Callable[[Query], ReadPair]
    alert_metrics: Callable[[Query], ReadPair]
    alert_suppressions: Callable[[Query], ReadPair]
    incidents: Callable[[Query], ReadPair]
    reanalysis_runs: Callable[[Query], ReadPair]
    incident_case_group: Callable[[str], tuple[int, str]]
    api_error: Callable[[str, int], ReadPair]
    adjudication_history: Callable[..., ReadPair]
    incident_detail: Callable[[str], ReadPair]
    alert_detail_fragment: Callable[[str], ReadPair]
    alert_detail: Callable[[str], ReadPair]


SOC_READ_OPERATIONS = frozenset({
    "llm_analysis_current",
    "llm_analysis_logs",
    "soc_alert_status",
    "soc_settings_prompt",
    "soc_agent_memory",
    "soc_ai_model",
    "soc_ollama_models",
    "soc_alerts",
    "soc_alert_metrics",
    "soc_alert_suppressions",
    "soc_incidents",
    "soc_reanalysis_runs",
    "incident_adjudications",
    "incident_detail",
    "alert_adjudications",
    "alert_detail_fragment",
    "alert_detail",
})


def _first(query: Query, key: str, default: str = "") -> str:
    values = query.get(key)
    return str(values[0] or "") if values else default


def _limit(query: Query) -> int:
    try:
        return int(_first(query, "limit", "25"))
    except (TypeError, ValueError):
        return 25


def _pair_result(pair: ReadPair, *, encoded: bool = False) -> SocReadResult:
    status, payload = pair
    return SocReadResult(int(status), payload, encoded)


def _health_result(payload: dict) -> SocReadResult:
    return SocReadResult(200 if payload.get("ok") else 500, payload)


def _incident_adjudications(
    case_id: str,
    query: Query,
    callbacks: SocReadCallbacks,
) -> SocReadResult:
    case_status, group_id = callbacks.incident_case_group(case_id)
    if int(case_status) != 200:
        message = "Incident case not found" if int(case_status) == 404 else "Invalid incident case id"
        return _pair_result(callbacks.api_error(message, int(case_status)))
    return _pair_result(
        callbacks.adjudication_history(
            group_id,
            case_id=case_id,
            limit=_limit(query),
        )
    )


def dispatch_soc_read(
    operation: str | None,
    *,
    path: str,
    resource_id: str | None,
    query: Query,
    callbacks: SocReadCallbacks,
) -> SocReadResult | None:
    """Dispatch one classified JSON read without owning HTTP serialization."""
    if operation not in SOC_READ_OPERATIONS:
        return None
    resource = resource_id or ""
    handlers: dict[str, Callable[[], SocReadResult]] = {
        "llm_analysis_current": lambda: SocReadResult(200, callbacks.llm_current()),
        "llm_analysis_logs": lambda: SocReadResult(200, callbacks.llm_logs(query)),
        "soc_alert_status": lambda: SocReadResult(200, callbacks.alert_status()),
        "soc_settings_prompt": lambda: _health_result(callbacks.settings_prompt(path)),
        "soc_agent_memory": lambda: _pair_result(callbacks.agent_memory(_first(query, "key"))),
        "soc_ai_model": lambda: _health_result(callbacks.ai_settings()),
        "soc_ollama_models": lambda: SocReadResult(
            200,
            callbacks.ollama_models(
                _first(query, "refresh").strip().lower() in {"1", "true", "yes"}
            ),
        ),
        "soc_alerts": lambda: _pair_result(callbacks.alerts(query), encoded=True),
        "soc_alert_metrics": lambda: _pair_result(callbacks.alert_metrics(query)),
        "soc_alert_suppressions": lambda: _pair_result(callbacks.alert_suppressions(query)),
        "soc_incidents": lambda: _pair_result(callbacks.incidents(query)),
        "soc_reanalysis_runs": lambda: _pair_result(callbacks.reanalysis_runs(query)),
        "incident_adjudications": lambda: _incident_adjudications(resource, query, callbacks),
        "incident_detail": lambda: _pair_result(callbacks.incident_detail(resource)),
        "alert_adjudications": lambda: _pair_result(
            callbacks.adjudication_history(resource, limit=_limit(query))
        ),
        "alert_detail_fragment": lambda: _pair_result(callbacks.alert_detail_fragment(resource)),
        "alert_detail": lambda: _pair_result(callbacks.alert_detail(resource)),
    }
    return handlers[operation]()
