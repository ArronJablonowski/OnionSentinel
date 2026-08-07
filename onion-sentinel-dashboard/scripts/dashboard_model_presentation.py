"""Pure model-assignment and execution-provenance presentation policy."""
from __future__ import annotations

import html

from dashboard_model_routing import (
    CLI_HARNESS_MODEL_PATTERN,
    CODEX_CLI_MODEL_PATTERN,
    CODEX_CLI_REASONING_EFFORTS,
    _codex_cli_route,
    _hermes_agent_route,
    _openclaw_route,
    enabled_agent_model_routes,
    model_route_identity,
)


AGENT_LABELS = {
    "soc-analyst": "SOC Analyst",
    "incident-responder": "Incident Responder",
    "siem-engineer": "SIEM Engineer",
    "cyber-threat-intel": "Cyber Threat Intel",
    "threat-hunter": "Threat Hunter",
}
JOB_LABELS = {
    "soc-analyst": "SOC alert triage",
    "incident-responder": "Incident response investigation",
    "siem-engineer": "Detection engineering analysis",
    "cyber-threat-intel": "Threat-intelligence analysis",
    "threat-hunter": "Threat-hunting analysis",
}
PHASE_LABELS = {
    "preparing": "Preparing analysis",
    "primary_analysis": "Primary analysis",
    "second_opinion": "Second-opinion review",
    "disagreement_adjudication": "Disagreement adjudication",
    "live_follow_up": "Live-evidence follow-up",
    "post_processing": "Finalizing report",
    "concurrent": "Concurrent analyses",
}
PROVIDER_PATHS = {
    "frontier-codex-cli": ("Codex CLI", "codex-cli"),
    "hermes-agent": ("Hermes Agent", "hermes-agent"),
    "openclaw": ("OpenClaw", "openclaw"),
    "ollama": ("Ollama", "ollama"),
}


def codex_cli_route_parts(route: str, settings: dict) -> tuple[str, str] | None:
    """Resolve an exact Codex route or the legacy provider-only route."""
    if route.startswith("codex-cli:"):
        try:
            model, effort = route.removeprefix("codex-cli:").rsplit(":", 1)
        except ValueError:
            return None
        return (
            (model, effort)
            if CODEX_CLI_MODEL_PATTERN.fullmatch(model)
            and effort in CODEX_CLI_REASONING_EFFORTS
            else None
        )
    if route not in {"gpt-cli", "codex-cli"}:
        return None
    model = str(settings.get("codex_cli_model") or settings.get("cloud_model") or "gpt-5.5").strip()
    effort = str(settings.get("codex_cli_reasoning_effort") or "medium").strip()
    return model, effort


def provider_cli_route_parts(route: str, provider: str) -> tuple[str, str] | None:
    """Parse one exact CLI-harness route without constraining its namespace."""
    prefix = f"{provider}:"
    if not route.startswith(prefix):
        return None
    try:
        model, effort = route.removeprefix(prefix).rsplit(":", 1)
    except ValueError:
        return None
    return (
        (model, effort)
        if CLI_HARNESS_MODEL_PATTERN.fullmatch(model)
        and effort in CODEX_CLI_REASONING_EFFORTS
        else None
    )


def agent_route_label(route: str, settings: dict) -> str | None:
    if route.startswith("ollama:"):
        return f"Ollama: {route.removeprefix('ollama:')}"
    providers = (
        (codex_cli_route_parts(route, settings), "Codex CLI"),
        (provider_cli_route_parts(route, "hermes-agent"), "Hermes Agent"),
        (provider_cli_route_parts(route, "openclaw"), "OpenClaw"),
    )
    for parts, label in providers:
        if parts:
            model, effort = parts
            return f"{label}: {model} ({effort})"
    return None


def _assigned_route(settings: dict, key: str, role: str) -> str:
    assignments = settings.get(key) if isinstance(settings.get(key), dict) else {}
    return str(assignments.get(role) or "").strip()


def agent_model_route_label(settings: dict, role: str) -> str:
    return agent_route_label(_assigned_route(settings, "agent_models", role), settings) or "No analysis model assigned"


def agent_second_opinion_model_route_label(settings: dict, role: str) -> str:
    return agent_route_label(
        _assigned_route(settings, "agent_second_opinion_models", role), settings
    ) or "None selected"


def agent_adjudicator_model_route_label(settings: dict, role: str) -> str:
    return agent_route_label(
        _assigned_route(settings, "agent_adjudicator_models", role), settings
    ) or "None selected"


def _assignment_key(second_opinion: bool, adjudicator: bool) -> str:
    if adjudicator:
        return "agent_adjudicator_models"
    return "agent_second_opinion_models" if second_opinion else "agent_models"


def agent_model_option_rows(
    settings: dict,
    role: str,
    *,
    second_opinion: bool = False,
    adjudicator: bool = False,
) -> str:
    """Render enabled routes for a primary, reviewer, or adjudicator selector."""
    selected = _assigned_route(settings, _assignment_key(second_opinion, adjudicator), role)
    primary = _assigned_route(settings, "agent_models", role)
    reviewer = _assigned_route(settings, "agent_second_opinion_models", role)
    excluded = {model_route_identity(primary, settings)} if second_opinion or adjudicator else set()
    if adjudicator:
        excluded.add(model_route_identity(reviewer, settings))
    options = ['<option value="">Not assigned</option>'] if second_opinion or adjudicator else []
    for route in enabled_agent_model_routes(settings):
        label = agent_route_label(route, settings)
        if model_route_identity(route, settings) in excluded or not label:
            continue
        selected_attr = " selected" if route == selected else ""
        options.append(
            f'<option value="{html.escape(route, quote=True)}"{selected_attr}>'
            f"{html.escape(label)}</option>"
        )
    return "".join(options)


def _assignment_projection(
    provider: str,
    provider_key: str,
    model: str,
    effort: str,
    route: str,
) -> dict[str, str]:
    detail = f"{model} ({effort})" if effort else model
    return {
        "provider": provider,
        "provider_key": provider_key,
        "model": model,
        "model_detail": detail,
        "label": f"{provider} · {detail}",
        "route": route,
    }


def assigned_model_projection(settings: dict, role: str) -> dict[str, str] | None:
    """Project one valid configured assignment without inventing a fallback."""
    route = _assigned_route(settings, "agent_models", role)
    if route.startswith("ollama:") and (model := route.removeprefix("ollama:").strip()):
        return _assignment_projection("Ollama", "ollama", model, "", route)
    providers = (
        (codex_cli_route_parts(route, settings), "Codex CLI", "codex-cli", _codex_cli_route),
        (provider_cli_route_parts(route, "hermes-agent"), "Hermes Agent", "hermes-agent", _hermes_agent_route),
        (provider_cli_route_parts(route, "openclaw"), "OpenClaw", "openclaw", _openclaw_route),
    )
    for parts, provider, key, route_factory in providers:
        if parts:
            model, effort = parts
            return _assignment_projection(provider, key, model, effort, route_factory(model, effort))
    return None


def observed_model_projection(record: object) -> dict[str, str] | None:
    """Project stamped analysis provenance from one persisted result."""
    data = record if isinstance(record, dict) else {}
    response = data.get("response") if isinstance(data.get("response"), dict) else {}
    model = next((str(value).strip() for value in (
        data.get("analysis_model"), data.get("_analysis_model"), data.get("model"),
        response.get("_analysis_model"),
    ) if value), "")
    if not model:
        return None
    model_path = str(
        data.get("analysis_model_path") or data.get("_analysis_model_path")
        or response.get("_analysis_model_path") or ""
    ).strip().lower()
    provider, provider_key = PROVIDER_PATHS.get(model_path, ("Unknown provider", "unknown"))
    return _assignment_projection(provider, provider_key, model, "", "")


def unassigned_model_projection(fallback: object = "unassigned") -> dict[str, str]:
    model = str(fallback or "unassigned").strip() or "unassigned"
    return _assignment_projection("Unassigned", "unassigned", model, "", "")


def llm_agent_label(log: dict[str, object]) -> str:
    role = str(log.get("agent_role") or "").strip().lower().replace("_", "-")
    return AGENT_LABELS.get(role, "Unknown agent")


def llm_job_label(log: dict[str, object]) -> str:
    role = str(log.get("agent_role") or "").strip().lower().replace("_", "-")
    return JOB_LABELS.get(role, "Unknown analysis job")


def llm_phase_label(log: dict[str, object]) -> str:
    phase = str(log.get("active_phase") or "").strip().lower()
    fallback = "Completed run" if str(log.get("status") or "").lower() != "running" else "Analysis"
    return PHASE_LABELS.get(phase, fallback)


def _active_execution_fields(log: dict[str, object]) -> tuple[str, str, str, str] | None:
    route = str(log.get("active_model_route") or "").strip()
    model = str(log.get("active_model") or "").strip()
    phase = str(log.get("active_phase") or "").strip().lower()
    if phase == "post_processing" and not route and not model:
        return None
    return (
        route,
        model,
        str(log.get("active_model_path") or "").strip().lower(),
        str(log.get("active_provider") or "").strip().lower(),
    )


def _execution_fields(log: dict[str, object], live: bool) -> tuple[str, str, str, str] | None:
    if live and str(log.get("status") or "").lower() != "running":
        return None
    if live and "active_phase" in log:
        return _active_execution_fields(log)
    return (
        str(log.get("model_route") or "").strip(),
        str(log.get("model") or "").strip(),
        str(log.get("model_path") or "").strip().lower(),
        str(log.get("mode") or "").strip().lower(),
    )


def _execution_route(route: str, model: str) -> tuple[str, str, str]:
    for prefix, provider in (
        ("codex-cli:", "Codex CLI"),
        ("hermes-agent:", "Hermes Agent"),
        ("openclaw:", "OpenClaw"),
    ):
        if route.startswith(prefix):
            try:
                routed_model, effort = route.removeprefix(prefix).rsplit(":", 1)
            except ValueError:
                routed_model, effort = "", ""
            return provider, routed_model or model, effort
    if route.startswith("ollama:"):
        return "Ollama", route.removeprefix("ollama:").strip() or model, ""
    return "", model, ""


def _execution_provider(provider_key: str, model_path: str) -> str:
    if provider_key in {"codex-cli", "gpt-cli"} or model_path == "frontier-codex-cli":
        return "Codex CLI"
    if provider_key in {"hermes-agent", "openai-codex"} or model_path == "hermes-agent":
        return "Hermes Agent"
    if provider_key == "openclaw" or model_path == "openclaw":
        return "OpenClaw"
    if provider_key == "ollama" or model_path == "ollama":
        return "Ollama"
    return ""


def llm_executed_model_label(log: dict[str, object], *, live: bool = False) -> str:
    """Describe observed execution provenance without falling back to settings."""
    fields = _execution_fields(log, live)
    if fields is None:
        return "No model running"
    route, model, model_path, provider_key = fields
    provider, model, effort = _execution_route(route, model)
    provider = provider or _execution_provider(provider_key, model_path)
    if not model:
        return "No model running" if live else "No model started"
    label = " · ".join(part for part in (provider, model) if part) or model
    return f"{label} ({effort})" if provider in {"Codex CLI", "Hermes Agent", "OpenClaw"} and effort else label
