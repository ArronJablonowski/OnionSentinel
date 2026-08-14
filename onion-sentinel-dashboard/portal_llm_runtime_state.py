"""Pure live LLM execution provenance and phase presentation policy."""
from __future__ import annotations


CLI_PROVIDERS = frozenset({"Codex CLI", "Hermes Agent", "OpenClaw"})
PHASE_LABELS = {
    "preparing": "Preparing analysis",
    "second_opinion": "Second-opinion review",
    "disagreement_adjudication": "Disagreement adjudication",
    "live_follow_up": "Live-evidence follow-up",
    "primary_analysis": "Analyzing",
}


def _normalized_field(current: dict, key: str, fallback: str = "") -> str:
    return str(current.get(key) or fallback).strip()


def _normalized_lower_field(
    current: dict, key: str, fallback: str = ""
) -> str:
    return _normalized_field(current, key, fallback).lower()


def _execution_fields(current: dict) -> tuple[str, str, str, str, str]:
    if "active_phase" in current:
        return (
            _normalized_lower_field(current, "active_phase", "primary_analysis"),
            _normalized_field(current, "active_model_route"),
            _normalized_field(current, "active_model"),
            _normalized_lower_field(current, "active_provider"),
            _normalized_lower_field(current, "active_model_path"),
        )
    return (
        "primary_analysis",
        _normalized_field(current, "model_route"),
        _normalized_field(current, "model"),
        _normalized_lower_field(current, "mode"),
        _normalized_lower_field(current, "model_path"),
    )


def _route_projection(route: str, model: str) -> tuple[str, str, str]:
    providers = (
        ("codex-cli:", "Codex CLI"),
        ("hermes-agent:", "Hermes Agent"),
        ("openclaw:", "OpenClaw"),
    )
    for prefix, provider in providers:
        if route.startswith(prefix):
            try:
                routed_model, effort = route.removeprefix(prefix).rsplit(":", 1)
            except ValueError:
                routed_model, effort = "", ""
            return provider, routed_model or model, effort
    if route.startswith("ollama:"):
        return "Ollama", route.removeprefix("ollama:").strip() or model, ""
    return "", model, ""


def _provider_projection(provider_key: str, model_path: str) -> str:
    if provider_key in {"codex-cli", "gpt-cli"} or model_path == "frontier-codex-cli":
        return "Codex CLI"
    if provider_key in {"hermes-agent", "openai-codex"} or model_path == "hermes-agent":
        return "Hermes Agent"
    if provider_key == "openclaw" or model_path == "openclaw":
        return "OpenClaw"
    if provider_key == "ollama" or model_path == "ollama":
        return "Ollama"
    return ""


def _model_free_phase(phase: str, route: str, model: str) -> dict | None:
    if phase not in {"preparing", "post_processing"} or route or model:
        return None
    phase_label = (
        "Preparing analysis" if phase == "preparing" else "Finalizing analysis"
    )
    return {
        "running": True,
        "phase": phase,
        "phase_label": phase_label,
        "route": "",
        "model": "",
        "provider": "",
        "label": "No model running",
        "detail": f"{phase_label} · No model running",
    }


def llm_runtime_model_state(current: object) -> dict:
    """Describe the model executing now without inventing provenance."""
    if not isinstance(current, dict) or current.get("status") != "running":
        return {"running": False}
    phase, route, model, provider_key, model_path = _execution_fields(current)
    provider, model, effort = _route_projection(route, model)
    provider = provider or _provider_projection(provider_key, model_path)
    if model_free := _model_free_phase(phase, route, model):
        return model_free
    label = " · ".join(part for part in (provider, model) if part) or "Unknown model"
    if provider in CLI_PROVIDERS and effort:
        label += f" ({effort})"
    phase_label = PHASE_LABELS.get(phase, "Analyzing")
    return {
        "running": True,
        "phase": phase,
        "phase_label": phase_label,
        "route": route,
        "model": model,
        "provider": provider,
        "label": label,
        "detail": f"{phase_label} · Running: {label}",
    }
