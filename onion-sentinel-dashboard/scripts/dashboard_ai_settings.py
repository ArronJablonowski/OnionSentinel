"""Load and normalize persisted dashboard AI-provider settings."""
from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping
from pathlib import Path

from dashboard_model_routing import (
    CLI_HARNESS_MODEL_PATTERN,
    CODEX_CLI_REASONING_EFFORTS,
    CYBER_SECURITY_AGENT_ROLES,
    HERMES_AGENT_REASONING_EFFORT,
    _boolean_setting,
    _normalized_enabled_models,
    enabled_agent_model_routes,
    normalize_agent_adjudicator_models,
    normalize_agent_models,
    normalize_agent_second_opinion_models,
)


SOC_ANALYSIS_SEVERITY_THRESHOLDS = (
    "disabled",
    "critical",
    "high",
    "medium",
    "low",
    "informational",
)
CODEX_CLI_MODEL_CATALOG = (
    "gpt-5.5",
    "gpt-5.6-sol",
    "gpt-5.6-terra",
    "gpt-5.6-luna",
)
_STRUCTURED_SETTING_KEYS = frozenset({
    "enabled_ollama_models",
    "codex_cli_models",
    "gpt_cli_enabled",
    "hermes_agent_enabled",
    "openclaw_enabled",
    "agent_models",
    "agent_second_opinion_models",
    "agent_adjudicator_models",
})


def default_soc_ai_settings(environ: Mapping[str, str] | None = None) -> dict:
    """Return safe model-routing defaults for dashboard rendering."""
    environment = os.environ if environ is None else environ
    default_model = environment.get("SOC_AI_MODEL", "").strip() or "devstral:latest"
    return {
        "mode": "ollama",
        "ollama_model": default_model,
        "enabled_ollama_models": [default_model],
        "ollama_url": environment.get("OLLAMA_URL", "").strip() or "http://127.0.0.1:11434",
        "cloud_provider": "codex-cli",
        "cloud_model": "gpt-5.5",
        "cloud_command": "",
        "codex_cli_path": "codex",
        "codex_cli_model": "gpt-5.5",
        "codex_cli_reasoning_effort": "medium",
        "codex_cli_models": [
            {"model": model, "reasoning_effort": "medium", "enabled": False}
            for model in CODEX_CLI_MODEL_CATALOG
        ],
        "gpt_cli_enabled": False,
        "hermes_agent_enabled": False,
        "hermes_agent_path": "hermes",
        "hermes_agent_model": "gpt-5.5",
        "hermes_agent_reasoning_effort": "medium",
        "openclaw_enabled": False,
        "openclaw_path": "openclaw",
        "openclaw_model": "ollama/gemma4:26b-mlx",
        "openclaw_reasoning_effort": "medium",
        "soc_analyst_analysis_min_severity": "informational",
        "soc_analyst_pcap_min_severity": "informational",
        "pcap_capture_loss_threshold_percent": 5.0,
        "soc_analyst_incident_min_severity": "disabled",
        "agent_models": {
            role: f"ollama:{default_model}" for role in CYBER_SECURITY_AGENT_ROLES
        },
        "agent_second_opinion_models": {role: "" for role in CYBER_SECURITY_AGENT_ROLES},
        "agent_adjudicator_models": {role: "" for role in CYBER_SECURITY_AGENT_ROLES},
        "maxmind_geoip_asn_db_path": "~/n8n-local/config/maxmind/GeoLite2-ASN.mmdb",
        "maxmind_geoip_city_db_path": "~/n8n-local/config/maxmind/GeoLite2-City.mmdb",
        "maxmind_geoip_country_db_path": "~/n8n-local/config/maxmind/GeoLite2-Country.mmdb",
    }


def _normalized_cli_path(value: object, basename: str) -> str:
    """Return a safe executable name or absolute path."""
    configured = str(value or basename).strip()
    path = Path(configured)
    invalid = (
        not configured
        or len(configured) > 1024
        or bool(re.search(r"[\x00-\x1f\x7f]", configured))
        or (path.is_absolute() and path.name != basename)
        or (path.is_absolute() and not re.fullmatch(r"/[A-Za-z0-9._/+-]+", configured))
        or (not path.is_absolute() and configured != basename)
    )
    return basename if invalid else configured


def _normalized_provider_model(value: object, fallback: str) -> str:
    configured = str(value or fallback).strip()
    return configured if CLI_HARNESS_MODEL_PATTERN.fullmatch(configured) else fallback


def _normalized_openclaw_model(value: object) -> str:
    """Return an explicit Ollama route accepted by the isolated adapter."""
    fallback = "ollama/gemma4:26b-mlx"
    configured = _normalized_provider_model(value, fallback)
    return (
        configured
        if configured.lower().startswith("ollama/") and len(configured) > len("ollama/")
        else fallback
    )


def _normalized_hermes_model(value: object) -> str:
    configured = str(value or "gpt-5.5").strip()
    return configured if configured in CODEX_CLI_MODEL_CATALOG else "gpt-5.5"


def _normalized_reasoning_effort(value: object) -> str:
    effort = str(value or "medium").strip().lower()
    return effort if effort in CODEX_CLI_REASONING_EFFORTS else "medium"


def _normalized_codex_cli_models(
    value: object,
    *,
    legacy_model: str,
    legacy_effort: str,
    legacy_enabled: bool,
) -> list[dict]:
    """Normalize the fixed Codex catalog without rendering unsafe values."""
    raw_entries = value if isinstance(value, list) else [{
        "model": legacy_model,
        "reasoning_effort": legacy_effort,
        "enabled": legacy_enabled,
    }]
    configured: dict[str, dict] = {}
    for raw in raw_entries[:32]:
        if not isinstance(raw, dict):
            continue
        model = str(raw.get("model") or "").strip()
        effort = str(raw.get("reasoning_effort") or "medium").strip().lower()
        if model not in CODEX_CLI_MODEL_CATALOG or effort not in CODEX_CLI_REASONING_EFFORTS:
            continue
        if model not in configured:
            configured[model] = {
                "model": model,
                "reasoning_effort": effort,
                "enabled": _boolean_setting(raw.get("enabled")),
            }
    return [
        configured.get(model, {
            "model": model,
            "reasoning_effort": "medium",
            "enabled": False,
        })
        for model in CODEX_CLI_MODEL_CATALOG
    ]


def _read_settings(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _overlay_scalar_settings(settings: dict, data: dict) -> None:
    for key in settings:
        if key not in _STRUCTURED_SETTING_KEYS and key in data and data[key] is not None:
            settings[key] = str(data[key]).strip()
    if "maxmind_geoip_city_db_path" not in data and data.get("maxmind_geoip_db_path") is not None:
        settings["maxmind_geoip_city_db_path"] = str(data["maxmind_geoip_db_path"]).strip()


def _legacy_provider_state(settings: dict, data: dict) -> tuple[list[str], bool]:
    legacy_mode = settings["mode"] if settings["mode"] in {"ollama", "cloud", "hybrid"} else "ollama"
    enabled_models = (
        _normalized_enabled_models(data.get("enabled_ollama_models"))
        if "enabled_ollama_models" in data
        else ([] if legacy_mode == "cloud" else _normalized_enabled_models([settings["ollama_model"]]))
    )
    gpt_enabled = (
        _boolean_setting(data.get("gpt_cli_enabled"))
        if "gpt_cli_enabled" in data
        else legacy_mode in {"cloud", "hybrid"}
    )
    return enabled_models, gpt_enabled


def _codex_provider_state(settings: dict, data: dict, legacy_enabled: bool) -> tuple[list[dict], dict]:
    model = str(settings.get("codex_cli_model") or settings.get("cloud_model") or "gpt-5.5").strip()
    model = model or "gpt-5.5"
    effort = _normalized_reasoning_effort(settings.get("codex_cli_reasoning_effort"))
    roster = _normalized_codex_cli_models(
        data.get("codex_cli_models") if "codex_cli_models" in data else None,
        legacy_model=model,
        legacy_effort=effort,
        legacy_enabled=legacy_enabled,
    )
    return roster, next((entry for entry in roster if entry["enabled"]), roster[0])


def _ensure_enabled_provider(
    settings: dict,
    enabled_models: list[str],
    *provider_flags: bool,
) -> list[str]:
    if enabled_models or any(provider_flags):
        return enabled_models
    return [settings["ollama_model"] or "devstral:latest"]


def _normalize_provider_settings(settings: dict, data: dict) -> None:
    enabled_models, legacy_gpt_enabled = _legacy_provider_state(settings, data)
    settings["ollama_model"] = enabled_models[0] if enabled_models else (settings["ollama_model"] or "devstral:latest")
    settings["ollama_url"] = settings["ollama_url"] or "http://127.0.0.1:11434"
    roster, selected = _codex_provider_state(settings, data, legacy_gpt_enabled)
    gpt_enabled = any(entry["enabled"] for entry in roster)
    hermes_enabled = _boolean_setting(data.get("hermes_agent_enabled"))
    openclaw_enabled = _boolean_setting(data.get("openclaw_enabled"))
    enabled_models = _ensure_enabled_provider(
        settings, enabled_models, gpt_enabled, hermes_enabled, openclaw_enabled
    )
    settings.update({
        "enabled_ollama_models": enabled_models,
        "codex_cli_models": roster,
        "gpt_cli_enabled": gpt_enabled,
        "codex_cli_path": _normalized_cli_path(settings.get("codex_cli_path"), "codex"),
        "codex_cli_model": selected["model"],
        "codex_cli_reasoning_effort": selected["reasoning_effort"],
        "hermes_agent_enabled": hermes_enabled,
        "hermes_agent_path": _normalized_cli_path(settings.get("hermes_agent_path"), "hermes"),
        "hermes_agent_model": _normalized_hermes_model(settings.get("hermes_agent_model")),
        "hermes_agent_reasoning_effort": HERMES_AGENT_REASONING_EFFORT,
        "openclaw_enabled": openclaw_enabled,
        "openclaw_path": _normalized_cli_path(settings.get("openclaw_path"), "openclaw"),
        "openclaw_model": _normalized_openclaw_model(settings.get("openclaw_model")),
        "openclaw_reasoning_effort": _normalized_reasoning_effort(settings.get("openclaw_reasoning_effort")),
        "cloud_provider": "codex-cli",
        "cloud_model": selected["model"],
        "cloud_command": "",
    })
    local_enabled = bool(enabled_models) or openclaw_enabled
    hosted_enabled = gpt_enabled or hermes_enabled
    settings["mode"] = "hybrid" if local_enabled and hosted_enabled else ("cloud" if hosted_enabled else "ollama")


def _normalize_thresholds(settings: dict) -> None:
    for key, fallback in (
        ("soc_analyst_analysis_min_severity", "informational"),
        ("soc_analyst_pcap_min_severity", "informational"),
        ("soc_analyst_incident_min_severity", "disabled"),
    ):
        threshold = str(settings.get(key) or "").strip().lower()
        threshold = "informational" if threshold == "info" else threshold
        settings[key] = threshold if threshold in SOC_ANALYSIS_SEVERITY_THRESHOLDS else fallback


def _normalize_assignments(settings: dict, data: dict) -> None:
    routes = enabled_agent_model_routes(settings)
    settings["agent_models"] = normalize_agent_models(data.get("agent_models"), routes)
    settings["agent_second_opinion_models"] = normalize_agent_second_opinion_models(
        data.get("agent_second_opinion_models"), routes, settings["agent_models"], settings
    )
    settings["agent_adjudicator_models"] = normalize_agent_adjudicator_models(
        data.get("agent_adjudicator_models"),
        routes,
        settings["agent_models"],
        settings["agent_second_opinion_models"],
        settings,
    )


def load_ai_settings(path: Path, environ: Mapping[str, str] | None = None) -> dict:
    """Read, migrate, and normalize persisted dashboard AI settings."""
    settings = default_soc_ai_settings(environ)
    data = _read_settings(path)
    _overlay_scalar_settings(settings, data)
    _normalize_provider_settings(settings, data)
    _normalize_thresholds(settings)
    _normalize_assignments(settings, data)
    return settings
