"""Shared AI provider roster, route identity, and assignment policy."""
from __future__ import annotations

import os
from pathlib import Path
import re


MAXMIND_GEOIP_DATABASE_SETTINGS = {
    "asn": (
        "maxmind_geoip_asn_db_path",
        "~/n8n-local/config/maxmind/GeoLite2-ASN.mmdb",
    ),
    "city": (
        "maxmind_geoip_city_db_path",
        "~/n8n-local/config/maxmind/GeoLite2-City.mmdb",
    ),
    "country": (
        "maxmind_geoip_country_db_path",
        "~/n8n-local/config/maxmind/GeoLite2-Country.mmdb",
    ),
}

CYBER_SECURITY_AGENT_ROLES = (
    "soc-analyst",
    "incident-responder",
    "siem-engineer",
    "cyber-threat-intel",
    "threat-hunter",
)
CODEX_CLI_REASONING_EFFORTS = frozenset({"low", "medium", "high", "xhigh"})
HERMES_AGENT_REASONING_EFFORT = "medium"
CODEX_CLI_MODEL_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
CLI_HARNESS_MODEL_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,239}$")
OPENCLAW_SUPPORTED_OLLAMA_URLS = frozenset(
    {"http://127.0.0.1:11434", "http://localhost:11434"}
)
CODEX_CLI_MODEL_CATALOG = (
    "gpt-5.5",
    "gpt-5.6-sol",
    "gpt-5.6-terra",
    "gpt-5.6-luna",
)
SOC_ANALYSIS_SEVERITY_THRESHOLDS = frozenset(
    {"disabled", "critical", "high", "medium", "low", "informational"}
)
SOC_ANALYSIS_SEVERITY_ORDER = (
    "informational",
    "low",
    "medium",
    "high",
    "critical",
)


def _default_provider_settings(default_model: str) -> dict:
    return {
        "mode": "ollama",
        "ollama_model": default_model,
        "enabled_ollama_models": [default_model],
        "ollama_url": os.environ.get("OLLAMA_URL") or "http://127.0.0.1:11434",
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
    }


def _default_automation_settings() -> dict:
    return {
        "soc_analyst_analysis_min_severity": "informational",
        "soc_analyst_pcap_min_severity": "informational",
        "pcap_capture_loss_threshold_percent": 5.0,
        "soc_analyst_incident_min_severity": "disabled",
    }


def _default_agent_assignments(default_model: str) -> dict:
    return {
        "agent_models": {
            role: f"ollama:{default_model}" for role in CYBER_SECURITY_AGENT_ROLES
        },
        "agent_second_opinion_models": {
            role: "" for role in CYBER_SECURITY_AGENT_ROLES
        },
        "agent_adjudicator_models": {
            role: "" for role in CYBER_SECURITY_AGENT_ROLES
        },
    }


def default_soc_ai_settings() -> dict:
    """Return safe AI analysis routing defaults for the Settings page and runner."""
    default_model = os.environ.get("SOC_AI_MODEL") or "devstral:latest"
    return {
        **_default_provider_settings(default_model),
        **_default_automation_settings(),
        **_default_agent_assignments(default_model),
        **{
            setting_key: default_path
            for setting_key, default_path in MAXMIND_GEOIP_DATABASE_SETTINGS.values()
        },
    }


def _normalized_model_list(value: object) -> list[str]:
    """Return a bounded, ordered model roster without duplicate/control text."""
    if not isinstance(value, list):
        return []
    models = []
    for item in value[:32]:
        model = str(item or "").strip()[:240]
        if not model or re.search(r"[\x00-\x1f\x7f]", model) or model in models:
            continue
        models.append(model)
    return models


def _boolean_setting(value: object, default: bool = False) -> bool:
    """Normalize booleans without treating the string ``false`` as truthy."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on", "enabled"}:
            return True
        if normalized in {"0", "false", "no", "off", "disabled", ""}:
            return False
    return default


def _derive_model_mode(enabled_ollama_models: list[str], gpt_cli_enabled: bool) -> str:
    """Keep the legacy mode field deterministic for rolling deployments."""
    if enabled_ollama_models and gpt_cli_enabled:
        return "hybrid"
    if gpt_cli_enabled:
        return "cloud"
    return "ollama"


def _codex_cli_route(model: str, effort: str) -> str:
    return f"codex-cli:{model}:{effort}"


def _hermes_agent_route(model: str, effort: str) -> str:
    return f"hermes-agent:{model}:{effort}"


def _openclaw_route(model: str, effort: str) -> str:
    return f"openclaw:{model}:{effort}"


def _valid_cli_executable_path(value: str, basename: str) -> bool:
    """Accept only an exact command name or an absolute path to that command."""
    if not value or len(value) > 1024 or re.search(r"[\x00-\x1f\x7f]", value):
        return False
    path = Path(value)
    if not path.is_absolute():
        return value == basename
    return bool(path.name == basename and re.fullmatch(r"/[A-Za-z0-9._/+-]+", value))


def _valid_provider_model(value: str) -> bool:
    """Validate an argv-safe provider model identifier."""
    return bool(
        value and len(value) <= 240 and not re.search(r"[\x00-\x1f\x7f]", value)
    )


def _valid_openclaw_model(value: str) -> bool:
    """Limit the isolated OpenClaw adapter to credential-free Ollama routes."""
    return bool(
        CLI_HARNESS_MODEL_PATTERN.fullmatch(value)
        and value.lower().startswith("ollama/")
        and len(value) > len("ollama/")
    )


def _normalized_codex_entry(raw: object, configured: dict) -> bool:
    if not isinstance(raw, dict):
        return False
    model = str(raw.get("model") or "").strip()
    effort = str(raw.get("reasoning_effort") or "medium").strip().lower()
    if (
        model not in CODEX_CLI_MODEL_CATALOG
        or effort not in CODEX_CLI_REASONING_EFFORTS
        or model in configured
    ):
        return False
    configured[model] = {
        "model": model,
        "reasoning_effort": effort,
        "enabled": _boolean_setting(raw.get("enabled")),
    }
    return True


def _complete_codex_catalog(configured: dict) -> list[dict]:
    return [
        configured.get(
            model,
            {"model": model, "reasoning_effort": "medium", "enabled": False},
        )
        for model in CODEX_CLI_MODEL_CATALOG
    ]


def _normalize_codex_cli_models(
    value: object,
    *,
    legacy_model: str,
    legacy_effort: str,
    legacy_enabled: bool,
) -> tuple[bool, list[dict]]:
    """Validate settings for the fixed one-row-per-model Codex catalog."""
    raw_entries = value if isinstance(value, list) else [
        {
            "model": legacy_model,
            "reasoning_effort": legacy_effort,
            "enabled": legacy_enabled,
        }
    ]
    if len(raw_entries) > len(CODEX_CLI_MODEL_CATALOG):
        return False, []
    configured = {}
    if not all(_normalized_codex_entry(raw, configured) for raw in raw_entries):
        return False, []
    return True, _complete_codex_catalog(configured)


def _enabled_agent_model_routes(
    enabled_ollama_models: list[str],
    codex_cli_models: list[dict],
    *,
    hermes_agent_enabled: bool = False,
    hermes_agent_model: str = "gpt-5.5",
    hermes_agent_reasoning_effort: str = "medium",
    openclaw_enabled: bool = False,
    openclaw_model: str = "ollama/gemma4:26b-mlx",
    openclaw_reasoning_effort: str = "medium",
) -> list[str]:
    """Return stable route identifiers that agents may be assigned to."""
    routes = [f"ollama:{model}" for model in enabled_ollama_models]
    routes.extend(
        _codex_cli_route(entry["model"], entry["reasoning_effort"])
        for entry in codex_cli_models
        if entry.get("enabled") is True
    )
    if hermes_agent_enabled:
        routes.append(_hermes_agent_route(hermes_agent_model, hermes_agent_reasoning_effort))
    if openclaw_enabled:
        routes.append(_openclaw_route(openclaw_model, openclaw_reasoning_effort))
    return routes


def _first_route(enabled_routes: list[str], prefix: str, fallback: str) -> str:
    return next(
        (candidate for candidate in enabled_routes if candidate.startswith(prefix)),
        fallback,
    )


def _migrate_codex_route(normalized: str, enabled_routes: list[str]) -> str:
    if normalized in {"gpt-cli", "codex-cli"}:
        return _first_route(enabled_routes, "codex-cli:", normalized)
    if not normalized.startswith("codex-cli:") or normalized in enabled_routes:
        return normalized
    try:
        model, _ = normalized.removeprefix("codex-cli:").rsplit(":", 1)
    except ValueError:
        return normalized
    return _first_route(enabled_routes, f"codex-cli:{model}:", normalized)


def _canonical_agent_route(route: object, enabled_routes: list[str]) -> str:
    """Migrate provider-only and stale-effort routes to enabled equivalents."""
    normalized = _migrate_codex_route(str(route or "").strip()[:260], enabled_routes)
    if normalized in enabled_routes:
        return normalized
    for provider in ("hermes-agent", "openclaw"):
        prefix = f"{provider}:"
        if normalized.startswith(prefix):
            return _first_route(enabled_routes, prefix, normalized)
    return normalized


def _route_parts(normalized: str, prefix: str) -> tuple[str, str] | None:
    if not normalized.startswith(prefix):
        return None
    try:
        return normalized.removeprefix(prefix).rsplit(":", 1)
    except ValueError:
        return None


def _codex_identity(normalized: str, settings: dict | None) -> str | None:
    parts = _route_parts(normalized, "codex-cli:")
    if parts and parts[0] and parts[1] in CODEX_CLI_REASONING_EFFORTS:
        return f"openai-codex:{parts[0]}"
    if normalized not in {"gpt-cli", "codex-cli"}:
        return None
    model = str((settings or {}).get("codex_cli_model") or "configured-default")
    return f"openai-codex:{model.strip().lower()}"


def _hermes_identity(normalized: str) -> str | None:
    parts = _route_parts(normalized, "hermes-agent:")
    if parts and parts[0] and parts[1] in CODEX_CLI_REASONING_EFFORTS:
        return f"openai-codex:{parts[0]}"
    return None


def _openclaw_identity(normalized: str) -> str | None:
    parts = _route_parts(normalized, "openclaw:")
    if not parts or not parts[0] or parts[1] not in CODEX_CLI_REASONING_EFFORTS:
        return None
    if "/" in parts[0]:
        provider, name = parts[0].split("/", 1)
        return f"{provider}:{name}"
    return f"openclaw:{parts[0]}"


def _model_route_identity(route: object, settings: dict | None = None) -> str:
    """Return the effort-independent provider/model identity used by runtime."""
    normalized = str(route or "").strip().lower()
    return (
        _codex_identity(normalized, settings)
        or _hermes_identity(normalized)
        or _openclaw_identity(normalized)
        or normalized
    )


def _normalize_agent_models(value: object, enabled_routes: list[str]) -> dict[str, str]:
    """Keep every agent on exactly one enabled route after roster changes."""
    raw = value if isinstance(value, dict) else {}
    fallback = enabled_routes[0]
    assignments = {}
    for role in CYBER_SECURITY_AGENT_ROLES:
        route = _canonical_agent_route(raw.get(role), enabled_routes)
        assignments[role] = route if route in enabled_routes else fallback
    return assignments


def _normalize_agent_second_opinion_models(
    value: object,
    enabled_routes: list[str],
    primary_assignments: dict[str, str],
    settings: dict | None = None,
) -> dict[str, str]:
    """Validate optional secondary routes without inventing a fallback."""
    raw = value if isinstance(value, dict) else {}
    assignments = {}
    for role in CYBER_SECURITY_AGENT_ROLES:
        route = _canonical_agent_route(raw.get(role), enabled_routes)
        independent = _model_route_identity(route, settings) != _model_route_identity(
            primary_assignments.get(role), settings
        )
        assignments[role] = route if route in enabled_routes and independent else ""
    return assignments


def _normalize_agent_adjudicator_models(
    value: object,
    enabled_routes: list[str],
    primary_assignments: dict[str, str],
    reviewer_assignments: dict[str, str],
    settings: dict | None = None,
) -> dict[str, str]:
    """Validate optional adjudicators as a third provider/model identity."""
    raw = value if isinstance(value, dict) else {}
    assignments = {}
    for role in CYBER_SECURITY_AGENT_ROLES:
        route = _canonical_agent_route(raw.get(role), enabled_routes)
        identity = _model_route_identity(route, settings)
        excluded = {
            _model_route_identity(primary_assignments.get(role), settings),
            _model_route_identity(reviewer_assignments.get(role), settings),
        }
        assignments[role] = (
            route if route in enabled_routes and identity and identity not in excluded else ""
        )
    return assignments
