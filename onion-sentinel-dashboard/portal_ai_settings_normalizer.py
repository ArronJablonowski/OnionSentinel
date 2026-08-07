"""Pure orchestration for editable SOC AI model-routing settings."""
from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence, Set
from dataclasses import dataclass
import math
from pathlib import Path
import re


@dataclass(frozen=True)
class SocAiSettingsNormalizationPolicy:
    """Configuration and stable helper policies injected by the portal."""

    defaults: Callable[[], dict]
    maxmind_databases: Mapping[str, tuple[str, str]]
    codex_efforts: Set[str]
    hermes_effort: str
    codex_catalog: Sequence[str]
    severity_thresholds: Set[str]
    openclaw_ollama_urls: Set[str]
    normalized_model_list: Callable[[object], list[str]]
    boolean_setting: Callable[[object], bool]
    derive_model_mode: Callable[[list[str], bool], str]
    valid_cli_path: Callable[[str, str], bool]
    valid_provider_model: Callable[[str], bool]
    valid_openclaw_model: Callable[[str], bool]
    normalize_codex_models: Callable[..., tuple[bool, list[dict]]]
    enabled_routes: Callable[..., list[str]]
    normalize_primary_models: Callable[[object, list[str]], dict[str, str]]
    normalize_reviewer_models: Callable[..., dict[str, str]]
    normalize_adjudicator_models: Callable[..., dict[str, str]]


class SettingsValidationError(ValueError):
    """One stable operator-facing settings validation error."""


def _initial_settings(payload: dict, policy: SocAiSettingsNormalizationPolicy) -> dict:
    settings = policy.defaults()
    structured = {
        "enabled_ollama_models",
        "codex_cli_models",
        "gpt_cli_enabled",
        "hermes_agent_enabled",
        "openclaw_enabled",
        "agent_models",
        "agent_second_opinion_models",
        "agent_adjudicator_models",
    }
    for key in settings:
        if key not in structured and key in payload:
            settings[key] = str(payload.get(key) or "").strip()
    city_key = policy.maxmind_databases["city"][0]
    if city_key not in payload and payload.get("maxmind_geoip_db_path") is not None:
        settings[city_key] = str(payload.get("maxmind_geoip_db_path") or "").strip()
    return settings


def _legacy_mode(payload: dict, settings: dict) -> str:
    mode = str(payload.get("mode") or settings["mode"]).strip().lower()
    return mode if mode in {"ollama", "cloud", "hybrid"} else "ollama"


def _ollama_roster(
    payload: dict,
    settings: dict,
    policy: SocAiSettingsNormalizationPolicy,
) -> tuple[list[str], bool]:
    mode = _legacy_mode(payload, settings)
    if "enabled_ollama_models" in payload:
        models = policy.normalized_model_list(payload.get("enabled_ollama_models"))
    else:
        legacy = str(payload.get("ollama_model") or settings["ollama_model"]).strip()
        models = [] if mode == "cloud" else policy.normalized_model_list([legacy])
    legacy_gpt = (
        policy.boolean_setting(payload.get("gpt_cli_enabled"))
        if "gpt_cli_enabled" in payload
        else mode in {"cloud", "hybrid"}
    )
    if not settings["ollama_url"].startswith(("http://", "https://")):
        raise SettingsValidationError("Ollama URL must start with http:// or https://.")
    return models, legacy_gpt


def _codex_values(payload: dict, settings: dict) -> tuple[str, str, str]:
    path = str(settings.get("codex_cli_path") or "codex").strip()
    model = str(
        payload.get("codex_cli_model")
        or payload.get("cloud_model")
        or settings.get("codex_cli_model")
        or "gpt-5.5"
    ).strip()
    effort = str(settings.get("codex_cli_reasoning_effort") or "medium").strip().lower()
    return path, model, effort


def _validate_codex_values(path: str, model: str, effort: str, policy) -> None:
    if not policy.valid_cli_path(path, "codex"):
        raise SettingsValidationError(
            "Codex CLI path must be 'codex' or an absolute path ending in /codex."
        )
    if not policy.valid_provider_model(model):
        raise SettingsValidationError("Codex CLI model is invalid.")
    if effort not in policy.codex_efforts:
        raise SettingsValidationError(
            "Codex CLI reasoning effort must be low, medium, high, or xhigh."
        )


def _codex_roster(
    payload: dict,
    settings: dict,
    legacy_enabled: bool,
    policy: SocAiSettingsNormalizationPolicy,
) -> tuple[str, str, list[dict], bool]:
    path, model, effort = _codex_values(payload, settings)
    _validate_codex_values(path, model, effort, policy)
    valid, roster = policy.normalize_codex_models(
        payload.get("codex_cli_models") if "codex_cli_models" in payload else None,
        legacy_model=model,
        legacy_effort=effort,
        legacy_enabled=legacy_enabled,
    )
    if not valid:
        raise SettingsValidationError(
            "Codex CLI settings must use each supported catalog model at most once "
            "with a valid reasoning effort."
        )
    return path, model, roster, any(entry["enabled"] for entry in roster)


def _provider_values(payload: dict, settings: dict, policy) -> dict:
    values = {}
    for provider, model_default in (
        ("hermes_agent", "gpt-5.5"),
        ("openclaw", "ollama/gemma4:26b-mlx"),
    ):
        values[f"{provider}_enabled"] = policy.boolean_setting(
            payload.get(f"{provider}_enabled")
        )
        for suffix, fallback in (
            ("path", provider.replace("_agent", "")),
            ("model", model_default),
            ("reasoning_effort", "medium"),
        ):
            key = f"{provider}_{suffix}"
            raw = payload.get(key) if key in payload else settings.get(key, fallback)
            normalized = str(raw or fallback).strip()
            values[key] = normalized.lower() if suffix == "reasoning_effort" else normalized
    return values


def _validate_provider_paths(values: dict, policy) -> None:
    for label, provider, basename in (
        ("Hermes Agent", "hermes_agent", "hermes"),
        ("OpenClaw", "openclaw", "openclaw"),
    ):
        if policy.valid_cli_path(values[f"{provider}_path"], basename):
            continue
        raise SettingsValidationError(
            f"{label} path must be '{basename}' or an absolute path ending in /{basename}."
        )


def _validate_provider_models(values: dict, settings: dict, policy) -> None:
    if values["hermes_agent_model"] not in policy.codex_catalog:
        raise SettingsValidationError(
            "Hermes Agent model is not in the supported Codex model catalog."
        )
    if not policy.valid_openclaw_model(values["openclaw_model"]):
        raise SettingsValidationError(
            "OpenClaw currently supports explicit ollama/<model> routes only; "
            "hosted OpenClaw credentials are not admitted into the isolated runtime."
        )
    if (
        values["openclaw_enabled"]
        and settings["ollama_url"].rstrip("/") not in policy.openclaw_ollama_urls
    ):
        raise SettingsValidationError(
            "OpenClaw requires the loopback Ollama endpoint "
            "http://127.0.0.1:11434 or http://localhost:11434."
        )
    if values["hermes_agent_reasoning_effort"] != policy.hermes_effort:
        raise SettingsValidationError(
            "Hermes Agent reasoning effort must be medium because the installed "
            "one-shot CLI does not enforce other effort values."
        )
    if values["openclaw_reasoning_effort"] not in policy.codex_efforts:
        raise SettingsValidationError(
            "OpenClaw reasoning effort must be low, medium, high, or xhigh."
        )


def _require_provider(models: list[str], gpt_enabled: bool, values: dict) -> None:
    if models or gpt_enabled or values["hermes_agent_enabled"] or values["openclaw_enabled"]:
        return
    raise SettingsValidationError(
        "Enable at least one Ollama model, Codex CLI model, Hermes Agent, or OpenClaw."
    )


def _apply_provider_settings(
    settings: dict,
    models: list[str],
    codex_path: str,
    codex_roster: list[dict],
    gpt_enabled: bool,
    values: dict,
    policy,
) -> None:
    settings["enabled_ollama_models"] = models
    settings["codex_cli_models"] = codex_roster
    settings["gpt_cli_enabled"] = gpt_enabled
    settings.update(values)
    settings["mode"] = policy.derive_model_mode(
        models + (["openclaw-local"] if values["openclaw_enabled"] else []),
        gpt_enabled or values["hermes_agent_enabled"],
    )
    if models:
        settings["ollama_model"] = models[0]
    enabled = next(
        (entry for entry in codex_roster if entry["enabled"]),
        codex_roster[0],
    )
    settings["codex_cli_path"] = codex_path
    settings["codex_cli_model"] = enabled["model"]
    settings["codex_cli_reasoning_effort"] = enabled["reasoning_effort"]
    settings["cloud_provider"] = "codex-cli"
    settings["cloud_model"] = enabled["model"]
    settings["cloud_command"] = ""


def _apply_agent_assignments(payload: dict, settings: dict, policy) -> None:
    routes = policy.enabled_routes(
        settings["enabled_ollama_models"],
        settings["codex_cli_models"],
        hermes_agent_enabled=settings["hermes_agent_enabled"],
        hermes_agent_model=settings["hermes_agent_model"],
        hermes_agent_reasoning_effort=settings["hermes_agent_reasoning_effort"],
        openclaw_enabled=settings["openclaw_enabled"],
        openclaw_model=settings["openclaw_model"],
        openclaw_reasoning_effort=settings["openclaw_reasoning_effort"],
    )
    primary = policy.normalize_primary_models(payload.get("agent_models"), routes)
    reviewer = policy.normalize_reviewer_models(
        payload.get("agent_second_opinion_models"), routes, primary, settings
    )
    settings["agent_models"] = primary
    settings["agent_second_opinion_models"] = reviewer
    settings["agent_adjudicator_models"] = policy.normalize_adjudicator_models(
        payload.get("agent_adjudicator_models"), routes, primary, reviewer, settings
    )


def _normalize_thresholds(settings: dict, policy) -> None:
    labels = (
        ("soc_analyst_analysis_min_severity", "automatic AI analysis"),
        ("soc_analyst_pcap_min_severity", "PCAP analysis"),
        ("soc_analyst_incident_min_severity", "incident escalation"),
    )
    for key, label in labels:
        threshold = str(settings.get(key) or "").strip().lower()
        threshold = "informational" if threshold == "info" else threshold
        if threshold not in policy.severity_thresholds:
            raise SettingsValidationError(
                f"SOC Analyst {label} severity threshold is invalid."
            )
        settings[key] = threshold


def _normalize_capture_loss(settings: dict) -> None:
    try:
        threshold = float(settings.get("pcap_capture_loss_threshold_percent", 5.0))
    except (TypeError, ValueError):
        threshold = math.nan
    if not math.isfinite(threshold) or not 0.1 <= threshold <= 100.0:
        raise SettingsValidationError(
            "PCAP capture-loss threshold must be between 0.1 and 100 percent."
        )
    settings["pcap_capture_loss_threshold_percent"] = round(threshold, 4)


def _validate_geoip_paths(settings: dict, policy) -> None:
    for database_type, (key, _) in policy.maxmind_databases.items():
        path = settings[key]
        label = database_type.upper() if database_type == "asn" else database_type.title()
        if len(path) > 1024 or re.search(r"[\x00-\x1f\x7f]", path):
            raise SettingsValidationError(
                f"MaxMind GeoIP database path for {label} is invalid."
            )
        if not path.startswith(("/", "~/")):
            raise SettingsValidationError(
                f"MaxMind GeoIP database path for {label} must be absolute or start with ~/."
            )
        if Path(path).suffix.lower() != ".mmdb":
            raise SettingsValidationError(
                f"MaxMind GeoIP database path for {label} must end in .mmdb."
            )


def _truncate_compatibility_values(settings: dict) -> None:
    for key in (
        "ollama_model",
        "ollama_url",
        "cloud_provider",
        "cloud_model",
        "cloud_command",
        "codex_cli_model",
        "codex_cli_reasoning_effort",
        "hermes_agent_model",
        "hermes_agent_reasoning_effort",
        "openclaw_model",
        "openclaw_reasoning_effort",
    ):
        settings[key] = settings[key][:240]


def normalize_soc_ai_settings(
    payload: dict | None,
    policy: SocAiSettingsNormalizationPolicy,
) -> tuple[bool, dict]:
    """Validate and normalize editable SOC AI model-routing settings."""
    payload = payload if isinstance(payload, dict) else {}
    try:
        settings = _initial_settings(payload, policy)
        models, legacy_gpt = _ollama_roster(payload, settings, policy)
        codex_path, _legacy_model, codex_roster, gpt_enabled = _codex_roster(
            payload, settings, legacy_gpt, policy
        )
        providers = _provider_values(payload, settings, policy)
        _validate_provider_paths(providers, policy)
        _validate_provider_models(providers, settings, policy)
        _require_provider(models, gpt_enabled, providers)
        _apply_provider_settings(
            settings, models, codex_path, codex_roster, gpt_enabled, providers, policy
        )
        _apply_agent_assignments(payload, settings, policy)
        _normalize_thresholds(settings, policy)
        _normalize_capture_loss(settings)
        _validate_geoip_paths(settings, policy)
        _truncate_compatibility_values(settings)
    except SettingsValidationError as exc:
        return False, {"ok": False, "error": str(exc)}
    return True, settings
