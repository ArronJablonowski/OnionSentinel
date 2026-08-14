"""Pure model-roster and CLI provider settings normalization."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from typing import Any, Callable, Pattern


@dataclass(frozen=True)
class Policy:
    codex_catalog: tuple[str, ...]
    reasoning_efforts: frozenset[str]
    harness_model_pattern: Pattern[str]
    openclaw_ollama_prefix: str
    hermes_effort: str
    fallback_ollama_model: str


@dataclass(frozen=True)
class Dependencies:
    boolean_setting: Callable[[Any], bool]
    normalized_model_roster: Callable[[Any], list[str]]
    openclaw_uses_ollama: Callable[[str], bool]
    enabled_routes: Callable[[dict[str, Any]], list[str]]
    normalize_primary: Callable[[Any, list[str]], dict[str, str]]
    normalize_reviewer: Callable[..., dict[str, str]]
    normalize_adjudicator: Callable[..., dict[str, str]]
    error_type: type[Exception]


@dataclass(frozen=True)
class MergePolicy:
    protected_keys: frozenset[str]
    hybrid_policies: frozenset[str]
    default_hybrid_policy: str
    fallback_ollama_model: str
    default_ollama_url: str


@dataclass(frozen=True)
class MergeDependencies:
    normalize_codex: Callable[[dict[str, Any], dict[str, Any]], None]
    normalize_harnesses: Callable[[dict[str, Any], dict[str, Any]], None]
    apply_roster: Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]]


def codex_models(
    value: Any, *, legacy_model: str, legacy_effort: str,
    legacy_enabled: bool, policy: Policy, dependencies: Dependencies,
) -> list[dict[str, Any]]:
    """Return validated settings for the fixed Codex CLI catalog."""
    entries = value if isinstance(value, list) else [{
        "model": legacy_model, "reasoning_effort": legacy_effort,
        "enabled": legacy_enabled,
    }]
    if len(entries) > len(policy.codex_catalog):
        raise dependencies.error_type("Codex CLI model roster contains too many entries")
    configured: dict[str, dict[str, Any]] = {}
    for raw in entries:
        _add_codex_model(configured, raw, policy, dependencies)
    return [
        configured.get(model, {
            "model": model, "reasoning_effort": "medium", "enabled": False,
        })
        for model in policy.codex_catalog
    ]


def _add_codex_model(
    configured: dict[str, dict[str, Any]], raw: Any,
    policy: Policy, dependencies: Dependencies,
) -> None:
    if not isinstance(raw, dict):
        raise dependencies.error_type("Codex CLI model roster entries must be objects")
    model = str(raw.get("model") or "").strip()
    effort = str(raw.get("reasoning_effort") or "medium").strip().lower()
    if model not in policy.codex_catalog:
        raise dependencies.error_type("Codex CLI model is not in the supported catalog")
    if effort not in policy.reasoning_efforts:
        raise dependencies.error_type(
            "Codex CLI reasoning effort must be low, medium, high, or xhigh"
        )
    if model in configured:
        raise dependencies.error_type("Codex CLI model roster contains a duplicate model")
    configured[model] = {
        "model": model, "reasoning_effort": effort,
        "enabled": dependencies.boolean_setting(raw.get("enabled")),
    }


def normalize_codex(
    settings: dict[str, Any], raw: dict[str, Any], *,
    policy: Policy, dependencies: Dependencies,
) -> None:
    """Normalize the fixed Codex adapter without accepting shell fragments."""
    executable, model, effort = _codex_inputs(settings, raw)
    normalize_harness_executable(executable, "codex", "Codex CLI", dependencies.error_type)
    _validate_model_text(model, "Codex CLI model", dependencies.error_type)
    _require_effort(effort, "Codex CLI", policy, dependencies)
    enabled = _legacy_codex_enabled(raw, settings, dependencies)
    roster = codex_models(
        raw.get("codex_cli_models") if "codex_cli_models" in raw else None,
        legacy_model=model, legacy_effort=effort, legacy_enabled=enabled,
        policy=policy, dependencies=dependencies,
    )
    selected = next((entry for entry in roster if entry["enabled"]), roster[0])
    settings.update({
        "codex_cli_path": executable,
        "codex_cli_model": selected["model"],
        "codex_cli_reasoning_effort": selected["reasoning_effort"],
        "codex_cli_models": roster,
        "cloud_provider": "codex-cli",
        "cloud_model": selected["model"],
        "cloud_command": "",
    })


def _codex_inputs(
    settings: dict[str, Any], raw: dict[str, Any],
) -> tuple[str, str, str]:
    executable = _configured_text(raw, settings, ("codex_cli_path",), "codex_cli_path", "codex")
    model = _configured_text(raw, settings, ("codex_cli_model", "cloud_model"), "codex_cli_model", "gpt-5.5")
    effort = _configured_text(
        raw, settings, ("codex_cli_reasoning_effort",),
        "codex_cli_reasoning_effort", "medium",
    ).lower()
    return executable, model, effort


def _configured_text(
    raw: dict[str, Any], settings: dict[str, Any], raw_keys: tuple[str, ...],
    settings_key: str, default: str,
) -> str:
    value = next((raw.get(key) for key in raw_keys if raw.get(key)), None)
    return str(value or settings.get(settings_key) or default).strip()


def _require_effort(
    effort: str, label: str, policy: Policy, dependencies: Dependencies,
) -> None:
    if effort not in policy.reasoning_efforts:
        raise dependencies.error_type(
            f"{label} reasoning effort must be low, medium, high, or xhigh"
        )


def _legacy_codex_enabled(
    raw: dict[str, Any], settings: dict[str, Any], dependencies: Dependencies,
) -> bool:
    if "gpt_cli_enabled" in raw:
        return dependencies.boolean_setting(raw.get("gpt_cli_enabled"))
    mode = str(raw.get("mode") or settings.get("mode") or "ollama").strip().lower()
    return mode in {"cloud", "hybrid"}


def normalize_harnesses(
    settings: dict[str, Any], raw: dict[str, Any], *,
    policy: Policy, dependencies: Dependencies,
) -> None:
    """Normalize independently enabled Hermes and OpenClaw harnesses."""
    hermes_model, hermes_effort, openclaw_model, openclaw_effort = (
        _harness_inputs(settings, raw)
    )
    _validate_harness_models(
        hermes_model, hermes_effort, openclaw_model, openclaw_effort,
        policy, dependencies,
    )
    settings.update({
        "hermes_agent_enabled": dependencies.boolean_setting(raw.get("hermes_agent_enabled")),
        "hermes_agent_path": normalize_harness_executable(
            raw.get("hermes_agent_path") or settings.get("hermes_agent_path"),
            "hermes", "Hermes Agent", dependencies.error_type,
        ),
        "hermes_agent_model": hermes_model,
        "hermes_agent_reasoning_effort": hermes_effort,
        "openclaw_enabled": dependencies.boolean_setting(raw.get("openclaw_enabled")),
        "openclaw_path": normalize_harness_executable(
            raw.get("openclaw_path") or settings.get("openclaw_path"),
            "openclaw", "OpenClaw", dependencies.error_type,
        ),
        "openclaw_model": openclaw_model,
        "openclaw_reasoning_effort": openclaw_effort,
    })


def _harness_inputs(
    settings: dict[str, Any], raw: dict[str, Any],
) -> tuple[str, str, str, str]:
    hermes_model = _configured_text(
        raw, settings, ("hermes_agent_model",), "hermes_agent_model", "gpt-5.5",
    )
    hermes_effort = _configured_text(
        raw, settings, ("hermes_agent_reasoning_effort",),
        "hermes_agent_reasoning_effort", "medium",
    ).lower()
    openclaw_model = _configured_text(
        raw, settings, ("openclaw_model",), "openclaw_model", "ollama/gemma4:26b-mlx",
    )
    openclaw_effort = _configured_text(
        raw, settings, ("openclaw_reasoning_effort",),
        "openclaw_reasoning_effort", "medium",
    ).lower()
    return hermes_model, hermes_effort, openclaw_model, openclaw_effort


def _validate_harness_models(
    hermes_model: str, hermes_effort: str, openclaw_model: str,
    openclaw_effort: str, policy: Policy, dependencies: Dependencies,
) -> None:
    if hermes_model not in policy.codex_catalog:
        raise dependencies.error_type(
            "Hermes Agent model is not in the supported Codex model catalog"
        )
    if (
        not policy.harness_model_pattern.fullmatch(openclaw_model)
        or not dependencies.openclaw_uses_ollama(openclaw_model)
        or len(openclaw_model) <= len(policy.openclaw_ollama_prefix)
    ):
        raise dependencies.error_type(
            "OpenClaw currently supports explicit ollama/<model> routes only; "
            "hosted OpenClaw credentials are not admitted into the isolated runtime"
        )
    if hermes_effort != policy.hermes_effort:
        raise dependencies.error_type(
            "Hermes Agent one-shot runtime supports medium reasoning effort only"
        )
    if openclaw_effort not in policy.reasoning_efforts:
        raise dependencies.error_type(
            "OpenClaw reasoning effort must be low, medium, high, or xhigh"
        )


def _validate_model_text(value: str, label: str, error_type: type[Exception]) -> None:
    if not value or len(value) > 240 or re.search(r"[\x00-\x1f\x7f]", value):
        raise error_type(f"{label} is invalid")


def normalize_harness_executable(
    value: Any, basename: str, label: str, error_type: type[Exception],
) -> str:
    executable = str(value or basename).strip()
    if _invalid_executable_text(executable):
        invalid_label = "Codex CLI path" if basename == "codex" else f"{label} executable path"
        raise error_type(f"{invalid_label} is invalid")
    message = _executable_path_error(executable, basename, label)
    if message:
        raise error_type(message)
    return executable


def _invalid_executable_text(executable: str) -> bool:
    return bool(
        not executable or len(executable) > 1024
        or re.search(r"[\x00-\x1f\x7f]", executable)
    )


def _executable_path_error(executable: str, basename: str, label: str) -> str:
    if Path(executable).is_absolute():
        if Path(executable).name == basename and re.fullmatch(r"/[A-Za-z0-9._/+-]+", executable):
            return ""
        return (
            "Codex CLI path must resolve from an executable named codex"
            if basename == "codex" else f"{label} path must end in /{basename}"
        )
    if executable == basename:
        return ""
    return (
        "Codex CLI path must be 'codex' or an absolute path ending in /codex"
        if basename == "codex"
        else f"{label} path must be '{basename}' or an absolute path ending in /{basename}"
    )


def apply_roster(
    settings: dict[str, Any], raw: dict[str, Any], *,
    policy: Policy, dependencies: Dependencies,
) -> dict[str, Any]:
    """Migrate legacy single-model settings and derive compatibility mode."""
    mode = str(raw.get("mode") or settings.get("mode") or "ollama").strip().lower()
    mode = mode if mode in {"ollama", "cloud", "hybrid"} else "ollama"
    enabled_models = _enabled_ollama_models(settings, raw, mode, policy, dependencies)
    codex_enabled, hermes_enabled, openclaw_enabled = _provider_flags(
        settings, dependencies,
    )
    _require_enabled_route(
        enabled_models, codex_enabled, hermes_enabled, openclaw_enabled,
        dependencies,
    )
    openclaw_local = openclaw_enabled and dependencies.openclaw_uses_ollama(
        str(settings.get("openclaw_model") or "")
    )
    _set_compatibility_mode(
        settings, enabled_models, codex_enabled, hermes_enabled,
        openclaw_enabled, openclaw_local,
    )
    routes = dependencies.enabled_routes(settings)
    settings["agent_models"] = dependencies.normalize_primary(raw.get("agent_models"), routes)
    settings["agent_second_opinion_models"] = dependencies.normalize_reviewer(
        raw.get("agent_second_opinion_models"), routes,
        settings["agent_models"], settings,
    )
    settings["agent_adjudicator_models"] = dependencies.normalize_adjudicator(
        raw.get("agent_adjudicator_models"), routes, settings["agent_models"],
        settings["agent_second_opinion_models"], settings,
    )
    return settings


def _provider_flags(
    settings: dict[str, Any], dependencies: Dependencies,
) -> tuple[bool, bool, bool]:
    codex = any(
        isinstance(entry, dict) and entry.get("enabled") is True
        for entry in settings.get("codex_cli_models", [])
    )
    return (
        codex,
        dependencies.boolean_setting(settings.get("hermes_agent_enabled")),
        dependencies.boolean_setting(settings.get("openclaw_enabled")),
    )


def _require_enabled_route(
    enabled_models: list[str], codex: bool, hermes: bool, openclaw: bool,
    dependencies: Dependencies,
) -> None:
    if not any((enabled_models, codex, hermes, openclaw)):
        raise dependencies.error_type(
            "AI settings must enable at least one analysis model route"
        )


def _enabled_ollama_models(
    settings: dict[str, Any], raw: dict[str, Any], mode: str,
    policy: Policy, dependencies: Dependencies,
) -> list[str]:
    if "enabled_ollama_models" in raw:
        return dependencies.normalized_model_roster(raw.get("enabled_ollama_models"))
    legacy = str(raw.get("ollama_model") or settings.get("ollama_model") or policy.fallback_ollama_model).strip()
    return [] if mode == "cloud" else dependencies.normalized_model_roster([legacy])


def _set_compatibility_mode(
    settings: dict[str, Any], enabled_models: list[str], codex_enabled: bool,
    hermes_enabled: bool, openclaw_enabled: bool, openclaw_local: bool,
) -> None:
    local_enabled = bool(enabled_models) or openclaw_local
    hosted_enabled = codex_enabled or hermes_enabled or (openclaw_enabled and not openclaw_local)
    settings["enabled_ollama_models"] = enabled_models
    settings["gpt_cli_enabled"] = codex_enabled
    settings["mode"] = "hybrid" if local_enabled and hosted_enabled else (
        "cloud" if hosted_enabled else "ollama"
    )
    if enabled_models:
        settings["ollama_model"] = enabled_models[0]


def merge(
    settings: dict[str, Any], raw: dict[str, Any], *,
    policy: MergePolicy, dependencies: MergeDependencies,
) -> dict[str, Any]:
    """Merge a parsed settings object through all provider policy gates."""
    for key, value in raw.items():
        if key in policy.protected_keys or key not in settings or value is None:
            continue
        settings[key] = str(value).strip() if isinstance(value, str) else value
    dependencies.normalize_codex(settings, raw)
    dependencies.normalize_harnesses(settings, raw)
    dependencies.apply_roster(settings, raw)
    if settings.get("hybrid_policy") not in policy.hybrid_policies:
        settings["hybrid_policy"] = policy.default_hybrid_policy
    settings["ollama_model"] = str(
        settings.get("ollama_model") or policy.fallback_ollama_model
    ).strip()
    settings["ollama_url"] = str(
        settings.get("ollama_url") or policy.default_ollama_url
    ).strip()
    return settings
