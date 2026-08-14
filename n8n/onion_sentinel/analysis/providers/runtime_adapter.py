"""Legacy runtime bindings for provider settings and executable resolution."""
from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Any, Mapping

from . import settings as provider_settings


def default_ai_settings(bindings: Mapping[str, Any]) -> dict[str, Any]:
    b = bindings
    default_model = os.environ.get("SOC_AI_MODEL") or b["FALLBACK_OLLAMA_MODEL"]
    roles = b["CYBER_SECURITY_AGENT_ROLES"]
    return {
        "mode": "ollama",
        "ollama_model": default_model,
        "enabled_ollama_models": [default_model],
        "ollama_url": os.environ.get("OLLAMA_URL") or b["DEFAULT_OLLAMA_URL"],
        "cloud_provider": "codex-cli",
        "cloud_model": "gpt-5.5",
        "cloud_command": "",
        "codex_cli_path": "codex",
        "codex_cli_model": "gpt-5.5",
        "codex_cli_reasoning_effort": "medium",
        "codex_cli_models": [
            {"model": model, "reasoning_effort": "medium", "enabled": False}
            for model in b["CODEX_CLI_MODEL_CATALOG"]
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
        "hybrid_policy": "cloud_for_critical_high_or_recommended",
        "agent_models": {role: f"ollama:{default_model}" for role in roles},
        "agent_second_opinion_models": {role: "" for role in roles},
        "agent_adjudicator_models": {role: "" for role in roles},
    }


def _policy(b: Mapping[str, Any]) -> provider_settings.Policy:
    return provider_settings.Policy(
        codex_catalog=tuple(b["CODEX_CLI_MODEL_CATALOG"]),
        reasoning_efforts=frozenset(b["CODEX_CLI_REASONING_EFFORTS"]),
        harness_model_pattern=b["CLI_HARNESS_MODEL_PATTERN"],
        openclaw_ollama_prefix=b["OPENCLAW_OLLAMA_PROVIDER_PREFIX"],
        hermes_effort=b["HERMES_AGENT_REASONING_EFFORT"],
        fallback_ollama_model=b["FALLBACK_OLLAMA_MODEL"],
    )


def _dependencies(b: Mapping[str, Any]) -> provider_settings.Dependencies:
    return provider_settings.Dependencies(
        boolean_setting=b["boolean_setting"],
        normalized_model_roster=b["normalized_model_roster"],
        openclaw_uses_ollama=b["openclaw_model_uses_ollama_runtime"],
        enabled_routes=b["enabled_agent_model_routes"],
        normalize_primary=b["normalize_agent_models"],
        normalize_reviewer=b["normalize_agent_second_opinion_models"],
        normalize_adjudicator=b["normalize_agent_adjudicator_models"],
        error_type=b["RuntimeArtifactError"],
    )


def _merge_policy(b: Mapping[str, Any]) -> provider_settings.MergePolicy:
    return provider_settings.MergePolicy(
        protected_keys=frozenset({
            "enabled_ollama_models",
            "codex_cli_models",
            "gpt_cli_enabled",
            "hermes_agent_enabled",
            "openclaw_enabled",
            "agent_models",
            "agent_second_opinion_models",
            "agent_adjudicator_models",
        }),
        hybrid_policies=frozenset({
            "cloud_for_critical_high_or_recommended",
            "cloud_when_recommended_only",
        }),
        default_hybrid_policy="cloud_for_critical_high_or_recommended",
        fallback_ollama_model=b["FALLBACK_OLLAMA_MODEL"],
        default_ollama_url=b["DEFAULT_OLLAMA_URL"],
    )


def _merge_dependencies(
    b: Mapping[str, Any],
) -> provider_settings.MergeDependencies:
    return provider_settings.MergeDependencies(
        normalize_codex=b["normalize_codex_cli_settings"],
        normalize_harnesses=b["normalize_cli_harness_settings"],
        apply_roster=b["apply_model_roster"],
    )


def normalize_agent_models(
    bindings: Mapping[str, Any], value: Any, routes: list[str]
) -> dict[str, str]:
    b = bindings
    source = value if isinstance(value, dict) else {}
    fallback = routes[0] if routes else ""
    return {
        role: route
        if (route := b["canonical_model_route"](source.get(role), routes)) in routes
        else fallback
        for role in b["CYBER_SECURITY_AGENT_ROLES"]
    }


def normalize_agent_second_opinion_models(
    bindings: Mapping[str, Any],
    value: Any,
    routes: list[str],
    primary_assignments: dict[str, str],
    settings: dict[str, Any] | None = None,
) -> dict[str, str]:
    b = bindings
    source = value if isinstance(value, dict) else {}
    assignments: dict[str, str] = {}
    for role in b["CYBER_SECURITY_AGENT_ROLES"]:
        route = b["canonical_model_route"](source.get(role), routes)
        independent = b["model_route_identity"](
            route, settings
        ) != b["model_route_identity"](
            primary_assignments.get(role), settings
        )
        assignments[role] = route if route in routes and independent else ""
    return assignments


def normalize_agent_adjudicator_models(
    bindings: Mapping[str, Any],
    value: Any,
    routes: list[str],
    primary_assignments: dict[str, str],
    reviewer_assignments: dict[str, str],
    settings: dict[str, Any] | None,
) -> dict[str, str]:
    b = bindings
    source = value if isinstance(value, dict) else {}
    assignments: dict[str, str] = {}
    for role in b["CYBER_SECURITY_AGENT_ROLES"]:
        route = b["canonical_model_route"](source.get(role), routes)
        route_identity = b["model_route_identity"](route, settings)
        excluded = {
            b["model_route_identity"](primary_assignments.get(role), settings),
            b["model_route_identity"](reviewer_assignments.get(role), settings),
        }
        assignments[role] = (
            route
            if route in routes and route_identity and route_identity not in excluded
            else ""
        )
    return assignments


def apply_model_roster(
    bindings: Mapping[str, Any],
    settings: dict[str, Any],
    raw: dict[str, Any],
) -> dict[str, Any]:
    return provider_settings.apply_roster(
        settings,
        raw,
        policy=_policy(bindings),
        dependencies=_dependencies(bindings),
    )


def normalize_codex_cli_settings(
    bindings: Mapping[str, Any],
    settings: dict[str, Any],
    raw: dict[str, Any],
) -> None:
    provider_settings.normalize_codex(
        settings,
        raw,
        policy=_policy(bindings),
        dependencies=_dependencies(bindings),
    )


def normalize_harness_executable(
    bindings: Mapping[str, Any], value: Any, basename: str
) -> str:
    label = "Hermes Agent" if basename == "hermes" else "OpenClaw"
    return provider_settings.normalize_harness_executable(
        value, basename, label, bindings["RuntimeArtifactError"]
    )


def normalize_cli_harness_settings(
    bindings: Mapping[str, Any],
    settings: dict[str, Any],
    raw: dict[str, Any],
) -> None:
    provider_settings.normalize_harnesses(
        settings,
        raw,
        policy=_policy(bindings),
        dependencies=_dependencies(bindings),
    )


def load_ai_settings(bindings: Mapping[str, Any], path: Path) -> dict[str, Any]:
    b = bindings
    configured = b["default_ai_settings"]()
    if not path.exists():
        return configured
    try:
        data = json.loads(
            b["read_bytes_bounded"](
                path, b["DEFAULT_MAX_SETTINGS_BYTES"]
            ).decode("utf-8", errors="strict")
        )
    except (b["RuntimeArtifactError"], UnicodeError, json.JSONDecodeError) as exc:
        raise b["RuntimeArtifactError"](
            f"invalid AI settings in {path}: {exc}"
        ) from exc
    if not isinstance(data, dict):
        raise b["RuntimeArtifactError"](
            f"AI settings root must be an object: {path}"
        )
    return provider_settings.merge(
        configured,
        data,
        policy=_merge_policy(b),
        dependencies=_merge_dependencies(b),
    )


def _resolve_executable(
    configured: str, basename: str, label: str
) -> str:
    if Path(configured).is_absolute():
        candidates = [Path(configured).expanduser()]
    else:
        candidates: list[Path] = []
        if discovered := shutil.which(basename):
            candidates.append(Path(discovered))
        candidates.extend([
            Path.home() / ".local" / "bin" / basename,
            Path("/opt/homebrew/bin") / basename,
            Path("/usr/local/bin") / basename,
        ])
    for candidate in candidates:
        if (
            candidate.name == basename
            and candidate.is_file()
            and os.access(candidate, os.X_OK)
        ):
            return str(candidate)
    checked = ", ".join(str(candidate) for candidate in candidates)
    raise SystemExit(f"{label} executable is unavailable; checked: {checked}")


def resolve_codex_cli(
    bindings: Mapping[str, Any], settings: dict[str, Any]
) -> str:
    configured = str(settings.get("codex_cli_path") or "codex").strip()
    return _resolve_executable(configured, "codex", "Codex CLI")


def resolve_cli_harness(
    bindings: Mapping[str, Any],
    settings: dict[str, Any],
    *,
    setting_key: str,
    basename: str,
    label: str,
) -> str:
    configured = bindings["_normalize_harness_executable"](
        settings.get(setting_key) or basename, basename
    )
    return _resolve_executable(configured, basename, label)


def effective_ai_settings(
    bindings: Mapping[str, Any], args: Any
) -> dict[str, Any]:
    b = bindings
    settings = b["load_ai_settings"](args.ai_settings_file)
    if args.analysis_mode:
        settings["mode"] = args.analysis_mode
        settings["gpt_cli_enabled"] = args.analysis_mode in {"cloud", "hybrid"}
        if (
            args.analysis_mode in {"ollama", "hybrid"}
            and not settings.get("enabled_ollama_models")
        ):
            settings["enabled_ollama_models"] = [
                settings.get("ollama_model") or b["FALLBACK_OLLAMA_MODEL"]
            ]
    if args.model:
        settings["ollama_model"] = args.model
        settings["enabled_ollama_models"] = [args.model]
        settings["agent_models"]["soc-analyst"] = f"ollama:{args.model}"
    if args.ollama_url:
        settings["ollama_url"] = args.ollama_url
    routes = b["enabled_agent_model_routes"](settings)
    settings["agent_models"] = b["normalize_agent_models"](
        settings.get("agent_models"), routes
    )
    settings["agent_second_opinion_models"] = b[
        "normalize_agent_second_opinion_models"
    ](
        settings.get("agent_second_opinion_models"),
        routes,
        settings["agent_models"],
        settings,
    )
    settings["agent_adjudicator_models"] = b[
        "normalize_agent_adjudicator_models"
    ](
        settings.get("agent_adjudicator_models"),
        routes,
        settings["agent_models"],
        settings["agent_second_opinion_models"],
        settings,
    )
    return settings
