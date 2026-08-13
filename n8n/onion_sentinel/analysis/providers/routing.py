"""Pure, fail-closed model route construction and identity policy."""
from __future__ import annotations

import re
from typing import Any


CYBER_SECURITY_AGENT_ROLES = (
    "soc-analyst",
    "incident-responder",
    "siem-engineer",
    "cyber-threat-intel",
    "threat-hunter",
)
CODEX_CLI_REASONING_EFFORTS = frozenset({"low", "medium", "high", "xhigh"})
CODEX_CLI_MODEL_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
CLI_HARNESS_MODEL_PATTERN = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,239}$"
)
OPENCLAW_OLLAMA_PROVIDER_PREFIX = "ollama/"
HERMES_AGENT_REASONING_EFFORT = "medium"


def normalized_model_roster(value: Any) -> list[str]:
    """Return a bounded, ordered, duplicate-free local model roster."""
    if not isinstance(value, list):
        return []
    models: list[str] = []
    for item in value[:32]:
        model = str(item or "").strip()[:240]
        if not model or re.search(r"[\x00-\x1f\x7f]", model) or model in models:
            continue
        models.append(model)
    return models


def boolean_setting(value: Any, default: bool = False) -> bool:
    """Normalize persisted booleans without truthy-string ambiguity."""
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


def codex_cli_route(model: str, effort: str) -> str:
    return f"codex-cli:{model}:{effort}"


def cli_harness_route(provider: str, model: str, effort: str) -> str:
    """Return one stable route for a bounded third-party CLI harness."""
    return f"{provider}:{model}:{effort}"


def parse_cli_harness_route(route: str, provider: str) -> tuple[str, str] | None:
    """Return the exact model/effort encoded in a Hermes or OpenClaw route."""
    prefix = f"{provider}:"
    if not route.startswith(prefix):
        return None
    try:
        model, effort = route.removeprefix(prefix).rsplit(":", 1)
    except ValueError:
        return None
    if (
        not CLI_HARNESS_MODEL_PATTERN.fullmatch(model)
        or effort not in CODEX_CLI_REASONING_EFFORTS
        or (provider == "hermes-agent" and effort != HERMES_AGENT_REASONING_EFFORT)
    ):
        return None
    return model, effort


def openclaw_model_uses_ollama_runtime(model: str) -> bool:
    """Return whether OpenClaw consumes the serialized local Ollama lane."""
    normalized = str(model or "").strip().lower()
    return normalized.startswith(OPENCLAW_OLLAMA_PROVIDER_PREFIX)


def enabled_agent_model_routes(settings: dict[str, Any]) -> list[str]:
    """Return the exact model routes agents may select from the enabled roster."""
    routes = [
        f"ollama:{model}"
        for model in normalized_model_roster(settings.get("enabled_ollama_models"))
    ]
    routes.extend(
        codex_cli_route(entry["model"], entry["reasoning_effort"])
        for entry in settings.get("codex_cli_models", [])
        if isinstance(entry, dict) and entry.get("enabled") is True
    )
    if boolean_setting(settings.get("hermes_agent_enabled")):
        routes.append(
            cli_harness_route(
                "hermes-agent",
                str(settings.get("hermes_agent_model") or "gpt-5.5"),
                HERMES_AGENT_REASONING_EFFORT,
            )
        )
    if boolean_setting(settings.get("openclaw_enabled")):
        routes.append(
            cli_harness_route(
                "openclaw",
                str(settings.get("openclaw_model") or "ollama/gemma4:26b-mlx"),
                str(settings.get("openclaw_reasoning_effort") or "medium"),
            )
        )
    return routes


def _first_route(routes: list[str], prefix: str, fallback: str) -> str:
    return next(
        (candidate for candidate in routes if candidate.startswith(prefix)),
        fallback,
    )


def _canonical_codex_route(route: str, routes: list[str]) -> str | None:
    if route in {"gpt-cli", "codex-cli"}:
        return _first_route(routes, "codex-cli:", route)
    if not route.startswith("codex-cli:") or route in routes:
        return None
    try:
        model, _ = route.removeprefix("codex-cli:").rsplit(":", 1)
    except ValueError:
        return route
    return _first_route(routes, f"codex-cli:{model}:", route)


def _canonical_harness_route(route: str, routes: list[str]) -> str | None:
    for provider in ("hermes-agent", "openclaw"):
        prefix = f"{provider}:"
        if route == provider:
            return _first_route(routes, prefix, route)
        if route.startswith(prefix) and route not in routes:
            return _first_route(routes, prefix, route)
    return None


def canonical_model_route(value: Any, routes: list[str] | None = None) -> str:
    """Map provider-only and stale-effort labels to an enabled exact route."""
    route = str(value or "").strip()
    if routes is None:
        return "codex-cli" if route == "gpt-cli" else route
    if (canonical := _canonical_codex_route(route, routes)) is not None:
        return canonical
    if (canonical := _canonical_harness_route(route, routes)) is not None:
        return canonical
    return route


def parse_codex_cli_route(route: str) -> tuple[str, str] | None:
    """Return the exact model/effort pair encoded in a Codex route."""
    if not route.startswith("codex-cli:"):
        return None
    try:
        model, effort = route.removeprefix("codex-cli:").rsplit(":", 1)
    except ValueError:
        return None
    if (
        not CODEX_CLI_MODEL_PATTERN.fullmatch(model)
        or effort not in CODEX_CLI_REASONING_EFFORTS
    ):
        return None
    return model, effort


def _harness_route_metadata(
    canonical: str,
    provider: str,
) -> tuple[str, str, str, str] | None:
    parsed = parse_cli_harness_route(canonical, provider)
    if not parsed:
        return None
    model, _ = parsed
    if provider == "hermes-agent":
        return canonical, model, provider, "openai-codex"
    return canonical, model, provider, (
        model.split("/", 1)[0] if "/" in model else provider
    )


def model_route_metadata(
    settings: dict[str, Any], route: str
) -> tuple[str, str, str, str]:
    """Return canonical route, model, model path, and provider."""
    canonical = canonical_model_route(route, enabled_agent_model_routes(settings))
    if canonical.startswith("ollama:"):
        model = canonical.removeprefix("ollama:").strip()
        if model:
            return canonical, model, "ollama", "ollama"
    if parsed := parse_codex_cli_route(canonical):
        model, _ = parsed
        return canonical, model, "frontier-codex-cli", "codex-cli"
    if metadata := _harness_route_metadata(canonical, "hermes-agent"):
        return metadata
    if metadata := _harness_route_metadata(canonical, "openclaw"):
        return metadata
    if canonical == "codex-cli":
        model = str(
            settings.get("codex_cli_model") or settings.get("cloud_model") or ""
        ).strip()
        if model:
            return canonical, model, "frontier-codex-cli", "codex-cli"
    return canonical, "", "unknown", "unknown"


def assigned_model_metadata(
    settings: dict[str, Any], agent_role: str
) -> tuple[str, str, str]:
    """Resolve pre-inference UI/log metadata from the exact assignment."""
    role = agent_role if agent_role in CYBER_SECURITY_AGENT_ROLES else "soc-analyst"
    route = canonical_model_route(
        (settings.get("agent_models") or {}).get(role),
        enabled_agent_model_routes(settings),
    )
    _, model, model_path, provider = model_route_metadata(settings, route)
    if model:
        return model, model_path, provider
    return "", "unknown", str(settings.get("mode") or "unknown")


def model_route_identity(route: Any, settings: dict[str, Any] | None = None) -> str:
    """Return a reasoning-effort-independent reviewer model identity."""
    normalized = str(route or "").strip().lower()
    parsed = (
        parse_codex_cli_route(normalized)
        if normalized.startswith("codex-cli:")
        else None
    )
    if parsed:
        return f"openai-codex:{parsed[0].lower()}"
    if normalized in {"gpt-cli", "codex-cli"}:
        configured_model = str(
            (settings or {}).get("codex_cli_model") or "configured-default"
        ).strip().lower()
        return f"openai-codex:{configured_model}"
    if parsed := parse_cli_harness_route(normalized, "hermes-agent"):
        return f"openai-codex:{parsed[0].lower()}"
    if parsed := parse_cli_harness_route(normalized, "openclaw"):
        model = parsed[0].lower()
        if "/" in model:
            provider, name = model.split("/", 1)
            return f"{provider}:{name}"
        return f"openclaw:{model}"
    if normalized.startswith("ollama:"):
        return normalized
    return normalized
