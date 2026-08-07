"""Dashboard adapter over Onion Sentinel's canonical model-routing policy."""
from __future__ import annotations

import sys
from pathlib import Path


def _install_package_root() -> None:
    """Expose the canonical package in repository and deployed layouts."""
    root = Path(__file__).resolve().parents[2]
    for candidate in (root / "n8n", root):
        if (candidate / "onion_sentinel" / "analysis" / "providers" / "routing.py").is_file():
            if str(candidate) not in sys.path:
                sys.path.insert(0, str(candidate))
            return
    raise ImportError("canonical Onion Sentinel provider-routing package is unavailable")


_install_package_root()

from onion_sentinel.analysis.providers.routing import (  # noqa: E402
    CLI_HARNESS_MODEL_PATTERN,
    CODEX_CLI_MODEL_PATTERN,
    CYBER_SECURITY_AGENT_ROLES,
    HERMES_AGENT_REASONING_EFFORT,
    boolean_setting,
    canonical_model_route,
    cli_harness_route,
    codex_cli_route,
    enabled_agent_model_routes as canonical_enabled_agent_model_routes,
    model_route_identity as canonical_model_route_identity,
    normalized_model_roster,
)


CODEX_CLI_REASONING_EFFORTS = ("low", "medium", "high", "xhigh")
SUPPORTED_HERMES_MODELS = frozenset({"gpt-5.5", "gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna"})
DEFAULT_OPENCLAW_MODEL = "ollama/gemma4:26b-mlx"


def _normalized_enabled_models(value: object) -> list[str]:
    """Compatibility name for the canonical bounded Ollama roster."""
    return normalized_model_roster(value)


def _boolean_setting(value: object, default: bool = False) -> bool:
    """Compatibility name for canonical persisted-boolean parsing."""
    return boolean_setting(value, default)


def _codex_cli_route(model: str, effort: str) -> str:
    return codex_cli_route(model, effort)


def _hermes_agent_route(model: str, effort: str) -> str:
    return cli_harness_route("hermes-agent", model, effort)


def _openclaw_route(model: str, effort: str) -> str:
    return cli_harness_route("openclaw", model, effort)


def enabled_agent_model_routes(settings: dict) -> list[str]:
    """Return exact enabled routes using the shared runtime policy."""
    normalized = dict(settings)
    hermes_model = str(normalized.get("hermes_agent_model") or "gpt-5.5").strip()
    normalized["hermes_agent_model"] = (
        hermes_model if hermes_model in SUPPORTED_HERMES_MODELS else "gpt-5.5"
    )
    openclaw_model = str(normalized.get("openclaw_model") or DEFAULT_OPENCLAW_MODEL).strip()
    normalized["openclaw_model"] = (
        openclaw_model if openclaw_model.startswith("ollama/") else DEFAULT_OPENCLAW_MODEL
    )
    effort = str(normalized.get("openclaw_reasoning_effort") or "medium").strip().lower()
    normalized["openclaw_reasoning_effort"] = (
        effort if effort in CODEX_CLI_REASONING_EFFORTS else "medium"
    )
    return canonical_enabled_agent_model_routes(normalized)


def _canonical_agent_route(route: object, enabled_routes: list[str]) -> str:
    """Map legacy/stale assignments onto an enabled exact route."""
    return canonical_model_route(route, enabled_routes)


def model_route_identity(route: object, settings: dict | None = None) -> str:
    """Return the provider/model identity used for reviewer isolation."""
    return canonical_model_route_identity(route, settings)


def normalize_agent_models(value: object, enabled_routes: list[str]) -> dict[str, str]:
    """Assign every agent one enabled route, falling back after roster changes."""
    raw = value if isinstance(value, dict) else {}
    fallback = enabled_routes[0]
    assignments: dict[str, str] = {}
    for role in CYBER_SECURITY_AGENT_ROLES:
        route = _canonical_agent_route(raw.get(role), enabled_routes)
        assignments[role] = route if route in enabled_routes else fallback
    return assignments


def normalize_agent_second_opinion_models(
    value: object,
    enabled_routes: list[str],
    primary_assignments: dict[str, str],
    settings: dict | None = None,
) -> dict[str, str]:
    """Keep optional reviewer routes enabled, independent, and fail-closed."""
    raw = value if isinstance(value, dict) else {}
    assignments: dict[str, str] = {}
    for role in CYBER_SECURITY_AGENT_ROLES:
        route = _canonical_agent_route(raw.get(role), enabled_routes)
        independent = (
            model_route_identity(route, settings)
            != model_route_identity(primary_assignments.get(role), settings)
        )
        assignments[role] = route if route in enabled_routes and independent else ""
    return assignments


def normalize_agent_adjudicator_models(
    value: object,
    enabled_routes: list[str],
    primary_assignments: dict[str, str],
    reviewer_assignments: dict[str, str],
    settings: dict | None = None,
) -> dict[str, str]:
    """Keep optional adjudicators distinct from both independent positions."""
    raw = value if isinstance(value, dict) else {}
    assignments: dict[str, str] = {}
    for role in CYBER_SECURITY_AGENT_ROLES:
        route = _canonical_agent_route(raw.get(role), enabled_routes)
        identity = model_route_identity(route, settings)
        excluded = {
            model_route_identity(primary_assignments.get(role), settings),
            model_route_identity(reviewer_assignments.get(role), settings),
        }
        assignments[role] = (
            route if route in enabled_routes and identity and identity not in excluded else ""
        )
    return assignments
