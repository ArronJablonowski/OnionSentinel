"""Fail-closed scheduler projections of untrusted AI settings."""
from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class SchedulerSettingsPolicy:
    max_bytes: int
    agent_roles: tuple[str, ...]
    codex_models: frozenset[str]
    codex_efforts: frozenset[str]


@dataclass(frozen=True)
class StrictSettingsSources:
    load_ai_settings: Callable[[Path], dict[str, Any]]
    read_bytes_bounded: Callable[[Path, int], bytes]
    enabled_agent_model_routes: Callable[[dict[str, Any]], Sequence[str]]
    max_settings_bytes: int


def load_untrusted_settings(
    path: Path,
    policy: SchedulerSettingsPolicy,
) -> dict[str, Any] | None:
    """Load one bounded UTF-8 object, returning no settings on any failure."""
    try:
        if not path.is_file() or path.stat().st_size > policy.max_bytes:
            return None
        raw_bytes = path.read_bytes()
        if len(raw_bytes) > policy.max_bytes:
            return None
        raw = json.loads(raw_bytes.decode("utf-8", errors="strict"))
    except (OSError, UnicodeError, ValueError, TypeError):
        return None
    return raw if isinstance(raw, dict) else None


def _enabled_codex_routes(
    raw: dict[str, Any],
    policy: SchedulerSettingsPolicy,
) -> set[str]:
    roster = raw.get("codex_cli_models", [])
    if not isinstance(roster, list):
        return set()
    enabled: set[str] = set()
    for entry in roster:
        if not isinstance(entry, dict) or entry.get("enabled") is not True:
            continue
        model = str(entry.get("model") or "").strip()
        effort = str(entry.get("reasoning_effort") or "").strip().lower()
        if model in policy.codex_models and effort in policy.codex_efforts:
            enabled.add(f"codex-cli:{model}:{effort}")
    return enabled


def _enabled_hermes_route(
    raw: dict[str, Any],
    policy: SchedulerSettingsPolicy,
) -> str:
    if raw.get("hermes_agent_enabled") is not True:
        return ""
    model = str(raw.get("hermes_agent_model") or "gpt-5.5").strip()
    effort = str(
        raw.get("hermes_agent_reasoning_effort") or "medium"
    ).strip().lower()
    if model not in policy.codex_models or effort != "medium":
        return ""
    return f"hermes-agent:{model}:{effort}"


def cli_agent_roles(
    path: Path,
    policy: SchedulerSettingsPolicy,
) -> set[str]:
    """Return roles explicitly assigned to a valid hosted CLI route."""
    raw = load_untrusted_settings(path, policy)
    if raw is None:
        return set()
    assignments = raw.get("agent_models")
    if not isinstance(assignments, dict):
        return set()
    hosted_routes = _enabled_codex_routes(raw, policy)
    hermes_route = _enabled_hermes_route(raw, policy)
    if hermes_route:
        hosted_routes.add(hermes_route)
    selected: set[str] = set()
    for role in policy.agent_roles:
        route = str(assignments.get(role) or "").strip()
        if route.lower() in {"gpt-cli", "codex-cli"}:
            selected.add(role)
        elif route in hosted_routes:
            selected.add(role)
    return selected


def role_uses_codex_cli(
    path: Path,
    policy: SchedulerSettingsPolicy,
    role: str,
) -> bool:
    """Return whether any configured lane for a role invokes Codex CLI."""
    raw = load_untrusted_settings(path, policy)
    if raw is None:
        return False
    routes: list[str] = []
    for field in (
        "agent_models",
        "agent_second_opinion_models",
        "agent_adjudicator_models",
    ):
        mapping = raw.get(field)
        if isinstance(mapping, dict):
            routes.append(str(mapping.get(role) or "").strip().lower())
    return any(
        route in {"gpt-cli", "codex-cli"}
        or route.startswith("codex-cli:")
        for route in routes
    )


def configured_analysis_levels(
    path: Path,
    policy: SchedulerSettingsPolicy,
    configured_levels: str,
    severity_priority: tuple[str, ...],
) -> list[str]:
    """Constrain the launch allowlist by the saved automatic-analysis floor."""
    requested = {
        level.strip().lower()
        for level in str(configured_levels or "").split(",")
        if level.strip().lower() in severity_priority
    }
    raw = load_untrusted_settings(path, policy) or {}
    threshold = _analysis_threshold(raw, severity_priority)
    if threshold == "disabled":
        return []
    last_index = severity_priority.index(threshold)
    return [
        level
        for level in severity_priority[: last_index + 1]
        if level in requested
    ]


def _analysis_threshold(
    raw: dict[str, Any], severity_priority: tuple[str, ...]
) -> str:
    threshold = str(
        raw.get("soc_analyst_analysis_min_severity", "informational") or ""
    ).strip().lower()
    if threshold == "info":
        threshold = "informational"
    if threshold == "disabled":
        return threshold
    if threshold not in severity_priority:
        return "informational"
    return threshold


def strict_controlled_ai_settings(
    settings_path: Path,
    scheduler_max_bytes: int,
    sources: StrictSettingsSources,
) -> tuple[dict[str, Any], dict[str, Any], set[str]]:
    """Return normalized settings plus exact persisted assignments."""
    if (
        not settings_path.is_file()
        or settings_path.stat().st_size > scheduler_max_bytes
    ):
        raise RuntimeError("settings file is missing or oversized")
    settings = sources.load_ai_settings(settings_path)
    raw = json.loads(
        sources.read_bytes_bounded(
            settings_path, sources.max_settings_bytes
        ).decode("utf-8", errors="strict")
    )
    if not isinstance(settings, dict) or not isinstance(raw, dict):
        raise RuntimeError("AI settings root must be an object")
    enabled = set(sources.enabled_agent_model_routes(settings))
    return settings, raw, enabled
