"""Fail-closed controlled-result lease identity and route admission."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, MutableMapping


@dataclass(frozen=True)
class Policy:
    result_environment: Mapping[str, str]
    release_environment_key: str
    model_route_pattern: Any
    job_roles: Mapping[str, str]
    maximum_settings_bytes: int


@dataclass(frozen=True)
class Dependencies:
    environment: MutableMapping[str, str]
    enabled_routes: Callable[[dict[str, Any]], Any]


def _consume_environment(
    policy: Policy,
    dependencies: Dependencies,
) -> dict[str, str]:
    supplied = {
        field: str(dependencies.environment.get(key) or "")
        for field, key in policy.result_environment.items()
    }
    for key in policy.result_environment.values():
        dependencies.environment.pop(key, None)
    return supplied


def _parse_job_id(supplied: dict[str, str]) -> int:
    try:
        return int(supplied["job_id"])
    except ValueError as exc:
        raise SystemExit(
            "controlled evaluation job identity is invalid"
        ) from exc


def _valid_attempt(
    supplied: dict[str, str],
    reanalysis_attempt_id: str,
) -> bool:
    job_type = supplied["job_type"]
    attempt = supplied["reanalysis_attempt_id"]
    if job_type == "ai_analysis":
        return not attempt and not reanalysis_attempt_id
    return bool(
        job_type == "incident_response_analysis"
        and re.fullmatch(r"ira-[a-f0-9]{40}", attempt)
        and attempt == str(reanalysis_attempt_id or "")
    )


def _valid_routes(supplied: dict[str, str], policy: Policy) -> bool:
    assigned = supplied["expected_assigned_route"]
    reviewer = supplied["expected_reviewer_route"]
    return bool(
        policy.model_route_pattern.fullmatch(assigned)
        and policy.model_route_pattern.fullmatch(reviewer)
        and assigned.rsplit(":", 1)[0] != reviewer.rsplit(":", 1)[0]
        and supplied["reviewer_required"] == "1"
    )


def _valid_stable_key(value: str) -> bool:
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise SystemExit(
            "controlled evaluation stable group key is invalid"
        ) from exc
    return bool(value and "\x00" not in value and len(encoded) <= 2048)


def _valid_core(
    supplied: dict[str, str],
    job_id: int,
    expected_role: str | None,
    stable_key_valid: bool,
) -> bool:
    return bool(
        job_id >= 1
        and expected_role is not None
        and supplied["agent_role"] == expected_role
        and re.fullmatch(
            r"[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-"
            r"[89ab][a-f0-9]{3}-[a-f0-9]{12}",
            supplied["lease_token"],
        )
        and re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._-]{2,63}", supplied["cohort_id"]
        )
        and re.fullmatch(r"[a-f0-9]{64}", supplied["dispatch_id"])
        and re.fullmatch(
            r"[A-Za-z0-9._:@=-]{1,256}",
            supplied["representative_alert_id"],
        )
        and re.fullmatch(r"[a-f0-9]{20}", supplied["stable_group_id"])
        and stable_key_valid
    )


def _admit_mode(enabled: bool, supplied: dict[str, str]) -> bool:
    if not enabled:
        if any(supplied.values()):
            raise SystemExit(
                "controlled result identity requires controlled evaluation mode"
            )
        return False
    if any(
        not value for field, value in supplied.items()
        if field != "reanalysis_attempt_id"
    ):
        raise SystemExit("controlled evaluation result identity is incomplete")
    return True


def _runtime_release(
    supplied: dict[str, str],
    policy: Policy,
    dependencies: Dependencies,
) -> str:
    release = str(
        dependencies.environment.get(policy.release_environment_key) or ""
    ).strip()
    if (
        not re.fullmatch(r"[a-f0-9]{40}", release)
        or supplied["release_id"] != release
    ):
        raise SystemExit("controlled evaluation release identity is invalid")
    return release


def identity(
    enabled: bool,
    *,
    reanalysis_attempt_id: str,
    policy: Policy,
    dependencies: Dependencies,
) -> dict[str, Any] | None:
    """Consume and validate one exact server-owned durable lease identity."""
    supplied = _consume_environment(policy, dependencies)
    if not _admit_mode(enabled, supplied):
        return None
    job_id = _parse_job_id(supplied)
    expected_role = policy.job_roles.get(supplied["job_type"])
    stable_key_valid = _valid_stable_key(supplied["stable_group_key"])
    valid = (
        _valid_core(supplied, job_id, expected_role, stable_key_valid)
        and _valid_attempt(supplied, reanalysis_attempt_id)
        and _valid_routes(supplied, policy)
    )
    if not valid:
        raise SystemExit("controlled evaluation result identity is invalid")
    runtime_release = _runtime_release(supplied, policy, dependencies)
    return {
        **supplied,
        "job_id": job_id,
        "release_id": runtime_release,
        "reviewer_required": True,
    }


def _valid_route_identity(
    identity: dict[str, Any],
    agent_role: str,
    policy: Policy,
) -> bool:
    assigned = identity.get("expected_assigned_route")
    reviewer = identity.get("expected_reviewer_route")
    return bool(
        identity.get("reviewer_required") is True
        and identity.get("agent_role") == agent_role
        and isinstance(assigned, str)
        and isinstance(reviewer, str)
        and policy.model_route_pattern.fullmatch(assigned)
        and policy.model_route_pattern.fullmatch(reviewer)
        and assigned.rsplit(":", 1)[0] != reviewer.rsplit(":", 1)[0]
    )


def _read_settings(path: Path, maximum_bytes: int) -> dict[str, Any]:
    try:
        if not path.is_file() or path.stat().st_size > maximum_bytes:
            raise ValueError("settings file is missing or oversized")
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError, TypeError) as exc:
        raise SystemExit(
            "controlled evaluation route settings are unavailable"
        ) from exc
    return raw if isinstance(raw, dict) else {}


def _settings_match(
    raw: dict[str, Any],
    settings: dict[str, Any],
    agent_role: str,
    assigned: str,
    reviewer: str,
    enabled: Any,
) -> bool:
    raw_assigned = raw.get("agent_models")
    raw_reviewers = raw.get("agent_second_opinion_models")
    return bool(
        isinstance(raw_assigned, dict)
        and raw_assigned.get(agent_role) == assigned
        and isinstance(raw_reviewers, dict)
        and raw_reviewers.get(agent_role) == reviewer
        and (settings.get("agent_models") or {}).get(agent_role) == assigned
        and (settings.get("agent_second_opinion_models") or {}).get(agent_role)
        == reviewer
        and assigned in enabled
        and reviewer in enabled
    )


def require_routes(
    identity_value: dict[str, Any] | None,
    settings_path: Path,
    settings: dict[str, Any],
    agent_role: str,
    *,
    policy: Policy,
    dependencies: Dependencies,
) -> None:
    """Recheck frozen route assignments before Relay or model invocation."""
    if identity_value is None:
        return
    if not _valid_route_identity(identity_value, agent_role, policy):
        raise SystemExit("controlled evaluation route identity is invalid")
    raw = _read_settings(settings_path, policy.maximum_settings_bytes)
    assigned = identity_value["expected_assigned_route"]
    reviewer = identity_value["expected_reviewer_route"]
    enabled = dependencies.enabled_routes(settings)
    if not _settings_match(
        raw, settings, agent_role, assigned, reviewer, enabled
    ):
        raise SystemExit(
            "controlled evaluation routes do not exactly match enabled settings"
        )
