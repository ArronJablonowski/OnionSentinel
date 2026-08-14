"""Atomic SOC AI settings persistence and per-agent assignment service."""
from __future__ import annotations

import json
from collections.abc import Callable, Collection
from dataclasses import dataclass
from pathlib import Path
from typing import ContextManager

from portal_atomic_json_store import write_owner_only_json


@dataclass(frozen=True)
class AiSettingsStoreSources:
    path: Path
    lock: ContextManager
    normalize: Callable[[object], tuple[bool, dict]]
    readiness: Callable[[dict], tuple[bool, str]]
    enabled_routes: Callable[[dict], Collection[str]]
    route_identity: Callable[[str, dict], object]
    geoip_databases: Callable[[dict], dict]
    geoip_city: Callable[[dict], dict]
    roles: Collection[str]


def _read_raw_settings(sources: AiSettingsStoreSources) -> tuple[bool, dict]:
    try:
        return True, json.loads(sources.path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return True, {}
    except Exception as exc:
        return False, {
            "ok": False,
            "error": f"Could not read SOC AI settings: {exc}",
            "path": str(sources.path),
        }


def _settings_response(sources: AiSettingsStoreSources, settings: dict) -> dict:
    return {
        "ok": True,
        "settings": settings,
        "geoip_databases": sources.geoip_databases(settings),
        "geoip_database": sources.geoip_city(settings),
        "path": str(sources.path),
    }


def read_soc_ai_settings(sources: AiSettingsStoreSources) -> dict:
    with sources.lock:
        readable, raw = _read_raw_settings(sources)
    if not readable:
        return raw
    ok, normalized = sources.normalize(raw)
    if not ok:
        return {
            "ok": False,
            "error": str(
                normalized.get("error")
                or "SOC AI settings validation failed."
            ),
            "path": str(sources.path),
        }
    return _settings_response(sources, normalized)


def write_soc_ai_settings(
    sources: AiSettingsStoreSources,
    normalized: dict,
) -> tuple[bool, dict]:
    """Write one normalized document while the caller holds the settings lock."""
    try:
        write_owner_only_json(sources.path, normalized)
    except Exception as exc:
        return False, {
            "ok": False,
            "error": f"Could not save SOC AI settings: {exc}",
            "path": str(sources.path),
        }
    response = _settings_response(sources, normalized)
    response["message"] = "SOC AI model and MaxMind GeoIP settings saved."
    return True, response


def save_soc_ai_settings(
    sources: AiSettingsStoreSources,
    payload: object,
) -> tuple[bool, dict]:
    with sources.lock:
        ok, normalized = sources.normalize(
            payload if isinstance(payload, dict) else {}
        )
        if not ok:
            return False, normalized
        ready, readiness_error = sources.readiness(normalized)
        if not ready:
            return False, {"ok": False, "error": readiness_error}
        return write_soc_ai_settings(sources, normalized)


def _agent_routes(payload: dict) -> tuple[str, str, str, str]:
    return (
        str(payload.get("role") or "").strip(),
        str(payload.get("model_route") or payload.get("model") or "").strip()[:260],
        str(
            payload.get("second_opinion_model_route")
            or payload.get("second_opinion_model")
            or ""
        ).strip()[:260],
        str(
            payload.get("adjudicator_model_route")
            or payload.get("adjudicator_model")
            or ""
        ).strip()[:260],
    )


def _validate_enabled_routes(
    enabled: Collection[str],
    primary: str,
    reviewer: str,
    adjudicator: str,
) -> str:
    if primary not in enabled:
        return (
            "That model is not enabled. Save the global model roster before "
            "assigning it to an agent."
        )
    if reviewer and reviewer not in enabled:
        return (
            "That second-opinion model is not enabled. Save the global model "
            "roster first."
        )
    if adjudicator and adjudicator not in enabled:
        return (
            "That adjudicator model is not enabled. Save the global model "
            "roster first."
        )
    return ""


def _validate_independent_routes(
    sources: AiSettingsStoreSources,
    settings: dict,
    primary: str,
    reviewer: str,
    adjudicator: str,
) -> str:
    primary_identity = sources.route_identity(primary, settings)
    reviewer_identity = sources.route_identity(reviewer, settings)
    if reviewer and reviewer_identity == primary_identity:
        return (
            "The second-opinion model must differ from the assigned primary "
            "and resolve to a different provider/model identity."
        )
    adjudicator_identity = sources.route_identity(adjudicator, settings)
    if adjudicator and adjudicator_identity in {
        primary_identity,
        reviewer_identity,
    }:
        return (
            "The adjudicator must differ from both the primary and "
            "second-opinion provider/model identities."
        )
    return ""


def save_soc_agent_model(
    sources: AiSettingsStoreSources,
    payload: object,
) -> tuple[bool, dict]:
    current_payload = payload if isinstance(payload, dict) else {}
    role, primary, reviewer, adjudicator = _agent_routes(current_payload)
    if role not in sources.roles:
        return False, {
            "ok": False,
            "error": "Cyber Security Agent role is invalid.",
        }
    with sources.lock:
        readable, raw = _read_raw_settings(sources)
        if not readable:
            return False, raw
        ok, current = sources.normalize(raw)
        if not ok:
            return False, current
        ready, readiness_error = sources.readiness(current)
        if not ready:
            return False, {"ok": False, "error": readiness_error}
        enabled_error = _validate_enabled_routes(
            sources.enabled_routes(current), primary, reviewer, adjudicator
        )
        if enabled_error:
            return False, {"ok": False, "error": enabled_error}
        independence_error = _validate_independent_routes(
            sources, current, primary, reviewer, adjudicator
        )
        if independence_error:
            return False, {"ok": False, "error": independence_error}
        current["agent_models"][role] = primary
        current["agent_second_opinion_models"][role] = reviewer
        current["agent_adjudicator_models"][role] = adjudicator
        ok, normalized = sources.normalize(current)
        if not ok:
            return False, normalized
        saved, response = write_soc_ai_settings(sources, normalized)
        if saved:
            _agent_assignment_response(response, normalized, role)
        return saved, response


def _agent_assignment_response(
    response: dict, normalized: dict, role: str
) -> None:
    response.update({
        "message": f"Model assignment saved for {role}.",
        "role": role,
        "model_route": normalized["agent_models"][role],
        "second_opinion_model_route": (
            normalized["agent_second_opinion_models"][role]
        ),
        "adjudicator_model_route": normalized["agent_adjudicator_models"][role],
    })
