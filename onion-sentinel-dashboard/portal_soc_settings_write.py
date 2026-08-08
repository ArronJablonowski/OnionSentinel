"""Transport-neutral orchestration for SOC Settings write requests."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from portal_json_body import parse_json_body
from portal_request_routes import PostRoute


AI_MODEL_PATH = "/api/soc-settings/ai-model"
AGENT_MODEL_PATH = "/api/soc-settings/agent-model"

SaveResult = tuple[bool, dict]


@dataclass(frozen=True)
class SocSettingsWriteCallbacks:
    save_prompt: Callable[[str, object], SaveResult]
    save_ai_settings: Callable[[object], SaveResult]
    save_agent_model: Callable[[object], SaveResult]


@dataclass(frozen=True)
class SocSettingsWriteResult:
    status: int
    payload: dict


def is_soc_settings_write(route: PostRoute) -> bool:
    return route.prompt_write or route.path in {AI_MODEL_PATH, AGENT_MODEL_PATH}


def prepare_soc_settings_write(
    route: PostRoute,
    raw: str,
    *,
    admin_authenticated: Callable[[], bool],
    callbacks: SocSettingsWriteCallbacks,
) -> SocSettingsWriteResult | None:
    """Authorize and dispatch one classified settings mutation."""
    if not is_soc_settings_write(route):
        return None
    payload = parse_json_body(raw, empty_object=True).value_or({})
    if not admin_authenticated():
        return SocSettingsWriteResult(403, {
            "ok": False,
            "error": "Sign in to Administration before saving SOC settings.",
        })
    if route.prompt_write:
        prompt = payload.get("prompt", "") if isinstance(payload, dict) else ""
        ok, response = callbacks.save_prompt(route.path, prompt)
    elif route.path == AI_MODEL_PATH:
        ok, response = callbacks.save_ai_settings(payload)
    else:
        ok, response = callbacks.save_agent_model(payload)
    return SocSettingsWriteResult(200 if ok else 400, response)
