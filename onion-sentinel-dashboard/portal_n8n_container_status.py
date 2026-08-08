"""Bounded Docker and healthz status service for the n8n Administration card."""
from __future__ import annotations

from dataclasses import dataclass
import datetime as dt
import json
from typing import Callable


@dataclass(frozen=True)
class N8nContainerStatusSources:
    docker_bin: str
    container_name: str
    health_url: str
    environment: dict[str, str]
    pipe: object
    run: Callable
    now: Callable[[], dt.datetime]
    format_timestamp: Callable[[dt.datetime], str]


def _base(sources: N8nContainerStatusSources) -> tuple[dict[str, object], str]:
    now = sources.now().astimezone()
    return ({
        "id": "n8n",
        "label": "n8n container",
        "startable": False,
        "checked_at": sources.format_timestamp(now),
    }, sources.format_timestamp(now))


def _failure(
    base: dict[str, object],
    value: str,
    detail: str,
) -> dict[str, object]:
    return {
        **base, "running": False, "level": "alert",
        "value": value, "detail": detail,
    }


def _inspect_container(
    sources: N8nContainerStatusSources,
    base: dict[str, object],
    checked_label: str,
) -> tuple[dict, dict[str, object] | None]:
    try:
        proc = sources.run(
            [sources.docker_bin, "inspect", sources.container_name],
            text=True, stdout=sources.pipe, stderr=sources.pipe, timeout=5, check=False,
            env=sources.environment,
        )
    except Exception as exc:
        detail = f"WARNING: unable to inspect {sources.container_name}: {exc} · checked {checked_label}"
        return {}, _failure(base, "Docker unavailable", detail)
    if proc.returncode != 0:
        lines = (proc.stderr or proc.stdout or "docker inspect failed").strip().splitlines()
        reason = lines[-1] if lines else "docker inspect failed"
        missing = "no such object" in reason.lower() or "no such container" in reason.lower()
        detail = f"WARNING: {sources.container_name} status unavailable: {reason} · healthz not checked · checked {checked_label}"
        return {}, _failure(base, "Missing" if missing else "Docker unavailable", detail)
    try:
        payload = json.loads(proc.stdout)
        return (payload[0] if isinstance(payload, list) and payload else {}), None
    except Exception as exc:
        detail = f"WARNING: unable to parse docker inspect output for {sources.container_name}: {exc} · checked {checked_label}"
        return {}, _failure(base, "Unknown", detail)


def _health_check(
    sources: N8nContainerStatusSources,
    state: str,
) -> tuple[bool, str]:
    if state != "running":
        return False, "not checked"
    try:
        proc = sources.run(
            ["/usr/bin/curl", "-fsS", "--max-time", "5", sources.health_url],
            text=True, stdout=sources.pipe, stderr=sources.pipe, timeout=7, check=False,
        )
        body = proc.stdout.strip()
        if proc.returncode != 0:
            errors = (proc.stderr or body or "curl failed").strip().splitlines()
            return False, errors[-1] if errors else "curl failed"
        try:
            healthy = json.loads(body).get("status") == "ok"
        except Exception:
            healthy = body == '{"status":"ok"}'
        detail = "ok" if healthy else f"unexpected response: {body[:120] or 'empty body'}"
        return healthy, detail
    except Exception as exc:
        return False, f"health check error: {exc}"


def _state_level(state: str, health_ok: bool, restart_policy: str) -> tuple[str, str]:
    if state != "running":
        return "alert", state if state != "unknown" else "Unknown"
    if not health_ok:
        return "warn", "Health warning"
    if restart_policy != "unless-stopped":
        return "warn", "Policy warning"
    return "ok", "Healthy"


def compose_n8n_container_status(
    sources: N8nContainerStatusSources,
) -> dict[str, object]:
    """Inspect n8n and project only bounded, non-sensitive health metadata."""
    base, checked_label = _base(sources)
    container, failure = _inspect_container(sources, base, checked_label)
    if failure is not None:
        return failure
    state_obj = (container.get("State") or {}) if isinstance(container, dict) else {}
    host_config = (container.get("HostConfig") or {}) if isinstance(container, dict) else {}
    restart_obj = host_config.get("RestartPolicy") or {}
    state = str(state_obj.get("Status") or "unknown")
    started_at = str(state_obj.get("StartedAt") or "unknown")
    restart_policy = str(restart_obj.get("Name") or "none")
    health_ok, health_detail = _health_check(sources, state)
    level, value = _state_level(state, health_ok, restart_policy)
    detail = (
        f"state={state} · healthz={health_detail} · restart={restart_policy} "
        f"· started={started_at} · checked {checked_label}"
    )
    return {
        **base,
        "running": level == "ok",
        "level": level,
        "value": value,
        "detail": detail,
        "container_state": state,
        "healthz": health_detail,
        "restart_policy": restart_policy,
        "started_at": started_at,
    }
