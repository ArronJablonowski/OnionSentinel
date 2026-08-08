"""Administration service-card composition and allowlisted startup policy."""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass


@dataclass(frozen=True)
class AdminServiceStartSources:
    labels: Mapping[str, str]
    start_commands: Mapping[str, list[str]]
    statuses: Callable[[], dict[str, dict[str, object]]]
    spawn: Callable[[list[str]], None]


def compose_admin_service_statuses(
    labels: Mapping[str, str],
    checks: Mapping[str, Callable[[], tuple[bool, str]]],
    n8n_status: Callable[[], dict[str, object]],
) -> dict[str, dict[str, object]]:
    """Compose stable Administration cards from bounded service probes."""
    statuses = {}
    for service_id, checker in checks.items():
        running, detail = checker()
        statuses[service_id] = {
            "id": service_id,
            "label": labels[service_id],
            "running": running,
            "level": "ok" if running else "warn",
            "startable": True,
            "value": "Running" if running else "Not running",
            "detail": detail,
        }
    statuses["n8n"] = n8n_status()
    return statuses


def start_admin_service(
    service_id: str, sources: AdminServiceStartSources
) -> tuple[bool, str, dict[str, object] | None]:
    """Start one allowlisted service and return its latest observed card."""
    command = sources.start_commands.get(service_id)
    if command is None:
        return False, "Unknown service.", None
    status = sources.statuses().get(service_id)
    label = sources.labels[service_id]
    if status and status.get("running"):
        return True, f"{label} is already running.", status
    try:
        sources.spawn(list(command))
        status = sources.statuses().get(service_id)
        return (
            True,
            f"Started {label}. The card will update when it reports running.",
            status,
        )
    except Exception as exc:
        status = sources.statuses().get(service_id)
        return False, f"Unable to start {label}: {exc}", status
