"""Read policy for asynchronous Resource Library action status."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re


@dataclass(frozen=True)
class ResourceActionReadResult:
    status: int
    payload: dict | bytes
    encoded: bool = False


def read_resource_action_status(
    operation: str | None,
    query: dict[str, list[str]],
    *,
    status_directory: Path,
) -> ResourceActionReadResult | None:
    """Validate and read one classified Resource Library action status."""
    if operation != "resource_action_status":
        return None
    action_id = (query.get("id") or [""])[0]
    if not re.fullmatch(r"[a-f0-9-]{32,36}", action_id):
        return ResourceActionReadResult(
            400, {"ok": False, "error": "Invalid action id"},
        )
    status_path = status_directory / f"{action_id}.json"
    if not status_path.exists():
        return ResourceActionReadResult(200, {"ok": True, "state": "pending"})
    return ResourceActionReadResult(200, status_path.read_bytes(), encoded=True)
