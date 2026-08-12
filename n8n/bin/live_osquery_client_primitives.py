"""Shared types, limits, and scalar policy for the live OSQuery client."""
from __future__ import annotations

import datetime as dt
import re
from pathlib import Path
from typing import Any


DEFAULT_CONFIG_FILE = Path.home() / "n8n-local" / "config" / "live-osquery.json"
DEFAULT_ARTIFACT_DIR = (
    Path.home()
    / "n8n-local"
    / "soc-alerts"
    / "incident-evidence"
    / "live-osquery"
)
MAX_CONFIG_BYTES = 64 * 1024
MAX_STDERR_BYTES = 256 * 1024
DEFAULT_MAX_SAVED_BATCHES_PER_CASE = 8
SAFE_HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
SAFE_USER = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}$")
SAFE_BINDING_HOST = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,253}[A-Za-z0-9])?$"
)
ALLOWED_AGENT_ROLES = frozenset({"soc-analyst", "incident-responder"})
DEFAULT_ALLOWED_AGENT_ROLES = ("incident-responder",)


class LiveOsqueryClientError(RuntimeError):
    """The local live-query client could not satisfy its restricted contract."""

    def __init__(
        self,
        message: str,
        *,
        reason_code: str = "configuration_error",
    ) -> None:
        super().__init__(message)
        self.reason_code = reason_code


def project_now() -> str:
    return dt.datetime.now().astimezone().isoformat().replace("T", "  ")


def bounded_int(
    value: Any,
    *,
    label: str,
    default: int,
    minimum: int,
    maximum: int,
) -> int:
    try:
        parsed = int(value if value not in (None, "") else default)
    except (TypeError, ValueError) as exc:
        raise LiveOsqueryClientError(f"{label} must be an integer") from exc
    if parsed < minimum or parsed > maximum:
        raise LiveOsqueryClientError(
            f"{label} must be between {minimum} and {maximum}"
        )
    return parsed
