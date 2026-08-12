"""Exact compatibility facade for the report-portal runtime namespace."""
from __future__ import annotations

from portal_runtime_standard_dependencies import *  # noqa: F403
from portal_runtime_settings_dependencies import *  # noqa: F403
from portal_runtime_admin_dependencies import *  # noqa: F403
from portal_runtime_soc_dependencies import *  # noqa: F403
from portal_runtime_constants import *  # noqa: F403


@dataclass(frozen=True)  # type: ignore[name-defined]  # noqa: F405
class CronJobSummary:
    jid: str
    name: str
    schedule: str
    next_run: str
    enabled: bool
    state: str
    last_status: str
    sort_key: str
