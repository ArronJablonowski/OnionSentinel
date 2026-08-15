#!/usr/bin/env python3
"""Stable facade for secure, bounded access to local application logs."""
from __future__ import annotations

import sys
from pathlib import Path


DASHBOARD_DIR = Path(__file__).resolve().parent
if str(DASHBOARD_DIR) not in sys.path:
    sys.path.insert(0, str(DASHBOARD_DIR))

from application_log_catalog import (  # noqa: E402,F401
    _family_members,
    _fixed_members,
    _spec_catalog_item,
    catalog_response,
)
from application_log_content import (  # noqa: E402,F401
    _bounded_gzip_page,
    _bounded_regular_page,
    _bounded_tail,
    _page_content,
    _redact,
    _resolve_member,
    _utf8_tail,
    content_response,
)
from application_log_contract import (  # noqa: E402,F401
    AUTHORIZATION_RE,
    ANALYSIS_ROTATION_BACKUPS,
    ANALYSIS_ROTATION_BYTES,
    BEARER_RE,
    COOKIE_RE,
    DEFAULT_ROTATION_BACKUPS,
    DEFAULT_ROTATION_BYTES,
    DEFAULT_RETENTION_DAYS,
    DEFAULT_TAIL_LINES,
    ENSURE_STACK_RE,
    DISK_PRESSURE_PERCENT,
    LAUNCHD_STEMS,
    LOG_ID_RE,
    LOG_SPECS,
    LOG_SPECS_BY_ID,
    MAX_ENV_BYTES,
    MAX_FAMILY_MEMBERS,
    MAX_TAIL_BYTES,
    MAX_TAIL_LINES,
    OTHER_SPECS,
    PRIVATE_KEY_RE,
    SECRET_ASSIGNMENT_RE,
    STRUCTURED_SPECS,
    ApplicationLogError,
    LogSpec,
    _launchd_specs,
    is_application_log_id,
)
from application_log_filesystem import (  # noqa: E402,F401
    _alert_store_policy,
    _bounded_int,
    _iso_timestamp,
    _member_metadata,
    _open_regular,
    _root_descriptor,
    _roots,
    _safe_env_values,
    _validate_basename,
)


__all__ = [
    "ApplicationLogError",
    "DEFAULT_TAIL_LINES",
    "LOG_SPECS",
    "MAX_TAIL_BYTES",
    "MAX_TAIL_LINES",
    "catalog_response",
    "content_response",
    "is_application_log_id",
]
