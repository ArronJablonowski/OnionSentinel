#!/usr/bin/env python3
"""Collect a complete, bounded software-inventory snapshot through the relay.

The collector never dispatches a live OSQuery action and never writes to
Security Onion.  It reads three fixed, paginated aggregations through the
existing incident-evidence SSH lane.  A new snapshot replaces the last good
state only after every source reaches a valid terminal page.
"""
from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import stat
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Set, Tuple
from urllib import error as urllib_error
from urllib import request as urllib_request

from bounded_process import BoundedProcessError, run_bounded_command
from security_jsonl_log import SecurityJsonlLogger


CONTRACT = "onion-sentinel-software-inventory-v1"
STATE_SCHEMA = "onion-sentinel-software-inventory-state-v1"
OPERATION = "software_observations"
TRANSPORT_RECEIPT_CONTRACT = "onion-sentinel-evidence-receipt-v1"
SOURCES = ("osquery_apps", "zeek_software", "http_user_agent")
SOURCE_POLICY = {
    "osquery_apps": {
        "index": "logs-osquery_manager.result-default",
        "dataset": "osquery_manager.result",
        "tier": "installed",
        "confidence": "high",
        "platform": "darwin",
        "asset_ref_type": "host",
        "additional_datasets": {"osquery.live.software_inventory"},
        "operating_system_sources": {
            "osquery_manager.result:host.os",
            "osquery.live:os_version",
        },
    },
    "zeek_software": {
        "index": "logs-zeek-so",
        "dataset": "zeek.software",
        "tier": "observed",
        "confidence": "medium",
        "platform": "",
        "asset_ref_type": "ip",
    },
    "http_user_agent": {
        "index": "logs-zeek-so",
        "dataset": "zeek.http",
        "tier": "inferred",
        "confidence": "low",
        "platform": "",
        "asset_ref_type": "ip",
    },
}
RESPONSE_KEYS = {
    "ok",
    "contract",
    "read_only",
    "source",
    "window",
    "returned",
    "complete",
    "truncated",
    "after",
    "records",
    "query_audit",
}
RESPONSE_KEY_SETS = {
    frozenset(RESPONSE_KEYS),
    frozenset(RESPONSE_KEYS | {"audit_receipt"}),
}
AUDIT_RECEIPT_KEYS = {
    "receipt_contract",
    "correlation_id",
    "request_digest",
    "response_payload_digest",
    "elastic_search_count",
    "osquery_query_count",
    "helper_invocation_count",
    "read_only",
    "terminal_status",
}
RECORD_KEYS = {
    "evidence_id",
    "source",
    "source_dataset",
    "tier",
    "confidence",
    "asset_ref_type",
    "asset_ref",
    "platform",
    "operating_system_type",
    "operating_system_version",
    "operating_system_source",
    "operating_system_confidence",
    "product",
    "version",
    "category",
    "first_seen",
    "last_seen",
    "observation_count",
}
LEGACY_RECORD_KEYS = RECORD_KEYS - {
    "operating_system_type",
    "operating_system_version",
    "operating_system_source",
    "operating_system_confidence",
}
RECORD_KEY_SETS = {
    frozenset(RECORD_KEYS),
    frozenset(LEGACY_RECORD_KEYS),
}
CURSOR_KEYS = {"asset", "product", "version"}
QUERY_AUDIT_KEYS = {"index", "dataset", "query_digest"}
STATE_KEYS = {"schema", "version", "updated_at", "collection", "records"}
COLLECTION_KEYS = {
    "status",
    "last_attempt_at",
    "last_success_at",
    "last_error",
    "window",
    "source_statuses",
    "complete",
}
COLLECTION_KEY_SETS = {
    frozenset(COLLECTION_KEYS),
    frozenset(COLLECTION_KEYS | {"osquery_ready"}),
}
SOURCE_STATUS_KEYS = {
    "status",
    "complete",
    "pages",
    "returned",
    "freshness",
    "latest_observation_at",
}

MAX_CONFIG_BYTES = 64 * 1024
MAX_STATE_BYTES = 256 * 1024 * 1024
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_STDERR_BYTES = 128 * 1024
MAX_PAGE_SIZE = 500
MAX_PAGES_PER_SOURCE = 512
MAX_TOTAL_RECORDS = 250_000
MAX_OBSERVATION_COUNT = 1_000_000_000
WINDOW_DAYS = 30
FRESH_SECONDS = 24 * 60 * 60
STALE_SECONDS = 7 * 24 * 60 * 60
_SAFE_HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
_SAFE_USER = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}$")
_HEX_24 = re.compile(r"^[0-9a-f]{24}$")
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_CORRELATION_ID = re.compile(r"^[0-9a-f]{32}$")
_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_LAN_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "fc00::/7",
    )
)
CONFIG_KEYS = {
    "enabled",
    "host",
    "ssh_user",
    "ssh_key",
    "known_hosts",
    "port",
    "connect_timeout_seconds",
    "timeout_seconds",
    "max_collection_seconds",
    "max_response_bytes",
    "max_stderr_bytes",
    "page_size",
    "max_pages_per_source",
}

HOME = Path.home()
DEFAULT_CONFIG = HOME / "n8n-local" / "config" / "software-inventory.json"
DEFAULT_STATE = (
    HOME
    / "n8n-local"
    / "software-inventory"
    / "software-inventory.json"
)
DEFAULT_LOG = HOME / "n8n-local" / "logs" / "software-inventory.jsonl"
DEFAULT_ENDPOINT_CACHE = (
    HOME / "n8n-local" / "software-inventory" / "endpoint-cache.json"
)
DEFAULT_ENV = HOME / "n8n-local" / ".env"
DEFAULT_DATABASE_API_URL = "http://127.0.0.1:8787"
DATABASE_CHUNK_SIZE = 500


class SoftwareInventoryError(RuntimeError):
    """The fixed software-inventory collection contract was not satisfied."""

    def __init__(
        self,
        message: str,
        source_statuses: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> None:
        super().__init__(message)
        self.source_statuses = source_statuses




def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def parse_timestamp(value: object) -> dt.datetime:
    text = str(value or "").strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = dt.datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        raise ValueError("timestamp lacks a UTC offset")
    return parsed.astimezone(dt.timezone.utc)


def format_timestamp(value: dt.datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("timestamp lacks a UTC offset")
    return (
        value.astimezone(dt.timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _bounded_text(
    value: object,
    *,
    field: str,
    maximum: int,
    required: bool = False,
) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    text = value
    if (
        text != text.strip()
        or (required and not text)
        or len(text.encode("utf-8")) > maximum
    ):
        raise ValueError(f"{field} is invalid")
    if any(not character.isprintable() for character in text):
        raise ValueError(f"{field} contains control characters")
    return text


def _bounded_integer(
    value: object,
    *,
    field: str,
    minimum: int,
    maximum: int,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field} must be an integer")
    if value < minimum or value > maximum:
        raise ValueError(f"{field} must be from {minimum} through {maximum}")
    return value


def _owner_file(
    path: Path,
    *,
    maximum_bytes: int,
    exact_mode: Optional[int] = None,
) -> os.stat_result:
    info = path.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_size > maximum_bytes
    ):
        raise ValueError(f"{path.name} is not a bounded owner-controlled file")
    mode = stat.S_IMODE(info.st_mode)
    if exact_mode is not None and mode != exact_mode:
        raise ValueError(f"{path.name} must have mode {exact_mode:04o}")
    if exact_mode is None and mode & 0o022:
        raise ValueError(f"{path.name} must not be group/world writable")
    return info


def _read_json_file(
    path: Path,
    maximum_bytes: int,
    *,
    exact_mode: Optional[int] = None,
) -> object:
    _owner_file(path, maximum_bytes=maximum_bytes, exact_mode=exact_mode)
    return json.loads(path.read_text(encoding="utf-8"))


def _config_document(value: object) -> Dict[str, Any]:
    if not isinstance(value, dict) or set(value) != CONFIG_KEYS:
        raise ValueError("software inventory config contains unsupported or missing fields")
    if not isinstance(value.get("enabled"), bool):
        raise ValueError("software inventory config enabled must be boolean")
    return value


def _config_endpoint(value: Dict[str, Any]) -> Tuple[str, str]:
    host = _bounded_text(
        value.get("host"),
        field="software inventory host",
        maximum=255,
        required=True,
    )
    user = _bounded_text(
        value.get("ssh_user"),
        field="software inventory SSH user",
        maximum=64,
        required=True,
    )
    if not _SAFE_HOST.fullmatch(host) or not _SAFE_USER.fullmatch(user):
        raise ValueError("software inventory SSH endpoint is invalid")
    return host, user


def _config_numeric_values(value: Dict[str, Any]) -> Dict[str, int]:
    numeric_limits = {
        "port": (1, 65535),
        "connect_timeout_seconds": (1, 60),
        "timeout_seconds": (5, 300),
        "max_collection_seconds": (30, 1800),
        "max_response_bytes": (1024, MAX_RESPONSE_BYTES),
        "max_stderr_bytes": (1024, MAX_STDERR_BYTES),
        "page_size": (1, MAX_PAGE_SIZE),
        "max_pages_per_source": (1, MAX_PAGES_PER_SOURCE),
    }
    normalized: Dict[str, int] = {}
    for key, limits in numeric_limits.items():
        normalized[key] = _bounded_integer(
            value.get(key),
            field=f"software inventory config {key}",
            minimum=limits[0],
            maximum=limits[1],
        )
    return normalized


def _config_paths(value: Dict[str, Any]) -> Dict[str, str]:
    normalized: Dict[str, str] = {}
    for key in ("ssh_key", "known_hosts"):
        text = _bounded_text(
            value.get(key),
            field=f"software inventory {key}",
            maximum=1024,
            required=True,
        )
        normalized[key] = str(Path(text).expanduser())
    return normalized


def _verify_config_files(normalized: Dict[str, Any]) -> None:
    if normalized["enabled"]:
        _owner_file(
            Path(normalized["ssh_key"]),
            maximum_bytes=1024 * 1024,
            exact_mode=0o600,
        )
        _owner_file(
            Path(normalized["known_hosts"]),
            maximum_bytes=1024 * 1024,
        )


def load_config(path: Path) -> Dict[str, Any]:
    value = _config_document(
        _read_json_file(path, MAX_CONFIG_BYTES, exact_mode=0o600)
    )
    host, user = _config_endpoint(value)
    normalized: Dict[str, Any] = {
        "enabled": value["enabled"],
        "host": host,
        "ssh_user": user,
    }
    normalized.update(_config_numeric_values(value))
    normalized.update(_config_paths(value))
    _verify_config_files(normalized)
    return normalized


def collection_window(now: dt.datetime) -> Dict[str, str]:
    current = now.astimezone(dt.timezone.utc)
    return {
        "start": format_timestamp(current - dt.timedelta(days=WINDOW_DAYS)),
        "end": format_timestamp(current),
    }


def _empty_source_status(status: str = "not_run") -> Dict[str, Any]:
    return {
        "status": status,
        "complete": False,
        "pages": 0,
        "returned": 0,
        "freshness": "unknown",
        "latest_observation_at": "",
    }


def empty_state() -> Dict[str, Any]:
    return {
        "schema": STATE_SCHEMA,
        "version": 1,
        "updated_at": "",
        "collection": {
            "status": "never_run",
            "last_attempt_at": "",
            "last_success_at": "",
            "last_error": "",
            "window": {},
            "source_statuses": {
                source: _empty_source_status()
                for source in SOURCES
            },
            "complete": False,
        },
        "records": [],
    }
