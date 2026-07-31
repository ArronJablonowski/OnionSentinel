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

from bounded_process import BoundedProcessError, run_bounded_command
from security_jsonl_log import SecurityJsonlLogger


CONTRACT = "onion-sentinel-software-inventory-v1"
STATE_SCHEMA = "onion-sentinel-software-inventory-state-v1"
OPERATION = "software_observations"
SOURCES = ("osquery_apps", "zeek_software", "http_user_agent")
SOURCE_POLICY = {
    "osquery_apps": {
        "index": "logs-osquery_manager.result-default",
        "dataset": "osquery_manager.result",
        "tier": "installed",
        "confidence": "high",
        "platform": "darwin",
        "asset_ref_type": "host",
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
SOURCE_STATUS_KEYS = {
    "status",
    "complete",
    "pages",
    "returned",
    "freshness",
    "latest_observation_at",
}

MAX_CONFIG_BYTES = 64 * 1024
MAX_STATE_BYTES = 32 * 1024 * 1024
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_STDERR_BYTES = 128 * 1024
MAX_PAGE_SIZE = 500
MAX_PAGES_PER_SOURCE = 64
MAX_TOTAL_RECORDS = 25_000
MAX_OBSERVATION_COUNT = 1_000_000_000
WINDOW_DAYS = 30
FRESH_SECONDS = 24 * 60 * 60
STALE_SECONDS = 7 * 24 * 60 * 60
_SAFE_HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
_SAFE_USER = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}$")
_HEX_24 = re.compile(r"^[0-9a-f]{24}$")
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
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


def load_config(path: Path) -> Dict[str, Any]:
    value = _read_json_file(path, MAX_CONFIG_BYTES, exact_mode=0o600)
    if not isinstance(value, dict) or set(value) != CONFIG_KEYS:
        raise ValueError("software inventory config contains unsupported or missing fields")
    if not isinstance(value.get("enabled"), bool):
        raise ValueError("software inventory config enabled must be boolean")
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
    normalized: Dict[str, Any] = {
        "enabled": value["enabled"],
        "host": host,
        "ssh_user": user,
    }
    for key, limits in numeric_limits.items():
        normalized[key] = _bounded_integer(
            value.get(key),
            field=f"software inventory config {key}",
            minimum=limits[0],
            maximum=limits[1],
        )
    for key in ("ssh_key", "known_hosts"):
        text = _bounded_text(
            value.get(key),
            field=f"software inventory {key}",
            maximum=1024,
            required=True,
        )
        normalized[key] = str(Path(text).expanduser())
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


def _normalize_window(value: object, *, allow_empty: bool = False) -> Dict[str, str]:
    if allow_empty and value == {}:
        return {}
    if not isinstance(value, dict) or set(value) != {"start", "end"}:
        raise ValueError("software inventory window is invalid")
    start = parse_timestamp(value.get("start"))
    end = parse_timestamp(value.get("end"))
    if start >= end or end - start > dt.timedelta(days=31):
        raise ValueError("software inventory window is out of bounds")
    return {"start": format_timestamp(start), "end": format_timestamp(end)}


def _normalize_cursor(
    value: object,
    *,
    allow_none: bool,
    expected_source: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    if value is None and allow_none:
        return None
    if not isinstance(value, dict) or set(value) != CURSOR_KEYS:
        raise ValueError("software inventory cursor is invalid")
    asset = _bounded_text(
        value.get("asset"),
        field="software inventory cursor asset",
        maximum=512,
        required=True,
    )
    product = _bounded_text(
        value.get("product"),
        field="software inventory cursor product",
        maximum=4096,
        required=True,
    )
    raw_version = value.get("version")
    if raw_version is None:
        version = None
    else:
        version = _bounded_text(
            raw_version,
            field="software inventory cursor version",
            maximum=1024,
        )
    if expected_source == "osquery_apps" and _UUID.fullmatch(asset):
        raise ValueError("software inventory cursor host must not be UUID-shaped")
    return {"asset": asset, "product": product, "version": version}


def _cursor_order(value: Dict[str, Any]) -> Tuple[str, str, Tuple[int, str]]:
    version = value.get("version")
    return (
        str(value["asset"]),
        str(value["product"]),
        (0, "") if version in (None, "") else (1, str(version)),
    )


def _cursor_public_identity(
    source: str,
    cursor: Dict[str, Any],
) -> Tuple[str, str, str]:
    raw_asset = str(cursor["asset"])
    if source == "osquery_apps":
        normalized_host = raw_asset.strip().rstrip(".").lower()
        public_asset = hashlib.sha256(
            ("host\0" + normalized_host).encode("utf-8")
        ).hexdigest()[:24]
    else:
        public_asset = str(ipaddress.ip_address(raw_asset))
    return (
        public_asset,
        str(cursor["product"]),
        str(cursor["version"] or ""),
    )


def _normalize_record(
    value: object,
    *,
    expected_source: Optional[str] = None,
    expected_window: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    if (
        not isinstance(value, dict)
        or frozenset(value) not in RECORD_KEY_SETS
    ):
        raise ValueError("software inventory record has an invalid shape")
    source = _bounded_text(
        value.get("source"),
        field="software inventory record source",
        maximum=32,
        required=True,
    )
    if source not in SOURCE_POLICY or (
        expected_source is not None and source != expected_source
    ):
        raise ValueError("software inventory record source is invalid")
    policy = SOURCE_POLICY[source]
    dataset = _bounded_text(
        value.get("source_dataset"),
        field="software inventory source dataset",
        maximum=100,
        required=True,
    )
    if dataset != policy["dataset"]:
        raise ValueError("software inventory record dataset is invalid")
    tier = _bounded_text(
        value.get("tier"),
        field="software inventory evidence tier",
        maximum=16,
        required=True,
    )
    confidence = _bounded_text(
        value.get("confidence"),
        field="software inventory confidence",
        maximum=16,
        required=True,
    )
    if tier != policy["tier"] or confidence != policy["confidence"]:
        raise ValueError("software inventory record evidence semantics are invalid")
    evidence_id = _bounded_text(
        value.get("evidence_id"),
        field="software inventory evidence identifier",
        maximum=24,
        required=True,
    )
    if not _HEX_24.fullmatch(evidence_id):
        raise ValueError("software inventory evidence identifier is invalid")
    asset_ref_type = _bounded_text(
        value.get("asset_ref_type"),
        field="software inventory asset reference type",
        maximum=8,
        required=True,
    )
    if asset_ref_type != policy["asset_ref_type"]:
        raise ValueError("software inventory asset reference type is invalid")
    asset_ref = _bounded_text(
        value.get("asset_ref"),
        field="software inventory asset reference",
        maximum=253,
        required=True,
    )
    if asset_ref_type == "ip":
        address = ipaddress.ip_address(asset_ref)
        asset_ref = str(address)
        if not any(address in network for network in _LAN_NETWORKS):
            raise ValueError("software inventory IP reference is not a LAN address")
    elif asset_ref_type == "host":
        if source != "osquery_apps" or not _HEX_24.fullmatch(asset_ref):
            raise ValueError("software inventory host reference is invalid")
    else:
        raise ValueError("software inventory asset reference type is invalid")
    platform = _bounded_text(
        value.get("platform"),
        field="software inventory platform",
        maximum=160,
    ).lower()
    required_platform = str(policy.get("platform") or "")
    if platform != required_platform:
        raise ValueError("software inventory platform conflicts with its source")
    product = _bounded_text(
        value.get("product"),
        field="software inventory product",
        maximum=4096,
        required=True,
    )
    version = _bounded_text(
        value.get("version"),
        field="software inventory version",
        maximum=1024,
    )
    if source == "http_user_agent" and version:
        raise ValueError("HTTP user-agent evidence must not invent a version")
    category = _bounded_text(
        value.get("category"),
        field="software inventory category",
        maximum=256,
    )
    operating_system_type = _bounded_text(
        value.get("operating_system_type") or "",
        field="software inventory operating system type",
        maximum=160,
    )
    operating_system_version = _bounded_text(
        value.get("operating_system_version") or "",
        field="software inventory operating system version",
        maximum=512,
    )
    operating_system_source = _bounded_text(
        value.get("operating_system_source") or "",
        field="software inventory operating system source",
        maximum=128,
    )
    operating_system_confidence = _bounded_text(
        value.get("operating_system_confidence") or "",
        field="software inventory operating system confidence",
        maximum=16,
    ).lower()
    os_present = bool(operating_system_type or operating_system_version)
    if source == "osquery_apps":
        if os_present and (
            operating_system_source != "osquery_manager.result:host.os"
            or operating_system_confidence != "high"
        ):
            raise ValueError(
                "endpoint operating system evidence has invalid provenance"
            )
        if not os_present and (
            operating_system_source or operating_system_confidence
        ):
            raise ValueError(
                "empty endpoint operating system evidence claims provenance"
            )
    elif any(
        (
            operating_system_type,
            operating_system_version,
            operating_system_source,
            operating_system_confidence,
        )
    ):
        raise ValueError(
            "passive software evidence cannot assert an exact operating system"
        )
    first_seen = parse_timestamp(value.get("first_seen"))
    last_seen = parse_timestamp(value.get("last_seen"))
    if first_seen > last_seen:
        raise ValueError("software inventory record timestamps are reversed")
    if expected_window is not None:
        start = parse_timestamp(expected_window["start"])
        end = parse_timestamp(expected_window["end"])
        if first_seen < start or last_seen >= end:
            raise ValueError("software inventory record falls outside the query window")
    observation_count = _bounded_integer(
        value.get("observation_count"),
        field="software inventory observation count",
        minimum=1,
        maximum=MAX_OBSERVATION_COUNT,
    )
    return {
        "evidence_id": evidence_id,
        "source": source,
        "source_dataset": dataset,
        "tier": tier,
        "confidence": confidence,
        "asset_ref_type": asset_ref_type,
        "asset_ref": asset_ref,
        "platform": platform,
        "operating_system_type": operating_system_type,
        "operating_system_version": operating_system_version,
        "operating_system_source": operating_system_source,
        "operating_system_confidence": operating_system_confidence,
        "product": product,
        "version": version,
        "category": category,
        "first_seen": format_timestamp(first_seen),
        "last_seen": format_timestamp(last_seen),
        "observation_count": observation_count,
    }


def _freshness(latest: str, now: dt.datetime) -> str:
    if not latest:
        return "empty"
    age = max(
        0.0,
        (
            now.astimezone(dt.timezone.utc) - parse_timestamp(latest)
        ).total_seconds(),
    )
    if age <= FRESH_SECONDS:
        return "fresh"
    if age <= STALE_SECONDS:
        return "stale"
    return "expired"


def _source_status(
    *,
    status: str,
    complete: bool,
    pages: int,
    returned: int,
    latest: str,
    now: dt.datetime,
) -> Dict[str, Any]:
    return {
        "status": status,
        "complete": complete,
        "pages": pages,
        "returned": returned,
        "freshness": _freshness(latest, now) if status == "ok" else "unknown",
        "latest_observation_at": latest,
    }


def _normalize_source_status(value: object, source: str) -> Dict[str, Any]:
    if not isinstance(value, dict) or set(value) != SOURCE_STATUS_KEYS:
        raise ValueError(f"software inventory {source} source status is invalid")
    status = _bounded_text(
        value.get("status"),
        field=f"software inventory {source} status",
        maximum=16,
        required=True,
    )
    if status not in {"not_run", "disabled", "ok", "failed"}:
        raise ValueError(f"software inventory {source} status is unsupported")
    if not isinstance(value.get("complete"), bool):
        raise ValueError(f"software inventory {source} completeness is invalid")
    pages = _bounded_integer(
        value.get("pages"),
        field=f"software inventory {source} page count",
        minimum=0,
        maximum=MAX_PAGES_PER_SOURCE,
    )
    returned = _bounded_integer(
        value.get("returned"),
        field=f"software inventory {source} returned count",
        minimum=0,
        maximum=MAX_TOTAL_RECORDS,
    )
    freshness = _bounded_text(
        value.get("freshness"),
        field=f"software inventory {source} freshness",
        maximum=16,
        required=True,
    )
    if freshness not in {"unknown", "empty", "fresh", "stale", "expired"}:
        raise ValueError(f"software inventory {source} freshness is invalid")
    latest = _bounded_text(
        value.get("latest_observation_at"),
        field=f"software inventory {source} latest observation",
        maximum=40,
    )
    if latest:
        latest = format_timestamp(parse_timestamp(latest))
    if status == "ok" and value["complete"] is not True:
        raise ValueError(f"software inventory {source} successful status is incomplete")
    if status != "ok" and freshness != "unknown":
        raise ValueError(f"software inventory {source} failed status claims freshness")
    return {
        "status": status,
        "complete": value["complete"],
        "pages": pages,
        "returned": returned,
        "freshness": freshness,
        "latest_observation_at": latest,
    }


def validate_state(value: object) -> Dict[str, Any]:
    if not isinstance(value, dict) or set(value) != STATE_KEYS:
        raise ValueError("software inventory state has an invalid shape")
    if value.get("schema") != STATE_SCHEMA or value.get("version") != 1:
        raise ValueError("software inventory state schema is unsupported")
    updated_at = _bounded_text(
        value.get("updated_at"),
        field="software inventory state updated_at",
        maximum=40,
    )
    if updated_at:
        updated_at = format_timestamp(parse_timestamp(updated_at))
    collection = value.get("collection")
    if not isinstance(collection, dict) or set(collection) != COLLECTION_KEYS:
        raise ValueError("software inventory collection metadata is invalid")
    status = _bounded_text(
        collection.get("status"),
        field="software inventory collection status",
        maximum=16,
        required=True,
    )
    if status not in {"never_run", "disabled", "ok", "failed"}:
        raise ValueError("software inventory collection status is unsupported")
    timestamps: Dict[str, str] = {}
    for key in ("last_attempt_at", "last_success_at"):
        text = _bounded_text(
            collection.get(key),
            field=f"software inventory collection {key}",
            maximum=40,
        )
        timestamps[key] = format_timestamp(parse_timestamp(text)) if text else ""
    error = _bounded_text(
        collection.get("last_error"),
        field="software inventory collection error",
        maximum=500,
    )
    window = _normalize_window(collection.get("window"), allow_empty=True)
    if not isinstance(collection.get("complete"), bool):
        raise ValueError("software inventory collection completeness is invalid")
    statuses = collection.get("source_statuses")
    if not isinstance(statuses, dict) or set(statuses) != set(SOURCES):
        raise ValueError("software inventory source status roster is invalid")
    normalized_statuses = {
        source: _normalize_source_status(statuses[source], source)
        for source in SOURCES
    }
    if status == "ok" and (
        collection["complete"] is not True
        or any(not item["complete"] for item in normalized_statuses.values())
    ):
        raise ValueError("successful software inventory state is incomplete")
    records = value.get("records")
    if not isinstance(records, list) or len(records) > MAX_TOTAL_RECORDS:
        raise ValueError("software inventory state record list is invalid")
    normalized_records: List[Dict[str, Any]] = []
    evidence_ids: Set[str] = set()
    for raw in records:
        record = _normalize_record(raw)
        if record["evidence_id"] in evidence_ids:
            raise ValueError("software inventory state contains duplicate evidence")
        evidence_ids.add(record["evidence_id"])
        normalized_records.append(record)
    return {
        "schema": STATE_SCHEMA,
        "version": 1,
        "updated_at": updated_at,
        "collection": {
            "status": status,
            "last_attempt_at": timestamps["last_attempt_at"],
            "last_success_at": timestamps["last_success_at"],
            "last_error": error,
            "window": window,
            "source_statuses": normalized_statuses,
            "complete": collection["complete"],
        },
        "records": normalized_records,
    }


def load_state(path: Path) -> Dict[str, Any]:
    try:
        value = _read_json_file(path, MAX_STATE_BYTES, exact_mode=0o600)
    except FileNotFoundError:
        return empty_state()
    return validate_state(value)


def _prepare_private_directory(path: Path) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        try:
            path.mkdir(parents=True, exist_ok=False, mode=0o700)
        except FileExistsError:
            # Another same-UID collector may have created it between lstat and
            # mkdir; the ownership/type checks below still decide trust.
            pass
        info = path.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
    ):
        raise ValueError(
            "software inventory state directory is not owner-controlled"
        )
    os.chmod(path, 0o700)


def atomic_write_json(path: Path, payload: Dict[str, Any]) -> None:
    normalized = validate_state(payload)
    encoded = (
        json.dumps(normalized, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    if len(encoded) > MAX_STATE_BYTES:
        raise ValueError("software inventory state exceeds its byte limit")
    _prepare_private_directory(path.parent)
    if path.exists() or path.is_symlink():
        _owner_file(path, maximum_bytes=MAX_STATE_BYTES, exact_mode=0o600)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        dir=str(path.parent),
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        os.replace(str(temporary), str(path))
        os.chmod(path, 0o600)
        directory_descriptor = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


@contextlib.contextmanager
def collector_lock(state_path: Path) -> Iterator[None]:
    _prepare_private_directory(state_path.parent)
    lock_path = state_path.parent / ".collector.lock"
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(str(lock_path), flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
            raise ValueError("software inventory collector lock is invalid")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise SoftwareInventoryError(
                "software inventory collection is already running"
            ) from exc
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def build_request(
    source: str,
    window: Dict[str, str],
    page_size: int,
    after: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    if source not in SOURCE_POLICY:
        raise ValueError("software inventory source is unsupported")
    normalized_window = _normalize_window(window)
    bounded_page_size = _bounded_integer(
        page_size,
        field="software inventory page size",
        minimum=1,
        maximum=MAX_PAGE_SIZE,
    )
    cursor = _normalize_cursor(
        after,
        allow_none=True,
        expected_source=source,
    )
    return {
        "contract": CONTRACT,
        "operation": OPERATION,
        "source": source,
        "window": normalized_window,
        "page_size": bounded_page_size,
        "after": cursor,
    }


def relay_failure_diagnostic(stdout: object, stderr: object) -> str:
    messages: List[str] = []
    try:
        payload = json.loads(str(stdout or ""))
    except json.JSONDecodeError:
        payload = None
    if isinstance(payload, dict):
        for key in (
            "error",
            "detail",
            "upstream_error",
            "upstream_detail",
            "transport_detail",
        ):
            raw = payload.get(key)
            if not isinstance(raw, str):
                continue
            text = " ".join(
                "".join(
                    character if character.isprintable() else " "
                    for character in raw
                ).split()
            )
            if text:
                messages.append(text[:300])
    stderr_text = " ".join(
        "".join(
            character if character.isprintable() else " "
            for character in str(stderr or "")
        ).split()
    )
    if stderr_text:
        messages.append(stderr_text[:300])
    return "; ".join(messages)[:700]


def validate_response(
    value: object,
    *,
    expected_source: str,
    expected_window: Dict[str, str],
    requested_page_size: int,
    previous_after: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    if not isinstance(value, dict) or set(value) != RESPONSE_KEYS:
        raise ValueError("relay response has an invalid software inventory shape")
    if (
        value.get("ok") is not True
        or value.get("contract") != CONTRACT
        or value.get("read_only") is not True
        or value.get("source") != expected_source
    ):
        raise ValueError("relay response failed the software inventory contract")
    window = _normalize_window(value.get("window"))
    if window != _normalize_window(expected_window):
        raise ValueError("relay response window does not match the request")
    records = value.get("records")
    returned = value.get("returned")
    if (
        not isinstance(records, list)
        or isinstance(returned, bool)
        or not isinstance(returned, int)
        or returned != len(records)
        or returned > requested_page_size
    ):
        raise ValueError("relay response result accounting is invalid")
    complete = value.get("complete")
    truncated = value.get("truncated")
    if not isinstance(complete, bool) or not isinstance(truncated, bool):
        raise ValueError("relay response pagination state is invalid")
    after = _normalize_cursor(
        value.get("after"),
        allow_none=True,
        expected_source=expected_source,
    )
    if complete:
        if truncated or after is not None:
            raise ValueError("terminal software inventory page is inconsistent")
    elif (
        not truncated
        or after is None
        or returned != requested_page_size
        or returned == 0
    ):
        raise ValueError("non-terminal software inventory page is inconsistent")
    audit = value.get("query_audit")
    policy = SOURCE_POLICY[expected_source]
    if (
        not isinstance(audit, dict)
        or set(audit) != QUERY_AUDIT_KEYS
        or audit.get("index") != policy["index"]
        or audit.get("dataset") != policy["dataset"]
        or not _HEX_64.fullmatch(str(audit.get("query_digest") or ""))
    ):
        raise ValueError("relay response fixed-query audit is invalid")
    normalized_records: List[Dict[str, Any]] = []
    previous_cursor = (
        _normalize_cursor(
            previous_after,
            allow_none=False,
            expected_source=expected_source,
        )
        if previous_after is not None
        else None
    )
    for raw in records:
        record = _normalize_record(
            raw,
            expected_source=expected_source,
            expected_window=window,
        )
        normalized_records.append(record)
    if after is not None:
        # OSQuery cursors contain the indexed hostname, while the public
        # records intentionally contain only a hostname digest.  Therefore a
        # cursor must never be derived from or compared with a public record.
        # It is validated solely as a strictly advancing, transient token.
        if previous_cursor is not None and (
            _cursor_order(after) <= _cursor_order(previous_cursor)
        ):
            raise ValueError("software inventory cursor did not advance")
        if not normalized_records or _cursor_public_identity(
            expected_source,
            after,
        ) != (
            normalized_records[-1]["asset_ref"],
            normalized_records[-1]["product"],
            normalized_records[-1]["version"],
        ):
            raise ValueError(
                "software inventory cursor does not identify the last public record"
            )
    normalized = dict(value)
    normalized["window"] = window
    normalized["after"] = after
    normalized["records"] = normalized_records
    normalized["query_audit"] = {
        "index": policy["index"],
        "dataset": policy["dataset"],
        "query_digest": str(audit["query_digest"]),
    }
    return normalized


def query_page(
    config: Dict[str, Any],
    source: str,
    window: Dict[str, str],
    page_size: int,
    after: Optional[Dict[str, Any]],
    timeout_seconds: float,
) -> Dict[str, Any]:
    """Read one fixed aggregation page through the forced SSH command."""
    request = build_request(source, window, page_size, after)
    command = [
        "/usr/bin/ssh",
        "-T",
        "-o",
        "BatchMode=yes",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={config['known_hosts']}",
        "-o",
        f"ConnectTimeout={config['connect_timeout_seconds']}",
        "-o",
        "ServerAliveInterval=15",
        "-o",
        "ServerAliveCountMax=3",
        "-i",
        str(config["ssh_key"]),
        "-p",
        str(config["port"]),
        f"{config['ssh_user']}@{config['host']}",
    ]
    completed = run_bounded_command(
        command,
        stdin_text=json.dumps(request, separators=(",", ":"), sort_keys=True),
        timeout_seconds=max(1.0, float(timeout_seconds)),
        max_stdout_bytes=config["max_response_bytes"],
        max_stderr_bytes=config["max_stderr_bytes"],
    )
    if completed.returncode != 0:
        detail = relay_failure_diagnostic(completed.stdout, completed.stderr)
        raise SoftwareInventoryError(
            f"software inventory relay returned {completed.returncode}: "
            f"{detail or 'no bounded diagnostic'}"
        )
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise SoftwareInventoryError(
            "software inventory relay returned invalid JSON"
        ) from exc
    return validate_response(
        payload,
        expected_source=source,
        expected_window=request["window"],
        requested_page_size=page_size,
        previous_after=after,
    )


PageFetcher = Callable[
    [
        Dict[str, Any],
        str,
        Dict[str, str],
        int,
        Optional[Dict[str, Any]],
        float,
    ],
    Dict[str, Any],
]


def collect_source(
    config: Dict[str, Any],
    source: str,
    window: Dict[str, str],
    now: dt.datetime,
    deadline: float,
    page_fetcher: PageFetcher = query_page,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    evidence_ids: Set[str] = set()
    cursors: Set[str] = set()
    after: Optional[Dict[str, Any]] = None
    pages = 0
    latest = ""
    try:
        while pages < config["max_pages_per_source"]:
            remaining = deadline - time.monotonic()
            if remaining <= 1:
                raise SoftwareInventoryError(
                    "software inventory collection exceeded its wall-clock budget"
                )
            response = page_fetcher(
                config,
                source,
                window,
                config["page_size"],
                after,
                min(float(config["timeout_seconds"]), remaining),
            )
            # An injected page fetcher used by tests must satisfy the same
            # contract as the transport adapter.
            response = validate_response(
                response,
                expected_source=source,
                expected_window=window,
                requested_page_size=config["page_size"],
                previous_after=after,
            )
            pages += 1
            for record in response["records"]:
                evidence_id = record["evidence_id"]
                if evidence_id in evidence_ids:
                    raise SoftwareInventoryError(
                        "software inventory source repeated an evidence identity"
                    )
                evidence_ids.add(evidence_id)
                records.append(record)
                if not latest or record["last_seen"] > latest:
                    latest = record["last_seen"]
            if len(records) > MAX_TOTAL_RECORDS:
                raise SoftwareInventoryError(
                    "software inventory source exceeded the record limit"
                )
            if response["complete"]:
                return records, _source_status(
                    status="ok",
                    complete=True,
                    pages=pages,
                    returned=len(records),
                    latest=latest,
                    now=now,
                )
            after = response["after"]
            cursor_token = json.dumps(
                after,
                separators=(",", ":"),
                sort_keys=True,
            )
            if cursor_token in cursors:
                raise SoftwareInventoryError(
                    "software inventory relay repeated a pagination cursor"
                )
            cursors.add(cursor_token)
        raise SoftwareInventoryError(
            "software inventory source exceeded its page limit"
        )
    except (
        BoundedProcessError,
        OSError,
        UnicodeError,
        ValueError,
        RuntimeError,
        json.JSONDecodeError,
    ) as exc:
        source_status = _source_status(
            status="failed",
            complete=False,
            pages=pages,
            returned=len(records),
            latest=latest,
            now=now,
        )
        if isinstance(exc, SoftwareInventoryError):
            message = str(exc)
        else:
            message = f"{type(exc).__name__}: {exc}"
        raise SoftwareInventoryError(message, {source: source_status}) from exc


def collect_snapshot(
    config: Dict[str, Any],
    previous_state: Dict[str, Any],
    now: dt.datetime,
    page_fetcher: PageFetcher = query_page,
) -> Dict[str, Any]:
    del previous_state  # A complete collection is a replacement, not a merge.
    window = collection_window(now)
    deadline = time.monotonic() + config["max_collection_seconds"]
    statuses = {
        source: _empty_source_status()
        for source in SOURCES
    }
    records: List[Dict[str, Any]] = []
    evidence_ids: Set[str] = set()
    for source in SOURCES:
        try:
            source_records, source_status = collect_source(
                config,
                source,
                window,
                now,
                deadline,
                page_fetcher=page_fetcher,
            )
        except SoftwareInventoryError as exc:
            if exc.source_statuses:
                statuses.update(exc.source_statuses)
            raise SoftwareInventoryError(str(exc), statuses) from exc
        statuses[source] = source_status
        for record in source_records:
            if record["evidence_id"] in evidence_ids:
                raise SoftwareInventoryError(
                    "software inventory snapshot repeated an evidence identity",
                    statuses,
                )
            evidence_ids.add(record["evidence_id"])
            records.append(record)
            if len(records) > MAX_TOTAL_RECORDS:
                raise SoftwareInventoryError(
                    "software inventory snapshot exceeded the record limit",
                    statuses,
                )
    records.sort(
        key=lambda item: (
            item["asset_ref"].casefold(),
            item["product"].casefold(),
            item["version"].casefold(),
            item["source"],
            item["evidence_id"],
        )
    )
    stamp = format_timestamp(now)
    return validate_state(
        {
            "schema": STATE_SCHEMA,
            "version": 1,
            "updated_at": stamp,
            "collection": {
                "status": "ok",
                "last_attempt_at": stamp,
                "last_success_at": stamp,
                "last_error": "",
                "window": window,
                "source_statuses": statuses,
                "complete": True,
            },
            "records": records,
        }
    )


def failed_state(
    previous_state: Dict[str, Any],
    now: dt.datetime,
    error: str,
    source_statuses: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    previous = validate_state(previous_state)
    prior_collection = previous["collection"]
    has_snapshot = bool(
        previous["updated_at"]
        and prior_collection["last_success_at"]
        and previous["updated_at"] == prior_collection["last_success_at"]
        and prior_collection["window"]
    )
    statuses = {
        source: _empty_source_status()
        for source in SOURCES
    }
    if source_statuses:
        for source in SOURCES:
            if source in source_statuses:
                statuses[source] = source_statuses[source]
    stamp = format_timestamp(now)
    return validate_state(
        {
            "schema": STATE_SCHEMA,
            "version": 1,
            "updated_at": previous["updated_at"] if has_snapshot else stamp,
            "collection": {
                "status": "failed",
                "last_attempt_at": stamp,
                "last_success_at": (
                    str(prior_collection["last_success_at"])
                    if has_snapshot
                    else ""
                ),
                "last_error": " ".join(str(error).split())[:500],
                "window": (
                    dict(prior_collection["window"])
                    if has_snapshot
                    else collection_window(now)
                ),
                "source_statuses": statuses,
                "complete": False,
            },
            "records": list(previous["records"]) if has_snapshot else [],
        }
    )


def disabled_state(
    previous_state: Dict[str, Any],
    now: dt.datetime,
) -> Dict[str, Any]:
    previous = validate_state(previous_state)
    prior_collection = previous["collection"]
    has_snapshot = bool(
        previous["updated_at"]
        and prior_collection["last_success_at"]
        and previous["updated_at"] == prior_collection["last_success_at"]
        and prior_collection["window"]
    )
    stamp = format_timestamp(now)
    return validate_state(
        {
            "schema": STATE_SCHEMA,
            "version": 1,
            "updated_at": previous["updated_at"] if has_snapshot else stamp,
            "collection": {
                "status": "disabled",
                "last_attempt_at": stamp,
                "last_success_at": (
                    str(prior_collection["last_success_at"])
                    if has_snapshot
                    else ""
                ),
                "last_error": "",
                "window": (
                    dict(prior_collection["window"])
                    if has_snapshot
                    else collection_window(now)
                ),
                "source_statuses": {
                    source: _empty_source_status("disabled")
                    for source in SOURCES
                },
                "complete": False,
            },
            "records": list(previous["records"]) if has_snapshot else [],
        }
    )


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--state", type=Path, default=DEFAULT_STATE)
    parser.add_argument("--log", type=Path, default=DEFAULT_LOG)
    args = parser.parse_args(argv)
    logger = SecurityJsonlLogger(args.log, service="software-inventory")
    attempted_at = utc_now()
    previous: Optional[Dict[str, Any]] = None
    try:
        with collector_lock(args.state):
            previous = load_state(args.state)
            config = load_config(args.config)
            if not config["enabled"]:
                updated = disabled_state(previous, attempted_at)
                atomic_write_json(args.state, updated)
                logger.log(
                    "info",
                    "software_inventory.disabled",
                    retained=len(updated["records"]),
                )
                return 0
            updated = collect_snapshot(config, previous, attempted_at)
            atomic_write_json(args.state, updated)
            logger.log(
                "info",
                "software_inventory.completed",
                returned=len(updated["records"]),
                source_statuses=updated["collection"]["source_statuses"],
            )
            return 0
    except (
        BoundedProcessError,
        OSError,
        UnicodeError,
        ValueError,
        RuntimeError,
        json.JSONDecodeError,
    ) as exc:
        message = " ".join(str(exc).split())[:500]
        statuses = (
            exc.source_statuses
            if isinstance(exc, SoftwareInventoryError)
            else None
        )
        if previous is not None:
            try:
                updated = failed_state(
                    previous,
                    attempted_at,
                    message,
                    statuses,
                )
                atomic_write_json(args.state, updated)
            except (OSError, UnicodeError, ValueError, RuntimeError):
                pass
        logger.log(
            "error",
            "software_inventory.failed",
            error=message,
            retained=len(previous["records"]) if previous else 0,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
