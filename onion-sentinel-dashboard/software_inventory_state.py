#!/usr/bin/env python3
"""Bounded, provenance-aware Software Inventory state reader.

The public dashboard reads a collector-produced, last-known-good snapshot. It
never accepts query language or dispatches work to Security Onion from a web
request.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import json
import os
import re
import stat
from pathlib import Path
from typing import Any


STATE_SCHEMA = "onion-sentinel-software-inventory-state-v1"
API_SCHEMA = "onion-sentinel-software-inventory-api-v1"
MAX_STATE_BYTES = 256 * 1024 * 1024
MAX_RECORDS = 250_000
MAX_OFFSET = 50_000
MAX_LIMIT = 250
DEFAULT_LIMIT = 100
ASSET_LABEL_PAGE_SIZE = 500
ASSET_LABEL_MAX_PAGES = 10
ASSET_LABEL_MAX_RECORDS = ASSET_LABEL_PAGE_SIZE * ASSET_LABEL_MAX_PAGES
SOURCES = {
    "osquery_apps": ("installed", "high"),
    "zeek_software": ("observed", "medium"),
    "http_user_agent": ("inferred", "low"),
}
SOURCE_DATASETS = {
    "osquery_apps": {"osquery_manager.result", "osquery.live.software_inventory"},
    "zeek_software": {"zeek.software"},
    "http_user_agent": {"zeek.http"},
}
ENDPOINT_OS_SOURCES = {
    "osquery_manager.result:host.os",
    "osquery.live:os_version",
}
ASSET_OS_ASSOCIATION = "asset_inventory:unique-host-static-ip"
LAN_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "fc00::/7",
    )
)
TIERS = frozenset({"installed", "observed", "inferred"})
CONFIDENCES = frozenset({"high", "medium", "low"})
FRESHNESS_VALUES = frozenset(
    {"current", "recent", "historical", "expired"}
)
WINDOWS = {
    "24h": dt.timedelta(hours=24),
    "7d": dt.timedelta(days=7),
    "30d": dt.timedelta(days=30),
}
SORT_FIELDS = frozenset(
    {"last_seen", "first_seen", "product", "asset", "tier", "confidence"}
)
EVIDENCE_ID_RE = re.compile(r"[0-9a-f]{24}")
SAFE_ASSET_REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@-]{0,252}")
AGENT_UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}",
    re.IGNORECASE,
)


class InventoryStateError(ValueError):
    """Raised when the local last-known-good state is unavailable or invalid."""


class InventoryQueryError(ValueError):
    """Raised when a public API filter is outside the fixed query contract."""


def _utc_iso(value: dt.datetime) -> str:
    if value.tzinfo is None:
        raise InventoryStateError("timestamp lacks a UTC offset")
    return (
        value.astimezone(dt.timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def _parse_timestamp(value: object, field: str) -> dt.datetime:
    raw = str(value or "").strip()
    if not raw or len(raw) > 64:
        raise InventoryStateError(f"{field} is missing or too long")
    cleaned = raw.replace("  ", "T", 1).replace("Z", "+00:00")
    try:
        parsed = dt.datetime.fromisoformat(cleaned)
    except ValueError as exc:
        raise InventoryStateError(f"{field} is not ISO 8601") from exc
    if parsed.tzinfo is None:
        raise InventoryStateError(f"{field} lacks a UTC offset")
    return parsed.astimezone(dt.timezone.utc)


def _safe_text(
    value: object,
    field: str,
    *,
    maximum: int,
    required: bool = False,
) -> str:
    text = str(value or "").strip()
    if required and not text:
        raise InventoryStateError(f"{field} is required")
    if len(text) > maximum or any(ord(char) < 32 for char in text):
        raise InventoryStateError(f"{field} is invalid")
    return text


def _read_bounded_regular_json(path: Path, maximum_bytes: int) -> tuple[dict, str]:
    """Read one owner-controlled regular file without following symlinks."""
    try:
        before = path.lstat()
    except FileNotFoundError as exc:
        raise InventoryStateError("Software Inventory has not been collected yet") from exc
    except OSError as exc:
        raise InventoryStateError("Software Inventory state is unavailable") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise InventoryStateError("Software Inventory state is not a regular file")
    if before.st_uid != os.getuid():
        raise InventoryStateError("Software Inventory state has an unexpected owner")
    if before.st_mode & 0o022:
        raise InventoryStateError("Software Inventory state is writable by another user")
    if before.st_size <= 0 or before.st_size > maximum_bytes:
        raise InventoryStateError("Software Inventory state exceeds its size boundary")

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(str(path), flags)
        try:
            opened = os.fstat(descriptor)
            if (
                opened.st_dev != before.st_dev
                or opened.st_ino != before.st_ino
                or not stat.S_ISREG(opened.st_mode)
                or opened.st_size != before.st_size
            ):
                raise InventoryStateError("Software Inventory state changed while opening")
            chunks: list[bytes] = []
            remaining = maximum_bytes + 1
            while remaining > 0:
                chunk = os.read(descriptor, min(1024 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
        finally:
            os.close(descriptor)
    except InventoryStateError:
        raise
    except OSError as exc:
        raise InventoryStateError("Software Inventory state could not be read") from exc
    if len(raw) > maximum_bytes:
        raise InventoryStateError("Software Inventory state exceeds its size boundary")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InventoryStateError("Software Inventory state is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise InventoryStateError("Software Inventory state must be an object")
    return payload, hashlib.sha256(raw).hexdigest()


def _sanitize_source_statuses(raw: object) -> dict[str, dict[str, object]]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise InventoryStateError("collection.source_statuses must be an object")
    result: dict[str, dict[str, object]] = {}
    for source in SOURCES:
        item = raw.get(source)
        if item is None:
            continue
        if isinstance(item, str):
            result[source] = {
                "status": _safe_text(
                    item, f"source_statuses.{source}.status", maximum=32
                )
            }
            continue
        if not isinstance(item, dict):
            raise InventoryStateError(
                f"collection.source_statuses.{source} must be an object"
            )
        status = {
            "status": _safe_text(
                item.get("status"),
                f"source_statuses.{source}.status",
                maximum=32,
            )
        }
        if "complete" in item:
            if not isinstance(item.get("complete"), bool):
                raise InventoryStateError(
                    f"collection.source_statuses.{source}.complete must be boolean"
                )
            status["complete"] = item["complete"]
        for key in ("records", "returned", "pages"):
            if key not in item:
                continue
            value = item.get(key)
            if isinstance(value, bool) or not isinstance(value, int):
                raise InventoryStateError(
                    f"collection.source_statuses.{source}.{key} must be an integer"
                )
            status[key] = max(0, min(value, MAX_RECORDS))
        freshness = _safe_text(
            item.get("freshness"),
            f"source_statuses.{source}.freshness",
            maximum=16,
        )
        if freshness:
            if freshness not in {
                "unknown",
                "empty",
                "fresh",
                "stale",
                "expired",
            }:
                raise InventoryStateError(
                    f"collection.source_statuses.{source}.freshness is invalid"
                )
            status["freshness"] = freshness
        latest = item.get("latest_observation_at")
        if latest:
            status["latest_observation_at"] = _utc_iso(
                _parse_timestamp(
                    latest,
                    f"source_statuses.{source}.latest_observation_at",
                )
            )
        error = _safe_text(
            item.get("error"),
            f"source_statuses.{source}.error",
            maximum=300,
        )
        if error:
            status["error"] = error
        result[source] = status
    return result


def _sanitize_collection(raw: object, updated_at: str) -> dict[str, object]:
    if not isinstance(raw, dict):
        raise InventoryStateError("collection must be an object")
    status = _safe_text(raw.get("status"), "collection.status", maximum=32)
    if not isinstance(raw.get("complete"), bool):
        raise InventoryStateError("collection.complete must be boolean")
    raw_window = raw.get("window")
    if not isinstance(raw_window, dict) or set(raw_window) != {"start", "end"}:
        raise InventoryStateError(
            "collection.window must contain only start and end"
        )
    window_start = _parse_timestamp(
        raw_window.get("start"), "collection.window.start"
    )
    window_end = _parse_timestamp(
        raw_window.get("end"), "collection.window.end"
    )
    if (
        window_start >= window_end
        or window_end - window_start > dt.timedelta(days=31)
    ):
        raise InventoryStateError("collection.window is out of bounds")
    result: dict[str, object] = {
        "status": status or "unknown",
        "complete": raw["complete"],
        "window": {
            "start": _utc_iso(window_start),
            "end": _utc_iso(window_end),
        },
        "last_attempt_at": "",
        "last_success_at": "",
        "last_error": _safe_text(
            raw.get("last_error"), "collection.last_error", maximum=500
        ),
        "source_statuses": _sanitize_source_statuses(
            raw.get("source_statuses")
        ),
    }
    if "osquery_ready" in raw:
        osquery_ready = raw.get("osquery_ready")
        if (
            isinstance(osquery_ready, bool)
            or not isinstance(osquery_ready, int)
            or osquery_ready < 0
            or osquery_ready > MAX_RECORDS
        ):
            raise InventoryStateError("collection.osquery_ready is invalid")
        result["osquery_ready"] = osquery_ready
    for key in ("last_attempt_at", "last_success_at"):
        if raw.get(key):
            result[key] = _utc_iso(_parse_timestamp(raw.get(key), key))
    if not result["last_success_at"] and result["complete"]:
        result["last_success_at"] = updated_at
    return result


def _record_identity(
    raw: dict[str, object],
) -> tuple[str, str, str, str]:
    evidence_id = _safe_text(
        raw.get("evidence_id"), "evidence_id", maximum=24, required=True
    ).lower()
    if not EVIDENCE_ID_RE.fullmatch(evidence_id):
        raise InventoryStateError("evidence_id must be 24 lowercase hex characters")
    source = _safe_text(
        raw.get("source"), "source", maximum=32, required=True
    ).lower()
    if source not in SOURCES:
        raise InventoryStateError("record source is unsupported")
    expected_tier, expected_confidence = SOURCES[source]
    tier = _safe_text(raw.get("tier"), "tier", maximum=16, required=True).lower()
    confidence = _safe_text(
        raw.get("confidence"), "confidence", maximum=16, required=True
    ).lower()
    if tier != expected_tier or confidence != expected_confidence:
        raise InventoryStateError("record provenance does not match its source")
    return evidence_id, source, tier, confidence


def _canonical_passive_asset_ref(asset_ref: str) -> None:
    if AGENT_UUID_RE.fullmatch(asset_ref):
        raise InventoryStateError("raw endpoint identifiers are not public")
    try:
        address = ipaddress.ip_address(asset_ref)
    except ValueError as exc:
        raise InventoryStateError(
            "passive asset_ref must be an IP address"
        ) from exc
    if str(address) != asset_ref or not any(
        address in network for network in LAN_NETWORKS
    ):
        raise InventoryStateError(
            "passive asset_ref is not a canonical LAN IP"
        )


def _record_asset_reference(
    raw: dict[str, object], source: str
) -> tuple[str, str]:
    asset_ref_type = _safe_text(
        raw.get("asset_ref_type"),
        "asset_ref_type",
        maximum=8,
        required=True,
    ).lower()
    expected_ref_type = "host" if source == "osquery_apps" else "ip"
    if asset_ref_type != expected_ref_type:
        raise InventoryStateError("asset_ref_type does not match its source")
    asset_ref = _safe_text(
        raw.get("asset_ref"), "asset_ref", maximum=253, required=True
    )
    if not SAFE_ASSET_REF_RE.fullmatch(asset_ref):
        raise InventoryStateError("asset_ref is invalid")
    if source == "osquery_apps":
        if not EVIDENCE_ID_RE.fullmatch(asset_ref.lower()):
            raise InventoryStateError(
                "OSQuery asset references must be pseudonymous identifiers"
            )
    else:
        _canonical_passive_asset_ref(asset_ref)
    return asset_ref_type, asset_ref


def _record_observation(
    raw: dict[str, object],
) -> tuple[dt.datetime, dt.datetime, int]:
    first_seen = _parse_timestamp(raw.get("first_seen"), "first_seen")
    last_seen = _parse_timestamp(raw.get("last_seen"), "last_seen")
    if first_seen > last_seen:
        raise InventoryStateError("first_seen is after last_seen")
    observation_count = raw.get("observation_count")
    if (
        isinstance(observation_count, bool)
        or not isinstance(observation_count, int)
        or observation_count < 1
        or observation_count > 2_147_483_647
    ):
        raise InventoryStateError("observation_count is invalid")
    return first_seen, last_seen, observation_count


def _record_dataset_version(
    raw: dict[str, object], source: str
) -> tuple[str, str]:
    source_dataset = _safe_text(
        raw.get("source_dataset"),
        "source_dataset",
        maximum=160,
        required=True,
    )
    if source_dataset not in SOURCE_DATASETS[source]:
        raise InventoryStateError("source_dataset does not match its source")
    version = _safe_text(raw.get("version"), "version", maximum=1024)
    if source == "http_user_agent" and version:
        raise InventoryStateError("HTTP User-Agent evidence cannot invent a version")
    return source_dataset, version


def _validate_endpoint_operating_system(
    os_present: bool,
    source: str,
    confidence: str,
) -> None:
    if os_present and (
        source not in ENDPOINT_OS_SOURCES or confidence != "high"
    ):
        raise InventoryStateError(
            "endpoint operating-system provenance is invalid"
        )
    if not os_present and (source or confidence):
        raise InventoryStateError(
            "empty endpoint operating-system evidence claims provenance"
        )


def _validate_passive_operating_system(values: tuple[str, ...]) -> None:
    if any(values):
        raise InventoryStateError(
            "passive software evidence cannot assert an exact operating system"
        )


def _record_operating_system(
    raw: dict[str, object], source: str
) -> tuple[str, str, str, str]:
    operating_system_type = _safe_text(
        raw.get("operating_system_type"),
        "operating_system_type",
        maximum=160,
    )
    operating_system_version = _safe_text(
        raw.get("operating_system_version"),
        "operating_system_version",
        maximum=512,
    )
    operating_system_source = _safe_text(
        raw.get("operating_system_source"),
        "operating_system_source",
        maximum=128,
    )
    operating_system_confidence = _safe_text(
        raw.get("operating_system_confidence"),
        "operating_system_confidence",
        maximum=16,
    ).lower()
    os_present = bool(operating_system_type or operating_system_version)
    if operating_system_confidence not in {"", "low", "medium", "high"}:
        raise InventoryStateError(
            "operating_system_confidence is unsupported"
        )
    if source == "osquery_apps":
        _validate_endpoint_operating_system(
            os_present,
            operating_system_source,
            operating_system_confidence,
        )
    else:
        _validate_passive_operating_system(
            (
                operating_system_type,
                operating_system_version,
                operating_system_source,
                operating_system_confidence,
            )
        )
    return (
        operating_system_type,
        operating_system_version,
        operating_system_source,
        operating_system_confidence,
    )


def _sanitize_record(raw: object) -> dict[str, object]:
    if not isinstance(raw, dict):
        raise InventoryStateError("records must contain objects")
    evidence_id, source, tier, confidence = _record_identity(raw)
    asset_ref_type, asset_ref = _record_asset_reference(raw, source)
    first_seen, last_seen, observation_count = _record_observation(raw)
    source_dataset, version = _record_dataset_version(raw, source)
    (
        operating_system_type,
        operating_system_version,
        operating_system_source,
        operating_system_confidence,
    ) = _record_operating_system(raw, source)
    return {
        "evidence_id": evidence_id,
        "source": source,
        "source_dataset": source_dataset,
        "tier": tier,
        "confidence": confidence,
        "asset_ref_type": asset_ref_type,
        "asset_ref": asset_ref,
        "platform": _safe_text(
            raw.get("platform"), "platform", maximum=160
        ),
        "operating_system_type": operating_system_type,
        "operating_system_version": operating_system_version,
        "operating_system_source": operating_system_source,
        "operating_system_confidence": operating_system_confidence,
        "product": _safe_text(
            raw.get("product"), "product", maximum=4096, required=True
        ),
        "version": version,
        "category": _safe_text(
            raw.get("category"), "category", maximum=256
        ),
        "first_seen": _utc_iso(first_seen),
        "last_seen": _utc_iso(last_seen),
        "observation_count": observation_count,
        "_first_seen": first_seen,
        "_last_seen": last_seen,
    }


def load_state(
    path: Path,
    *,
    maximum_bytes: int = MAX_STATE_BYTES,
) -> tuple[dict[str, object], str]:
    raw, revision = _read_bounded_regular_json(path, maximum_bytes)
    if raw.get("schema") != STATE_SCHEMA or raw.get("version") != 1:
        raise InventoryStateError("Software Inventory state schema is unsupported")
    updated_at = _utc_iso(_parse_timestamp(raw.get("updated_at"), "updated_at"))
    records = raw.get("records")
    if not isinstance(records, list):
        raise InventoryStateError("records must be an array")
    if len(records) > MAX_RECORDS:
        raise InventoryStateError("Software Inventory has too many records")
    sanitized = [_sanitize_record(item) for item in records]
    evidence_ids = [str(item["evidence_id"]) for item in sanitized]
    if len(evidence_ids) != len(set(evidence_ids)):
        raise InventoryStateError("Software Inventory contains duplicate evidence IDs")
    return {
        "schema": STATE_SCHEMA,
        "version": 1,
        "updated_at": updated_at,
        "collection": _sanitize_collection(raw.get("collection"), updated_at),
        "records": sanitized,
    }, revision
