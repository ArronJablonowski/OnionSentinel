#!/usr/bin/env python3
"""Fail-closed Software Inventory contracts for the incident evidence broker."""
from __future__ import annotations

import datetime as dt
import ipaddress
import re


SOFTWARE_INVENTORY_CONTRACT = "onion-sentinel-software-inventory-v1"
SOFTWARE_INVENTORY_OPERATION = "software_observations"
SOFTWARE_INVENTORY_SOURCES = {
    "osquery_apps": {
        "index": "logs-osquery_manager.result-default",
        "dataset": "osquery_manager.result",
        "tier": "installed",
        "confidence": "high",
        "asset_ref_type": "host",
        "platform": "darwin",
    },
    "zeek_software": {
        "index": "logs-zeek-so",
        "dataset": "zeek.software",
        "tier": "observed",
        "confidence": "medium",
        "asset_ref_type": "ip",
        "platform": "",
    },
    "http_user_agent": {
        "index": "logs-zeek-so",
        "dataset": "zeek.http",
        "tier": "inferred",
        "confidence": "low",
        "asset_ref_type": "ip",
        "platform": "",
    },
}
SOFTWARE_CURSOR_KEYS = {"asset", "product", "version"}
SOFTWARE_RESPONSE_KEYS = {
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
SOFTWARE_RECORD_KEYS = {
    "evidence_id",
    "source",
    "source_dataset",
    "tier",
    "confidence",
    "asset_ref_type",
    "asset_ref",
    "platform",
    "product",
    "version",
    "category",
    "first_seen",
    "last_seen",
    "observation_count",
}
SOFTWARE_OS_RECORD_KEYS = SOFTWARE_RECORD_KEYS | {
    "operating_system_type",
    "operating_system_version",
    "operating_system_source",
    "operating_system_confidence",
}
SOFTWARE_RECORD_KEY_SETS = {
    frozenset(SOFTWARE_RECORD_KEYS),
    frozenset(SOFTWARE_OS_RECORD_KEYS),
}
SOFTWARE_TEXT_LIMITS = {
    "asset": 512,
    "product": 4096,
    "version": 1024,
    "platform": 160,
    "category": 256,
    "operating_system_type": 160,
    "operating_system_version": 512,
    "operating_system_source": 128,
    "operating_system_confidence": 16,
}
SOFTWARE_LAN_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "fc00::/7",
    )
)
HEX_24_RE = re.compile(r"[0-9a-f]{24}")
HEX_64_RE = re.compile(r"[0-9a-f]{64}")
UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
    re.IGNORECASE,
)

__all__ = [
    "SOFTWARE_CURSOR_KEYS",
    "SOFTWARE_INVENTORY_CONTRACT",
    "SOFTWARE_INVENTORY_OPERATION",
    "SOFTWARE_INVENTORY_SOURCES",
    "SOFTWARE_LAN_NETWORKS",
    "SOFTWARE_OS_RECORD_KEYS",
    "SOFTWARE_RECORD_KEYS",
    "SOFTWARE_RECORD_KEY_SETS",
    "SOFTWARE_RESPONSE_KEYS",
    "SOFTWARE_TEXT_LIMITS",
    "validate_software_cursor",
    "validate_software_request",
    "validate_software_response",
]


def _parse_timestamp(value: object) -> dt.datetime:
    parsed = dt.datetime.fromisoformat(
        str(value or "").strip().replace("Z", "+00:00")
    )
    if parsed.tzinfo is None:
        raise ValueError("timestamp lacks offset")
    return parsed.astimezone(dt.timezone.utc)


def _software_text(
    value: object,
    maximum_bytes: int,
    *,
    field: str,
    allow_empty: bool = False,
) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    if value != value.strip() or any(
        not character.isprintable() for character in value
    ):
        raise ValueError(
            f"{field} contains invalid whitespace or control characters"
        )
    if not value and not allow_empty:
        raise ValueError(f"{field} must not be empty")
    if len(value.encode("utf-8")) > maximum_bytes:
        raise ValueError(f"{field} exceeds its byte limit")
    return value


def validate_software_cursor(
    value: object,
    source: str | None = None,
) -> dict | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != SOFTWARE_CURSOR_KEYS:
        raise ValueError(
            "software cursor must be null or contain asset, product, and version"
        )
    cursor = {
        "asset": _software_text(
            value["asset"],
            SOFTWARE_TEXT_LIMITS["asset"],
            field="after.asset",
        ),
        "product": _software_text(
            value["product"],
            SOFTWARE_TEXT_LIMITS["product"],
            field="after.product",
        ),
        "version": None,
    }
    if value["version"] is not None:
        cursor["version"] = _software_text(
            value["version"],
            SOFTWARE_TEXT_LIMITS["version"],
            field="after.version",
            allow_empty=True,
        )
    if source == "osquery_apps" and UUID_RE.fullmatch(cursor["asset"]):
        raise ValueError("software cursor host must not be UUID-shaped")
    return cursor


def _validate_request_identity(request: object) -> dict:
    expected = {
        "contract",
        "operation",
        "source",
        "window",
        "page_size",
        "after",
    }
    if not isinstance(request, dict) or set(request) != expected:
        raise ValueError(
            "request fields do not match the software inventory contract"
        )
    if (
        request["contract"] != SOFTWARE_INVENTORY_CONTRACT
        or request["operation"] != SOFTWARE_INVENTORY_OPERATION
    ):
        raise ValueError("unsupported software inventory operation")
    if (
        not isinstance(request["source"], str)
        or request["source"] not in SOFTWARE_INVENTORY_SOURCES
    ):
        raise ValueError("software inventory source is not allowed")
    return request


def _validate_request_window(request: dict) -> None:
    window = request["window"]
    if not isinstance(window, dict) or set(window) != {"start", "end"}:
        raise ValueError("invalid software inventory window")
    start = _parse_timestamp(window["start"])
    end = _parse_timestamp(window["end"])
    if start >= end or end - start > dt.timedelta(days=31):
        raise ValueError(
            "software inventory window must be positive and no longer than 31 days"
        )
    if end > dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5):
        raise ValueError("software inventory window ends too far in the future")


def _validate_request_page(request: dict) -> None:
    page_size = request["page_size"]
    if (
        isinstance(page_size, bool)
        or not isinstance(page_size, int)
        or not 1 <= page_size <= 500
    ):
        raise ValueError(
            "software inventory page_size must be from 1 through 500"
        )
    validate_software_cursor(request["after"], request["source"])


def validate_software_request(request: object) -> None:
    admitted = _validate_request_identity(request)
    _validate_request_window(admitted)
    _validate_request_page(admitted)


def _validate_record_identity(
    record: dict,
    source: str,
    expected: dict,
) -> None:
    if (
        record["source"] != source
        or record["source_dataset"] != expected["dataset"]
        or record["tier"] != expected["tier"]
        or record["confidence"] != expected["confidence"]
        or record["asset_ref_type"] != expected["asset_ref_type"]
        or record["platform"] != expected["platform"]
    ):
        raise ValueError(
            "software inventory record semantics failed validation"
        )
    if not isinstance(record["evidence_id"], str) or not HEX_24_RE.fullmatch(
        record["evidence_id"]
    ):
        raise ValueError("software inventory evidence_id failed validation")


def _validate_asset_reference(record: dict, expected: dict) -> None:
    asset_ref = record["asset_ref"]
    if expected["asset_ref_type"] == "host":
        if not isinstance(asset_ref, str) or not HEX_24_RE.fullmatch(asset_ref):
            raise ValueError(
                "software inventory host reference failed validation"
            )
        return
    if not isinstance(asset_ref, str):
        raise ValueError("software inventory IP reference failed validation")
    try:
        address = ipaddress.ip_address(asset_ref)
    except ValueError as exc:
        raise ValueError(
            "software inventory IP reference failed validation"
        ) from exc
    if str(address) != asset_ref or not any(
        address in network for network in SOFTWARE_LAN_NETWORKS
    ):
        raise ValueError("software inventory IP reference failed validation")


def _validate_record_text(record: dict) -> None:
    for field in ("product", "platform", "version", "category"):
        _software_text(
            record[field],
            SOFTWARE_TEXT_LIMITS[field],
            field=f"record.{field}",
            allow_empty=field != "product",
        )


def _validate_operating_system(record: dict, source: str) -> None:
    if set(record) != SOFTWARE_OS_RECORD_KEYS:
        return
    fields = (
        "operating_system_type",
        "operating_system_version",
        "operating_system_source",
        "operating_system_confidence",
    )
    for field in fields:
        _software_text(
            record[field],
            SOFTWARE_TEXT_LIMITS[field],
            field=f"record.{field}",
            allow_empty=True,
        )
    os_present = bool(
        record["operating_system_type"]
        or record["operating_system_version"]
    )
    if source == "osquery_apps":
        if os_present and (
            record["operating_system_source"]
            != "osquery_manager.result:host.os"
            or record["operating_system_confidence"] != "high"
        ):
            raise ValueError(
                "endpoint operating-system provenance failed validation"
            )
        if not os_present and (
            record["operating_system_source"]
            or record["operating_system_confidence"]
        ):
            raise ValueError(
                "empty endpoint operating-system evidence claims provenance"
            )
    elif any(record[field] for field in fields):
        raise ValueError(
            "passive software evidence cannot assert an exact operating system"
        )


def _validate_record_observations(
    record: dict,
    start: dt.datetime,
    end: dt.datetime,
) -> None:
    first_seen = _parse_timestamp(record["first_seen"])
    last_seen = _parse_timestamp(record["last_seen"])
    if first_seen > last_seen or first_seen < start or last_seen >= end:
        raise ValueError(
            "software inventory record timestamps failed validation"
        )
    count = record["observation_count"]
    if isinstance(count, bool) or not isinstance(count, int) or count < 1:
        raise ValueError(
            "software inventory observation_count failed validation"
        )


def _validate_software_record(
    record: object,
    *,
    source: str,
    start: dt.datetime,
    end: dt.datetime,
) -> None:
    if (
        not isinstance(record, dict)
        or frozenset(record) not in SOFTWARE_RECORD_KEY_SETS
    ):
        raise ValueError(
            "software inventory record fields failed validation"
        )
    expected = SOFTWARE_INVENTORY_SOURCES[source]
    _validate_record_identity(record, source, expected)
    _validate_asset_reference(record, expected)
    _validate_record_text(record)
    _validate_operating_system(record, source)
    _validate_record_observations(record, start, end)


def _validate_response_identity(response: object, request: dict) -> tuple[dict, str, dict]:
    if not isinstance(response, dict) or set(response) != SOFTWARE_RESPONSE_KEYS:
        raise ValueError(
            "software inventory response fields failed validation"
        )
    source = request["source"]
    expected = SOFTWARE_INVENTORY_SOURCES[source]
    if (
        response["ok"] is not True
        or response["contract"] != SOFTWARE_INVENTORY_CONTRACT
        or response["read_only"] is not True
        or response["source"] != source
    ):
        raise ValueError(
            "software inventory response identity failed validation"
        )
    return response, source, expected


def _validate_response_window(
    response: dict,
    request: dict,
) -> tuple[dt.datetime, dt.datetime]:
    window = response["window"]
    if not isinstance(window, dict) or set(window) != {"start", "end"}:
        raise ValueError(
            "software inventory response window failed validation"
        )
    start = _parse_timestamp(window["start"])
    end = _parse_timestamp(window["end"])
    request_start = _parse_timestamp(request["window"]["start"])
    request_end = _parse_timestamp(request["window"]["end"])
    if start != request_start or end != request_end:
        raise ValueError(
            "software inventory response window changed in transit"
        )
    return start, end


def _validate_response_page(
    response: dict,
    request: dict,
    source: str,
    start: dt.datetime,
    end: dt.datetime,
) -> None:
    records = response["records"]
    returned = response["returned"]
    if (
        not isinstance(records, list)
        or isinstance(returned, bool)
        or not isinstance(returned, int)
        or returned != len(records)
        or not 0 <= returned <= request["page_size"]
    ):
        raise ValueError(
            "software inventory response count failed validation"
        )
    if (
        not isinstance(response["complete"], bool)
        or not isinstance(response["truncated"], bool)
        or response["complete"] == response["truncated"]
    ):
        raise ValueError(
            "software inventory pagination state failed validation"
        )
    cursor = validate_software_cursor(response["after"], source)
    if response["complete"] and cursor is not None:
        raise ValueError(
            "complete software inventory response retained a cursor"
        )
    if response["truncated"] and (cursor is None or returned < 1):
        raise ValueError(
            "truncated software inventory response omitted its cursor"
        )
    for record in records:
        _validate_software_record(
            record,
            source=source,
            start=start,
            end=end,
        )


def _validate_query_audit(audit: object, expected: dict) -> None:
    if not isinstance(audit, dict) or set(audit) != {
        "index",
        "dataset",
        "query_digest",
    }:
        raise ValueError(
            "software inventory query audit fields failed validation"
        )
    if (
        audit["index"] != expected["index"]
        or audit["dataset"] != expected["dataset"]
    ):
        raise ValueError(
            "software inventory query audit scope failed validation"
        )
    if not isinstance(audit["query_digest"], str) or not HEX_64_RE.fullmatch(
        audit["query_digest"]
    ):
        raise ValueError(
            "software inventory query digest failed validation"
        )


def validate_software_response(response: object, request: dict) -> None:
    admitted, source, expected = _validate_response_identity(response, request)
    start, end = _validate_response_window(admitted, request)
    _validate_response_page(admitted, request, source, start, end)
    _validate_query_audit(admitted["query_audit"], expected)
