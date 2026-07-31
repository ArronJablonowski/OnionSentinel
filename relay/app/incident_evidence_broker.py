#!/usr/bin/env python3
"""Forced-command relay for bounded Security Onion incident evidence.

The Mac Studio can send only the wrapper's JSON protocol.  This broker never
interprets SSH_ORIGINAL_COMMAND and never exposes a relay or Security Onion
shell, forwarding, arbitrary paths, or arbitrary Elasticsearch queries.
"""
from __future__ import annotations

import json
import os
import sys
import datetime as dt
import ipaddress
import re
from pathlib import Path

from process_io import BoundedProcessError, run_bounded_command


MAX_REQUEST_BYTES = 16 * 1024
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_ERROR_FIELD_BYTES = 500
DEFAULT_CONFIG = Path("/etc/so-alert-relay/incident-evidence.json")
DHCP_DISCOVERY_CONTRACT = "onion-sentinel-dhcp-asset-discovery-v1"
DHCP_DISCOVERY_OPERATION = "dhcp_observations"
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
    for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
)
HEX_24_RE = re.compile(r"[0-9a-f]{24}")
HEX_64_RE = re.compile(r"[0-9a-f]{64}")
UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
    re.IGNORECASE,
)


def _parse_dhcp_timestamp(value: object) -> dt.datetime:
    parsed = dt.datetime.fromisoformat(str(value or "").strip().replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp lacks offset")
    return parsed.astimezone(dt.timezone.utc)


def validate_dhcp_request(request: object) -> None:
    if not isinstance(request, dict) or set(request) != {"contract", "operation", "window", "size"}:
        raise ValueError("request fields do not match the DHCP discovery contract")
    if request["contract"] != DHCP_DISCOVERY_CONTRACT or request["operation"] != DHCP_DISCOVERY_OPERATION:
        raise ValueError("unsupported DHCP discovery operation")
    window = request["window"]
    if not isinstance(window, dict) or set(window) != {"start", "end"}:
        raise ValueError("invalid DHCP discovery window")
    start = _parse_dhcp_timestamp(window["start"])
    end = _parse_dhcp_timestamp(window["end"])
    if start >= end or end - start > dt.timedelta(hours=24):
        raise ValueError("DHCP discovery window must be positive and no longer than 24 hours")
    size = request["size"]
    if isinstance(size, bool) or not isinstance(size, int) or not 1 <= size <= 1000:
        raise ValueError("DHCP discovery size must be from 1 through 1000")


def _software_text(
    value: object,
    maximum_bytes: int,
    *,
    field: str,
    allow_empty: bool = False,
) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    if value != value.strip() or any(not character.isprintable() for character in value):
        raise ValueError(f"{field} contains invalid whitespace or control characters")
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
    if source == "osquery_apps":
        if UUID_RE.fullmatch(cursor["asset"]):
            raise ValueError("software cursor host must not be UUID-shaped")
    return cursor


def validate_software_request(request: object) -> None:
    expected = {"contract", "operation", "source", "window", "page_size", "after"}
    if not isinstance(request, dict) or set(request) != expected:
        raise ValueError("request fields do not match the software inventory contract")
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
    window = request["window"]
    if not isinstance(window, dict) or set(window) != {"start", "end"}:
        raise ValueError("invalid software inventory window")
    start = _parse_dhcp_timestamp(window["start"])
    end = _parse_dhcp_timestamp(window["end"])
    if start >= end or end - start > dt.timedelta(days=31):
        raise ValueError(
            "software inventory window must be positive and no longer than 31 days"
        )
    if end > dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5):
        raise ValueError("software inventory window ends too far in the future")
    page_size = request["page_size"]
    if (
        isinstance(page_size, bool)
        or not isinstance(page_size, int)
        or not 1 <= page_size <= 500
    ):
        raise ValueError("software inventory page_size must be from 1 through 500")
    validate_software_cursor(request["after"], request["source"])


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
        raise ValueError("software inventory record fields failed validation")
    expected = SOFTWARE_INVENTORY_SOURCES[source]
    if (
        record["source"] != source
        or record["source_dataset"] != expected["dataset"]
        or record["tier"] != expected["tier"]
        or record["confidence"] != expected["confidence"]
        or record["asset_ref_type"] != expected["asset_ref_type"]
        or record["platform"] != expected["platform"]
    ):
        raise ValueError("software inventory record semantics failed validation")
    if not isinstance(record["evidence_id"], str) or not HEX_24_RE.fullmatch(
        record["evidence_id"]
    ):
        raise ValueError("software inventory evidence_id failed validation")
    asset_ref = record["asset_ref"]
    if expected["asset_ref_type"] == "host":
        if not isinstance(asset_ref, str) or not HEX_24_RE.fullmatch(asset_ref):
            raise ValueError("software inventory host reference failed validation")
    else:
        if not isinstance(asset_ref, str):
            raise ValueError("software inventory IP reference failed validation")
        try:
            address = ipaddress.ip_address(asset_ref)
        except ValueError as exc:
            raise ValueError("software inventory IP reference failed validation") from exc
        if (
            str(address) != asset_ref
            or not any(address in network for network in SOFTWARE_LAN_NETWORKS)
        ):
            raise ValueError("software inventory IP reference failed validation")
    for field in ("product", "platform", "version", "category"):
        _software_text(
            record[field],
            SOFTWARE_TEXT_LIMITS[field],
            field=f"record.{field}",
            allow_empty=field != "product",
        )
    if set(record) == SOFTWARE_OS_RECORD_KEYS:
        for field in (
            "operating_system_type",
            "operating_system_version",
            "operating_system_source",
            "operating_system_confidence",
        ):
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
        elif any(
            record[field]
            for field in (
                "operating_system_type",
                "operating_system_version",
                "operating_system_source",
                "operating_system_confidence",
            )
        ):
            raise ValueError(
                "passive software evidence cannot assert an exact operating system"
            )
    first_seen = _parse_dhcp_timestamp(record["first_seen"])
    last_seen = _parse_dhcp_timestamp(record["last_seen"])
    if first_seen > last_seen or first_seen < start or last_seen >= end:
        raise ValueError("software inventory record timestamps failed validation")
    count = record["observation_count"]
    if isinstance(count, bool) or not isinstance(count, int) or count < 1:
        raise ValueError("software inventory observation_count failed validation")


def validate_software_response(response: object, request: dict) -> None:
    if not isinstance(response, dict) or set(response) != SOFTWARE_RESPONSE_KEYS:
        raise ValueError("software inventory response fields failed validation")
    source = request["source"]
    expected = SOFTWARE_INVENTORY_SOURCES[source]
    if (
        response["ok"] is not True
        or response["contract"] != SOFTWARE_INVENTORY_CONTRACT
        or response["read_only"] is not True
        or response["source"] != source
    ):
        raise ValueError("software inventory response identity failed validation")
    window = response["window"]
    if not isinstance(window, dict) or set(window) != {"start", "end"}:
        raise ValueError("software inventory response window failed validation")
    start = _parse_dhcp_timestamp(window["start"])
    end = _parse_dhcp_timestamp(window["end"])
    request_start = _parse_dhcp_timestamp(request["window"]["start"])
    request_end = _parse_dhcp_timestamp(request["window"]["end"])
    if start != request_start or end != request_end:
        raise ValueError("software inventory response window changed in transit")
    records = response["records"]
    returned = response["returned"]
    if (
        not isinstance(records, list)
        or isinstance(returned, bool)
        or not isinstance(returned, int)
        or returned != len(records)
        or not 0 <= returned <= request["page_size"]
    ):
        raise ValueError("software inventory response count failed validation")
    if (
        not isinstance(response["complete"], bool)
        or not isinstance(response["truncated"], bool)
        or response["complete"] == response["truncated"]
    ):
        raise ValueError("software inventory pagination state failed validation")
    cursor = validate_software_cursor(response["after"], source)
    if response["complete"] and cursor is not None:
        raise ValueError("complete software inventory response retained a cursor")
    if response["truncated"] and (cursor is None or returned < 1):
        raise ValueError("truncated software inventory response omitted its cursor")
    for record in records:
        _validate_software_record(record, source=source, start=start, end=end)
    audit = response["query_audit"]
    if not isinstance(audit, dict) or set(audit) != {
        "index",
        "dataset",
        "query_digest",
    }:
        raise ValueError("software inventory query audit fields failed validation")
    if audit["index"] != expected["index"] or audit["dataset"] != expected["dataset"]:
        raise ValueError("software inventory query audit scope failed validation")
    if not isinstance(audit["query_digest"], str) or not HEX_64_RE.fullmatch(
        audit["query_digest"]
    ):
        raise ValueError("software inventory query digest failed validation")


def emit(payload: dict, code: int = 0) -> int:
    sys.stdout.write(json.dumps(payload, separators=(",", ":"), sort_keys=True) + "\n")
    return code


def _bounded_diagnostic_text(value: object, maximum_bytes: int) -> str:
    """Return one printable line from an untrusted diagnostic value."""
    if isinstance(value, bytes):
        text = value.decode("utf-8", "replace")
    elif isinstance(value, str):
        text = value
    else:
        return ""
    printable = "".join(
        character if character.isprintable() else " "
        for character in text
    )
    compact = " ".join(printable.split())
    encoded = compact.encode("utf-8")
    if len(encoded) <= maximum_bytes:
        return compact
    suffix = b"...[truncated]"
    prefix = encoded[: max(0, maximum_bytes - len(suffix))].decode(
        "utf-8",
        "ignore",
    )
    return prefix + suffix.decode("ascii")


def _json_error_fields(raw: object) -> dict[str, str]:
    """Extract only bounded fields from the inner JSON error envelope."""
    if isinstance(raw, bytes):
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return {}
    elif isinstance(raw, str):
        text = raw
    else:
        return {}
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return {}
    if not isinstance(value, dict):
        return {}
    fields = {}
    for key in ("error", "detail"):
        diagnostic = _bounded_diagnostic_text(
            value.get(key),
            MAX_ERROR_FIELD_BYTES,
        )
        if diagnostic:
            fields[key] = diagnostic
    return fields


def _failed_command_payload(
    proc: object,
) -> dict[str, object]:
    """Build a bounded two-hop failure without reflecting arbitrary output."""
    payload: dict[str, object] = {
        "ok": False,
        "error": "restricted Security Onion evidence command failed",
    }
    upstream = _json_error_fields(getattr(proc, "stdout", b""))
    if upstream.get("error"):
        payload["upstream_error"] = upstream["error"]
    if upstream.get("detail"):
        payload["upstream_detail"] = upstream["detail"]
    stderr = _bounded_diagnostic_text(
        getattr(proc, "stderr", b""),
        MAX_ERROR_FIELD_BYTES,
    )
    if stderr:
        payload["detail"] = stderr
    return payload


def main() -> int:
    if os.environ.get("SSH_ORIGINAL_COMMAND", "").strip():
        return emit({"ok": False, "error": "commands are not accepted by this forced endpoint"}, 2)
    raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if len(raw) > MAX_REQUEST_BYTES:
        return emit({"ok": False, "error": "request exceeds the broker byte limit"}, 2)
    try:
        request = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return emit({"ok": False, "error": f"invalid JSON request: {exc}"}, 2)
    if not isinstance(request, dict):
        return emit({"ok": False, "error": "request root must be an object"}, 2)
    is_dhcp_request = (
        request.get("contract") == DHCP_DISCOVERY_CONTRACT
        or request.get("operation") == DHCP_DISCOVERY_OPERATION
    )
    is_software_request = (
        request.get("contract") == SOFTWARE_INVENTORY_CONTRACT
        or request.get("operation") == SOFTWARE_INVENTORY_OPERATION
    )
    if is_dhcp_request:
        try:
            validate_dhcp_request(request)
        except ValueError as exc:
            return emit({"ok": False, "error": f"invalid DHCP discovery request: {exc}"}, 2)
    if is_software_request:
        try:
            validate_software_request(request)
        except ValueError as exc:
            return emit(
                {"ok": False, "error": f"invalid software inventory request: {exc}"},
                2,
            )
    config_path = Path(os.environ.get("ONION_SENTINEL_INCIDENT_EVIDENCE_CONFIG", DEFAULT_CONFIG))
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return emit({"ok": False, "error": f"broker configuration unavailable: {exc}"}, 3)
    command = [
        "/usr/bin/ssh", "-T", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
        "-o", f"ConnectTimeout={int(config.get('connect_timeout_seconds', 20))}",
        "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={config['known_hosts']}",
        "-i", str(config["ssh_key"]),
        f"{config.get('ssh_user', 'so-ai-relay')}@{config['host']}",
    ]
    try:
        proc = run_bounded_command(
            command,
            input_bytes=json.dumps(request, separators=(",", ":")).encode(),
            timeout_seconds=float(config.get("timeout_seconds", 400)),
            max_stdout_bytes=min(
                int(config.get("max_response_bytes", MAX_RESPONSE_BYTES)),
                (
                    4 * 1024 * 1024
                    if is_dhcp_request or is_software_request
                    else MAX_RESPONSE_BYTES
                ),
            ),
            max_stderr_bytes=int(config.get("max_stderr_bytes", 256 * 1024)),
        )
    except (BoundedProcessError, OSError, ValueError, KeyError) as exc:
        return emit({"ok": False, "error": f"restricted Security Onion evidence transport failed: {exc}"}, 4)
    if proc.returncode != 0:
        return emit(_failed_command_payload(proc), 4)
    try:
        response = json.loads(proc.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return emit({"ok": False, "error": f"invalid Security Onion evidence response: {exc}"}, 4)
    if not isinstance(response, dict):
        return emit({"ok": False, "error": "Security Onion evidence response root was not an object"}, 4)
    if is_dhcp_request and response.get("contract") != DHCP_DISCOVERY_CONTRACT:
        return emit({"ok": False, "error": "Security Onion DHCP response failed contract validation"}, 4)
    if is_software_request:
        try:
            validate_software_response(response, request)
        except ValueError:
            return emit(
                {
                    "ok": False,
                    "error": "Security Onion software inventory response failed contract validation",
                },
                4,
            )
    return emit(response, 0 if response.get("ok") else 5)


if __name__ == "__main__":
    raise SystemExit(main())
