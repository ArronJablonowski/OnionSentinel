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
import hashlib
import re
import syslog
import uuid
from pathlib import Path

from incident_evidence_inventory_contract import (
    DHCP_DISCOVERY_CONTRACT,
    DHCP_DISCOVERY_OPERATION,
    HEX_24_RE,
    HEX_64_RE,
    SOFTWARE_CURSOR_KEYS,
    SOFTWARE_INVENTORY_CONTRACT,
    SOFTWARE_INVENTORY_OPERATION,
    SOFTWARE_INVENTORY_SOURCES,
    SOFTWARE_LAN_NETWORKS,
    SOFTWARE_OS_RECORD_KEYS,
    SOFTWARE_RECORD_KEYS,
    SOFTWARE_RECORD_KEY_SETS,
    SOFTWARE_RESPONSE_KEYS,
    SOFTWARE_TEXT_LIMITS,
    UUID_RE,
    _parse_dhcp_timestamp,
    _software_text,
    _validate_software_record,
    validate_dhcp_request,
    validate_software_cursor,
    validate_software_request,
    validate_software_response,
)
from process_io import BoundedProcessError, run_bounded_command


MAX_REQUEST_BYTES = 16 * 1024
MAX_TRANSPORT_REQUEST_BYTES = 20 * 1024
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_ERROR_FIELD_BYTES = 500
DEFAULT_CONFIG = Path("/etc/so-alert-relay/incident-evidence.json")
TRANSPORT_AUDIT_CONTRACT = "onion-sentinel-evidence-transport-v1"
TRANSPORT_RECEIPT_CONTRACT = "onion-sentinel-evidence-receipt-v1"
CORRELATION_ID_RE = re.compile(r"^[a-f0-9]{32}$")
AUDIT_OPERATIONS = {
    "incident_evidence",
    "investigation_pivots",
    DHCP_DISCOVERY_OPERATION,
    SOFTWARE_INVENTORY_OPERATION,
}


def _canonical_digest(value: object) -> str:
    encoded = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    return hashlib.sha256(encoded).hexdigest()


def _audit_value(value: object) -> str:
    text = str(value if value is not None else "")[:160]
    return re.sub(r"[^A-Za-z0-9_.:@+-]", "_", text)


def _audit_log(event: str, audit: dict, **fields: object) -> None:
    if "operation" in fields and fields["operation"] not in AUDIT_OPERATIONS:
        fields["operation"] = "unknown"
    allowed = {
        "event": event,
        "correlation_id": audit.get("correlation_id", ""),
        "request_digest": audit.get("request_digest", ""),
        **fields,
    }
    message = " ".join(
        f"{key}={_audit_value(value)}" for key, value in allowed.items()
    )
    try:
        syslog.syslog(syslog.LOG_INFO, "onion-sentinel-evidence " + message)
    except OSError:
        pass


def _transport_envelope(value: object) -> tuple[dict, dict]:
    if not isinstance(value, dict):
        raise ValueError("request root must be an object")
    if value.get("transport_contract") == TRANSPORT_AUDIT_CONTRACT:
        if set(value) != {
            "transport_contract", "correlation_id", "request_digest", "payload"
        }:
            raise ValueError("transport envelope fields are invalid")
        payload = value.get("payload")
        correlation_id = value.get("correlation_id")
        request_digest = value.get("request_digest")
        if (
            not isinstance(payload, dict)
            or not isinstance(correlation_id, str)
            or not CORRELATION_ID_RE.fullmatch(correlation_id)
            or not isinstance(request_digest, str)
            or not HEX_64_RE.fullmatch(request_digest)
            or request_digest != _canonical_digest(payload)
        ):
            raise ValueError("transport envelope failed validation")
    else:
        payload = value
        correlation_id = uuid.uuid4().hex
        request_digest = _canonical_digest(payload)
    if len(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()) > MAX_REQUEST_BYTES:
        raise ValueError("request payload exceeds the broker byte limit")
    audit = {
        "transport_contract": TRANSPORT_AUDIT_CONTRACT,
        "correlation_id": correlation_id,
        "request_digest": request_digest,
    }
    return payload, {**audit, "payload": payload}


def _validate_receipt(response: dict, audit: dict, request: dict) -> dict:
    receipt = response.get("audit_receipt")
    if not isinstance(receipt, dict) or set(receipt) != {
        "receipt_contract",
        "correlation_id",
        "request_digest",
        "response_payload_digest",
        "elastic_search_count",
        "osquery_query_count",
        "helper_invocation_count",
        "read_only",
        "terminal_status",
    }:
        raise ValueError("Security Onion response omitted its audit receipt")
    without_receipt = {
        key: value for key, value in response.items() if key != "audit_receipt"
    }
    if (
        receipt.get("receipt_contract") != TRANSPORT_RECEIPT_CONTRACT
        or receipt.get("correlation_id") != audit["correlation_id"]
        or receipt.get("request_digest") != audit["request_digest"]
        or receipt.get("response_payload_digest") != _canonical_digest(without_receipt)
        or receipt.get("read_only") is not True
        or receipt.get("terminal_status")
        != ("complete" if response.get("complete") is True else "partial")
        or any(
            not isinstance(receipt.get(field), int)
            or isinstance(receipt.get(field), bool)
            or receipt.get(field) < 0
            for field in (
                "elastic_search_count",
                "osquery_query_count",
                "helper_invocation_count",
            )
        )
    ):
        raise ValueError("Security Onion audit receipt failed validation")
    if request.get("operation") == "investigation_pivots":
        expected = len(request.get("queries") or []) + 2
        if (
            receipt.get("elastic_search_count") != expected
            or receipt.get("osquery_query_count") != 0
            or receipt.get("helper_invocation_count") != 0
        ):
            raise ValueError("Security Onion search accounting is inconsistent")
    elif (
        request.get("contract") == DHCP_DISCOVERY_CONTRACT
        or request.get("operation") == DHCP_DISCOVERY_OPERATION
        or request.get("contract") == SOFTWARE_INVENTORY_CONTRACT
        or request.get("operation") == SOFTWARE_INVENTORY_OPERATION
    ):
        if (
            receipt.get("elastic_search_count") != 0
            or receipt.get("osquery_query_count") != 0
            or receipt.get("helper_invocation_count") != 1
        ):
            raise ValueError("Security Onion helper accounting is inconsistent")
    else:
        controls = response.get("controls") if isinstance(response.get("controls"), dict) else {}
        expected_control_searches = sum(
            1
            for name in ("positive_anchor", "negative_filter")
            if isinstance(controls.get(name), dict)
            and controls[name].get("status") != "not_requested"
        )
        if (
            receipt.get("elastic_search_count")
            != len(response.get("results") or []) + expected_control_searches
            or receipt.get("osquery_query_count")
            != len(response.get("osquery_results") or [])
            or receipt.get("helper_invocation_count") != 0
        ):
            raise ValueError("Security Onion evidence accounting is inconsistent")
    return receipt


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
    raw = sys.stdin.buffer.read(MAX_TRANSPORT_REQUEST_BYTES + 1)
    if len(raw) > MAX_TRANSPORT_REQUEST_BYTES:
        return emit({"ok": False, "error": "request exceeds the transport byte limit"}, 2)
    try:
        received = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return emit({"ok": False, "error": f"invalid JSON request: {exc}"}, 2)
    try:
        request, envelope = _transport_envelope(received)
    except ValueError as exc:
        return emit({"ok": False, "error": str(exc)}, 2)
    audit = {
        "correlation_id": envelope["correlation_id"],
        "request_digest": envelope["request_digest"],
    }
    _audit_log("relay_start", audit, operation=request.get("operation", "incident_evidence"))
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
            _audit_log("relay_terminal", audit, status="invalid_dhcp_request")
            return emit({"ok": False, "error": f"invalid DHCP discovery request: {exc}"}, 2)
    if is_software_request:
        try:
            validate_software_request(request)
        except ValueError as exc:
            _audit_log("relay_terminal", audit, status="invalid_software_request")
            return emit(
                {"ok": False, "error": f"invalid software inventory request: {exc}"},
                2,
            )
    config_path = Path(os.environ.get("ONION_SENTINEL_INCIDENT_EVIDENCE_CONFIG", DEFAULT_CONFIG))
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        _audit_log("relay_terminal", audit, status="configuration_error")
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
            input_bytes=json.dumps(envelope, separators=(",", ":"), sort_keys=True).encode(),
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
        _audit_log("relay_terminal", audit, status="transport_error")
        return emit({"ok": False, "error": f"restricted Security Onion evidence transport failed: {exc}"}, 4)
    if proc.returncode != 0:
        _audit_log("relay_terminal", audit, status="upstream_error")
        return emit(_failed_command_payload(proc), 4)
    try:
        response = json.loads(proc.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        _audit_log("relay_terminal", audit, status="invalid_json")
        return emit({"ok": False, "error": f"invalid Security Onion evidence response: {exc}"}, 4)
    if not isinstance(response, dict):
        _audit_log("relay_terminal", audit, status="invalid_root")
        return emit({"ok": False, "error": "Security Onion evidence response root was not an object"}, 4)
    try:
        receipt = _validate_receipt(response, audit, request)
    except ValueError as exc:
        _audit_log("relay_terminal", audit, status="invalid_receipt")
        return emit({"ok": False, "error": str(exc)}, 4)
    if is_dhcp_request and response.get("contract") != DHCP_DISCOVERY_CONTRACT:
        _audit_log("relay_terminal", audit, status="invalid_dhcp_contract")
        return emit({"ok": False, "error": "Security Onion DHCP response failed contract validation"}, 4)
    if is_software_request:
        try:
            validate_software_response(
                {
                    key: value
                    for key, value in response.items()
                    if key != "audit_receipt"
                },
                request,
            )
        except ValueError:
            _audit_log("relay_terminal", audit, status="invalid_software_contract")
            return emit(
                {
                    "ok": False,
                    "error": "Security Onion software inventory response failed contract validation",
                },
                4,
            )
    _audit_log(
        "relay_terminal",
        audit,
        status=("complete" if response.get("complete") is True else "partial"),
        elastic_search_count=receipt.get("elastic_search_count", 0),
        response_payload_digest=receipt.get("response_payload_digest", ""),
    )
    return emit(response, 0 if response.get("ok") else 5)


if __name__ == "__main__":
    raise SystemExit(main())
