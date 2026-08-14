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
import re
import syslog
from pathlib import Path

from incident_evidence_diagnostics import (
    MAX_ERROR_FIELD_BYTES,
    _bounded_diagnostic_text,
    _failed_command_payload,
    _json_error_fields,
)
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
from incident_evidence_transport_contract import (
    CORRELATION_ID_RE,
    MAX_REQUEST_BYTES,
    TRANSPORT_AUDIT_CONTRACT,
    TRANSPORT_RECEIPT_CONTRACT,
    _canonical_digest,
    _transport_envelope,
    _validate_receipt,
)
from process_io import BoundedProcessError, run_bounded_command


MAX_TRANSPORT_REQUEST_BYTES = 20 * 1024
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
DEFAULT_CONFIG = Path("/etc/so-alert-relay/incident-evidence.json")
AUDIT_OPERATIONS = {
    "incident_evidence",
    "investigation_pivots",
    DHCP_DISCOVERY_OPERATION,
    SOFTWARE_INVENTORY_OPERATION,
}


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


def emit(payload: dict, code: int = 0) -> int:
    sys.stdout.write(json.dumps(payload, separators=(",", ":"), sort_keys=True) + "\n")
    return code


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
