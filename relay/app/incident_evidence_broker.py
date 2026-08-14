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
import uuid
from pathlib import Path

from incident_evidence_dhcp import *  # noqa: F401,F403
from incident_evidence_dhcp import _parse_dhcp_timestamp
from incident_evidence_software import *  # noqa: F401,F403
from incident_evidence_software import (
    HEX_24_RE,
    UUID_RE,
    _software_text,
    _validate_software_record,
)
from incident_evidence_transport import (
    CORRELATION_ID_RE,
    HEX_64_RE,
    TRANSPORT_AUDIT_CONTRACT,
    TRANSPORT_RECEIPT_CONTRACT,
    _canonical_digest,
    _receipt_counters_valid,
    receipt_identity,
    transport_envelope,
)
from process_io import BoundedProcessError, run_bounded_command


MAX_REQUEST_BYTES = 16 * 1024
MAX_TRANSPORT_REQUEST_BYTES = 20 * 1024
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_ERROR_FIELD_BYTES = 500
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


def _transport_envelope(value: object) -> tuple[dict, dict]:
    return transport_envelope(
        value,
        maximum_payload_bytes=MAX_REQUEST_BYTES,
        uuid_factory=uuid.uuid4,
    )


def _receipt_identity(response: dict, audit: dict) -> dict:
    return receipt_identity(response, audit)


def _expected_control_searches(response: dict) -> int:
    controls = (
        response.get("controls")
        if isinstance(response.get("controls"), dict)
        else {}
    )
    return sum(
        1
        for name in ("positive_anchor", "negative_filter")
        if isinstance(controls.get(name), dict)
        and controls[name].get("status") != "not_requested"
    )


def _validate_pivot_accounting(
    receipt: dict,
    request: dict,
) -> None:
    expected = len(request.get("queries") or []) + 2
    if (
        receipt.get("elastic_search_count") != expected
        or receipt.get("osquery_query_count") != 0
        or receipt.get("helper_invocation_count") != 0
    ):
        raise ValueError("Security Onion search accounting is inconsistent")


def _is_helper_request(request: dict) -> bool:
    return (
        request.get("contract") == DHCP_DISCOVERY_CONTRACT
        or request.get("operation") == DHCP_DISCOVERY_OPERATION
        or request.get("contract") == SOFTWARE_INVENTORY_CONTRACT
        or request.get("operation") == SOFTWARE_INVENTORY_OPERATION
    )


def _validate_helper_accounting(receipt: dict) -> None:
    if (
        receipt.get("elastic_search_count") != 0
        or receipt.get("osquery_query_count") != 0
        or receipt.get("helper_invocation_count") != 1
    ):
        raise ValueError("Security Onion helper accounting is inconsistent")


def _validate_evidence_accounting(receipt: dict, response: dict) -> None:
    expected_control_searches = _expected_control_searches(response)
    if (
        receipt.get("elastic_search_count")
        != len(response.get("results") or []) + expected_control_searches
        or receipt.get("osquery_query_count")
        != len(response.get("osquery_results") or [])
        or receipt.get("helper_invocation_count") != 0
    ):
        raise ValueError("Security Onion evidence accounting is inconsistent")


def _validate_receipt_accounting(
    receipt: dict,
    response: dict,
    request: dict,
) -> None:
    if request.get("operation") == "investigation_pivots":
        _validate_pivot_accounting(receipt, request)
    elif _is_helper_request(request):
        _validate_helper_accounting(receipt)
    else:
        _validate_evidence_accounting(receipt, response)


def _validate_receipt(response: dict, audit: dict, request: dict) -> dict:
    receipt = _receipt_identity(response, audit)
    _validate_receipt_accounting(receipt, response, request)
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


def _admit_transport_request() -> tuple:
    if os.environ.get("SSH_ORIGINAL_COMMAND", "").strip():
        code = emit(
            {
                "ok": False,
                "error": "commands are not accepted by this forced endpoint",
            },
            2,
        )
        return None, None, None, code
    raw = sys.stdin.buffer.read(MAX_TRANSPORT_REQUEST_BYTES + 1)
    if len(raw) > MAX_TRANSPORT_REQUEST_BYTES:
        code = emit(
            {"ok": False, "error": "request exceeds the transport byte limit"},
            2,
        )
        return None, None, None, code
    try:
        received = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        code = emit({"ok": False, "error": f"invalid JSON request: {exc}"}, 2)
        return None, None, None, code
    try:
        request, envelope = _transport_envelope(received)
    except ValueError as exc:
        code = emit({"ok": False, "error": str(exc)}, 2)
        return None, None, None, code
    audit = {
        "correlation_id": envelope["correlation_id"],
        "request_digest": envelope["request_digest"],
    }
    _audit_log(
        "relay_start",
        audit,
        operation=request.get("operation", "incident_evidence"),
    )
    return request, envelope, audit, None


def _request_kinds(request: dict) -> tuple:
    is_dhcp_request = (
        request.get("contract") == DHCP_DISCOVERY_CONTRACT
        or request.get("operation") == DHCP_DISCOVERY_OPERATION
    )
    is_software_request = (
        request.get("contract") == SOFTWARE_INVENTORY_CONTRACT
        or request.get("operation") == SOFTWARE_INVENTORY_OPERATION
    )
    return is_dhcp_request, is_software_request


def _validate_special_request(
    request: dict,
    audit: dict,
    is_dhcp_request: bool,
    is_software_request: bool,
) -> object:
    if is_dhcp_request:
        try:
            validate_dhcp_request(request)
        except ValueError as exc:
            _audit_log("relay_terminal", audit, status="invalid_dhcp_request")
            return emit(
                {"ok": False, "error": f"invalid DHCP discovery request: {exc}"},
                2,
            )
    if is_software_request:
        try:
            validate_software_request(request)
        except ValueError as exc:
            _audit_log("relay_terminal", audit, status="invalid_software_request")
            return emit(
                {"ok": False, "error": f"invalid software inventory request: {exc}"},
                2,
            )
    return None


def _load_broker_config(audit: dict) -> tuple:
    config_path = Path(
        os.environ.get("ONION_SENTINEL_INCIDENT_EVIDENCE_CONFIG", DEFAULT_CONFIG)
    )
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        _audit_log("relay_terminal", audit, status="configuration_error")
        code = emit(
            {"ok": False, "error": f"broker configuration unavailable: {exc}"},
            3,
        )
        return None, code
    return config, None


def _upstream_command(config: dict) -> list:
    return [
        "/usr/bin/ssh",
        "-T",
        "-o",
        "BatchMode=yes",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        f"ConnectTimeout={int(config.get('connect_timeout_seconds', 20))}",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={config['known_hosts']}",
        "-i",
        str(config["ssh_key"]),
        f"{config.get('ssh_user', 'so-ai-relay')}@{config['host']}",
    ]


def _run_upstream(
    command: list,
    envelope: dict,
    config: dict,
    audit: dict,
    is_dhcp_request: bool,
    is_software_request: bool,
) -> tuple:
    try:
        proc = run_bounded_command(
            command,
            input_bytes=json.dumps(
                envelope,
                separators=(",", ":"),
                sort_keys=True,
            ).encode(),
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
        code = emit(
            {
                "ok": False,
                "error": (
                    "restricted Security Onion evidence transport failed: "
                    f"{exc}"
                ),
            },
            4,
        )
        return None, code
    if proc.returncode != 0:
        _audit_log("relay_terminal", audit, status="upstream_error")
        return None, emit(_failed_command_payload(proc), 4)
    return proc, None


def _decode_upstream_response(proc: object, audit: dict) -> tuple:
    try:
        response = json.loads(proc.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        _audit_log("relay_terminal", audit, status="invalid_json")
        code = emit(
            {
                "ok": False,
                "error": f"invalid Security Onion evidence response: {exc}",
            },
            4,
        )
        return None, code
    if not isinstance(response, dict):
        _audit_log("relay_terminal", audit, status="invalid_root")
        code = emit(
            {
                "ok": False,
                "error": "Security Onion evidence response root was not an object",
            },
            4,
        )
        return None, code
    return response, None


def _validate_upstream_response(
    response: dict,
    audit: dict,
    request: dict,
    is_dhcp_request: bool,
    is_software_request: bool,
) -> tuple:
    try:
        receipt = _validate_receipt(response, audit, request)
    except ValueError as exc:
        _audit_log("relay_terminal", audit, status="invalid_receipt")
        return None, emit({"ok": False, "error": str(exc)}, 4)
    if is_dhcp_request and response.get("contract") != DHCP_DISCOVERY_CONTRACT:
        _audit_log("relay_terminal", audit, status="invalid_dhcp_contract")
        code = emit(
            {
                "ok": False,
                "error": "Security Onion DHCP response failed contract validation",
            },
            4,
        )
        return None, code
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
            code = emit(
                {
                    "ok": False,
                    "error": (
                        "Security Onion software inventory response failed "
                        "contract validation"
                    ),
                },
                4,
            )
            return None, code
    return receipt, None


def _emit_upstream_response(response: dict, receipt: dict, audit: dict) -> int:
    _audit_log(
        "relay_terminal",
        audit,
        status=("complete" if response.get("complete") is True else "partial"),
        elastic_search_count=receipt.get("elastic_search_count", 0),
        response_payload_digest=receipt.get("response_payload_digest", ""),
    )
    return emit(response, 0 if response.get("ok") else 5)


def main() -> int:
    request, envelope, audit, code = _admit_transport_request()
    if code is not None:
        return code
    is_dhcp_request, is_software_request = _request_kinds(request)
    code = _validate_special_request(
        request,
        audit,
        is_dhcp_request,
        is_software_request,
    )
    if code is not None:
        return code
    config, code = _load_broker_config(audit)
    if code is not None:
        return code
    proc, code = _run_upstream(
        _upstream_command(config),
        envelope,
        config,
        audit,
        is_dhcp_request,
        is_software_request,
    )
    if code is not None:
        return code
    response, code = _decode_upstream_response(proc, audit)
    if code is not None:
        return code
    receipt, code = _validate_upstream_response(
        response,
        audit,
        request,
        is_dhcp_request,
        is_software_request,
    )
    if code is not None:
        return code
    return _emit_upstream_response(response, receipt, audit)


if __name__ == "__main__":
    raise SystemExit(main())
