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
from pathlib import Path

from process_io import BoundedProcessError, run_bounded_command


MAX_REQUEST_BYTES = 16 * 1024
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_ERROR_FIELD_BYTES = 500
DEFAULT_CONFIG = Path("/etc/so-alert-relay/incident-evidence.json")
DHCP_DISCOVERY_CONTRACT = "onion-sentinel-dhcp-asset-discovery-v1"
DHCP_DISCOVERY_OPERATION = "dhcp_observations"


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
    if is_dhcp_request:
        try:
            validate_dhcp_request(request)
        except ValueError as exc:
            return emit({"ok": False, "error": f"invalid DHCP discovery request: {exc}"}, 2)
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
                4 * 1024 * 1024 if is_dhcp_request else MAX_RESPONSE_BYTES,
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
    return emit(response, 0 if response.get("ok") else 5)


if __name__ == "__main__":
    raise SystemExit(main())
