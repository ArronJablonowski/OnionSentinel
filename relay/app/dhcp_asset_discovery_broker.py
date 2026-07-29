#!/usr/bin/env python3
"""Forced relay for the bounded Security Onion DHCP discovery contract."""
from __future__ import annotations

import datetime as dt
import json
import os
import sys
from pathlib import Path

from process_io import BoundedProcessError, run_bounded_command


CONTRACT = "onion-sentinel-dhcp-asset-discovery-v1"
MAX_REQUEST_BYTES = 16 * 1024
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
DEFAULT_CONFIG = Path("/etc/so-alert-relay/dhcp-asset-discovery.json")


def emit(payload: dict, code: int = 0) -> int:
    sys.stdout.write(json.dumps(payload, separators=(",", ":"), sort_keys=True) + "\n")
    return code


def parse_timestamp(value: object) -> dt.datetime:
    parsed = dt.datetime.fromisoformat(str(value or "").strip().replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp lacks offset")
    return parsed.astimezone(dt.timezone.utc)


def validate_request(request: object) -> None:
    if not isinstance(request, dict) or set(request) != {"contract", "operation", "window", "size"}:
        raise ValueError("request fields do not match the DHCP discovery contract")
    if request["contract"] != CONTRACT or request["operation"] != "dhcp_observations":
        raise ValueError("unsupported DHCP discovery operation")
    window = request["window"]
    if not isinstance(window, dict) or set(window) != {"start", "end"}:
        raise ValueError("invalid DHCP discovery window")
    start, end = parse_timestamp(window["start"]), parse_timestamp(window["end"])
    if start >= end or end - start > dt.timedelta(hours=24):
        raise ValueError("DHCP discovery window must be positive and no longer than 24 hours")
    size = request["size"]
    if isinstance(size, bool) or not isinstance(size, int) or not 1 <= size <= 1000:
        raise ValueError("DHCP discovery size must be from 1 through 1000")


def main() -> int:
    if os.environ.get("SSH_ORIGINAL_COMMAND", "").strip():
        return emit({"ok": False, "error": "commands are not accepted by this forced endpoint"}, 2)
    raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if len(raw) > MAX_REQUEST_BYTES:
        return emit({"ok": False, "error": "request exceeds the broker byte limit"}, 2)
    try:
        request = json.loads(raw.decode("utf-8"))
        validate_request(request)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        return emit({"ok": False, "error": f"invalid DHCP discovery request: {exc}"}, 2)
    config_path = Path(os.environ.get("ONION_SENTINEL_DHCP_DISCOVERY_CONFIG", DEFAULT_CONFIG))
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
        if config.get("enabled") is not True:
            raise ValueError("DHCP discovery relay is disabled")
        command = [
            "/usr/bin/ssh", "-T", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
            "-o", f"ConnectTimeout={int(config.get('connect_timeout_seconds', 20))}",
            "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={config['known_hosts']}",
            "-i", str(config["ssh_key"]),
            f"{config.get('ssh_user', 'so-ai-relay')}@{config['host']}",
        ]
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        return emit({"ok": False, "error": f"broker configuration unavailable: {exc}"}, 3)
    try:
        proc = run_bounded_command(
            command,
            input_bytes=json.dumps(request, separators=(",", ":")).encode("utf-8"),
            timeout_seconds=float(config.get("timeout_seconds", 90)),
            max_stdout_bytes=min(int(config.get("max_response_bytes", MAX_RESPONSE_BYTES)), MAX_RESPONSE_BYTES),
            max_stderr_bytes=min(int(config.get("max_stderr_bytes", 128 * 1024)), 128 * 1024),
        )
    except (BoundedProcessError, OSError, TypeError, ValueError) as exc:
        return emit({"ok": False, "error": f"restricted DHCP discovery transport failed: {exc}"}, 4)
    if proc.returncode != 0:
        detail = " ".join(proc.stderr.decode("utf-8", "replace").split())[:500]
        return emit({"ok": False, "error": "restricted Security Onion DHCP command failed", "detail": detail}, 4)
    try:
        response = json.loads(proc.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return emit({"ok": False, "error": f"invalid Security Onion DHCP response: {exc}"}, 4)
    if not isinstance(response, dict) or response.get("contract") != CONTRACT:
        return emit({"ok": False, "error": "Security Onion DHCP response failed contract validation"}, 4)
    return emit(response, 0 if response.get("ok") else 5)


if __name__ == "__main__":
    raise SystemExit(main())
