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
from pathlib import Path

from process_io import BoundedProcessError, run_bounded_command


MAX_REQUEST_BYTES = 16 * 1024
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
DEFAULT_CONFIG = Path("/etc/so-alert-relay/incident-evidence.json")


def emit(payload: dict, code: int = 0) -> int:
    sys.stdout.write(json.dumps(payload, separators=(",", ":"), sort_keys=True) + "\n")
    return code


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
            max_stdout_bytes=int(config.get("max_response_bytes", MAX_RESPONSE_BYTES)),
            max_stderr_bytes=int(config.get("max_stderr_bytes", 256 * 1024)),
        )
    except (BoundedProcessError, OSError, ValueError, KeyError) as exc:
        return emit({"ok": False, "error": f"restricted Security Onion evidence transport failed: {exc}"}, 4)
    if proc.returncode != 0:
        return emit({"ok": False, "error": "restricted Security Onion evidence command failed", "detail": proc.stderr.decode("utf-8", "replace")[:1000]}, 4)
    try:
        response = json.loads(proc.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return emit({"ok": False, "error": f"invalid Security Onion evidence response: {exc}"}, 4)
    if not isinstance(response, dict):
        return emit({"ok": False, "error": "Security Onion evidence response root was not an object"}, 4)
    return emit(response, 0 if response.get("ok") else 5)


if __name__ == "__main__":
    raise SystemExit(main())
