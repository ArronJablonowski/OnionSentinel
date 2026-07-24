#!/usr/bin/env python3
"""Relay one bounded live-host OSQuery request to Security Onion.

This forced command accepts only the shared JSON contract. It deliberately
ignores no part of that contract and never accepts a shell command, filesystem
path, Fleet agent ID, or Kibana credential from the Mac Studio.
"""
from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

from live_osquery_contract import (
    MAX_RESPONSE_BYTES,
    LiveOsqueryContractError,
    bounded_json_bytes,
    validate_result_artifact,
    validate_transport_payload,
)
from process_io import BoundedProcessError, run_bounded_command


MAX_REQUEST_BYTES = 64 * 1024
MAX_STDERR_BYTES = 256 * 1024
DEFAULT_CONFIG = Path("/etc/so-alert-relay/live-osquery.json")


class BrokerError(RuntimeError):
    """A request could not safely cross the relay trust boundary."""


def _emit(payload: dict[str, Any], code: int = 0) -> int:
    sys.stdout.buffer.write(bounded_json_bytes(payload) + b"\n")
    return code


def _load_config(path: Path) -> dict[str, Any]:
    try:
        info = path.lstat()
    except OSError as exc:
        raise BrokerError("live OSQuery broker configuration is unavailable") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise BrokerError("live OSQuery broker configuration must be a regular file")
    if info.st_uid != 0 or info.st_mode & 0o007:
        raise BrokerError(
            "live OSQuery broker configuration must be root-owned and not world-accessible"
        )
    if info.st_size > MAX_REQUEST_BYTES:
        raise BrokerError("live OSQuery broker configuration exceeds its byte limit")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BrokerError("live OSQuery broker configuration is invalid") from exc
    if not isinstance(value, dict):
        raise BrokerError("live OSQuery broker configuration root must be an object")
    if value.get("enabled") is not True:
        raise BrokerError("live-host OSQuery is disabled on the relay")
    return value


def _read_request() -> dict[str, Any]:
    raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if len(raw) > MAX_REQUEST_BYTES:
        raise BrokerError("live OSQuery request exceeds the relay byte limit")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BrokerError("live OSQuery request is not valid JSON") from exc
    if not isinstance(value, dict):
        raise BrokerError("live OSQuery request root must be an object")
    return value


def main() -> int:
    if os.environ.get("SSH_ORIGINAL_COMMAND", "").strip():
        return _emit({"error": "commands are not accepted by this forced endpoint"}, 2)
    try:
        config_path = Path(
            os.environ.get("ONION_SENTINEL_LIVE_OSQUERY_CONFIG", DEFAULT_CONFIG)
        ).expanduser()
        config = _load_config(config_path)
        request = validate_transport_payload(
            _read_request(),
            allowed_aliases=config.get("allowed_target_aliases") or [],
        )
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
            f"ConnectTimeout={int(config.get('connect_timeout_seconds', 20))}",
            "-o",
            "ServerAliveInterval=15",
            "-o",
            "ServerAliveCountMax=3",
            "-i",
            str(config["ssh_key"]),
            "-p",
            str(int(config.get("port", 22))),
            f"{config.get('ssh_user', 'so-ai-relay')}@{config['host']}",
        ]
        proc = run_bounded_command(
            command,
            input_bytes=bounded_json_bytes(request),
            timeout_seconds=float(config.get("timeout_seconds", 180)),
            max_stdout_bytes=min(
                int(config.get("max_response_bytes", MAX_RESPONSE_BYTES)),
                MAX_RESPONSE_BYTES,
            ),
            max_stderr_bytes=min(
                int(config.get("max_stderr_bytes", MAX_STDERR_BYTES)),
                MAX_STDERR_BYTES,
            ),
        )
        if proc.returncode != 0:
            raise BrokerError("restricted Security Onion live-query command failed")
        response = json.loads(proc.stdout.decode("utf-8"))
        artifact = validate_result_artifact(
            response,
            expected_requests=request["requests"],
        )
        if artifact["case_id"] != request["case_id"]:
            raise BrokerError("live OSQuery response case_id did not match the request")
        return _emit(artifact)
    except (
        BrokerError,
        BoundedProcessError,
        LiveOsqueryContractError,
        KeyError,
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        TypeError,
        ValueError,
    ) as exc:
        # Error text is intentionally bounded and excludes remote response bodies,
        # agent IDs, paths supplied by callers, and authorization material.
        return _emit({"error": str(exc)[:1000]}, 3)


if __name__ == "__main__":
    raise SystemExit(main())
