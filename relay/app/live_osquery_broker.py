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
    sys.stdout.buffer.write(
        bounded_json_bytes(payload, maximum=MAX_RESPONSE_BYTES - 1) + b"\n"
    )
    return code


def _config_snapshot(path: Path) -> os.stat_result:
    try:
        return path.lstat()
    except OSError as exc:
        raise BrokerError("live OSQuery broker configuration is unavailable") from exc


def _validate_config_file(info: os.stat_result) -> None:
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise BrokerError("live OSQuery broker configuration must be a regular file")
    if (
        info.st_uid != 0
        or info.st_gid != os.getegid()
        or stat.S_IMODE(info.st_mode) != 0o640
    ):
        raise BrokerError(
            "live OSQuery broker configuration must be root-owned, grouped to "
            "the broker service account, and mode 0640"
        )
    if info.st_size > MAX_REQUEST_BYTES:
        raise BrokerError("live OSQuery broker configuration exceeds its byte limit")


def _decode_config(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BrokerError("live OSQuery broker configuration is invalid") from exc


def _validate_config(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BrokerError("live OSQuery broker configuration root must be an object")
    if value.get("enabled") is not True:
        raise BrokerError("live-host OSQuery is disabled on the relay")
    return value


def _load_config(path: Path) -> dict[str, Any]:
    _validate_config_file(_config_snapshot(path))
    return _validate_config(_decode_config(path))


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


def _config_path() -> Path:
    return Path(
        os.environ.get("ONION_SENTINEL_LIVE_OSQUERY_CONFIG", DEFAULT_CONFIG)
    ).expanduser()


def _validated_request(config: dict[str, Any]) -> dict[str, Any]:
    return validate_transport_payload(
        _read_request(),
        allowed_aliases=config.get("allowed_target_aliases") or [],
    )


def _ssh_command(config: dict[str, Any]) -> list[str]:
    return [
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


def _run_query(config: dict[str, Any], request: dict[str, Any]) -> object:
    proc = run_bounded_command(
        _ssh_command(config),
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
    return proc


def _validated_response(proc: object, request: dict[str, Any]) -> dict[str, Any]:
    response = json.loads(proc.stdout.decode("utf-8"))
    artifact = validate_result_artifact(
        response,
        expected_requests=request["requests"],
    )
    if artifact["case_id"] != request["case_id"]:
        raise BrokerError("live OSQuery response case_id did not match the request")
    return artifact


def _execute_request() -> dict[str, Any]:
    config = _load_config(_config_path())
    request = _validated_request(config)
    return _validated_response(_run_query(config, request), request)


def _emit_failure(exc: Exception) -> int:
    # Error text is intentionally bounded and excludes remote response bodies,
    # agent IDs, paths supplied by callers, and authorization material.
    return _emit({"error": str(exc)[:1000]}, 3)


BROKER_FAILURES = (
        BrokerError,
        BoundedProcessError,
        LiveOsqueryContractError,
        KeyError,
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        TypeError,
        ValueError,
)


def main() -> int:
    if os.environ.get("SSH_ORIGINAL_COMMAND", "").strip():
        return _emit({"error": "commands are not accepted by this forced endpoint"}, 2)
    try:
        return _emit(_execute_request())
    except BROKER_FAILURES as exc:
        return _emit_failure(exc)


if __name__ == "__main__":
    raise SystemExit(main())
