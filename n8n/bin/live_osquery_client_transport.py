"""Fixed restricted transport and response binding for live OSQuery."""
from __future__ import annotations

import json
from typing import Any, Callable

from bounded_process import BoundedProcessError
from live_osquery_client_primitives import (
    MAX_STDERR_BYTES,
    LiveOsqueryClientError,
)
from live_osquery_contract import (
    MAX_RESPONSE_BYTES,
    LiveOsqueryContractError,
)


def command(config: dict[str, Any]) -> list[str]:
    return [
        "ssh",
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
        f"ConnectTimeout={config['connect_timeout_seconds']}",
        "-o",
        "ServerAliveInterval=15",
        "-o",
        "ServerAliveCountMax=3",
        "-i",
        str(config["identity_file"]),
        "-p",
        str(config["port"]),
        f"{config['relay_user']}@{config['relay_host']}",
    ]


def run_restricted_transport(
    command_value: list[str],
    *,
    stdin_text: str,
    timeout_seconds: float,
    run_command: Callable[..., Any],
) -> Any:
    try:
        completed = run_command(
            command_value,
            stdin_text=stdin_text,
            timeout_seconds=timeout_seconds,
            max_stdout_bytes=MAX_RESPONSE_BYTES,
            max_stderr_bytes=MAX_STDERR_BYTES,
        )
    except BoundedProcessError as exc:
        reason_code = (
            "broker_timeout"
            if "timed out" in str(exc).lower()
            else "transport_failure"
        )
        raise LiveOsqueryClientError(
            f"restricted live OSQuery transport failed: {exc}",
            reason_code=reason_code,
        ) from exc
    except OSError as exc:
        raise LiveOsqueryClientError(
            f"restricted live OSQuery transport failed: {exc}",
            reason_code="connect_failure",
        ) from exc
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip()[:1000]
        raise LiveOsqueryClientError(
            f"restricted live OSQuery transport exited {completed.returncode}: {detail}",
            reason_code=(
                "connect_failure"
                if completed.returncode == 255
                else "broker_rejection"
            ),
        )
    return completed


def validated_response(
    completed: Any,
    *,
    normalized: list[dict[str, Any]],
    case_id: str,
    validate: Callable[..., dict[str, Any]],
) -> dict[str, Any]:
    try:
        raw_result = json.loads(completed.stdout)
        artifact = validate(raw_result, expected_requests=normalized)
    except (json.JSONDecodeError, LiveOsqueryContractError) as exc:
        raise LiveOsqueryClientError(
            f"restricted live OSQuery response was invalid: {exc}",
            reason_code="invalid_response",
        ) from exc
    if artifact["case_id"] != case_id:
        raise LiveOsqueryClientError(
            "restricted live OSQuery response case_id did not match the request",
            reason_code="response_mismatch",
        )
    return artifact
