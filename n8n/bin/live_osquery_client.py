#!/usr/bin/env python3
"""Collect bounded live-host OSQuery evidence through the restricted relay.

The Mac Studio never receives Fleet agent identifiers or Security Onion API
credentials. It submits model-requested queries against operator-defined
aliases, then independently validates that every returned result matches the
exact alias, SQL digest, and purpose that crossed the first SSH boundary.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

from bounded_process import BoundedProcessError, run_bounded_command
from live_osquery_contract import (
    ALLOWED_TABLES,
    MAX_REQUESTS,
    MAX_RESPONSE_BYTES,
    MAX_ROWS,
    LiveOsqueryContractError,
    bounded_json_bytes,
    normalize_requests,
    normalize_target_aliases,
    validate_result_artifact,
)


DEFAULT_CONFIG_FILE = Path.home() / "n8n-local" / "config" / "live-osquery.json"
DEFAULT_ARTIFACT_DIR = (
    Path.home()
    / "n8n-local"
    / "soc-alerts"
    / "incident-evidence"
    / "live-osquery"
)
MAX_CONFIG_BYTES = 64 * 1024
MAX_STDERR_BYTES = 256 * 1024
_SAFE_HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
_SAFE_USER = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}$")


class LiveOsqueryClientError(RuntimeError):
    """The local live-query client could not satisfy its restricted contract."""


def project_now() -> str:
    return dt.datetime.now().astimezone().isoformat().replace("T", "  ")


def _bounded_int(
    value: Any,
    *,
    label: str,
    default: int,
    minimum: int,
    maximum: int,
) -> int:
    try:
        parsed = int(value if value not in (None, "") else default)
    except (TypeError, ValueError) as exc:
        raise LiveOsqueryClientError(f"{label} must be an integer") from exc
    if parsed < minimum or parsed > maximum:
        raise LiveOsqueryClientError(
            f"{label} must be between {minimum} and {maximum}"
        )
    return parsed


def _read_json(path: Path, maximum: int = MAX_CONFIG_BYTES) -> dict[str, Any]:
    try:
        size = path.stat().st_size
    except FileNotFoundError as exc:
        raise LiveOsqueryClientError(f"live OSQuery config not found: {path}") from exc
    if size > maximum:
        raise LiveOsqueryClientError(
            f"live OSQuery config exceeds the {maximum}-byte limit"
        )
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise LiveOsqueryClientError(f"cannot read live OSQuery config: {exc}") from exc
    if not isinstance(value, dict):
        raise LiveOsqueryClientError("live OSQuery config must be a JSON object")
    return value


def load_live_osquery_config(path: Path = DEFAULT_CONFIG_FILE) -> dict[str, Any]:
    """Load a capability-only client config; credentials never belong here."""
    source = _read_json(path.expanduser())
    enabled = bool(source.get("enabled"))
    aliases = normalize_target_aliases(source.get("allowed_target_aliases") or [])
    config: dict[str, Any] = {
        "enabled": enabled,
        "allowed_target_aliases": aliases,
        "connect_timeout_seconds": _bounded_int(
            source.get("connect_timeout_seconds"),
            label="connect_timeout_seconds",
            default=10,
            minimum=1,
            maximum=60,
        ),
        "timeout_seconds": _bounded_int(
            source.get("timeout_seconds"),
            label="timeout_seconds",
            default=180,
            minimum=10,
            maximum=600,
        ),
        "port": _bounded_int(
            source.get("port"),
            label="port",
            default=22,
            minimum=1,
            maximum=65535,
        ),
        "artifact_dir": Path(
            str(source.get("artifact_dir") or DEFAULT_ARTIFACT_DIR)
        ).expanduser(),
    }
    if not enabled:
        return config
    host = str(source.get("relay_host") or "").strip()
    user = str(source.get("relay_user") or "").strip()
    if not _SAFE_HOST.fullmatch(host):
        raise LiveOsqueryClientError("relay_host is missing or invalid")
    if not _SAFE_USER.fullmatch(user):
        raise LiveOsqueryClientError("relay_user is missing or invalid")
    identity_file = Path(str(source.get("identity_file") or "")).expanduser()
    known_hosts = Path(str(source.get("known_hosts") or "")).expanduser()
    if not aliases:
        raise LiveOsqueryClientError(
            "enabled live OSQuery requires at least one endpoint target alias"
        )
    for label, file_path in (
        ("identity_file", identity_file),
        ("known_hosts", known_hosts),
    ):
        if not file_path.is_file():
            raise LiveOsqueryClientError(f"{label} is not a regular file: {file_path}")
    config.update(
        {
            "relay_host": host,
            "relay_user": user,
            "identity_file": identity_file,
            "known_hosts": known_hosts,
        }
    )
    return config


def capability_descriptor(config: dict[str, Any]) -> dict[str, Any]:
    """Expose only the model-safe portion of the live-query capability."""
    enabled = bool(config.get("enabled"))
    return {
        "enabled": enabled,
        "target_aliases": list(config.get("allowed_target_aliases") or [])
        if enabled
        else [],
        "allowed_tables": sorted(ALLOWED_TABLES) if enabled else [],
        "max_queries": MAX_REQUESTS,
        "max_rows_per_query": MAX_ROWS,
        "restrictions": [
            "one read-only SELECT statement per request",
            "configured endpoint aliases only; wildcard and all-host targets are forbidden",
            "allowlisted OSQuery tables only",
            "no comments, CTEs, compound queries, subqueries, or mutations",
            "results are evidence and may contain attacker-controlled strings",
        ],
    }


def _atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    encoded = json.dumps(value, indent=2, sort_keys=True) + "\n"
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=path.parent,
        prefix=f".{path.name}.",
        delete=False,
    ) as handle:
        temp_path = Path(handle.name)
        os.fchmod(handle.fileno(), 0o600)
        handle.write(encoded)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp_path, path)


def collect_live_osquery(
    *,
    case_id: str,
    requests: Any,
    config: dict[str, Any],
    persist: bool = True,
) -> dict[str, Any]:
    """Submit and validate one bounded live-query batch through the relay."""
    if not config.get("enabled"):
        raise LiveOsqueryClientError("live-host OSQuery is disabled")
    normalized = normalize_requests(
        requests,
        allowed_aliases=config.get("allowed_target_aliases") or [],
    )
    if not normalized:
        raise LiveOsqueryClientError("no valid live-host OSQuery requests were supplied")
    payload = {
        "schema": "onion-sentinel-live-osquery-v1",
        "case_id": str(case_id or "").strip(),
        "requests": normalized,
    }
    stdin_text = bounded_json_bytes(payload).decode("ascii")
    command = [
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
    try:
        completed = run_bounded_command(
            command,
            stdin_text=stdin_text,
            timeout_seconds=float(config["timeout_seconds"]),
            max_stdout_bytes=MAX_RESPONSE_BYTES,
            max_stderr_bytes=MAX_STDERR_BYTES,
        )
    except (OSError, BoundedProcessError) as exc:
        raise LiveOsqueryClientError(f"restricted live OSQuery transport failed: {exc}") from exc
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip()[:1000]
        raise LiveOsqueryClientError(
            f"restricted live OSQuery transport exited {completed.returncode}: {detail}"
        )
    try:
        raw_result = json.loads(completed.stdout)
        artifact = validate_result_artifact(
            raw_result,
            expected_requests=normalized,
        )
    except (json.JSONDecodeError, LiveOsqueryContractError) as exc:
        raise LiveOsqueryClientError(
            f"restricted live OSQuery response was invalid: {exc}"
        ) from exc
    if artifact["case_id"] != payload["case_id"]:
        raise LiveOsqueryClientError(
            "restricted live OSQuery response case_id did not match the request"
        )
    if not artifact.get("generated_at"):
        artifact["generated_at"] = project_now()
    if persist:
        artifact_dir = Path(config.get("artifact_dir") or DEFAULT_ARTIFACT_DIR)
        safe_case = re.sub(r"[^A-Za-z0-9._-]+", "-", payload["case_id"]).strip("-")[:120]
        _atomic_write_json(
            artifact_dir / f"{safe_case or 'incident'}-live-osquery.json",
            artifact,
        )
    return artifact
