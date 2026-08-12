#!/usr/bin/env python3
"""Compatibility facade for restricted, read-only live OSQuery collection."""
from __future__ import annotations

import datetime as dt
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import stat
import tempfile
from pathlib import Path
from typing import Any

from bounded_process import BoundedProcessError, run_bounded_command
from live_osquery_contract import (
    ALLOWED_TABLE_COLUMNS,
    ALLOWED_TABLES,
    MAX_REQUESTS,
    MAX_RESPONSE_BYTES,
    MAX_ROWS,
    TARGET_OSQUERY_VERSION,
    TARGET_PLATFORM,
    LiveOsqueryContractError,
    bounded_json_bytes,
    normalize_requests,
    normalize_target_aliases,
    validate_result_artifact,
)
from live_osquery_client_primitives import (
    ALLOWED_AGENT_ROLES,
    DEFAULT_ALLOWED_AGENT_ROLES,
    DEFAULT_ARTIFACT_DIR,
    DEFAULT_CONFIG_FILE,
    DEFAULT_MAX_SAVED_BATCHES_PER_CASE,
    MAX_CONFIG_BYTES,
    MAX_STDERR_BYTES,
    SAFE_BINDING_HOST as _SAFE_BINDING_HOST,
    SAFE_HOST as _SAFE_HOST,
    SAFE_USER as _SAFE_USER,
    LiveOsqueryClientError,
    bounded_int as _bounded_int,
    project_now,
)

import live_osquery_client_config as __config
import live_osquery_client_custody as __custody
import live_osquery_client_policy as __policy
import live_osquery_client_transport as __transport


def _read_json(path: Path, maximum: int = MAX_CONFIG_BYTES) -> dict[str, Any]:
    return __config.read_json(path, maximum)


def load_live_osquery_config(path: Path = DEFAULT_CONFIG_FILE) -> dict[str, Any]:
    """Load a capability-only client config; credentials never belong here."""
    return __config.load_config(path)


def harness_operator_approved(
    config: dict[str, Any] | None,
    target_alias: Any,
    *,
    now: dt.datetime | None = None,
) -> bool:
    """Return a fail-closed, time-bounded operator approval decision."""
    return __policy.harness_operator_approved(config, target_alias, now=now)


def scheduled_inventory_approved(
    config: dict[str, Any] | None,
    target_alias: Any,
) -> bool:
    """Authorize only the fixed, operator-installed inventory scheduler."""
    return __policy.scheduled_inventory_approved(config, target_alias)


def capability_descriptor(config: dict[str, Any]) -> dict[str, Any]:
    """Expose only the model-safe portion of the live-query capability."""
    return __policy.capability_descriptor(config)


def _atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    __custody.atomic_write_json(path, value)


def _open_locked_case_manifest(case_dir: Path) -> int:
    """Open and exclusively lock one owner-controlled per-case lock file."""
    return __custody.open_locked_case_manifest(case_dir)


def _persist_live_osquery_artifact(
    *,
    artifact_dir: Path,
    case_id: str,
    request_payload: dict[str, Any],
    artifact: dict[str, Any],
    maximum_batches: int,
) -> Path:
    """Persist immutable batches and one atomic, retention-bounded manifest."""
    return __custody.persist_artifact(
        artifact_dir=artifact_dir,
        case_id=case_id,
        request_payload=request_payload,
        artifact=artifact,
        maximum_batches=maximum_batches,
        read_json=_read_json,
        write_json=_atomic_write_json,
        open_lock=_open_locked_case_manifest,
    )


def _run_restricted_transport(
    command: list[str],
    *,
    stdin_text: str,
    timeout_seconds: float,
):
    return __transport.run_restricted_transport(
        command,
        stdin_text=stdin_text,
        timeout_seconds=timeout_seconds,
        run_command=run_bounded_command,
    )


def __approval_check(approval_scope: str):
    if approval_scope == "harness":
        return harness_operator_approved
    if approval_scope == "scheduled_inventory":
        return scheduled_inventory_approved
    raise LiveOsqueryClientError("live-host OSQuery approval scope is invalid")


def __authorized_payload(
    case_id: str,
    requests: Any,
    config: dict[str, Any],
    approval_scope: str,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    normalized = normalize_requests(
        requests,
        allowed_aliases=config.get("allowed_target_aliases") or [],
    )
    if not normalized:
        raise LiveOsqueryClientError(
            "no valid live-host OSQuery requests were supplied"
        )
    approval_check = __approval_check(approval_scope)
    unapproved_aliases = sorted({
        item["target_alias"]
        for item in normalized
        if not approval_check(config, item["target_alias"])
    })
    if unapproved_aliases:
        raise LiveOsqueryClientError(
            "live-host OSQuery operator approval is missing, expired, or "
            "not scoped to every requested target"
        )
    return normalized, {
        "schema": "onion-sentinel-live-osquery-v1",
        "case_id": str(case_id or "").strip(),
        "requests": normalized,
    }


def __validated_artifact(
    normalized: list[dict[str, Any]],
    payload: dict[str, Any],
    config: dict[str, Any],
) -> dict[str, Any]:
    completed = _run_restricted_transport(
        __transport.command(config),
        stdin_text=bounded_json_bytes(payload).decode("ascii"),
        timeout_seconds=float(config["timeout_seconds"]),
    )
    artifact = __transport.validated_response(
        completed,
        normalized=normalized,
        case_id=payload["case_id"],
        validate=validate_result_artifact,
    )
    if not artifact.get("generated_at"):
        artifact["generated_at"] = project_now()
    return artifact


def __persist_result(
    artifact: dict[str, Any],
    payload: dict[str, Any],
    config: dict[str, Any],
) -> None:
    _persist_live_osquery_artifact(
        artifact_dir=Path(config.get("artifact_dir") or DEFAULT_ARTIFACT_DIR),
        case_id=payload["case_id"],
        request_payload=payload,
        artifact=artifact,
        maximum_batches=_bounded_int(
            config.get("max_saved_batches_per_case"),
            label="max_saved_batches_per_case",
            default=DEFAULT_MAX_SAVED_BATCHES_PER_CASE,
            minimum=1,
            maximum=32,
        ),
    )


def collect_live_osquery(
    *,
    case_id: str,
    requests: Any,
    config: dict[str, Any],
    persist: bool = True,
    approval_scope: str = "harness",
) -> dict[str, Any]:
    """Submit and validate one bounded live-query batch through the relay."""
    if config.get("enabled") is not True:
        raise LiveOsqueryClientError("live-host OSQuery is disabled")
    normalized, payload = __authorized_payload(
        case_id,
        requests,
        config,
        approval_scope,
    )
    artifact = __validated_artifact(normalized, payload, config)
    if persist:
        __persist_result(artifact, payload, config)
    return artifact
