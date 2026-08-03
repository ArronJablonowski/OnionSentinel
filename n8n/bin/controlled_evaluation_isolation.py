#!/usr/bin/env python3
"""Fail-closed filesystem and transport boundaries for controlled evaluation."""
from __future__ import annotations

import json
import os
import stat
import tempfile
from pathlib import Path
from typing import Any


INCIDENT_EVIDENCE_CONTRACT = "onion-sentinel-investigation-pivots-v2"
INCIDENT_EVIDENCE_HOST = "10.88.8.8"
INCIDENT_EVIDENCE_SSH_USER = "aj"
INCIDENT_EVIDENCE_KEY_BASENAME = (
    "onion-sentinel-incident-evidence_ed25519"
)
INCIDENT_EVIDENCE_KNOWN_HOSTS_BASENAME = "relay_known_hosts"
INCIDENT_EVIDENCE_CONFIG_KEYS = frozenset(
    {
        "investigation_query_contract",
        "host",
        "ssh_user",
        "ssh_key",
        "known_hosts",
        "connect_timeout_seconds",
        "timeout_seconds",
        "max_response_bytes",
        "max_stderr_bytes",
    }
)
MAX_INCIDENT_EVIDENCE_CONFIG_BYTES = 64 * 1024
MAX_INCIDENT_EVIDENCE_CONNECT_TIMEOUT_SECONDS = 20
MAX_INCIDENT_EVIDENCE_TIMEOUT_SECONDS = 420
MAX_INCIDENT_EVIDENCE_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_INCIDENT_EVIDENCE_STDERR_BYTES = 256 * 1024


class ControlledEvaluationIsolationError(ValueError):
    """One controlled-evaluation path or route is not isolated."""


def _owner_private_existing_path(
    candidate: Path,
    *,
    label: str,
    kind: str,
) -> Path:
    try:
        metadata = candidate.lstat()
        resolved = candidate.resolve(strict=True)
    except (FileNotFoundError, OSError, ValueError) as exc:
        raise ControlledEvaluationIsolationError(
            f"{label} must be a canonical owner-private {kind}"
        ) from exc
    expected_kind = (
        stat.S_ISREG(metadata.st_mode)
        if kind == "file"
        else stat.S_ISDIR(metadata.st_mode)
    )
    if (
        not candidate.is_absolute()
        or resolved != candidate
        or candidate.is_symlink()
        or not expected_kind
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise ControlledEvaluationIsolationError(
            f"{label} must be a canonical owner-private {kind}"
        )
    return resolved


def pin_controlled_tmpdir(runtime_root: Path) -> Path:
    """Validate and pin Python and child-process temporary storage."""
    raw_tmpdir = str(os.environ.get("TMPDIR") or "").strip()
    if not raw_tmpdir:
        raise ControlledEvaluationIsolationError(
            "TMPDIR must be an explicit canonical owner-private directory "
            "inside the evaluation runtime"
        )
    candidate = Path(raw_tmpdir)
    resolved = _owner_private_existing_path(
        candidate,
        label="TMPDIR",
        kind="directory",
    )
    try:
        resolved.relative_to(runtime_root)
    except ValueError as exc:
        raise ControlledEvaluationIsolationError(
            "TMPDIR must be an explicit canonical owner-private directory "
            "inside the evaluation runtime"
        ) from exc
    os.environ["TMPDIR"] = str(resolved)
    tempfile.tempdir = str(resolved)
    return resolved


def _canonical_private_route_file(value: Any, *, label: str) -> Path:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ControlledEvaluationIsolationError(
            f"Relay evidence {label} must be a canonical owner-private file"
        )
    path = _owner_private_existing_path(
        Path(value),
        label=f"Relay evidence {label}",
        kind="file",
    )
    if path.stat().st_size < 1:
        raise ControlledEvaluationIsolationError(
            f"Relay evidence {label} must not be empty"
        )
    return path


def _read_private_config(path: Path) -> bytes:
    """Read one admitted config without following a swapped symlink."""
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ControlledEvaluationIsolationError(
            "Relay evidence transport config is invalid"
        ) from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
            or metadata.st_size < 2
            or metadata.st_size > MAX_INCIDENT_EVIDENCE_CONFIG_BYTES
        ):
            raise ControlledEvaluationIsolationError(
                "Relay evidence transport config exceeds its byte contract"
            )
        chunks: list[bytes] = []
        remaining = MAX_INCIDENT_EVIDENCE_CONFIG_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
    finally:
        os.close(descriptor)
    if len(payload) != metadata.st_size:
        raise ControlledEvaluationIsolationError(
            "Relay evidence transport config changed while it was read"
        )
    return payload


def validate_controlled_incident_evidence_route(
    config_path: Path,
    runtime_root: Path,
    *,
    expected_home: Path | None = None,
) -> dict[str, Any]:
    """Validate the one exact, bounded, read-only Relay transport route."""
    config = _owner_private_existing_path(
        config_path,
        label="Relay evidence transport config",
        kind="file",
    )
    try:
        config.relative_to(runtime_root)
    except ValueError as exc:
        raise ControlledEvaluationIsolationError(
            "Relay evidence transport config must stay inside the "
            "evaluation runtime"
        ) from exc
    try:
        document = json.loads(_read_private_config(config).decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ControlledEvaluationIsolationError(
            "Relay evidence transport config is invalid"
        ) from exc
    if not isinstance(document, dict) or set(document) != set(
        INCIDENT_EVIDENCE_CONFIG_KEYS
    ):
        raise ControlledEvaluationIsolationError(
            "Relay evidence transport config must contain only the exact "
            "read-only route fields"
        )
    expected_route = {
        "investigation_query_contract": INCIDENT_EVIDENCE_CONTRACT,
        "host": INCIDENT_EVIDENCE_HOST,
        "ssh_user": INCIDENT_EVIDENCE_SSH_USER,
    }
    if any(document.get(key) != value for key, value in expected_route.items()):
        raise ControlledEvaluationIsolationError(
            "Relay evidence transport config does not select the exact "
            "read-only route"
        )
    key_path = _canonical_private_route_file(
        document.get("ssh_key"),
        label="SSH key",
    )
    known_hosts_path = _canonical_private_route_file(
        document.get("known_hosts"),
        label="known-hosts file",
    )
    home = Path.home() if expected_home is None else Path(expected_home)
    try:
        approved_key_path = (
            home.resolve(strict=True)
            / ".ssh"
            / INCIDENT_EVIDENCE_KEY_BASENAME
        )
    except (OSError, ValueError) as exc:
        raise ControlledEvaluationIsolationError(
            "Relay evidence SSH key home is not canonical"
        ) from exc
    if key_path != approved_key_path:
        raise ControlledEvaluationIsolationError(
            "Relay evidence SSH key path is not approved"
        )
    approved_known_hosts_path = (
        runtime_root / INCIDENT_EVIDENCE_KNOWN_HOSTS_BASENAME
    )
    if known_hosts_path != approved_known_hosts_path:
        raise ControlledEvaluationIsolationError(
            "Relay evidence known-hosts path is not approved"
        )
    limits = {
        "connect_timeout_seconds": (
            MAX_INCIDENT_EVIDENCE_CONNECT_TIMEOUT_SECONDS
        ),
        "timeout_seconds": MAX_INCIDENT_EVIDENCE_TIMEOUT_SECONDS,
        "max_response_bytes": MAX_INCIDENT_EVIDENCE_RESPONSE_BYTES,
        "max_stderr_bytes": MAX_INCIDENT_EVIDENCE_STDERR_BYTES,
    }
    for field, maximum in limits.items():
        value = document.get(field)
        if type(value) is not int or value < 1 or value > maximum:
            raise ControlledEvaluationIsolationError(
                f"Relay evidence {field} exceeds its bounded transport limit"
            )
    return document
