#!/usr/bin/env python3
"""Verify alert-store receipts and write digest-bound private artifacts."""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from typing import Any, Callable, Mapping, Pattern, Sequence


@dataclass(frozen=True)
class AlertStoreReceiptPolicy:
    error: type[RuntimeError]
    maximum_response_bytes: int
    sha256_pattern: Pattern[str]
    canonical_sha256_javascript: str
    node_candidates: Sequence[Path]


@dataclass(frozen=True)
class DigestArtifactPolicy:
    error: type[RuntimeError]
    sha256_pattern: Pattern[str]
    sha256_value: Callable[[Any], str]
    constant_time_equal: Callable[[str, str], bool]


def _node_binary(policy: AlertStoreReceiptPolicy) -> str:
    node = shutil.which("node")
    if node:
        return node
    for candidate in policy.node_candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    raise policy.error("Node.js is required to verify alert-store response receipts")


def alert_store_response_sha256(
    raw_response: str,
    policy: AlertStoreReceiptPolicy,
) -> str:
    """Reproduce the alert-store JavaScript canonical response digest exactly."""
    encoded = raw_response.encode("utf-8")
    if not encoded or len(encoded) > policy.maximum_response_bytes:
        raise policy.error("stored analysis response exceeds its safe bound")
    try:
        completed = subprocess.run(
            [_node_binary(policy), "-e", policy.canonical_sha256_javascript],
            input=encoded,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise policy.error("could not canonicalize the stored analysis response") from exc
    digest = completed.stdout.decode("ascii", errors="ignore").strip()
    if completed.returncode != 0 or not policy.sha256_pattern.fullmatch(digest):
        raise policy.error("alert-store response canonicalization failed closed")
    return digest


def digest_bound(
    document: Mapping[str, Any],
    field: str,
    policy: DigestArtifactPolicy,
) -> dict[str, Any]:
    output = dict(document)
    output.pop(field, None)
    output[field] = policy.sha256_value(output)
    return output


def validate_digest(
    document: Mapping[str, Any],
    field: str,
    policy: DigestArtifactPolicy,
) -> None:
    expected = str(document.get(field) or "")
    unsigned = dict(document)
    unsigned.pop(field, None)
    if not policy.sha256_pattern.fullmatch(expected):
        raise policy.error(f"{field} is missing or malformed")
    if not policy.constant_time_equal(expected, policy.sha256_value(unsigned)):
        raise policy.error(f"{field} does not match the document")


def _private_parent(path: Path, policy: DigestArtifactPolicy) -> Path:
    parent = path.expanduser().resolve().parent
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if parent.is_symlink() or not parent.is_dir():
        raise policy.error(f"output parent is not a real directory: {parent}")
    os.chmod(parent, 0o700)
    return parent


def _commit_private_json(
    descriptor: int,
    temporary: Path,
    target: Path,
    document: Mapping[str, Any],
) -> None:
    os.fchmod(descriptor, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(json.dumps(document, indent=2, sort_keys=True).encode("utf-8"))
        handle.write(b"\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, target)
    os.chmod(target, 0o600)
    directory_fd = os.open(target.parent, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def write_private_json(
    path: Path,
    document: Mapping[str, Any],
    *,
    digest_field: str,
    policy: DigestArtifactPolicy,
    replace: bool = True,
) -> dict[str, Any]:
    """Atomically write a digest-bound JSON document with mode 0600."""
    target = path.expanduser()
    parent = _private_parent(target, policy)
    if target.is_symlink():
        raise policy.error(f"refusing to replace symlink: {target}")
    if target.exists() and not replace:
        raise policy.error(f"refusing to overwrite existing file: {target}")
    bound = digest_bound(document, digest_field, policy)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.", suffix=".tmp", dir=parent
    )
    temporary = Path(temporary_name)
    try:
        _commit_private_json(descriptor, temporary, target, bound)
    finally:
        if temporary.exists():
            temporary.unlink()
    return bound
