"""Literal runtime release loading and controlled claim attestation."""
from __future__ import annotations

import stat
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Pattern


@dataclass(frozen=True)
class ControlledReleasePolicy:
    environment_key: str
    default_env_path: Path
    max_env_bytes: int
    release_pattern: Pattern[str]


def _explicit_environment_release(
    policy: ControlledReleasePolicy,
    environ: object,
) -> tuple[bool, str]:
    try:
        explicitly_supplied = policy.environment_key in environ
    except TypeError:
        return False, ""
    if not explicitly_supplied:
        return False, ""
    candidate = environ.get(policy.environment_key, "")
    if (
        isinstance(candidate, str)
        and policy.release_pattern.fullmatch(candidate)
    ):
        return True, candidate
    return True, ""


def _bounded_literal_env_lines(
    path: Path,
    max_bytes: int,
) -> list[str] | None:
    try:
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            return None
        if metadata.st_size > max_bytes:
            return None
        raw = path.read_bytes()
    except OSError:
        return None
    if len(raw) > max_bytes:
        return None
    try:
        return raw.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        return None


def _literal_release_candidates(
    lines: list[str], environment_key: str
) -> list[str]:
    candidates: list[str] = []
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key.strip() == environment_key:
            candidates.append(value.strip())
    return candidates


def current_runtime_release_id(
    policy: ControlledReleasePolicy,
    *,
    environ: object,
    env_path: Path | None = None,
) -> str:
    """Return an explicit or bounded literal deployed commit attestation."""
    explicit, release_id = _explicit_environment_release(policy, environ)
    if explicit:
        return release_id
    path = policy.default_env_path if env_path is None else Path(env_path)
    lines = _bounded_literal_env_lines(path, policy.max_env_bytes)
    if lines is None:
        return ""
    candidates = _literal_release_candidates(lines, policy.environment_key)
    if len(candidates) != 1:
        return ""
    candidate = candidates[0]
    return (
        candidate
        if policy.release_pattern.fullmatch(candidate)
        else ""
    )


def require_controlled_release_attestation(
    policy: ControlledReleasePolicy,
    claimed_payload: dict[str, object],
    runtime_release_id: str,
    reject: Callable[[str], BaseException],
) -> str:
    """Require the durable claim release to equal the deployed runtime."""
    payload_release_id = claimed_payload.get("release_id")
    if (
        not isinstance(payload_release_id, str)
        or not policy.release_pattern.fullmatch(payload_release_id)
        or not runtime_release_id
        or payload_release_id != runtime_release_id
    ):
        raise reject(
            "controlled AI claim release_id did not match the deployed runtime"
        )
    return runtime_release_id
