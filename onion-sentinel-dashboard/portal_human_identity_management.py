"""Service-offline owner management for delegated human identities."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import tempfile

from portal_human_identity_store import (
    HumanIdentity,
    HumanIdentityConfigurationError,
    HumanIdentityStore,
    load_enforcement_human_identity_store,
    serialize_human_identity_store,
)


PASSWORD_ITERATIONS = 600_000
PASSWORD_MINIMUM_BYTES = 16
PASSWORD_MAXIMUM_BYTES = 1024


class HumanIdentityManagementError(RuntimeError):
    """Raised when a delegated identity update cannot be committed safely."""


@dataclass(frozen=True)
class HumanIdentityManagementResult:
    action: str
    username: str
    principal_id: str
    role: str
    generation: int
    identity_count: int


def _password_bytes(value: object) -> bytes:
    if not isinstance(value, str):
        raise HumanIdentityManagementError("identity password has an invalid type")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise HumanIdentityManagementError(
            "identity password has an invalid encoding"
        ) from exc
    if (
        not PASSWORD_MINIMUM_BYTES <= len(encoded) <= PASSWORD_MAXIMUM_BYTES
        or b"\x00" in encoded
    ):
        raise HumanIdentityManagementError(
            "identity password does not meet the bounded policy"
        )
    return encoded


def _password_record(
    password: object,
    random_bytes: Callable[[int], bytes],
) -> dict[str, object]:
    encoded = _password_bytes(password)
    try:
        salt = random_bytes(32)
    except Exception as exc:
        raise HumanIdentityManagementError(
            "identity password salt generation failed"
        ) from exc
    if not isinstance(salt, bytes) or len(salt) != 32:
        raise HumanIdentityManagementError(
            "identity password salt generation failed"
        )
    return {
        "algorithm": "pbkdf2_sha256",
        "hash": hashlib.pbkdf2_hmac(
            "sha256", encoded, salt, PASSWORD_ITERATIONS
        ).hex(),
        "iterations": PASSWORD_ITERATIONS,
        "salt": salt.hex(),
    }


def _load(path: Path) -> HumanIdentityStore:
    try:
        return load_enforcement_human_identity_store(path)
    except HumanIdentityConfigurationError as exc:
        raise HumanIdentityManagementError(str(exc)) from exc


def _atomic_write(path: Path, payload: bytes) -> None:
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            os.fchmod(handle.fileno(), 0o600)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        temporary = None
        path.chmod(0o600)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError as exc:
        raise HumanIdentityManagementError(
            "human identity store commit failed"
        ) from exc
    finally:
        if temporary is not None:
            try:
                temporary.unlink()
            except OSError:
                pass


def _commit(
    path: Path,
    current: HumanIdentityStore,
    identities: dict[str, HumanIdentity],
) -> HumanIdentityStore:
    candidate = HumanIdentityStore(current.generation + 1, identities)
    try:
        payload = serialize_human_identity_store(candidate)
    except HumanIdentityConfigurationError as exc:
        raise HumanIdentityManagementError(str(exc)) from exc
    _atomic_write(path, payload)
    return candidate


def set_human_identity(
    path: Path,
    *,
    username: str,
    principal_id: str,
    role: str,
    password: object,
    random_bytes: Callable[[int], bytes] = os.urandom,
) -> HumanIdentityManagementResult:
    """Create or replace one Viewer/Analyst identity and bump generation."""
    target = Path(path)
    current = _load(target)
    identities = dict(current.identities)
    identities[username] = HumanIdentity(
        username=username,
        principal_id=principal_id,
        role=role,
        password_record=_password_record(password, random_bytes),
    )
    updated = _commit(target, current, identities)
    identity = updated.identities[username]
    return HumanIdentityManagementResult(
        "set",
        identity.username,
        identity.principal_id,
        identity.role,
        updated.generation,
        len(updated.identities),
    )


def remove_human_identity(
    path: Path,
    *,
    username: str,
) -> HumanIdentityManagementResult:
    """Remove one exact identity and bump the session policy generation."""
    target = Path(path)
    current = _load(target)
    identity = current.identities.get(username)
    if identity is None:
        raise HumanIdentityManagementError("human identity does not exist")
    identities = dict(current.identities)
    del identities[username]
    updated = _commit(target, current, identities)
    return HumanIdentityManagementResult(
        "remove",
        identity.username,
        identity.principal_id,
        identity.role,
        updated.generation,
        len(updated.identities),
    )


__all__ = (
    "HumanIdentityManagementError",
    "HumanIdentityManagementResult",
    "remove_human_identity",
    "set_human_identity",
)
