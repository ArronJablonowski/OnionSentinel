"""Owner-controlled password recovery and human-session invalidation."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile

from portal_human_session_store import STORE_SCHEMA


ADMIN_PASSWORD_FILENAME = "onion-sentinel-admin-password.json"
LEGACY_SESSION_FILENAME = ".admin_sessions.json"
HUMAN_SESSION_FILENAME = ".human_sessions.json"
PASSWORD_ITERATIONS = 600_000
PASSWORD_MINIMUM_BYTES = 16
PASSWORD_MAXIMUM_BYTES = 1024


class AdminRecoveryError(RuntimeError):
    """Raised when administrator recovery cannot preserve safe custody."""


@dataclass(frozen=True)
class AdminRecoveryResult:
    password_reset: bool
    legacy_sessions_revoked: bool
    human_sessions_revoked: bool


def _private_directory(path: Path) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        try:
            path.mkdir(parents=True, mode=0o700)
            path.chmod(0o700)
            metadata = path.lstat()
        except OSError as exc:
            raise AdminRecoveryError(
                "administrator recovery directory could not be prepared"
            ) from exc
    except OSError as exc:
        raise AdminRecoveryError(
            "administrator recovery directory metadata is unavailable"
        ) from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise AdminRecoveryError(
            "administrator recovery requires an owner-only directory"
        )


def _private_file(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise AdminRecoveryError(
            "administrator recovery file metadata is unavailable"
        ) from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise AdminRecoveryError(
            "administrator recovery requires an owner-only regular file"
        )
    return True


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
        raise AdminRecoveryError(
            "administrator recovery state commit failed"
        ) from exc
    finally:
        if temporary is not None:
            try:
                temporary.unlink()
            except OSError:
                pass


def _password_bytes(value: object) -> bytes:
    if not isinstance(value, str):
        raise AdminRecoveryError("administrator password has an invalid type")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise AdminRecoveryError(
            "administrator password has an invalid encoding"
        ) from exc
    if (
        not PASSWORD_MINIMUM_BYTES <= len(encoded) <= PASSWORD_MAXIMUM_BYTES
        or b"\x00" in encoded
    ):
        raise AdminRecoveryError(
            "administrator password does not meet the bounded policy"
        )
    return encoded


def _password_record(
    password: object,
    *,
    random_bytes: Callable[[int], bytes],
) -> bytes:
    encoded = _password_bytes(password)
    try:
        salt = random_bytes(32)
    except Exception as exc:
        raise AdminRecoveryError(
            "administrator password salt generation failed"
        ) from exc
    if not isinstance(salt, bytes) or len(salt) != 32:
        raise AdminRecoveryError(
            "administrator password salt generation failed"
        )
    digest = hashlib.pbkdf2_hmac(
        "sha256", encoded, salt, PASSWORD_ITERATIONS
    )
    return json.dumps(
        {
            "algorithm": "pbkdf2_sha256",
            "hash": digest.hex(),
            "iterations": PASSWORD_ITERATIONS,
            "salt": salt.hex(),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii") + b"\n"


def recover_admin_access(
    stack_dir: Path,
    *,
    new_password: str | None,
    revoke_sessions: bool,
    random_bytes: Callable[[int], bytes] = os.urandom,
) -> AdminRecoveryResult:
    """Reset local credentials and/or revoke sessions without audit mutation.

    The dashboard write listener must be stopped by the operator before this
    transaction.  Every existing target is custody-validated before any file
    is replaced, so unsafe links or permissions cannot cause partial changes.
    """
    if new_password is None and not revoke_sessions:
        raise AdminRecoveryError("administrator recovery requested no action")
    root = Path(stack_dir).expanduser()
    config_dir = root / "config"
    state_dir = root / "admin-state"
    _private_directory(config_dir)
    _private_directory(state_dir)
    password_path = config_dir / ADMIN_PASSWORD_FILENAME
    legacy_path = state_dir / LEGACY_SESSION_FILENAME
    human_path = state_dir / HUMAN_SESSION_FILENAME

    targets = [legacy_path, human_path]
    if new_password is not None:
        targets.append(password_path)
    for path in targets:
        _private_file(path)

    password_payload = (
        None
        if new_password is None
        else _password_record(new_password, random_bytes=random_bytes)
    )
    if password_payload is not None:
        _atomic_write(password_path, password_payload)
    if revoke_sessions:
        _atomic_write(legacy_path, b"{}\n")
        _atomic_write(
            human_path,
            json.dumps(
                {"schema": STORE_SCHEMA, "sessions": {}},
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii") + b"\n",
        )
    return AdminRecoveryResult(
        password_reset=password_payload is not None,
        legacy_sessions_revoked=revoke_sessions,
        human_sessions_revoked=revoke_sessions,
    )


__all__ = (
    "ADMIN_PASSWORD_FILENAME",
    "HUMAN_SESSION_FILENAME",
    "LEGACY_SESSION_FILENAME",
    "AdminRecoveryError",
    "AdminRecoveryResult",
    "recover_admin_access",
)
