"""Administration token, password, and session persistence policy."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
import tempfile
from collections.abc import Callable
from pathlib import Path


PASSWORD_RECORD_FIELDS = frozenset({
    "algorithm", "iterations", "salt", "hash",
})
MAXIMUM_PASSWORD_RECORD_BYTES = 4096
MAXIMUM_LEGACY_SESSION_BYTES = 1024 * 1024
MAXIMUM_LEGACY_SESSIONS = 256


class AdminPasswordConfigurationError(RuntimeError):
    """Raised when enforcement cannot safely admit the password record."""


class AdminSessionStoreError(RuntimeError):
    """Raised when legacy session state cannot be safely committed."""


def _password_hex(value: object, *, minimum: int, maximum: int) -> bytes:
    if not isinstance(value, str):
        raise AdminPasswordConfigurationError(
            "administrator password record has an invalid format"
        )
    try:
        decoded = bytes.fromhex(value)
    except ValueError as exc:
        raise AdminPasswordConfigurationError(
            "administrator password record has an invalid format"
        ) from exc
    if not minimum <= len(decoded) <= maximum or decoded.hex() != value:
        raise AdminPasswordConfigurationError(
            "administrator password record has an invalid format"
        )
    return decoded


def _validate_password_parent(path: Path) -> None:
    try:
        parent = path.parent.lstat()
    except OSError as exc:
        raise AdminPasswordConfigurationError(
            "administrator password record is unavailable"
        ) from exc
    if (
        not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != os.getuid()
        or stat.S_IMODE(parent.st_mode) != 0o700
    ):
        raise AdminPasswordConfigurationError(
            "administrator password directory must be owner-only"
        )


def _owner_private_password_payload(path: Path) -> bytes:
    _validate_password_parent(path)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise AdminPasswordConfigurationError(
            "administrator password record is unavailable"
        ) from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or not 1 <= metadata.st_size <= MAXIMUM_PASSWORD_RECORD_BYTES
        ):
            raise AdminPasswordConfigurationError(
                "administrator password record must be an owner-only regular file"
            )
        payload = os.read(descriptor, MAXIMUM_PASSWORD_RECORD_BYTES + 1)
    finally:
        os.close(descriptor)
    return payload


def validate_password_record(record: object) -> dict[str, object]:
    """Validate one exact PBKDF2 record independent of its file owner."""
    if (
        not isinstance(record, dict)
        or set(record) != PASSWORD_RECORD_FIELDS
        or record.get("algorithm") != "pbkdf2_sha256"
    ):
        raise AdminPasswordConfigurationError(
            "administrator password record has an invalid format"
        )
    iterations = record.get("iterations")
    if (
        not isinstance(iterations, int)
        or isinstance(iterations, bool)
        or not 200_000 <= iterations <= 5_000_000
    ):
        raise AdminPasswordConfigurationError(
            "administrator password record has an invalid format"
        )
    _password_hex(record.get("salt"), minimum=16, maximum=64)
    _password_hex(record.get("hash"), minimum=32, maximum=32)
    return dict(record)


def _validated_password_record(payload: bytes) -> dict[str, object]:
    try:
        record = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AdminPasswordConfigurationError(
            "administrator password record has an invalid format"
        ) from exc
    return validate_password_record(record)


def load_enforcement_admin_password_record(path: Path) -> dict[str, object]:
    """Load an exact owner-only record without following filesystem links."""
    return _validated_password_record(_owner_private_password_payload(path))


def _admin_session_parent_present(state_dir: Path) -> bool:
    try:
        parent = state_dir.lstat()
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise AdminSessionStoreError(
            "administrator session directory metadata is unavailable"
        ) from exc
    if (
        not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != os.getuid()
        or stat.S_IMODE(parent.st_mode) != 0o700
    ):
        raise AdminSessionStoreError(
            "administrator session directory must be owner-only"
        )
    return True


def _owner_private_legacy_session_payload(path: Path) -> bytes | None:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise AdminSessionStoreError(
            "administrator session file is unavailable"
        ) from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size > MAXIMUM_LEGACY_SESSION_BYTES
        ):
            raise AdminSessionStoreError(
                "administrator session file must be a bounded owner-only regular file"
            )
        return os.read(descriptor, MAXIMUM_LEGACY_SESSION_BYTES + 1)
    finally:
        os.close(descriptor)


def validate_admin_session_store(state_dir: Path, path: Path) -> int:
    """Validate retained legacy session custody without creating state."""
    if Path(path).parent != Path(state_dir):
        raise AdminSessionStoreError(
            "administrator session file must remain inside its state directory"
        )
    if not _admin_session_parent_present(state_dir):
        return 0
    payload = _owner_private_legacy_session_payload(path)
    if payload is None:
        return 0
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AdminSessionStoreError(
            "administrator session file is malformed"
        ) from exc
    if not isinstance(value, dict) or len(value) > MAXIMUM_LEGACY_SESSIONS:
        raise AdminSessionStoreError(
            "administrator session file has an invalid session map"
        )
    return len(value)


def ensure_admin_token(
    path: Path,
    *,
    random_bytes: Callable[[int], bytes],
) -> str:
    try:
        token = path.read_text(encoding="utf-8").strip()
        if re.fullmatch(r"[a-f0-9]{64}", token):
            return token
    except Exception:
        pass
    path.parent.mkdir(parents=True, exist_ok=True)
    token = random_bytes(32).hex()
    path.write_text(token, encoding="utf-8")
    try:
        path.chmod(0o600)
    except Exception:
        pass
    return token


def load_admin_password_record(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and data.get("algorithm") == "pbkdf2_sha256":
            return data
    except Exception:
        pass
    return None


def verify_admin_password(password: str, record: dict | None) -> bool:
    if not record or not password:
        return False
    try:
        iterations = int(record.get("iterations", 0))
        salt = bytes.fromhex(str(record.get("salt", "")))
        expected = bytes.fromhex(str(record.get("hash", "")))
        if iterations < 200_000 or not salt or not expected:
            return False
        actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, iterations
        )
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def admin_session_hash(session_id: str) -> str:
    return hashlib.sha256(session_id.encode("utf-8")).hexdigest()


def load_admin_sessions(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _prepare_private_session_directory(path: Path) -> None:
    try:
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        metadata = path.lstat()
        if (
            stat.S_ISDIR(metadata.st_mode)
            and metadata.st_uid == os.getuid()
            and stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            path.chmod(0o700)
            metadata = path.lstat()
    except OSError as exc:
        raise AdminSessionStoreError(
            "administrator session directory could not be prepared"
        ) from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise AdminSessionStoreError(
            "administrator session directory must be owner-only"
        )


def _validate_session_file(path: Path) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise AdminSessionStoreError(
            "administrator session file metadata is unavailable"
        ) from exc
    if (
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == os.getuid()
        and stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        try:
            path.chmod(0o600)
            metadata = path.lstat()
        except OSError as exc:
            raise AdminSessionStoreError(
                "administrator session file permissions could not be tightened"
            ) from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise AdminSessionStoreError(
            "administrator session file must be an owner-only regular file"
        )


def _atomic_session_write(path: Path, payload: bytes) -> None:
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
        raise AdminSessionStoreError(
            "administrator session commit failed"
        ) from exc
    finally:
        if temporary is not None:
            try:
                temporary.unlink()
            except OSError:
                pass


def save_admin_sessions(state_dir: Path, path: Path, sessions: dict) -> None:
    if Path(path).parent != Path(state_dir):
        raise AdminSessionStoreError(
            "administrator session file must remain inside its state directory"
        )
    _prepare_private_session_directory(state_dir)
    _validate_session_file(path)
    try:
        payload = json.dumps(
            sessions, indent=2, sort_keys=True
        ).encode("utf-8") + b"\n"
    except (TypeError, ValueError) as exc:
        raise AdminSessionStoreError(
            "administrator session state is not serializable"
        ) from exc
    _atomic_session_write(path, payload)


def prune_admin_sessions(
    sessions: dict,
    *,
    now_timestamp: int,
    save_sessions: Callable[[dict], None],
) -> dict:
    pruned = {
        sid_hash: meta
        for sid_hash, meta in sessions.items()
        if isinstance(meta, dict)
        and int(meta.get("expires_at", 0) or 0) > now_timestamp
    }
    if pruned != sessions:
        save_sessions(pruned)
    return pruned


def create_admin_session(
    client_ip: str,
    *,
    now_timestamp: int,
    ttl_seconds: int,
    new_session_id: Callable[[], str],
    load_pruned_sessions: Callable[[], dict],
    save_sessions: Callable[[dict], None],
) -> str:
    session_id = new_session_id()
    sessions = load_pruned_sessions()
    sessions[admin_session_hash(session_id)] = {
        "created_at": now_timestamp,
        "expires_at": now_timestamp + ttl_seconds,
        "client_ip": client_ip,
    }
    save_sessions(sessions)
    return session_id


def destroy_admin_session(
    session_id: str,
    *,
    load_sessions: Callable[[], dict],
    save_sessions: Callable[[dict], None],
) -> None:
    if not session_id:
        return
    sessions = load_sessions()
    sessions.pop(admin_session_hash(session_id), None)
    save_sessions(sessions)


def parse_cookie_header(cookie_header: str | None) -> dict[str, str]:
    cookies: dict[str, str] = {}
    if not cookie_header:
        return cookies
    for part in cookie_header.split(";"):
        if "=" not in part:
            continue
        name, value = part.split("=", 1)
        cookies[name.strip()] = value.strip()
    return cookies


def admin_session_cookie_header(
    cookie_name: str,
    session_id: str,
    max_age: int,
) -> str:
    return f"{cookie_name}={session_id}; Path=/; Max-Age={max_age}; HttpOnly; SameSite=Strict"


def expired_admin_session_cookie_header(cookie_name: str) -> str:
    return f"{cookie_name}=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"
