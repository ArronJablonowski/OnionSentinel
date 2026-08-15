"""Owner-only atomic persistence for versioned human-session records."""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import threading
from typing import Callable, Iterator

from portal_session_principal import is_valid_session_record


STORE_SCHEMA = "onion-sentinel-human-session-store-v1"
DEFAULT_MAXIMUM_BYTES = 1024 * 1024
DEFAULT_MAXIMUM_SESSIONS = 256
SESSION_ID_MINIMUM_BYTES = 32
SESSION_ID_MAXIMUM_BYTES = 512
SESSION_KEY_RE = re.compile(r"^[a-f0-9]{64}$")
_STORE_LOCK = threading.Lock()


class HumanSessionStoreError(RuntimeError):
    """Raised when versioned session state is malformed or unsafe."""


def _bounds(maximum_bytes: int, maximum_sessions: int) -> None:
    if maximum_bytes < 1 or maximum_sessions < 1:
        raise HumanSessionStoreError("session store bounds must be positive")


def _session_key(session_id: object) -> str:
    if not isinstance(session_id, str):
        raise HumanSessionStoreError("session identifier has an invalid type")
    try:
        encoded = session_id.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise HumanSessionStoreError(
            "session identifier has an invalid encoding"
        ) from exc
    if not SESSION_ID_MINIMUM_BYTES <= len(encoded) <= SESSION_ID_MAXIMUM_BYTES:
        raise HumanSessionStoreError("session identifier has an invalid size")
    return hashlib.sha256(encoded).hexdigest()


def _private_parent(parent: Path, *, create: bool) -> bool:
    if not parent.exists():
        if not create:
            return False
        try:
            parent.mkdir(parents=True, mode=0o700)
            parent.chmod(0o700)
        except OSError as exc:
            raise HumanSessionStoreError(
                "session store directory could not be prepared"
            ) from exc
    try:
        metadata = parent.lstat()
    except OSError as exc:
        raise HumanSessionStoreError(
            "session store parent metadata could not be read"
        ) from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise HumanSessionStoreError(
            "session store parent must be an owner-only directory"
        )
    return True


def _private_file(path: Path, *, allow_missing: bool = True) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        if allow_missing:
            return False
        raise HumanSessionStoreError("session store file is unavailable")
    except OSError as exc:
        raise HumanSessionStoreError(
            "session store metadata could not be read"
        ) from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise HumanSessionStoreError(
            "session store must be an owner-only regular file"
        )
    return True


def _validate_records(
    records: object,
    maximum_sessions: int,
) -> dict[str, dict[str, object]]:
    if not isinstance(records, dict) or len(records) > maximum_sessions:
        raise HumanSessionStoreError("session store has an invalid session map")
    validated: dict[str, dict[str, object]] = {}
    for key, record in records.items():
        if (
            not isinstance(key, str)
            or not SESSION_KEY_RE.fullmatch(key)
            or not is_valid_session_record(record)
        ):
            raise HumanSessionStoreError(
                "session store contains an invalid record"
            )
        assert isinstance(record, dict)
        validated[key] = dict(record)
    return validated


def _decode_store(
    path: Path,
    maximum_bytes: int,
    maximum_sessions: int,
) -> dict[str, dict[str, object]]:
    if not _private_file(path):
        return {}
    try:
        metadata = path.stat()
        if metadata.st_size > maximum_bytes:
            raise HumanSessionStoreError("session store exceeds size limit")
        payload = path.read_bytes()
        envelope = json.loads(payload.decode("utf-8"))
    except HumanSessionStoreError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HumanSessionStoreError("session store is malformed") from exc
    if (
        not isinstance(envelope, dict)
        or set(envelope) != {"schema", "sessions"}
        or envelope.get("schema") != STORE_SCHEMA
    ):
        raise HumanSessionStoreError("session store envelope is invalid")
    return _validate_records(envelope.get("sessions"), maximum_sessions)


def _encode_store(
    records: dict[str, dict[str, object]],
    maximum_bytes: int,
    maximum_sessions: int,
) -> bytes:
    validated = _validate_records(records, maximum_sessions)
    payload = json.dumps(
        {"schema": STORE_SCHEMA, "sessions": validated},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8") + b"\n"
    if len(payload) > maximum_bytes:
        raise HumanSessionStoreError("session store exceeds size limit")
    return payload


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
        raise HumanSessionStoreError("session store commit failed") from exc
    finally:
        if temporary is not None:
            try:
                temporary.unlink()
            except OSError:
                pass


@contextmanager
def _locked(path: Path) -> Iterator[None]:
    lock_path = path.with_name(f".{path.name}.lock")
    _private_file(lock_path)
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(lock_path, flags, 0o600)
    except OSError as exc:
        raise HumanSessionStoreError("session store lock failed") from exc
    try:
        os.fchmod(descriptor, 0o600)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise HumanSessionStoreError("session store lock is unsafe")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        os.close(descriptor)


def _mutate(
    path: Path,
    operation: Callable[[dict[str, dict[str, object]]], tuple[object, bool]],
    *,
    maximum_bytes: int,
    maximum_sessions: int,
) -> object:
    _bounds(maximum_bytes, maximum_sessions)
    with _STORE_LOCK:
        _private_parent(path.parent, create=True)
        with _locked(path):
            records = _decode_store(path, maximum_bytes, maximum_sessions)
            result, changed = operation(records)
            if changed:
                _atomic_write(
                    path,
                    _encode_store(records, maximum_bytes, maximum_sessions),
                )
            return result


def load_session_record(
    path: Path,
    session_id: object,
    *,
    maximum_bytes: int = DEFAULT_MAXIMUM_BYTES,
    maximum_sessions: int = DEFAULT_MAXIMUM_SESSIONS,
) -> dict[str, object] | None:
    _bounds(maximum_bytes, maximum_sessions)
    key = _session_key(session_id)
    with _STORE_LOCK:
        if not _private_parent(path.parent, create=False):
            return None
        if not path.exists():
            return None
        with _locked(path):
            record = _decode_store(path, maximum_bytes, maximum_sessions).get(key)
            return dict(record) if record is not None else None


def put_session_record(
    path: Path,
    session_id: object,
    record: object,
    *,
    maximum_bytes: int = DEFAULT_MAXIMUM_BYTES,
    maximum_sessions: int = DEFAULT_MAXIMUM_SESSIONS,
) -> None:
    key = _session_key(session_id)
    if not is_valid_session_record(record):
        raise HumanSessionStoreError("session record has an invalid shape")
    assert isinstance(record, dict)

    def operation(records: dict[str, dict[str, object]]) -> tuple[None, bool]:
        if key not in records and len(records) >= maximum_sessions:
            raise HumanSessionStoreError("session store exceeds session limit")
        records[key] = dict(record)
        return None, True

    _mutate(
        path,
        operation,
        maximum_bytes=maximum_bytes,
        maximum_sessions=maximum_sessions,
    )


def replace_session_record(
    path: Path,
    session_id: object,
    *,
    expected_record: object,
    replacement: object,
    maximum_bytes: int = DEFAULT_MAXIMUM_BYTES,
    maximum_sessions: int = DEFAULT_MAXIMUM_SESSIONS,
) -> bool:
    key = _session_key(session_id)
    if not is_valid_session_record(replacement):
        raise HumanSessionStoreError("replacement session record is invalid")
    assert isinstance(replacement, dict)

    def operation(records: dict[str, dict[str, object]]) -> tuple[bool, bool]:
        if records.get(key) != expected_record:
            return False, False
        records[key] = dict(replacement)
        return True, True

    return bool(_mutate(
        path,
        operation,
        maximum_bytes=maximum_bytes,
        maximum_sessions=maximum_sessions,
    ))


def delete_session_record(
    path: Path,
    session_id: object,
    *,
    maximum_bytes: int = DEFAULT_MAXIMUM_BYTES,
    maximum_sessions: int = DEFAULT_MAXIMUM_SESSIONS,
) -> bool:
    key = _session_key(session_id)

    def operation(records: dict[str, dict[str, object]]) -> tuple[bool, bool]:
        if key not in records:
            return False, False
        del records[key]
        return True, True

    return bool(_mutate(
        path,
        operation,
        maximum_bytes=maximum_bytes,
        maximum_sessions=maximum_sessions,
    ))


__all__ = (
    "DEFAULT_MAXIMUM_BYTES",
    "DEFAULT_MAXIMUM_SESSIONS",
    "HumanSessionStoreError",
    "STORE_SCHEMA",
    "delete_session_record",
    "load_session_record",
    "put_session_record",
    "replace_session_record",
)
