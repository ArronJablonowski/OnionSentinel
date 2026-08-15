"""Owner-only atomic persistence for the keyed Administration audit chain."""
from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import tempfile
import threading

from portal_admin_audit_chain import (
    AuditContractError,
    build_event,
    verify_chain,
)


DEFAULT_MAXIMUM_BYTES = 8 * 1024 * 1024
DEFAULT_MAXIMUM_EVENTS = 10_000
_STORE_LOCK = threading.Lock()


class AuditStoreError(RuntimeError):
    """Raised when the audit ledger cannot be safely read or committed."""


def _bounds(maximum_bytes: int, maximum_events: int) -> None:
    if maximum_bytes < 1 or maximum_events < 1:
        raise AuditStoreError("audit ledger bounds must be positive")


def _regular_file(path: Path) -> None:
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise AuditStoreError("audit ledger must be a regular file")


def _ledger_payload(path: Path, maximum_bytes: int) -> bytes:
    _regular_file(path)
    if not path.exists():
        return b""
    try:
        if path.stat().st_size > maximum_bytes:
            raise AuditStoreError("audit ledger exceeds size limit")
        payload = path.read_bytes()
    except AuditStoreError:
        raise
    except OSError as exc:
        raise AuditStoreError("audit ledger could not be read") from exc
    if payload and not payload.endswith(b"\n"):
        raise AuditStoreError("audit ledger has an incomplete final event")
    return payload


def _decoded_events(path: Path, maximum_bytes: int, maximum_events: int) -> list[dict]:
    payload = _ledger_payload(path, maximum_bytes)
    lines = payload.splitlines()
    if len(lines) > maximum_events:
        raise AuditStoreError("audit ledger exceeds event limit")
    try:
        events = [json.loads(line.decode("utf-8")) for line in lines]
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AuditStoreError("audit ledger contains malformed JSON") from exc
    if any(not isinstance(event, dict) for event in events):
        raise AuditStoreError("audit ledger contains a non-object event")
    return events


def _verified_events(
    path: Path,
    signing_key: object,
    maximum_bytes: int,
    maximum_events: int,
) -> list[dict]:
    events = _decoded_events(path, maximum_bytes, maximum_events)
    verification = verify_chain(events, signing_key=signing_key)
    if not verification.valid:
        raise AuditStoreError(
            f"audit ledger verification failed: {verification.reason}"
        )
    return events


def load_verified_events(
    path: Path,
    *,
    signing_key: object,
    maximum_bytes: int = DEFAULT_MAXIMUM_BYTES,
    maximum_events: int = DEFAULT_MAXIMUM_EVENTS,
) -> list[dict]:
    _bounds(maximum_bytes, maximum_events)
    with _STORE_LOCK:
        return _verified_events(
            path, signing_key, maximum_bytes, maximum_events
        )


def _prepare_parent(path: Path) -> None:
    parent = path.parent
    created = not parent.exists()
    try:
        parent.mkdir(parents=True, exist_ok=True)
        if created:
            parent.chmod(0o700)
    except OSError as exc:
        raise AuditStoreError("audit ledger directory could not be prepared") from exc
    if parent.is_symlink() or not parent.is_dir():
        raise AuditStoreError("audit ledger parent must be a regular directory")


def _encoded_ledger(events: list[dict], maximum_bytes: int) -> bytes:
    encoded = b"".join(
        json.dumps(
            event, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8") + b"\n"
        for event in events
    )
    if len(encoded) > maximum_bytes:
        raise AuditStoreError("audit ledger exceeds size limit")
    return encoded


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
        raise AuditStoreError("audit ledger commit failed") from exc
    finally:
        if temporary is not None:
            try:
                temporary.unlink()
            except OSError:
                pass


def _append_locked(
    path: Path,
    fields: object,
    signing_key: object,
    maximum_bytes: int,
    maximum_events: int,
) -> dict[str, object]:
    lock_path = path.with_name(f".{path.name}.lock")
    _regular_file(lock_path)
    try:
        with lock_path.open("a+", encoding="utf-8") as lock_file:
            os.fchmod(lock_file.fileno(), 0o600)
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            events = _verified_events(
                path, signing_key, maximum_bytes, maximum_events
            )
            if len(events) >= maximum_events:
                raise AuditStoreError("audit ledger exceeds event limit")
            event = build_event(
                events[-1] if events else None,
                fields,
                signing_key=signing_key,
            )
            payload = _encoded_ledger([*events, event], maximum_bytes)
            _atomic_write(path, payload)
            return event
    except (AuditStoreError, AuditContractError):
        raise
    except OSError as exc:
        raise AuditStoreError("audit ledger lock failed") from exc


def append_verified_event(
    path: Path,
    fields: object,
    *,
    signing_key: object,
    maximum_bytes: int = DEFAULT_MAXIMUM_BYTES,
    maximum_events: int = DEFAULT_MAXIMUM_EVENTS,
) -> dict[str, object]:
    _bounds(maximum_bytes, maximum_events)
    build_event(None, fields, signing_key=signing_key)
    with _STORE_LOCK:
        _prepare_parent(path)
        _regular_file(path)
        return _append_locked(
            path, fields, signing_key, maximum_bytes, maximum_events
        )


__all__ = (
    "AuditStoreError",
    "DEFAULT_MAXIMUM_BYTES",
    "DEFAULT_MAXIMUM_EVENTS",
    "append_verified_event",
    "load_verified_events",
)
