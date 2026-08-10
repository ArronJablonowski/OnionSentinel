"""Capability, limit, timeout, and stdin policy for bounded subprocesses."""
from __future__ import annotations

import os
import secrets
import stat
import tempfile
import threading
import time
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass


class BoundedProcessError(RuntimeError):
    """Raised when a child exceeds its output or runtime contract."""


class _ProcessSnapshotError(BoundedProcessError):
    """Raised when a process-tree safety snapshot cannot be trusted."""


_PS_SNAPSHOT_TIMEOUT_SECONDS = 2.0
_PS_SNAPSHOT_STDOUT_BYTES = 16 * 1024 * 1024
_PS_SNAPSHOT_STDERR_BYTES = 64 * 1024
_PROCESS_STARTUP_TRACK_SECONDS = 2.0
_PROCESS_STARTUP_TRACK_INTERVAL_SECONDS = 0.2
_PROCESS_TRACK_INTERVAL_SECONDS = 5.0
_NATURAL_DESCENDANT_GRACE_SECONDS = 1.0
_TERMINATE_GRACE_SECONDS = 0.5
_KILL_GRACE_SECONDS = 1.0
_CONTAINMENT_FD_ENV = "ONION_SENTINEL_BOUNDED_CAPABILITY_FD"
_CONTAINMENT_TOKEN_ENV = "ONION_SENTINEL_BOUNDED_CAPABILITY_TOKEN"
_CONTAINMENT_PREFIX = b"onion-sentinel-bounded-v1\0"


@dataclass
class _ProcessContainment:
    """One inherited capability that keeps nested runners in one process group."""

    environment: dict[str, str]
    capability_fd: int
    owns_process_group: bool
    owned_capability: object | None = None

    def close(self) -> None:
        if self.owned_capability is not None:
            self.owned_capability.close()  # type: ignore[attr-defined]


def _validated_inherited_capability() -> tuple[int, str] | None:
    """Return the ambient bounded-run capability only when its FD proves it."""

    raw_fd = os.environ.get(_CONTAINMENT_FD_ENV, "")
    token = os.environ.get(_CONTAINMENT_TOKEN_ENV, "")
    if len(token) != 64 or any(
        character not in "0123456789abcdef" for character in token
    ):
        return None
    try:
        descriptor = int(raw_fd)
    except (TypeError, ValueError):
        return None
    if descriptor < 3:
        return None
    try:
        metadata = os.fstat(descriptor)
        expected = _CONTAINMENT_PREFIX + token.encode("ascii")
        actual = os.pread(descriptor, len(expected) + 1, 0)
    except (OSError, ValueError):
        return None
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
        or actual != expected
    ):
        return None
    return descriptor, token


def _new_process_capability() -> tuple[object, int, str]:
    owned_capability = tempfile.TemporaryFile()
    descriptor = owned_capability.fileno()
    os.fchmod(descriptor, 0o600)
    token = secrets.token_hex(32)
    payload = _CONTAINMENT_PREFIX + token.encode("ascii")
    owned_capability.write(payload)
    owned_capability.flush()
    if os.pread(descriptor, len(payload) + 1, 0) != payload:
        owned_capability.close()
        raise BoundedProcessError(
            "could not initialize the bounded-process containment capability"
        )
    return owned_capability, descriptor, token


def _prepare_process_containment(
    requested_environment: dict[str, str] | None,
) -> _ProcessContainment:
    """Create or inherit the private capability for one trusted process tree."""

    environment = dict(
        os.environ if requested_environment is None else requested_environment
    )
    environment.pop(_CONTAINMENT_FD_ENV, None)
    environment.pop(_CONTAINMENT_TOKEN_ENV, None)

    inherited = _validated_inherited_capability()
    if inherited is not None:
        descriptor, token = inherited
        owns_process_group = False
        owned_capability = None
    else:
        owned_capability, descriptor, token = _new_process_capability()
        owns_process_group = True

    environment[_CONTAINMENT_FD_ENV] = str(descriptor)
    environment[_CONTAINMENT_TOKEN_ENV] = token
    return _ProcessContainment(
        environment=environment,
        capability_fd=descriptor,
        owns_process_group=owns_process_group,
        owned_capability=owned_capability,
    )


def _validate_process_limits(
    *,
    timeout_seconds: float,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
    progress_interval_seconds: float | None = None,
) -> None:
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    if max_stdout_bytes <= 0 or max_stderr_bytes <= 0:
        raise ValueError("output limits must be positive")
    if progress_interval_seconds is not None and progress_interval_seconds <= 0:
        raise ValueError("progress_interval_seconds must be positive")


def _select_timeout(
    *,
    deadline: float,
    next_progress: float,
    progress_callback: Callable[[], None] | None,
) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return 0.0
    timeout = min(0.25, remaining)
    if progress_callback is not None:
        timeout = min(timeout, max(0.0, next_progress - time.monotonic()))
    return timeout


@contextmanager
def _pipe_stdin(payload: bytes):
    """Yield a pipe-backed stdin stream without staging payload bytes on disk."""

    read_fd, write_fd = os.pipe()
    read_stream = os.fdopen(read_fd, "rb", closefd=True)

    def write_payload() -> None:
        remaining = memoryview(payload)
        try:
            while remaining:
                written = os.write(write_fd, remaining[: 64 * 1024])
                remaining = remaining[written:]
        except (BrokenPipeError, OSError):
            pass
        finally:
            try:
                os.close(write_fd)
            except OSError:
                pass

    writer = threading.Thread(
        target=write_payload,
        name="bounded-process-stdin",
        daemon=True,
    )
    writer.start()
    try:
        yield read_stream
    finally:
        read_stream.close()
        writer.join(timeout=1.0)
