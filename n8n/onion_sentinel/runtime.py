"""Explicit runtime dependencies shared by future composition roots."""
from __future__ import annotations

from dataclasses import dataclass
import datetime as dt
from pathlib import Path
from typing import Any, Callable, Mapping, Optional, Sequence
import uuid


Clock = Callable[[], dt.datetime]
IdFactory = Callable[[], str]
ReadBytes = Callable[[Path, int], bytes]
AtomicWriteBytes = Callable[[Path, bytes], None]
HttpJson = Callable[
    [str, str, Mapping[str, str], Optional[bytes], float],
    Mapping[str, Any],
]
RunProcess = Callable[
    [Sequence[str], bytes, float, Mapping[str, str]],
    tuple[int, bytes, bytes],
]


def system_clock() -> dt.datetime:
    return dt.datetime.now().astimezone()


def uuid4_hex() -> str:
    return uuid.uuid4().hex


@dataclass(frozen=True)
class RuntimeDependencies:
    """Side-effect seams supplied by an executable composition root."""

    clock: Clock = system_clock
    id_factory: IdFactory = uuid4_hex
    read_bytes: ReadBytes | None = None
    atomic_write_bytes: AtomicWriteBytes | None = None
    http_json: HttpJson | None = None
    run_process: RunProcess | None = None

    def require_filesystem(self) -> tuple[ReadBytes, AtomicWriteBytes]:
        if self.read_bytes is None or self.atomic_write_bytes is None:
            raise RuntimeError("filesystem dependencies are not configured")
        return self.read_bytes, self.atomic_write_bytes

    def require_external_io(self) -> tuple[HttpJson, RunProcess]:
        if self.http_json is None or self.run_process is None:
            raise RuntimeError("external I/O dependencies are not configured")
        return self.http_json, self.run_process
