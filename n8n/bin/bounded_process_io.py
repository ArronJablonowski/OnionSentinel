"""Bounded stdout/stderr capture owners for subprocess execution."""
from __future__ import annotations

import os
import selectors
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import BinaryIO

from bounded_process_policy import BoundedProcessError


class _MemoryCapture:
    def __init__(self, *, max_stdout_bytes: int, max_stderr_bytes: int) -> None:
        self.targets = {
            "stdout": bytearray(),
            "stderr": bytearray(),
        }
        self.limits = {
            "stdout": max_stdout_bytes,
            "stderr": max_stderr_bytes,
        }

    def register(
        self,
        selector: selectors.BaseSelector,
        process: subprocess.Popen[bytes],
    ) -> None:
        assert process.stdout is not None and process.stderr is not None
        for label, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, label)

    def start(self) -> None:
        return None

    def consume(
        self,
        selector: selectors.BaseSelector,
        key: selectors.SelectorKey,
    ) -> None:
        stream = key.fileobj
        label = str(key.data)
        target = self.targets[label]
        limit = self.limits[label]
        try:
            chunk = os.read(
                stream.fileno(),
                min(64 * 1024, limit + 1 - len(target)),
            )
        except BlockingIOError:
            return
        if not chunk:
            selector.unregister(stream)
            return
        target.extend(chunk)
        if len(target) > limit:
            raise BoundedProcessError(
                f"command {label} exceeded the {limit}-byte limit"
            )

    def finish(self) -> None:
        return None

    def abort(self, exception: BaseException) -> None:
        del exception

    def completed(
        self,
        command: Sequence[str],
        return_code: int,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            list(command),
            return_code,
            bytes(self.targets["stdout"]).decode("utf-8", errors="replace"),
            bytes(self.targets["stderr"]).decode("utf-8", errors="replace"),
        )


class _FileCapture:
    def __init__(
        self,
        destination: Path | str,
        *,
        max_stdout_bytes: int,
        max_stderr_bytes: int,
    ) -> None:
        self.destination = Path(destination)
        self.max_stdout_bytes = max_stdout_bytes
        self.max_stderr_bytes = max_stderr_bytes
        self.stderr = bytearray()
        self.stdout_bytes = 0
        self.output: BinaryIO | None = None
        self.started = False

    def prepare(self) -> None:
        self.destination.parent.mkdir(parents=True, exist_ok=True)

    def register(
        self,
        selector: selectors.BaseSelector,
        process: subprocess.Popen[bytes],
    ) -> None:
        assert process.stdout is not None and process.stderr is not None
        for label, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, label)

    def start(self) -> None:
        self.output = self.destination.open("wb")
        self.started = True

    def consume(
        self,
        selector: selectors.BaseSelector,
        key: selectors.SelectorKey,
    ) -> None:
        stream = key.fileobj
        try:
            chunk = os.read(stream.fileno(), 64 * 1024)
        except BlockingIOError:
            return
        if not chunk:
            selector.unregister(stream)
            return
        if key.data == "stdout":
            self.stdout_bytes += len(chunk)
            if self.stdout_bytes > self.max_stdout_bytes:
                raise BoundedProcessError(
                    f"command stdout exceeded the {self.max_stdout_bytes}-byte file limit"
                )
            assert self.output is not None
            self.output.write(chunk)
            return
        if len(self.stderr) + len(chunk) > self.max_stderr_bytes:
            raise BoundedProcessError(
                f"command stderr exceeded the {self.max_stderr_bytes}-byte limit"
            )
        self.stderr.extend(chunk)

    def finish(self) -> None:
        assert self.output is not None
        self.output.flush()
        os.fsync(self.output.fileno())
        self.output.close()
        self.output = None

    def abort(self, exception: BaseException) -> None:
        if self.output is not None:
            try:
                self.output.close()
            except OSError:
                pass
            self.output = None
        if not self.started:
            return
        try:
            self.destination.unlink(missing_ok=True)
        except OSError as unlink_error:
            from bounded_process_termination import _attach_cleanup_diagnostic

            _attach_cleanup_diagnostic(
                exception,
                "partial output cleanup failed: "
                f"{type(unlink_error).__name__}: {unlink_error}",
            )

    def completed(
        self,
        command: Sequence[str],
        return_code: int,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            list(command),
            return_code,
            "",
            bytes(self.stderr).decode("utf-8", errors="replace"),
        )
