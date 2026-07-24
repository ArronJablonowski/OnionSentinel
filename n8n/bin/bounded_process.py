#!/usr/bin/env python3
"""Run external LLM harnesses without unbounded stdout/stderr buffering."""
from __future__ import annotations

import os
import selectors
import signal
import subprocess
import tempfile
import time
from collections.abc import Callable, Sequence
from pathlib import Path


class BoundedProcessError(RuntimeError):
    """Raised when a child exceeds its output or runtime contract."""


def run_bounded_command(
    command: Sequence[str],
    *,
    stdin_text: str = "",
    timeout_seconds: float,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
    cwd: Path | str | None = None,
    env: dict[str, str] | None = None,
    preexec_fn: Callable[[], None] | None = None,
    progress_callback: Callable[[], None] | None = None,
    progress_interval_seconds: float = 30,
) -> subprocess.CompletedProcess[str]:
    """Execute a command while continuously enforcing output ceilings.

    The input is staged in an anonymous temporary file so a large prompt cannot
    deadlock a pipe before stdout is drained.  stdout and stderr remain pipes,
    but are read incrementally and the child is killed as soon as either hard
    limit is crossed.
    """
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    if max_stdout_bytes <= 0 or max_stderr_bytes <= 0:
        raise ValueError("output limits must be positive")
    if progress_interval_seconds <= 0:
        raise ValueError("progress_interval_seconds must be positive")

    with tempfile.TemporaryFile() as stdin_file:
        stdin_file.write(stdin_text.encode("utf-8"))
        stdin_file.seek(0)
        process = subprocess.Popen(
            list(command),
            stdin=stdin_file,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(cwd) if cwd is not None else None,
            env=env,
            preexec_fn=preexec_fn,
            # A timed-out parser may have spawned helper processes. A new
            # session lets us terminate the complete tree instead of leaking
            # descendants that continue consuming CPU, memory, or disk.
            start_new_session=True,
        )
        assert process.stdout is not None and process.stderr is not None
        selector = selectors.DefaultSelector()
        streams = {
            process.stdout: ("stdout", bytearray(), max_stdout_bytes),
            process.stderr: ("stderr", bytearray(), max_stderr_bytes),
        }
        for stream in streams:
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ)

        deadline = time.monotonic() + timeout_seconds
        next_progress = time.monotonic() + progress_interval_seconds
        try:
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise BoundedProcessError(f"command timed out after {timeout_seconds:g} seconds")
                progress_remaining = max(0.0, next_progress - time.monotonic())
                events = selector.select(timeout=min(0.25, remaining, progress_remaining))
                if progress_callback is not None and time.monotonic() >= next_progress:
                    # The callback is deliberately synchronous: if durable
                    # ownership cannot be renewed, its exception enters the
                    # process-group cleanup path below and prevents an orphaned
                    # LLM invocation from publishing stale results.
                    progress_callback()
                    next_progress = time.monotonic() + progress_interval_seconds
                if not events and process.poll() is not None:
                    # One final nonblocking pass drains bytes written just
                    # before process exit; EOF then unregisters each stream.
                    events = [(key, selectors.EVENT_READ) for key in selector.get_map().values()]
                for key, _ in events:
                    stream = key.fileobj
                    label, target, limit = streams[stream]
                    try:
                        chunk = os.read(stream.fileno(), min(64 * 1024, limit + 1 - len(target)))
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(stream)
                        continue
                    target.extend(chunk)
                    if len(target) > limit:
                        raise BoundedProcessError(f"command {label} exceeded the {limit}-byte limit")
            return_code = process.wait(timeout=max(0.1, deadline - time.monotonic()))
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                process.kill()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
            raise
        finally:
            selector.close()
            process.stdout.close()
            process.stderr.close()

    stdout = bytes(streams[process.stdout][1]).decode("utf-8", errors="replace")
    stderr = bytes(streams[process.stderr][1]).decode("utf-8", errors="replace")
    return subprocess.CompletedProcess(list(command), return_code, stdout, stderr)


def run_bounded_command_to_file(
    command: Sequence[str],
    destination: Path | str,
    *,
    timeout_seconds: float,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
    cwd: Path | str | None = None,
    env: dict[str, str] | None = None,
    preexec_fn: Callable[[], None] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Stream child stdout to disk while enforcing time and byte ceilings.

    PCAP exports can be much larger than memory, so buffering stdout in a
    ``CompletedProcess`` is unsafe. This variant drains both pipes
    concurrently, writes stdout incrementally, and kills the complete process
    group on timeout or overflow. The caller atomically publishes the file only
    after validating its expected size and digest.
    """
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    if max_stdout_bytes <= 0 or max_stderr_bytes <= 0:
        raise ValueError("output limits must be positive")

    destination_path = Path(destination)
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    process = subprocess.Popen(
        list(command),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=str(cwd) if cwd is not None else None,
        env=env,
        preexec_fn=preexec_fn,
        start_new_session=True,
    )
    assert process.stdout is not None and process.stderr is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    stderr = bytearray()
    stdout_bytes = 0
    deadline = time.monotonic() + timeout_seconds

    try:
        with destination_path.open("wb") as output:
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise BoundedProcessError(f"command timed out after {timeout_seconds:g} seconds")
                events = selector.select(timeout=min(0.25, remaining))
                if not events and process.poll() is not None:
                    events = [(key, selectors.EVENT_READ) for key in selector.get_map().values()]
                for key, _ in events:
                    stream = key.fileobj
                    try:
                        chunk = os.read(stream.fileno(), 64 * 1024)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(stream)
                        continue
                    if key.data == "stdout":
                        stdout_bytes += len(chunk)
                        if stdout_bytes > max_stdout_bytes:
                            raise BoundedProcessError(
                                f"command stdout exceeded the {max_stdout_bytes}-byte file limit"
                            )
                        output.write(chunk)
                    else:
                        if len(stderr) + len(chunk) > max_stderr_bytes:
                            raise BoundedProcessError(
                                f"command stderr exceeded the {max_stderr_bytes}-byte limit"
                            )
                        stderr.extend(chunk)
            output.flush()
            os.fsync(output.fileno())
        return_code = process.wait(timeout=max(0.1, deadline - time.monotonic()))
    except BaseException:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            process.kill()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
        destination_path.unlink(missing_ok=True)
        raise
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()

    return subprocess.CompletedProcess(
        list(command),
        return_code,
        "",
        bytes(stderr).decode("utf-8", errors="replace"),
    )
