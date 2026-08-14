#!/usr/bin/env python3
"""Bound subprocess control channels used by the Raspberry Pi relay.

PCAP bytes use a separate streaming path.  The commands handled here exchange
small JSON acknowledgements and metadata; treating an oversized response as a
protocol error prevents a failed or compromised peer from exhausting relay
memory before systemd can restart the service.
"""
from __future__ import annotations

import os
import selectors
import signal
import subprocess
import tempfile
import time
from collections.abc import Sequence


class BoundedProcessError(RuntimeError):
    """A child exceeded its runtime or control-channel byte contract."""


def _start_bounded_process(
    command: Sequence[str],
    stdin_file: object,
) -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        list(command),
        stdin=stdin_file,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )


def _register_process_control_channels(
    process: subprocess.Popen[bytes],
    max_stdout_bytes: int,
    max_stderr_bytes: int,
) -> tuple[selectors.BaseSelector, dict[object, tuple[str, bytearray, int]]]:
    selector = selectors.DefaultSelector()
    buffers: dict[object, tuple[str, bytearray, int]] = {
        process.stdout: ("stdout", bytearray(), int(max_stdout_bytes)),
        process.stderr: ("stderr", bytearray(), int(max_stderr_bytes)),
    }
    for stream in buffers:
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ)
    return selector, buffers


def _drain_process_control_channels(
    process: subprocess.Popen[bytes],
    selector: selectors.BaseSelector,
    buffers: dict[object, tuple[str, bytearray, int]],
    deadline: float,
    timeout_seconds: float,
) -> int:
    while selector.get_map():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise BoundedProcessError(
                f"command timed out after {timeout_seconds:g} seconds"
            )
        events = selector.select(timeout=min(0.25, remaining))
        if not events and process.poll() is not None:
            events = [(key, selectors.EVENT_READ) for key in selector.get_map().values()]
        for key, _ in events:
            stream = key.fileobj
            label, target, limit = buffers[stream]
            try:
                chunk = os.read(stream.fileno(), min(64 * 1024, limit + 1 - len(target)))
            except BlockingIOError:
                continue
            if not chunk:
                selector.unregister(stream)
                continue
            target.extend(chunk)
            if len(target) > limit:
                raise BoundedProcessError(
                    f"command {label} exceeded the {limit}-byte limit"
                )
    return process.wait(timeout=max(0.1, deadline - time.monotonic()))


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        process.kill()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()


def _close_process_control_channels(
    process: subprocess.Popen[bytes],
    selector: selectors.BaseSelector,
) -> None:
    selector.close()
    process.stdout.close()
    process.stderr.close()


def run_bounded_command(
    command: Sequence[str],
    *,
    input_bytes: bytes = b"",
    timeout_seconds: float,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
) -> subprocess.CompletedProcess[bytes]:
    """Run one command while draining stdout and stderr under hard ceilings.
    Input is staged in an anonymous file instead of a pipe.  That detail avoids
    a deadlock when a peer writes diagnostics before it consumes all input.
    A new process group lets timeout/overflow cleanup include SSH helpers and
    any descendants they may have spawned.
    """
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    if max_stdout_bytes <= 0 or max_stderr_bytes <= 0:
        raise ValueError("output limits must be positive")

    with tempfile.TemporaryFile() as stdin_file:
        stdin_file.write(input_bytes)
        stdin_file.seek(0)
        process = _start_bounded_process(command, stdin_file)
        assert process.stdout is not None and process.stderr is not None
        selector, buffers = _register_process_control_channels(
            process,
            max_stdout_bytes,
            max_stderr_bytes,
        )
        deadline = time.monotonic() + float(timeout_seconds)
        try:
            return_code = _drain_process_control_channels(
                process,
                selector,
                buffers,
                deadline,
                timeout_seconds,
            )
        except BaseException:
            _terminate_process_group(process)
            raise
        finally:
            _close_process_control_channels(process, selector)

    return subprocess.CompletedProcess(
        list(command),
        return_code,
        bytes(buffers[process.stdout][1]),
        bytes(buffers[process.stderr][1]),
    )
