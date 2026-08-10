"""Process launch and bounded monitoring orchestration."""
from __future__ import annotations

import selectors
import subprocess
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from bounded_process_io import _FileCapture, _MemoryCapture
from bounded_process_observation import (
    _DescendantTracker,
    _read_process_snapshot,
)
from bounded_process_policy import (
    _NATURAL_DESCENDANT_GRACE_SECONDS,
    BoundedProcessError,
    _ProcessContainment,
    _pipe_stdin,
    _prepare_process_containment,
    _select_timeout,
    _validate_process_limits,
)
from bounded_process_termination import (
    _attach_cleanup_diagnostic,
    _cleanup_failed_process_initialization,
    _fallback_kill_root_group,
    _terminate_process_tree,
    _wait_for_natural_descendant_exit,
)


Capture = _MemoryCapture | _FileCapture


@dataclass
class _ProcessRuntime:
    command: Sequence[str]
    process: subprocess.Popen[bytes]
    containment: _ProcessContainment
    tracker: _DescendantTracker
    selector: selectors.BaseSelector
    capture: Capture
    deadline: float
    next_progress: float
    root_exit_at: float | None = None

    def close(self) -> None:
        self.selector.close()
        assert self.process.stdout is not None and self.process.stderr is not None
        self.process.stdout.close()
        self.process.stderr.close()
        self.containment.close()


def _launch_process(
    command: Sequence[str],
    *,
    stdin: BinaryIO | int,
    cwd: Path | str | None,
    env: dict[str, str] | None,
    preexec_fn: Callable[[], None] | None,
) -> tuple[subprocess.Popen[bytes], _ProcessContainment]:
    containment = _prepare_process_containment(env)
    try:
        process = subprocess.Popen(
            list(command),
            stdin=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(cwd) if cwd is not None else None,
            env=containment.environment,
            preexec_fn=preexec_fn,
            start_new_session=containment.owns_process_group,
            pass_fds=(containment.capability_fd,),
        )
    except BaseException:
        containment.close()
        raise
    return process, containment


def _initialize_runtime(
    command: Sequence[str],
    *,
    process: subprocess.Popen[bytes],
    containment: _ProcessContainment,
    capture: Capture,
    timeout_seconds: float,
    progress_interval_seconds: float,
) -> _ProcessRuntime:
    selector: selectors.BaseSelector | None = None
    try:
        if process.stdout is None or process.stderr is None:
            raise BoundedProcessError(
                "bounded process did not expose stdout and stderr pipes"
            )
        tracker = _DescendantTracker(process.pid)
        selector = selectors.DefaultSelector()
        capture.register(selector, process)
        now = time.monotonic()
        return _ProcessRuntime(
            command=command,
            process=process,
            containment=containment,
            tracker=tracker,
            selector=selector,
            capture=capture,
            deadline=now + timeout_seconds,
            next_progress=now + progress_interval_seconds,
        )
    except BaseException as initialization_exception:
        _cleanup_failed_process_initialization(
            process,
            containment,
            selector,
            initialization_exception,
        )
        raise


def _observe_root_exit(runtime: _ProcessRuntime) -> None:
    if runtime.process.poll() is None:
        return
    if runtime.root_exit_at is None:
        runtime.root_exit_at = time.monotonic()
    if (
        time.monotonic()
        < runtime.root_exit_at + _NATURAL_DESCENDANT_GRACE_SECONDS
    ):
        return
    snapshot = _read_process_snapshot()
    leaked = runtime.tracker.verified_records(snapshot, include_root=False)
    if leaked:
        raise BoundedProcessError(
            "command left surviving descendants: "
            + runtime.tracker.describe(leaked)
        )


def _selected_events(runtime: _ProcessRuntime, timeout: float):
    events = runtime.selector.select(timeout=timeout)
    if not events and runtime.process.poll() is not None:
        return [
            (key, selectors.EVENT_READ)
            for key in runtime.selector.get_map().values()
        ]
    return events


def _monitor_cycle(
    runtime: _ProcessRuntime,
    *,
    timeout_seconds: float,
    progress_callback: Callable[[], None] | None,
    progress_interval_seconds: float,
) -> None:
    remaining = runtime.deadline - time.monotonic()
    if remaining <= 0:
        raise BoundedProcessError(
            f"command timed out after {timeout_seconds:g} seconds"
        )
    events = _selected_events(
        runtime,
        _select_timeout(
            deadline=runtime.deadline,
            next_progress=runtime.next_progress,
            progress_callback=progress_callback,
        ),
    )
    runtime.tracker.observe(
        root_may_have_exited=runtime.process.poll() is not None
    )
    if progress_callback is not None and time.monotonic() >= runtime.next_progress:
        progress_callback()
        runtime.next_progress = time.monotonic() + progress_interval_seconds
    _observe_root_exit(runtime)
    for key, _ in events:
        runtime.capture.consume(runtime.selector, key)


def _finish_runtime(runtime: _ProcessRuntime) -> int:
    runtime.capture.finish()
    return_code = runtime.process.wait(
        timeout=max(0.1, runtime.deadline - time.monotonic())
    )
    if runtime.root_exit_at is None:
        runtime.root_exit_at = time.monotonic()
    leaked = _wait_for_natural_descendant_exit(
        runtime.tracker,
        root_exit_at=runtime.root_exit_at,
    )
    if leaked:
        raise BoundedProcessError(
            "command left surviving descendants: "
            + runtime.tracker.describe(leaked)
        )
    return return_code


def _cleanup_runtime_failure(
    runtime: _ProcessRuntime,
    original_exception: BaseException,
) -> None:
    try:
        remaining, cleanup_error = _terminate_process_tree(
            runtime.process,
            runtime.tracker,
            owns_process_group=runtime.containment.owns_process_group,
        )
        details: list[str] = []
        if remaining:
            details.append(
                "surviving PIDs " + runtime.tracker.describe(remaining)
            )
        if cleanup_error:
            details.append(cleanup_error)
        if details:
            _attach_cleanup_diagnostic(original_exception, "; ".join(details))
    except BaseException as cleanup_exception:
        _fallback_kill_root_group(
            runtime.process,
            owns_process_group=runtime.containment.owns_process_group,
        )
        _attach_cleanup_diagnostic(
            original_exception,
            f"{type(cleanup_exception).__name__}: {cleanup_exception}",
        )


def _execute_runtime(
    runtime: _ProcessRuntime,
    *,
    timeout_seconds: float,
    progress_callback: Callable[[], None] | None,
    progress_interval_seconds: float,
) -> subprocess.CompletedProcess[str]:
    try:
        runtime.tracker.observe(
            force=True,
            root_may_have_exited=runtime.process.poll() is not None,
        )
        runtime.capture.start()
        while runtime.selector.get_map():
            _monitor_cycle(
                runtime,
                timeout_seconds=timeout_seconds,
                progress_callback=progress_callback,
                progress_interval_seconds=progress_interval_seconds,
            )
        return_code = _finish_runtime(runtime)
    except BaseException as original_exception:
        _cleanup_runtime_failure(runtime, original_exception)
        runtime.capture.abort(original_exception)
        raise
    finally:
        runtime.close()
    return runtime.capture.completed(runtime.command, return_code)


def _run_with_capture(
    command: Sequence[str],
    *,
    stdin: BinaryIO | int,
    capture: Capture,
    timeout_seconds: float,
    cwd: Path | str | None,
    env: dict[str, str] | None,
    preexec_fn: Callable[[], None] | None,
    progress_callback: Callable[[], None] | None,
    progress_interval_seconds: float,
) -> subprocess.CompletedProcess[str]:
    process, containment = _launch_process(
        command,
        stdin=stdin,
        cwd=cwd,
        env=env,
        preexec_fn=preexec_fn,
    )
    runtime = _initialize_runtime(
        command,
        process=process,
        containment=containment,
        capture=capture,
        timeout_seconds=timeout_seconds,
        progress_interval_seconds=progress_interval_seconds,
    )
    return _execute_runtime(
        runtime,
        timeout_seconds=timeout_seconds,
        progress_callback=progress_callback,
        progress_interval_seconds=progress_interval_seconds,
    )


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
    """Execute a command while enforcing runtime, output, and tree ceilings."""

    _validate_process_limits(
        timeout_seconds=timeout_seconds,
        max_stdout_bytes=max_stdout_bytes,
        max_stderr_bytes=max_stderr_bytes,
        progress_interval_seconds=progress_interval_seconds,
    )
    capture = _MemoryCapture(
        max_stdout_bytes=max_stdout_bytes,
        max_stderr_bytes=max_stderr_bytes,
    )
    with _pipe_stdin(stdin_text.encode("utf-8")) as stdin_file:
        return _run_with_capture(
            command,
            stdin=stdin_file,
            capture=capture,
            timeout_seconds=timeout_seconds,
            cwd=cwd,
            env=env,
            preexec_fn=preexec_fn,
            progress_callback=progress_callback,
            progress_interval_seconds=progress_interval_seconds,
        )


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
    """Stream stdout to disk while enforcing runtime, byte, and tree ceilings."""

    _validate_process_limits(
        timeout_seconds=timeout_seconds,
        max_stdout_bytes=max_stdout_bytes,
        max_stderr_bytes=max_stderr_bytes,
    )
    capture = _FileCapture(
        destination,
        max_stdout_bytes=max_stdout_bytes,
        max_stderr_bytes=max_stderr_bytes,
    )
    capture.prepare()
    return _run_with_capture(
        command,
        stdin=subprocess.DEVNULL,
        capture=capture,
        timeout_seconds=timeout_seconds,
        cwd=cwd,
        env=env,
        preexec_fn=preexec_fn,
        progress_callback=None,
        progress_interval_seconds=30,
    )
