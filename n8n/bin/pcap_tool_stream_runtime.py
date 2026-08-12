"""Bounded selector-driven lifecycle for isolated parser streams."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, NamedTuple, Sequence


class StreamPolicy(NamedTuple):
    timeout_seconds: float
    max_stderr_bytes: int
    max_stream_bytes: int
    max_line_bytes: int
    parser_cpu_seconds: int
    parser_memory_bytes: int
    parser_file_bytes: int


class StreamDependencies(NamedTuple):
    isolated_command: Callable[[Sequence[str]], list[str]]
    parser_environment: Callable[[], dict[str, str]]
    parser_resource_limits: Callable[[], None]
    popen: Callable[..., Any]
    devnull: Any
    pipe: Any
    selector_factory: Callable[[], Any]
    event_read: int
    read: Callable[[int, int], bytes]
    killpg: Callable[[int, int], None]
    sigkill: int
    monotonic: Callable[[], float]
    which: Callable[[str], str | None]
    sys_platform_is_macos: Callable[[], bool]
    bounded_error: type[BaseException]
    timeout_error: type[BaseException]


@dataclass
class StreamState:
    deadline: float
    pending: bytearray
    stderr: bytearray
    stream_bytes: int = 0
    line_count: int = 0


def _start_process(
    command: Sequence[str],
    cwd: Path | None,
    dependencies: StreamDependencies,
) -> Any:
    return dependencies.popen(
        dependencies.isolated_command(command),
        stdin=dependencies.devnull,
        stdout=dependencies.pipe,
        stderr=dependencies.pipe,
        cwd=str(cwd) if cwd is not None else None,
        env=dependencies.parser_environment(),
        preexec_fn=dependencies.parser_resource_limits,
        start_new_session=True,
    )


def _selector_for(process: Any, dependencies: StreamDependencies) -> Any:
    selector = dependencies.selector_factory()
    selector.register(process.stdout, dependencies.event_read, "stdout")
    selector.register(process.stderr, dependencies.event_read, "stderr")
    return selector


def _selected_events(
    process: Any,
    selector: Any,
    state: StreamState,
    policy: StreamPolicy,
    dependencies: StreamDependencies,
) -> list[tuple[Any, int]]:
    remaining = state.deadline - dependencies.monotonic()
    if remaining <= 0:
        raise dependencies.bounded_error(
            f"command timed out after {policy.timeout_seconds:g} seconds"
        )
    events = selector.select(timeout=min(0.25, remaining))
    if not events and process.poll() is not None:
        return [
            (key, dependencies.event_read)
            for key in selector.get_map().values()
        ]
    return events


def _emit_line(
    raw_line: bytes,
    on_line: Callable[[str], None],
    state: StreamState,
) -> None:
    on_line(raw_line.decode("utf-8", errors="replace"))
    state.line_count += 1


def _consume_stdout(
    chunk: bytes,
    on_line: Callable[[str], None],
    state: StreamState,
    policy: StreamPolicy,
    dependencies: StreamDependencies,
) -> None:
    state.stream_bytes += len(chunk)
    if state.stream_bytes > policy.max_stream_bytes:
        raise dependencies.bounded_error(
            f"command stream exceeded the {policy.max_stream_bytes}-byte limit"
        )
    state.pending.extend(chunk)
    while True:
        newline = state.pending.find(b"\n")
        if newline < 0:
            if len(state.pending) > policy.max_line_bytes:
                raise dependencies.bounded_error(
                    f"command line exceeded the {policy.max_line_bytes}-byte limit"
                )
            break
        raw_line = bytes(state.pending[:newline])
        del state.pending[: newline + 1]
        if len(raw_line) > policy.max_line_bytes:
            raise dependencies.bounded_error(
                f"command line exceeded the {policy.max_line_bytes}-byte limit"
            )
        _emit_line(raw_line, on_line, state)


def _consume_stderr(
    chunk: bytes,
    state: StreamState,
    policy: StreamPolicy,
    dependencies: StreamDependencies,
) -> None:
    if len(state.stderr) + len(chunk) > policy.max_stderr_bytes:
        raise dependencies.bounded_error(
            f"command stderr exceeded the {policy.max_stderr_bytes}-byte limit"
        )
    state.stderr.extend(chunk)


def _read_event(
    key: Any,
    selector: Any,
    on_line: Callable[[str], None],
    state: StreamState,
    policy: StreamPolicy,
    dependencies: StreamDependencies,
) -> None:
    stream = key.fileobj
    try:
        chunk = dependencies.read(stream.fileno(), 64 * 1024)
    except BlockingIOError:
        return
    if not chunk:
        selector.unregister(stream)
    elif key.data == "stderr":
        _consume_stderr(chunk, state, policy, dependencies)
    else:
        _consume_stdout(chunk, on_line, state, policy, dependencies)


def _stream_until_eof(
    process: Any,
    selector: Any,
    on_line: Callable[[str], None],
    state: StreamState,
    policy: StreamPolicy,
    dependencies: StreamDependencies,
) -> int:
    while selector.get_map():
        events = _selected_events(
            process, selector, state, policy, dependencies
        )
        for key, _event in events:
            _read_event(
                key, selector, on_line, state, policy, dependencies
            )
    if state.pending:
        _emit_line(bytes(state.pending), on_line, state)
    return process.wait(
        timeout=max(0.1, state.deadline - dependencies.monotonic())
    )


def _terminate(process: Any, dependencies: StreamDependencies) -> None:
    try:
        dependencies.killpg(process.pid, dependencies.sigkill)
    except (ProcessLookupError, PermissionError):
        process.kill()
    try:
        process.wait(timeout=5)
    except dependencies.timeout_error:
        process.kill()


def _close_streams(process: Any, selector: Any) -> None:
    selector.close()
    process.stdout.close()
    process.stderr.close()


def _result(
    command: Sequence[str],
    return_code: int,
    state: StreamState,
    policy: StreamPolicy,
    dependencies: StreamDependencies,
) -> dict[str, Any]:
    return {
        "ok": return_code == 0,
        "returncode": return_code,
        "stderr": bytes(state.stderr).decode("utf-8", errors="replace"),
        "command": list(command),
        "line_count": state.line_count,
        "stream_bytes": state.stream_bytes,
        "isolation": {
            "network_disabled": bool(
                dependencies.which("sandbox-exec")
                and dependencies.sys_platform_is_macos()
            ),
            "stripped_environment": True,
            "cpu_seconds": policy.parser_cpu_seconds,
            "memory_bytes": policy.parser_memory_bytes,
            "file_bytes": policy.parser_file_bytes,
        },
    }


def stream_isolated_lines(
    command: Sequence[str],
    on_line: Callable[[str], None],
    *,
    cwd: Path | None,
    policy: StreamPolicy,
    dependencies: StreamDependencies,
) -> dict[str, Any]:
    process = _start_process(command, cwd, dependencies)
    assert process.stdout is not None and process.stderr is not None
    selector = _selector_for(process, dependencies)
    state = StreamState(
        dependencies.monotonic() + policy.timeout_seconds,
        bytearray(),
        bytearray(),
    )
    try:
        return_code = _stream_until_eof(
            process, selector, on_line, state, policy, dependencies
        )
    except BaseException:
        _terminate(process, dependencies)
        raise
    finally:
        _close_streams(process, selector)
    return _result(command, return_code, state, policy, dependencies)
