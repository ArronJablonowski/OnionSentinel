#!/usr/bin/env python3
"""Isolated process runners for offline PCAP parsers.

Zeek and TShark process hostile binary input.  They run with a stripped
environment, no network access on macOS when ``sandbox-exec`` is available,
hard resource limits, bounded output, and process-group termination.
"""
from __future__ import annotations

import os
import resource
import selectors
import shutil
import signal
import subprocess
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from bounded_process import BoundedProcessError, run_bounded_command


PARSER_MEMORY_BYTES = max(512 * 1024 * 1024, int(os.environ.get("PCAP_PARSER_MEMORY_BYTES", str(8 * 1024**3))))
PARSER_FILE_BYTES = max(64 * 1024 * 1024, int(os.environ.get("PCAP_PARSER_FILE_BYTES", str(8 * 1024**3))))
PARSER_CPU_SECONDS = max(30, int(os.environ.get("PCAP_PARSER_CPU_SECONDS", "900")))
PARSER_MAX_FDS = max(32, int(os.environ.get("PCAP_PARSER_MAX_FDS", "256")))
PARSER_STREAM_BYTES = max(64 * 1024 * 1024, int(os.environ.get("PCAP_PARSER_STREAM_BYTES", str(64 * 1024**3))))
PARSER_MAX_LINE_BYTES = max(4096, int(os.environ.get("PCAP_PARSER_MAX_LINE_BYTES", str(1024 * 1024))))


def parser_environment() -> dict[str, str]:
    """Return only non-secret variables required by Homebrew parser binaries."""
    allowed = {
        "HOME",
        "LANG",
        "LC_ALL",
        "PATH",
        "TMPDIR",
        "TZ",
        "WIRESHARK_CONFIG_DIR",
        "ZEEKPATH",
        "ZEEK_PLUGIN_PATH",
    }
    env = {key: value for key, value in os.environ.items() if key in allowed and value}
    env.setdefault("PATH", "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")
    env.setdefault("LANG", "C.UTF-8")
    return env


def _set_bounded_limit(kind: int, soft: int, hard: int | None = None) -> None:
    """Lower a child limit without exceeding the launcher's inherited ceiling."""
    _, inherited_hard = resource.getrlimit(kind)
    requested_hard = soft if hard is None else hard
    target_hard = requested_hard
    if inherited_hard != resource.RLIM_INFINITY:
        target_hard = min(target_hard, inherited_hard)
    resource.setrlimit(kind, (min(soft, target_hard), target_hard))


def parser_resource_limits() -> None:
    """Apply child-only limits before exec; parent launchd services are untouched."""
    _set_bounded_limit(resource.RLIMIT_CORE, 0)
    _set_bounded_limit(resource.RLIMIT_CPU, PARSER_CPU_SECONDS, PARSER_CPU_SECONDS + 5)
    _set_bounded_limit(resource.RLIMIT_FSIZE, PARSER_FILE_BYTES)
    _set_bounded_limit(resource.RLIMIT_NOFILE, PARSER_MAX_FDS)
    if hasattr(resource, "RLIMIT_AS"):
        try:
            _set_bounded_limit(resource.RLIMIT_AS, PARSER_MEMORY_BYTES)
        except (OSError, ValueError):
            # macOS may expose RLIMIT_AS without enforcing arbitrary reductions.
            pass


def isolated_command(command: Sequence[str]) -> list[str]:
    """Deny parser network access without relying on application cooperation."""
    sandbox_exec = shutil.which("sandbox-exec") if sys_platform_is_macos() else None
    if not sandbox_exec:
        return list(command)
    profile = "(version 1)(allow default)(deny network*)"
    return [sandbox_exec, "-p", profile, *command]


def sys_platform_is_macos() -> bool:
    return os.uname().sysname == "Darwin"


def run_isolated_command(
    command: Sequence[str],
    *,
    cwd: Path | None,
    timeout_seconds: float,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
) -> subprocess.CompletedProcess[str]:
    return run_bounded_command(
        isolated_command(command),
        cwd=cwd,
        timeout_seconds=timeout_seconds,
        max_stdout_bytes=max_stdout_bytes,
        max_stderr_bytes=max_stderr_bytes,
        env=parser_environment(),
        preexec_fn=parser_resource_limits,
    )


def stream_isolated_lines(
    command: Sequence[str],
    on_line: Callable[[str], None],
    *,
    cwd: Path | None = None,
    timeout_seconds: float = 900,
    max_stderr_bytes: int = 512 * 1024,
    max_stream_bytes: int = PARSER_STREAM_BYTES,
    max_line_bytes: int = PARSER_MAX_LINE_BYTES,
) -> dict[str, Any]:
    """Stream parser stdout through ``on_line`` without retaining the capture."""
    workflow = __import__("pcap_tool_stream_runtime")
    return workflow.stream_isolated_lines(
        command,
        on_line,
        cwd=cwd,
        policy=workflow.StreamPolicy(
            timeout_seconds,
            max_stderr_bytes,
            max_stream_bytes,
            max_line_bytes,
            PARSER_CPU_SECONDS,
            PARSER_MEMORY_BYTES,
            PARSER_FILE_BYTES,
        ),
        dependencies=workflow.StreamDependencies(
            isolated_command,
            parser_environment,
            parser_resource_limits,
            subprocess.Popen,
            subprocess.DEVNULL,
            subprocess.PIPE,
            selectors.DefaultSelector,
            selectors.EVENT_READ,
            os.read,
            os.killpg,
            signal.SIGKILL,
            time.monotonic,
            shutil.which,
            sys_platform_is_macos,
            BoundedProcessError,
            subprocess.TimeoutExpired,
        ),
    )
