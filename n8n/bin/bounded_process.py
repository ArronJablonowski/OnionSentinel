#!/usr/bin/env python3
"""Compatibility facade for bounded subprocess execution.

Capability policy, process observation, bounded I/O, verified termination, and
runtime orchestration are owned by separate flat-bin modules.  This facade
preserves the import and monkeypatch seams used by production callers and
characterization tests.
"""
from __future__ import annotations

import os
import selectors
import subprocess
import sys
from collections.abc import Callable, Sequence
from pathlib import Path


BIN_DIR = Path(__file__).resolve().parent
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))

import bounded_process_observation as _observation  # noqa: E402
import bounded_process_runtime as _runtime  # noqa: E402
from bounded_process_io import _FileCapture, _MemoryCapture  # noqa: E402,F401
from bounded_process_observation import (  # noqa: E402,F401
    _PS_PATH,
    _ProcessIdentity,
    _ProcessRecord,
    _bounded_ps_output,
    _kill_snapshot_process,
    _parse_ps_snapshot,
    _same_process,
    _same_process_across_exec,
)
from bounded_process_policy import (  # noqa: E402,F401
    _CONTAINMENT_FD_ENV,
    _CONTAINMENT_PREFIX,
    _CONTAINMENT_TOKEN_ENV,
    _KILL_GRACE_SECONDS,
    _NATURAL_DESCENDANT_GRACE_SECONDS,
    _PROCESS_STARTUP_TRACK_INTERVAL_SECONDS,
    _PROCESS_STARTUP_TRACK_SECONDS,
    _PROCESS_TRACK_INTERVAL_SECONDS,
    _PS_SNAPSHOT_STDERR_BYTES,
    _PS_SNAPSHOT_STDOUT_BYTES,
    _PS_SNAPSHOT_TIMEOUT_SECONDS,
    _TERMINATE_GRACE_SECONDS,
    BoundedProcessError,
    _pipe_stdin,
    _prepare_process_containment,
    _ProcessContainment,
    _ProcessSnapshotError,
    _select_timeout,
    _validated_inherited_capability,
    _validate_process_limits,
)
from bounded_process_termination import (  # noqa: E402,F401
    _attach_cleanup_diagnostic,
    _cleanup_failed_process_initialization,
    _fallback_kill_root_group,
    _signal_verified_tree,
    _terminate_process_tree,
    _wait_for_natural_descendant_exit,
    _wait_for_tree_exit,
)


_read_process_snapshot = _observation._read_process_snapshot


class _DescendantTracker(_observation._DescendantTracker):
    """Compatibility tracker whose snapshot seam follows facade monkeypatches."""

    def observe(
        self,
        *,
        force: bool = False,
        root_may_have_exited: bool = False,
    ):
        _observation._read_process_snapshot = globals()["_read_process_snapshot"]
        return super().observe(
            force=force,
            root_may_have_exited=root_may_have_exited,
        )


def _bind_compatibility_seams() -> None:
    """Bind mutable historical seams into the extracted runtime per invocation."""

    _observation._read_process_snapshot = globals()["_read_process_snapshot"]
    _runtime._DescendantTracker = globals()["_DescendantTracker"]
    _runtime._read_process_snapshot = globals()["_read_process_snapshot"]
    _runtime._terminate_process_tree = globals()["_terminate_process_tree"]
    _runtime._fallback_kill_root_group = globals()["_fallback_kill_root_group"]
    _runtime._attach_cleanup_diagnostic = globals()["_attach_cleanup_diagnostic"]
    _runtime._cleanup_failed_process_initialization = globals()[
        "_cleanup_failed_process_initialization"
    ]
    _runtime._wait_for_natural_descendant_exit = globals()[
        "_wait_for_natural_descendant_exit"
    ]
    _runtime._prepare_process_containment = globals()[
        "_prepare_process_containment"
    ]
    _runtime._pipe_stdin = globals()["_pipe_stdin"]
    _runtime._select_timeout = globals()["_select_timeout"]


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
    _bind_compatibility_seams()
    return _runtime.run_bounded_command(
        command,
        stdin_text=stdin_text,
        timeout_seconds=timeout_seconds,
        max_stdout_bytes=max_stdout_bytes,
        max_stderr_bytes=max_stderr_bytes,
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
    _bind_compatibility_seams()
    return _runtime.run_bounded_command_to_file(
        command,
        destination,
        timeout_seconds=timeout_seconds,
        max_stdout_bytes=max_stdout_bytes,
        max_stderr_bytes=max_stderr_bytes,
        cwd=cwd,
        env=env,
        preexec_fn=preexec_fn,
    )


__all__ = [
    "BoundedProcessError",
    "run_bounded_command",
    "run_bounded_command_to_file",
]
