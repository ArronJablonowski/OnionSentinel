"""Verified signal delivery and bounded process-tree termination."""
from __future__ import annotations

import os
import selectors
import signal
import subprocess
import time

from bounded_process_observation import (
    _DescendantTracker,
    _ProcessRecord,
)
from bounded_process_policy import (
    _KILL_GRACE_SECONDS,
    _NATURAL_DESCENDANT_GRACE_SECONDS,
    _TERMINATE_GRACE_SECONDS,
    _ProcessContainment,
)


def __signal_verified_groups(
    records: list[_ProcessRecord],
    signal_number: int,
    *,
    self_pgid: int,
) -> None:
    signaled_groups: set[int] = set()
    for record in records:
        pgid = record.identity.pgid
        if pgid <= 0 or pgid == self_pgid or pgid in signaled_groups:
            continue
        try:
            os.killpg(pgid, signal_number)
        except (ProcessLookupError, PermissionError):
            pass
        signaled_groups.add(pgid)


def __signal_verified_processes(
    records: list[_ProcessRecord],
    signal_number: int,
    *,
    self_pid: int,
) -> None:
    for record in records:
        if record.identity.pid == self_pid:
            continue
        try:
            os.kill(record.identity.pid, signal_number)
        except (ProcessLookupError, PermissionError):
            pass


def _signal_verified_tree(
    tracker: _DescendantTracker,
    signal_number: int,
) -> list[_ProcessRecord]:
    """Signal only identities reverified in a fresh snapshot."""

    snapshot = tracker.observe(force=True, root_may_have_exited=True) or {}
    records = tracker.verified_records(snapshot, include_root=True)
    self_pid = os.getpid()
    self_pgid = os.getpgrp()
    __signal_verified_groups(
        records,
        signal_number,
        self_pgid=self_pgid,
    )

    snapshot = tracker.observe(force=True, root_may_have_exited=True) or {}
    remaining = tracker.verified_records(snapshot, include_root=True)
    __signal_verified_processes(
        remaining,
        signal_number,
        self_pid=self_pid,
    )
    return remaining


def _wait_for_tree_exit(
    tracker: _DescendantTracker,
    *,
    timeout_seconds: float,
    include_root: bool,
) -> list[_ProcessRecord]:
    deadline = time.monotonic() + timeout_seconds
    last_records: list[_ProcessRecord] = []
    while True:
        snapshot = tracker.observe(force=True, root_may_have_exited=True) or {}
        last_records = tracker.verified_records(
            snapshot,
            include_root=include_root,
        )
        if not last_records or time.monotonic() >= deadline:
            return last_records
        time.sleep(min(0.1, max(0.0, deadline - time.monotonic())))


def _fallback_kill_root_group(
    process: subprocess.Popen[bytes],
    *,
    owns_process_group: bool,
) -> None:
    """Best-effort fail-closed fallback when process-table verification fails."""

    if process.poll() is not None:
        return
    if owns_process_group:
        try:
            os.killpg(process.pid, signal.SIGKILL)
            return
        except (ProcessLookupError, PermissionError):
            pass
    try:
        process.kill()
    except ProcessLookupError:
        pass


def _attach_cleanup_diagnostic(exception: BaseException, detail: str) -> None:
    """Expose cleanup trouble without replacing the causal exception."""

    try:
        setattr(exception, "bounded_process_cleanup", detail)
    except BaseException:
        pass
    add_note = getattr(exception, "add_note", None)
    if callable(add_note):
        try:
            add_note(f"Bounded-process cleanup: {detail}")
        except BaseException:
            pass


def _close_failed_streams(
    process: subprocess.Popen[bytes],
    diagnostics: list[str],
) -> None:
    for label, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
        if stream is None:
            continue
        try:
            stream.close()
        except BaseException as exc:
            diagnostics.append(f"{label} cleanup: {type(exc).__name__}: {exc}")


def _stop_failed_child(
    process: subprocess.Popen[bytes],
    *,
    owns_process_group: bool,
) -> None:
    _fallback_kill_root_group(
        process,
        owns_process_group=owns_process_group,
    )
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        _fallback_kill_root_group(
            process,
            owns_process_group=owns_process_group,
        )
        process.wait(timeout=1)


def _cleanup_failed_process_initialization(
    process: subprocess.Popen[bytes],
    containment: _ProcessContainment,
    selector: selectors.BaseSelector | None,
    original_exception: BaseException,
) -> None:
    """Fail closed if local setup fails after the external process was born."""

    diagnostics: list[str] = []
    try:
        _stop_failed_child(
            process,
            owns_process_group=containment.owns_process_group,
        )
    except BaseException as exc:
        diagnostics.append(f"process cleanup: {type(exc).__name__}: {exc}")
    if selector is not None:
        try:
            selector.close()
        except BaseException as exc:
            diagnostics.append(f"selector cleanup: {type(exc).__name__}: {exc}")
    _close_failed_streams(process, diagnostics)
    try:
        containment.close()
    except BaseException as exc:
        diagnostics.append(f"capability cleanup: {type(exc).__name__}: {exc}")
    if diagnostics:
        _attach_cleanup_diagnostic(original_exception, "; ".join(diagnostics))


def _terminate_process_tree(
    process: subprocess.Popen[bytes],
    tracker: _DescendantTracker,
    *,
    owns_process_group: bool,
) -> tuple[list[_ProcessRecord], str | None]:
    """Boundedly terminate every captured process without trusting bare PIDs."""

    diagnostic: str | None = None
    try:
        tracker.observe(force=True, root_may_have_exited=process.poll() is not None)
        _signal_verified_tree(tracker, signal.SIGTERM)
        remaining = _wait_for_tree_exit(
            tracker,
            timeout_seconds=_TERMINATE_GRACE_SECONDS,
            include_root=True,
        )
        if remaining:
            _signal_verified_tree(tracker, signal.SIGKILL)
            remaining = _wait_for_tree_exit(
                tracker,
                timeout_seconds=_KILL_GRACE_SECONDS,
                include_root=True,
            )
    except BaseException as exc:
        _fallback_kill_root_group(
            process,
            owns_process_group=owns_process_group,
        )
        remaining = []
        diagnostic = f"{type(exc).__name__}: {exc}"

    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        _fallback_kill_root_group(
            process,
            owns_process_group=owns_process_group,
        )
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            diagnostic = diagnostic or "direct child did not exit after bounded cleanup"
    return remaining, diagnostic


def _wait_for_natural_descendant_exit(
    tracker: _DescendantTracker,
    *,
    root_exit_at: float,
) -> list[_ProcessRecord]:
    """Allow a short natural-exit grace, then return verified leak survivors."""

    deadline = root_exit_at + _NATURAL_DESCENDANT_GRACE_SECONDS
    while True:
        snapshot = tracker.observe(force=True, root_may_have_exited=True) or {}
        survivors = tracker.verified_records(snapshot, include_root=False)
        if not survivors or time.monotonic() >= deadline:
            return survivors
        time.sleep(min(0.1, max(0.0, deadline - time.monotonic())))
