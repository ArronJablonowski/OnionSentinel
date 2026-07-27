#!/usr/bin/env python3
"""Run external LLM harnesses without unbounded stdout/stderr buffering."""
from __future__ import annotations

import hashlib
import os
import secrets
import selectors
import signal
import stat
import subprocess
import tempfile
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path


class BoundedProcessError(RuntimeError):
    """Raised when a child exceeds its output or runtime contract."""


class _ProcessSnapshotError(BoundedProcessError):
    """Raised when a process-tree safety snapshot cannot be trusted."""


_PS_PATH = Path("/bin/ps") if Path("/bin/ps").is_file() else Path("/usr/bin/ps")
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


@dataclass(frozen=True)
class _ProcessIdentity:
    """PID-reuse-resistant identity captured from one process-table row."""

    pid: int
    pgid: int
    uid: int
    start_time: str
    command_hash: str


@dataclass(frozen=True)
class _ProcessRecord:
    identity: _ProcessIdentity
    ppid: int
    state: str

    @property
    def is_zombie(self) -> bool:
        return self.state.upper().startswith("Z")


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
    if len(token) != 64 or any(character not in "0123456789abcdef" for character in token):
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


def _prepare_process_containment(
    requested_environment: dict[str, str] | None,
) -> _ProcessContainment:
    """Create or inherit the private capability for one trusted process tree.

    The capability prevents accidental environment spoofing and keeps nested
    Onion Sentinel helpers in the outer worker's process group. It is not a
    sandbox against a hostile same-UID launcher that controls inherited file
    descriptors, nor can portable polling contain an arbitrary program that
    deliberately closes the capability and calls setsid(2) between snapshots.
    """

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
        owns_process_group = True

    environment[_CONTAINMENT_FD_ENV] = str(descriptor)
    environment[_CONTAINMENT_TOKEN_ENV] = token
    return _ProcessContainment(
        environment=environment,
        capability_fd=descriptor,
        owns_process_group=owns_process_group,
        owned_capability=owned_capability,
    )


def _parse_ps_snapshot(output: str) -> dict[int, _ProcessRecord]:
    """Parse the shared BSD/GNU ``ps`` format used by the tree guard."""

    records: dict[int, _ProcessRecord] = {}
    for raw_line in output.splitlines():
        # lstart is five whitespace-delimited fields. command is the final,
        # possibly empty, field and may itself contain arbitrary whitespace.
        fields = raw_line.strip().split(None, 10)
        if len(fields) < 10:
            continue
        try:
            pid = int(fields[0])
            ppid = int(fields[1])
            pgid = int(fields[2])
            uid = int(fields[3])
        except ValueError:
            continue
        state = fields[4]
        start_time = " ".join(fields[5:10])
        command = fields[10] if len(fields) == 11 else ""
        identity = _ProcessIdentity(
            pid=pid,
            pgid=pgid,
            uid=uid,
            start_time=start_time,
            command_hash=hashlib.sha256(command.encode("utf-8", errors="replace")).hexdigest(),
        )
        records[pid] = _ProcessRecord(identity=identity, ppid=ppid, state=state)
    return records


def _kill_snapshot_process(process: subprocess.Popen[bytes]) -> None:
    # Once poll() observes exit, the snapshot child's PID/PGID may be reused;
    # never deliver a bare group signal after that point.
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            try:
                process.kill()
            except ProcessLookupError:
                pass
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except ProcessLookupError:
            pass


def _bounded_ps_output() -> str:
    """Read one process-table snapshot with strict time and byte ceilings."""

    snapshot_env = os.environ.copy()
    snapshot_env.update({"LC_ALL": "C", "LANG": "C"})
    process = subprocess.Popen(
        [
            str(_PS_PATH),
            "-ww",
            "-axo",
            "pid=,ppid=,pgid=,uid=,state=,lstart=,command=",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=snapshot_env,
        start_new_session=True,
    )
    assert process.stdout is not None and process.stderr is not None
    selector = selectors.DefaultSelector()
    streams = {
        process.stdout: ("stdout", bytearray(), _PS_SNAPSHOT_STDOUT_BYTES),
        process.stderr: ("stderr", bytearray(), _PS_SNAPSHOT_STDERR_BYTES),
    }
    for stream in streams:
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ)
    deadline = time.monotonic() + _PS_SNAPSHOT_TIMEOUT_SECONDS
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _ProcessSnapshotError("process-tree snapshot timed out")
            events = selector.select(timeout=min(0.1, remaining))
            if not events and process.poll() is not None:
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
                    raise _ProcessSnapshotError(
                        f"process-tree snapshot {label} exceeded the {limit}-byte limit"
                    )
        return_code = process.wait(timeout=max(0.1, deadline - time.monotonic()))
        if return_code != 0:
            stderr = bytes(streams[process.stderr][1]).decode("utf-8", errors="replace").strip()
            detail = f": {stderr[:240]}" if stderr else ""
            raise _ProcessSnapshotError(f"process-tree snapshot failed with exit {return_code}{detail}")
        return bytes(streams[process.stdout][1]).decode("utf-8", errors="replace")
    except BaseException:
        _kill_snapshot_process(process)
        raise
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()


def _read_process_snapshot() -> dict[int, _ProcessRecord]:
    records = _parse_ps_snapshot(_bounded_ps_output())
    if not records:
        raise _ProcessSnapshotError("process-tree snapshot returned no parseable rows")
    return records


def _same_process(left: _ProcessIdentity, right: _ProcessIdentity) -> bool:
    """Require every available immutable/audited identity field to match."""

    return (
        left.pid == right.pid
        and left.pgid == right.pgid
        and left.uid == right.uid
        and left.start_time == right.start_time
        and left.command_hash == right.command_hash
    )


def _same_process_across_exec(left: _ProcessIdentity, right: _ProcessIdentity) -> bool:
    """Match a live process while allowing its command and process group to change."""

    return (
        left.pid == right.pid
        and left.uid == right.uid
        and left.start_time == right.start_time
    )


class _DescendantTracker:
    """Accumulate exact descendant identities before they can be reparented."""

    def __init__(self, root_pid: int) -> None:
        self.root_pid = root_pid
        self.root_identity: _ProcessIdentity | None = None
        self._identities: dict[int, _ProcessIdentity] = {}
        self._depths: dict[int, int] = {}
        self._observed_order: dict[int, int] = {}
        self._sequence = 0
        self._created_at = time.monotonic()
        self._last_snapshot_at = 0.0

    def observe(
        self,
        *,
        force: bool = False,
        root_may_have_exited: bool = False,
    ) -> dict[int, _ProcessRecord] | None:
        now = time.monotonic()
        interval = (
            _PROCESS_STARTUP_TRACK_INTERVAL_SECONDS
            if now - self._created_at < _PROCESS_STARTUP_TRACK_SECONDS
            else _PROCESS_TRACK_INTERVAL_SECONDS
        )
        if not force and now - self._last_snapshot_at < interval:
            return None
        snapshot = _read_process_snapshot()
        self._last_snapshot_at = now

        root = snapshot.get(self.root_pid)
        if self.root_identity is None:
            if root is not None:
                self.root_identity = root.identity
                self._remember(root.identity, depth=0)
            elif not root_may_have_exited:
                raise _ProcessSnapshotError(
                    f"direct child {self.root_pid} was absent from the process-tree snapshot"
                )
        elif root is not None and _same_process(self.root_identity, root.identity):
            self._remember(root.identity, depth=0, refresh=True)

        trusted_depths: dict[int, int] = {}
        for pid, identity in tuple(self._identities.items()):
            current = snapshot.get(pid)
            if current is not None and _same_process(identity, current.identity):
                trusted_depths[pid] = self._depths.get(pid, 1)

        changed = True
        while changed:
            changed = False
            for record in snapshot.values():
                if record.identity.pid in trusted_depths:
                    continue
                parent_depth = trusted_depths.get(record.ppid)
                if parent_depth is None:
                    continue
                depth = parent_depth + 1
                previous = self._identities.get(record.identity.pid)
                if previous is not None and not _same_process_across_exec(
                    previous,
                    record.identity,
                ):
                    continue
                # Exact current ancestry authorizes refreshing PGID/command
                # after a legitimate exec(2) or setsid(2). A reparented PID
                # cannot refresh itself solely on a coarse lstart timestamp.
                self._remember(record.identity, depth=depth, refresh=previous is not None)
                trusted_depths[record.identity.pid] = depth
                changed = True
        return snapshot

    def _remember(self, identity: _ProcessIdentity, *, depth: int, refresh: bool = False) -> None:
        previous = self._identities.get(identity.pid)
        if previous is None:
            self._sequence += 1
            self._observed_order[identity.pid] = self._sequence
        elif not refresh and not _same_process_across_exec(previous, identity):
            # A reused PID is never silently substituted for the process that
            # was originally captured.
            return
        self._identities[identity.pid] = identity
        self._depths[identity.pid] = max(depth, self._depths.get(identity.pid, depth))

    def verified_records(
        self,
        snapshot: dict[int, _ProcessRecord],
        *,
        include_root: bool,
    ) -> list[_ProcessRecord]:
        records: list[_ProcessRecord] = []
        for pid, identity in self._identities.items():
            if not include_root and pid == self.root_pid:
                continue
            current = snapshot.get(pid)
            if current is None or current.is_zombie:
                continue
            # The command hash, UID, start time, and PGID must still be exact
            # immediately before a signal is authorized.
            if _same_process(identity, current.identity):
                records.append(current)
        records.sort(
            key=lambda record: (
                self._depths.get(record.identity.pid, 0),
                self._observed_order.get(record.identity.pid, 0),
            ),
            reverse=True,
        )
        return records

    def describe(self, records: Sequence[_ProcessRecord]) -> str:
        return ",".join(str(record.identity.pid) for record in records)


def _signal_verified_tree(
    tracker: _DescendantTracker,
    signal_number: int,
) -> list[_ProcessRecord]:
    """Signal only identities reverified in a fresh snapshot."""

    snapshot = tracker.observe(force=True, root_may_have_exited=True) or {}
    records = tracker.verified_records(snapshot, include_root=True)
    self_pid = os.getpid()
    self_pgid = os.getpgrp()

    # Signal isolated process groups first. Group membership is authorized only
    # when at least one exact captured identity still occupies that PGID.
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

    # Reverify after group delivery before addressing survivors by PID. This
    # closes the common PID-reuse race created when a group signal exits a
    # process between snapshot and exact-PID signaling.
    snapshot = tracker.observe(force=True, root_may_have_exited=True) or {}
    remaining = tracker.verified_records(snapshot, include_root=True)
    for record in remaining:
        if record.identity.pid == self_pid:
            continue
        try:
            os.kill(record.identity.pid, signal_number)
        except (ProcessLookupError, PermissionError):
            pass
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
        last_records = tracker.verified_records(snapshot, include_root=include_root)
        if not last_records or time.monotonic() >= deadline:
            return last_records
        time.sleep(min(0.1, max(0.0, deadline - time.monotonic())))


def _fallback_kill_root_group(
    process: subprocess.Popen[bytes],
    *,
    owns_process_group: bool,
) -> None:
    """Best-effort fail-closed fallback when process-table verification fails."""

    # Only a top-level bounded invocation created a session whose process-group
    # ID is the direct child's PID. Nested invocations inherit that group and
    # must never interpret their child's PID as a process-group ID.
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


def _cleanup_failed_process_initialization(
    process: subprocess.Popen[bytes],
    containment: _ProcessContainment,
    selector: selectors.BaseSelector | None,
    original_exception: BaseException,
) -> None:
    """Fail closed if local setup fails after the external process was born."""

    diagnostics: list[str] = []
    try:
        _fallback_kill_root_group(
            process,
            owns_process_group=containment.owns_process_group,
        )
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            _fallback_kill_root_group(
                process,
                owns_process_group=containment.owns_process_group,
            )
            process.wait(timeout=1)
    except BaseException as exc:
        diagnostics.append(f"process cleanup: {type(exc).__name__}: {exc}")
    if selector is not None:
        try:
            selector.close()
        except BaseException as exc:
            diagnostics.append(f"selector cleanup: {type(exc).__name__}: {exc}")
    for label, stream in (
        ("stdout", process.stdout),
        ("stderr", process.stderr),
    ):
        if stream is None:
            continue
        try:
            stream.close()
        except BaseException as exc:
            diagnostics.append(f"{label} cleanup: {type(exc).__name__}: {exc}")
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
        if not survivors:
            return []
        if time.monotonic() >= deadline:
            return survivors
        time.sleep(min(0.1, max(0.0, deadline - time.monotonic())))


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

    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    if max_stdout_bytes <= 0 or max_stderr_bytes <= 0:
        raise ValueError("output limits must be positive")
    if progress_interval_seconds <= 0:
        raise ValueError("progress_interval_seconds must be positive")

    with tempfile.TemporaryFile() as stdin_file:
        stdin_file.write(stdin_text.encode("utf-8"))
        stdin_file.seek(0)
        containment = _prepare_process_containment(env)
        try:
            process = subprocess.Popen(
                list(command),
                stdin=stdin_file,
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
        selector: selectors.BaseSelector | None = None
        try:
            if process.stdout is None or process.stderr is None:
                raise BoundedProcessError(
                    "bounded process did not expose stdout and stderr pipes"
                )
            tracker = _DescendantTracker(process.pid)
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
            root_exit_at: float | None = None
        except BaseException as initialization_exception:
            _cleanup_failed_process_initialization(
                process,
                containment,
                selector,
                initialization_exception,
            )
            raise
        assert selector is not None
        try:
            tracker.observe(force=True, root_may_have_exited=process.poll() is not None)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise BoundedProcessError(f"command timed out after {timeout_seconds:g} seconds")
                events = selector.select(
                    timeout=_select_timeout(
                        deadline=deadline,
                        next_progress=next_progress,
                        progress_callback=progress_callback,
                    )
                )
                tracker.observe(root_may_have_exited=process.poll() is not None)
                if progress_callback is not None and time.monotonic() >= next_progress:
                    # Preserve the callback exception: it is the authoritative
                    # lease/ownership failure, while cleanup remains secondary.
                    progress_callback()
                    next_progress = time.monotonic() + progress_interval_seconds
                if process.poll() is not None:
                    if root_exit_at is None:
                        root_exit_at = time.monotonic()
                    if time.monotonic() >= root_exit_at + _NATURAL_DESCENDANT_GRACE_SECONDS:
                        snapshot = _read_process_snapshot()
                        leaked = tracker.verified_records(snapshot, include_root=False)
                        if leaked:
                            raise BoundedProcessError(
                                "command left surviving descendants: " + tracker.describe(leaked)
                            )
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
            if root_exit_at is None:
                root_exit_at = time.monotonic()
            leaked = _wait_for_natural_descendant_exit(
                tracker,
                root_exit_at=root_exit_at,
            )
            if leaked:
                raise BoundedProcessError(
                    "command left surviving descendants: " + tracker.describe(leaked)
                )
        except BaseException as original_exception:
            try:
                remaining, cleanup_error = _terminate_process_tree(
                    process,
                    tracker,
                    owns_process_group=containment.owns_process_group,
                )
                details = []
                if remaining:
                    details.append("surviving PIDs " + tracker.describe(remaining))
                if cleanup_error:
                    details.append(cleanup_error)
                if details:
                    _attach_cleanup_diagnostic(original_exception, "; ".join(details))
            except BaseException as cleanup_exception:
                # Cleanup diagnostics must never replace the authoritative
                # timeout, ceiling, or lease-callback exception.
                _fallback_kill_root_group(
                    process,
                    owns_process_group=containment.owns_process_group,
                )
                _attach_cleanup_diagnostic(
                    original_exception,
                    f"{type(cleanup_exception).__name__}: {cleanup_exception}",
                )
            raise
        finally:
            selector.close()
            process.stdout.close()
            process.stderr.close()
            containment.close()

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
    """Stream stdout to disk while enforcing runtime, byte, and tree ceilings."""

    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    if max_stdout_bytes <= 0 or max_stderr_bytes <= 0:
        raise ValueError("output limits must be positive")

    destination_path = Path(destination)
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    containment = _prepare_process_containment(env)
    try:
        process = subprocess.Popen(
            list(command),
            stdin=subprocess.DEVNULL,
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
    selector: selectors.BaseSelector | None = None
    try:
        if process.stdout is None or process.stderr is None:
            raise BoundedProcessError(
                "bounded process did not expose stdout and stderr pipes"
            )
        tracker = _DescendantTracker(process.pid)
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        stderr = bytearray()
        stdout_bytes = 0
        deadline = time.monotonic() + timeout_seconds
        root_exit_at: float | None = None
    except BaseException as initialization_exception:
        _cleanup_failed_process_initialization(
            process,
            containment,
            selector,
            initialization_exception,
        )
        raise
    assert selector is not None

    try:
        tracker.observe(force=True, root_may_have_exited=process.poll() is not None)
        with destination_path.open("wb") as output:
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise BoundedProcessError(f"command timed out after {timeout_seconds:g} seconds")
                events = selector.select(timeout=min(0.25, remaining))
                tracker.observe(root_may_have_exited=process.poll() is not None)
                if process.poll() is not None:
                    if root_exit_at is None:
                        root_exit_at = time.monotonic()
                    if time.monotonic() >= root_exit_at + _NATURAL_DESCENDANT_GRACE_SECONDS:
                        snapshot = _read_process_snapshot()
                        leaked = tracker.verified_records(snapshot, include_root=False)
                        if leaked:
                            raise BoundedProcessError(
                                "command left surviving descendants: " + tracker.describe(leaked)
                            )
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
        if root_exit_at is None:
            root_exit_at = time.monotonic()
        leaked = _wait_for_natural_descendant_exit(
            tracker,
            root_exit_at=root_exit_at,
        )
        if leaked:
            raise BoundedProcessError(
                "command left surviving descendants: " + tracker.describe(leaked)
            )
    except BaseException as original_exception:
        try:
            remaining, cleanup_error = _terminate_process_tree(
                process,
                tracker,
                owns_process_group=containment.owns_process_group,
            )
            details = []
            if remaining:
                details.append("surviving PIDs " + tracker.describe(remaining))
            if cleanup_error:
                details.append(cleanup_error)
            if details:
                _attach_cleanup_diagnostic(original_exception, "; ".join(details))
        except BaseException as cleanup_exception:
            _fallback_kill_root_group(
                process,
                owns_process_group=containment.owns_process_group,
            )
            _attach_cleanup_diagnostic(
                original_exception,
                f"{type(cleanup_exception).__name__}: {cleanup_exception}",
            )
        try:
            destination_path.unlink(missing_ok=True)
        except OSError as unlink_error:
            _attach_cleanup_diagnostic(
                original_exception,
                f"partial output cleanup failed: {type(unlink_error).__name__}: {unlink_error}",
            )
        raise
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
        containment.close()

    return subprocess.CompletedProcess(
        list(command),
        return_code,
        "",
        bytes(stderr).decode("utf-8", errors="replace"),
    )
