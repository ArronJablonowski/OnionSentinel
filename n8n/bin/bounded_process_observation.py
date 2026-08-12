"""PID-reuse-resistant process snapshot and descendant observation."""
from __future__ import annotations

import hashlib
import os
import selectors
import signal
import subprocess
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from bounded_process_policy import (
    _PROCESS_STARTUP_TRACK_INTERVAL_SECONDS,
    _PROCESS_STARTUP_TRACK_SECONDS,
    _PROCESS_TRACK_INTERVAL_SECONDS,
    _PS_SNAPSHOT_STDERR_BYTES,
    _PS_SNAPSHOT_STDOUT_BYTES,
    _PS_SNAPSHOT_TIMEOUT_SECONDS,
    _ProcessSnapshotError,
)


_PS_PATH = Path("/bin/ps") if Path("/bin/ps").is_file() else Path("/usr/bin/ps")


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


def _parse_ps_snapshot(output: str) -> dict[int, _ProcessRecord]:
    """Parse the shared BSD/GNU ``ps`` format used by the tree guard."""

    records: dict[int, _ProcessRecord] = {}
    for raw_line in output.splitlines():
        fields = raw_line.strip().split(None, 10)
        if len(fields) < 10:
            continue
        try:
            pid, ppid, pgid, uid = (int(fields[index]) for index in range(4))
        except ValueError:
            continue
        command = fields[10] if len(fields) == 11 else ""
        identity = _ProcessIdentity(
            pid=pid,
            pgid=pgid,
            uid=uid,
            start_time=" ".join(fields[5:10]),
            command_hash=hashlib.sha256(
                command.encode("utf-8", errors="replace")
            ).hexdigest(),
        )
        records[pid] = _ProcessRecord(
            identity=identity,
            ppid=ppid,
            state=fields[4],
        )
    return records


def _kill_snapshot_process(process: subprocess.Popen[bytes]) -> None:
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


def _read_snapshot_stream(
    *,
    selector: selectors.BaseSelector,
    streams: dict[object, tuple[str, bytearray, int]],
    deadline: float,
    process: subprocess.Popen[bytes],
) -> None:
    while selector.get_map():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise _ProcessSnapshotError("process-tree snapshot timed out")
        events = selector.select(timeout=min(0.1, remaining))
        if not events and process.poll() is not None:
            events = [
                (key, selectors.EVENT_READ) for key in selector.get_map().values()
            ]
        for key, _ in events:
            stream = key.fileobj
            label, target, limit = streams[stream]
            try:
                chunk = os.read(
                    stream.fileno(),
                    min(64 * 1024, limit + 1 - len(target)),
                )
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


def __start_snapshot_process() -> subprocess.Popen[bytes]:
    snapshot_env = os.environ.copy()
    snapshot_env.update({"LC_ALL": "C", "LANG": "C"})
    return subprocess.Popen(
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


def _bounded_ps_output() -> str:
    """Read one process-table snapshot with strict time and byte ceilings."""

    process = __start_snapshot_process()
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
        _read_snapshot_stream(
            selector=selector,
            streams=streams,
            deadline=deadline,
            process=process,
        )
        return_code = process.wait(timeout=max(0.1, deadline - time.monotonic()))
        if return_code != 0:
            stderr = bytes(streams[process.stderr][1]).decode(
                "utf-8",
                errors="replace",
            ).strip()
            detail = f": {stderr[:240]}" if stderr else ""
            raise _ProcessSnapshotError(
                f"process-tree snapshot failed with exit {return_code}{detail}"
            )
        return bytes(streams[process.stdout][1]).decode(
            "utf-8",
            errors="replace",
        )
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
    return (
        left.pid == right.pid
        and left.pgid == right.pgid
        and left.uid == right.uid
        and left.start_time == right.start_time
        and left.command_hash == right.command_hash
    )


def _same_process_across_exec(
    left: _ProcessIdentity,
    right: _ProcessIdentity,
) -> bool:
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

    def _snapshot_due(self, *, force: bool, now: float) -> bool:
        interval = (
            _PROCESS_STARTUP_TRACK_INTERVAL_SECONDS
            if now - self._created_at < _PROCESS_STARTUP_TRACK_SECONDS
            else _PROCESS_TRACK_INTERVAL_SECONDS
        )
        return force or now - self._last_snapshot_at >= interval

    def _observe_root(
        self,
        snapshot: dict[int, _ProcessRecord],
        *,
        root_may_have_exited: bool,
    ) -> None:
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

    def _trusted_depths(
        self,
        snapshot: dict[int, _ProcessRecord],
    ) -> dict[int, int]:
        trusted: dict[int, int] = {}
        for pid, identity in tuple(self._identities.items()):
            current = snapshot.get(pid)
            if current is not None and _same_process(identity, current.identity):
                trusted[pid] = self._depths.get(pid, 1)
        return trusted

    def _discover_descendants(
        self,
        snapshot: dict[int, _ProcessRecord],
        trusted_depths: dict[int, int],
    ) -> None:
        changed = True
        while changed:
            changed = False
            for record in snapshot.values():
                pid = record.identity.pid
                parent_depth = trusted_depths.get(record.ppid)
                if pid in trusted_depths or parent_depth is None:
                    continue
                previous = self._identities.get(pid)
                if previous is not None and not _same_process_across_exec(
                    previous,
                    record.identity,
                ):
                    continue
                depth = parent_depth + 1
                self._remember(
                    record.identity,
                    depth=depth,
                    refresh=previous is not None,
                )
                trusted_depths[pid] = depth
                changed = True

    def observe(
        self,
        *,
        force: bool = False,
        root_may_have_exited: bool = False,
    ) -> dict[int, _ProcessRecord] | None:
        now = time.monotonic()
        if not self._snapshot_due(force=force, now=now):
            return None
        snapshot = _read_process_snapshot()
        self._last_snapshot_at = now
        self._observe_root(snapshot, root_may_have_exited=root_may_have_exited)
        self._discover_descendants(snapshot, self._trusted_depths(snapshot))
        return snapshot

    def _remember(
        self,
        identity: _ProcessIdentity,
        *,
        depth: int,
        refresh: bool = False,
    ) -> None:
        previous = self._identities.get(identity.pid)
        if previous is None:
            self._sequence += 1
            self._observed_order[identity.pid] = self._sequence
        elif not refresh and not _same_process_across_exec(previous, identity):
            return
        self._identities[identity.pid] = identity
        self._depths[identity.pid] = max(
            depth,
            self._depths.get(identity.pid, depth),
        )

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
