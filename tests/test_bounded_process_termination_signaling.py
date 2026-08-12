"""Characterization for verified bounded-process tree signal delivery."""
from __future__ import annotations

import hashlib
import inspect
import json
from pathlib import Path
import signal
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BIN_DIR = ROOT / "n8n" / "bin"
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))
import bounded_process_observation as observation  # noqa: E402
import bounded_process_termination as termination  # noqa: E402


def process_record(*, pid: int, pgid: int) -> observation._ProcessRecord:
    return observation._ProcessRecord(
        identity=observation._ProcessIdentity(
            pid=pid,
            pgid=pgid,
            uid=501,
            start_time="Mon Jul 27 10:00:00 2026",
            command_hash=f"{pid:064x}"[-64:],
        ),
        ppid=1,
        state="S",
    )


class BoundedProcessTerminationSignalingTests(unittest.TestCase):
    def test_surface_and_signature_are_exact(self) -> None:
        names = sorted(
            name for name in dir(termination) if not name.startswith("__")
        )
        encoded = json.dumps(names, separators=(",", ":"), sort_keys=True).encode()
        self.assertEqual(
            (len(names), hashlib.sha256(encoded).hexdigest()),
            (21, "0e928305c36e0c0bf379853e1587c22d0ce65fd4d9dd5315b82838667a4706cd"),
        )
        self.assertEqual(
            str(inspect.signature(termination._signal_verified_tree)),
            (
                "(tracker: '_DescendantTracker', signal_number: 'int') "
                "-> 'list[_ProcessRecord]'"
            ),
        )

    def test_group_then_fresh_pid_delivery_is_exact_and_bounded(self) -> None:
        first_snapshot = {1: process_record(pid=1, pgid=1)}
        second_snapshot = {2: process_record(pid=2, pgid=2)}
        first_records = [
            process_record(pid=301, pgid=300),
            process_record(pid=302, pgid=300),
            process_record(pid=303, pgid=200),
            process_record(pid=304, pgid=0),
            process_record(pid=305, pgid=400),
            process_record(pid=306, pgid=400),
        ]
        remaining = [
            process_record(pid=100, pgid=500),
            process_record(pid=301, pgid=300),
            process_record(pid=302, pgid=300),
        ]
        events: list[tuple[object, ...]] = []
        tracker = mock.Mock()

        def observe(**kwargs: object) -> dict[int, observation._ProcessRecord]:
            snapshot = first_snapshot if not events else second_snapshot
            events.append(("observe", kwargs))
            return snapshot

        def verified_records(
            snapshot: dict[int, observation._ProcessRecord],
            *,
            include_root: bool,
        ) -> list[observation._ProcessRecord]:
            events.append(("verified", snapshot, include_root))
            return first_records if snapshot is first_snapshot else remaining

        def killpg(pgid: int, signal_number: int) -> None:
            events.append(("killpg", pgid, signal_number))
            if pgid == 400:
                raise ProcessLookupError("group exited")

        def kill(pid: int, signal_number: int) -> None:
            events.append(("kill", pid, signal_number))
            if pid == 302:
                raise PermissionError("pid became unavailable")

        tracker.observe.side_effect = observe
        tracker.verified_records.side_effect = verified_records
        with mock.patch.object(
            termination.os,
            "getpid",
            return_value=100,
        ), mock.patch.object(
            termination.os,
            "getpgrp",
            return_value=200,
        ), mock.patch.object(
            termination.os,
            "killpg",
            side_effect=killpg,
        ), mock.patch.object(
            termination.os,
            "kill",
            side_effect=kill,
        ):
            self.assertIs(
                termination._signal_verified_tree(tracker, signal.SIGTERM),
                remaining,
            )

        self.assertEqual(
            events,
            [
                ("observe", {"force": True, "root_may_have_exited": True}),
                ("verified", first_snapshot, True),
                ("killpg", 300, signal.SIGTERM),
                ("killpg", 400, signal.SIGTERM),
                ("observe", {"force": True, "root_may_have_exited": True}),
                ("verified", second_snapshot, True),
                ("kill", 301, signal.SIGTERM),
                ("kill", 302, signal.SIGTERM),
            ],
        )

    def test_missing_snapshots_are_normalized_before_verification(self) -> None:
        tracker = mock.Mock()
        tracker.observe.side_effect = [None, None]
        tracker.verified_records.side_effect = [[], []]
        with mock.patch.object(
            termination.os,
            "getpid",
            return_value=100,
        ), mock.patch.object(
            termination.os,
            "getpgrp",
            return_value=200,
        ), mock.patch.object(termination.os, "killpg") as killpg, mock.patch.object(
            termination.os,
            "kill",
        ) as kill:
            self.assertEqual(
                termination._signal_verified_tree(tracker, signal.SIGKILL),
                [],
            )

        self.assertEqual(
            tracker.observe.call_args_list,
            [
                mock.call(force=True, root_may_have_exited=True),
                mock.call(force=True, root_may_have_exited=True),
            ],
        )
        self.assertEqual(
            tracker.verified_records.call_args_list,
            [
                mock.call({}, include_root=True),
                mock.call({}, include_root=True),
            ],
        )
        killpg.assert_not_called()
        kill.assert_not_called()

    def test_unexpected_group_signal_error_propagates_before_resnapshot(
        self,
    ) -> None:
        tracker = mock.Mock()
        tracker.observe.return_value = {1: process_record(pid=1, pgid=1)}
        tracker.verified_records.return_value = [process_record(pid=301, pgid=300)]
        with mock.patch.object(
            termination.os,
            "getpid",
            return_value=100,
        ), mock.patch.object(
            termination.os,
            "getpgrp",
            return_value=200,
        ), mock.patch.object(
            termination.os,
            "killpg",
            side_effect=OSError("unexpected signal failure"),
        ), mock.patch.object(termination.os, "kill") as kill:
            with self.assertRaisesRegex(OSError, "unexpected signal failure"):
                termination._signal_verified_tree(tracker, signal.SIGTERM)

        tracker.observe.assert_called_once_with(
            force=True,
            root_may_have_exited=True,
        )
        tracker.verified_records.assert_called_once()
        kill.assert_not_called()


if __name__ == "__main__":
    unittest.main()
