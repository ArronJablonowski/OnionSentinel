"""Characterization for bounded process-snapshot startup composition."""
from __future__ import annotations

import hashlib
import inspect
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BIN_DIR = ROOT / "n8n" / "bin"
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))
import bounded_process_observation as observation  # noqa: E402


class FakeStream:
    def __init__(self, descriptor: int) -> None:
        self.descriptor = descriptor
        self.closed = False

    def fileno(self) -> int:
        return self.descriptor

    def close(self) -> None:
        self.closed = True


class FakeProcess:
    def __init__(self) -> None:
        self.stdout = FakeStream(10)
        self.stderr = FakeStream(11)
        self.wait_calls: list[float] = []

    def wait(self, timeout: float) -> int:
        self.wait_calls.append(timeout)
        return 0


class FakeSelector:
    def __init__(self) -> None:
        self.registrations: list[tuple[object, int]] = []
        self.closed = False

    def register(self, stream: object, event: int) -> None:
        self.registrations.append((stream, event))

    def close(self) -> None:
        self.closed = True


class BoundedProcessObservationStartupTests(unittest.TestCase):
    def test_surface_and_signature_are_exact(self) -> None:
        names = sorted(name for name in dir(observation) if not name.startswith("__"))
        encoded = json.dumps(names, separators=(",", ":"), sort_keys=True).encode()
        self.assertEqual(
            (len(names), hashlib.sha256(encoded).hexdigest()),
            (28, "fd08a0067f0fe73e0c7b239d8e7e1f64193e30e0d893831a20f40a548eba1789"),
        )
        self.assertEqual(str(inspect.signature(observation._bounded_ps_output)), "() -> 'str'")

    def test_snapshot_startup_stream_caps_decode_and_cleanup_are_exact(self) -> None:
        process = FakeProcess()
        selector = FakeSelector()

        def read_snapshot_stream(**kwargs: object) -> None:
            streams = kwargs["streams"]
            streams[process.stdout][1].extend(b"synthetic rows\n")
            streams[process.stderr][1].extend(b"ignored on success")
            self.assertEqual(
                streams[process.stdout][2],
                observation._PS_SNAPSHOT_STDOUT_BYTES,
            )
            self.assertEqual(
                streams[process.stderr][2],
                observation._PS_SNAPSHOT_STDERR_BYTES,
            )

        with mock.patch.object(
            observation.os.environ,
            "copy",
            return_value={"INHERITED": "yes"},
        ), mock.patch.object(
            observation.subprocess,
            "Popen",
            return_value=process,
        ) as popen, mock.patch.object(
            observation.selectors,
            "DefaultSelector",
            return_value=selector,
        ), mock.patch.object(
            observation.os,
            "set_blocking",
        ) as set_blocking, mock.patch.object(
            observation.time,
            "monotonic",
            return_value=100.0,
        ), mock.patch.object(
            observation,
            "_read_snapshot_stream",
            side_effect=read_snapshot_stream,
        ) as read:
            self.assertEqual(observation._bounded_ps_output(), "synthetic rows\n")

        popen.assert_called_once_with(
            [
                str(observation._PS_PATH),
                "-ww",
                "-axo",
                "pid=,ppid=,pgid=,uid=,state=,lstart=,command=",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"INHERITED": "yes", "LC_ALL": "C", "LANG": "C"},
            start_new_session=True,
        )
        self.assertEqual(
            set_blocking.call_args_list,
            [mock.call(10, False), mock.call(11, False)],
        )
        self.assertEqual(
            selector.registrations,
            [
                (process.stdout, observation.selectors.EVENT_READ),
                (process.stderr, observation.selectors.EVENT_READ),
            ],
        )
        self.assertEqual(read.call_args.kwargs["deadline"], 100.0 + observation._PS_SNAPSHOT_TIMEOUT_SECONDS)
        self.assertEqual(process.wait_calls, [observation._PS_SNAPSHOT_TIMEOUT_SECONDS])
        self.assertTrue(selector.closed)
        self.assertTrue(process.stdout.closed)
        self.assertTrue(process.stderr.closed)


if __name__ == "__main__":
    unittest.main()
