"""Characterize forced-command PCAP rsync admission and dispatch."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "n8n/bin/onion-sentinel-pcap-intake.py"


def load_module(name: str = "pcap_intake_dispatch_projection"):
    spec = importlib.util.spec_from_file_location(name, MODULE_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError("PCAP intake cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Rejected(Exception):
    pass


class PcapIntakeDispatchProjectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.module = load_module(f"pcap_intake_projection_{id(self)}")
        self.module.ROOT = Path(self.temp.name) / "artifacts"

    def tearDown(self):
        self.temp.cleanup()

    def test_validate_rsync_preserves_identity_mutation_and_capacity_order(self):
        target = self.module.ROOT / "request-271"
        target.mkdir(parents=True)
        self.module.write_reservation("request-271", 1024)
        args = ["rsync", "--server", "-logDtpre", ".", str(target)]
        with mock.patch.object(self.module, "admit_capacity") as capacity:
            validated = self.module.validate_rsync(args)
        self.assertIs(validated, args)
        self.assertEqual(
            args,
            [
                "rsync",
                "--server",
                "-logDtpre",
                "--max-size=1024",
                ".",
                str(target),
            ],
        )
        capacity.assert_called_once_with(
            target.resolve(), 1024, "PCAP rsync request-271"
        )

        existing = [
            "rsync",
            "--server",
            "--max-size=2048",
            ".",
            str(target),
        ]
        with mock.patch.object(self.module, "admit_capacity") as capacity:
            self.assertIs(self.module.validate_rsync(existing), existing)
        self.assertEqual(
            existing,
            ["rsync", "--server", "--max-size=2048", ".", str(target)],
        )
        capacity.assert_called_once_with(
            target.resolve(), 1024, "PCAP rsync request-271"
        )

    def test_validate_rsync_rejection_policy_is_exact_and_precedes_reservation(self):
        outside = Path(self.temp.name) / "outside"
        cases = (
            ([], "only rsync server mode is permitted"),
            (["sh", "--server", ".", str(outside)], "only rsync server mode is permitted"),
            (["rsync", "--server", "--sender", ".", str(outside)], "only inbound rsync receiver mode is permitted"),
            (["rsync", "--server", "--daemon", ".", str(outside)], "only inbound rsync receiver mode is permitted"),
            (["rsync", "--server", "--delete", ".", str(outside)], "destructive or command-changing rsync options are not permitted"),
            (["rsync", "--server", "--remove-source-files", ".", str(outside)], "destructive or command-changing rsync options are not permitted"),
            (["rsync", "--server", "--rsync-path", ".", str(outside)], "destructive or command-changing rsync options are not permitted"),
            (["rsync", "--server", ".", str(outside)], "rsync target is outside a single request directory"),
        )
        for args, reason in cases:
            with self.subTest(args=args):
                with mock.patch.object(
                    self.module, "reject", side_effect=Rejected
                ) as reject, mock.patch.object(
                    self.module, "load_reservation"
                ) as reservation:
                    with self.assertRaises(Rejected):
                        self.module.validate_rsync(list(args))
                reject.assert_called_once_with(reason)
                reservation.assert_not_called()

    def _dispatch_ports(self):
        parent = mock.Mock()
        ports = {
            "prepare": mock.Mock(return_value=11),
            "verify": mock.Mock(return_value=12),
            "cleanup": mock.Mock(return_value=13),
            "validate_rsync": mock.Mock(
                return_value=["rsync", "--server", ".", "/synthetic/request"]
            ),
            "which": mock.Mock(return_value=None),
            "execv": mock.Mock(return_value=None),
            "reject": mock.Mock(side_effect=Rejected),
        }
        for name, port in ports.items():
            parent.attach_mock(port, name)
        return parent, ports

    def _invoke_main(self, command: str, ports, *, installed=()):
        stdout = io.StringIO()
        stderr = io.StringIO()
        installed = set(installed)

        def is_file(path):
            return str(path) in installed

        with contextlib.ExitStack() as stack:
            stack.enter_context(
                mock.patch.dict(
                    os.environ, {"SSH_ORIGINAL_COMMAND": command}, clear=False
                )
            )
            for name in ("prepare", "verify", "cleanup", "validate_rsync", "reject"):
                stack.enter_context(mock.patch.object(self.module, name, ports[name]))
            stack.enter_context(mock.patch.object(self.module.shutil, "which", ports["which"]))
            stack.enter_context(mock.patch.object(self.module.os, "execv", ports["execv"]))
            path_is_file = stack.enter_context(
                mock.patch.object(self.module.Path, "is_file", autospec=True, side_effect=is_file)
            )
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                result = self.module.main()
        return result, stdout.getvalue(), stderr.getvalue(), path_is_file

    def test_control_commands_preserve_exact_dispatch_and_short_circuit(self):
        cases = (
            ("onion-sentinel-pcap-intake prepare request-a 1024", 11, "prepare", ("request-a", "1024")),
            (
                "onion-sentinel-pcap-intake verify request-b request-b.tar 9 abc",
                12,
                "verify",
                ("request-b", "request-b.tar", "9", "abc"),
            ),
            ("onion-sentinel-pcap-intake cleanup request-c", 13, "cleanup", ("request-c",)),
        )
        for command, expected, port_name, arguments in cases:
            with self.subTest(command=command):
                parent, ports = self._dispatch_ports()
                result, stdout, stderr, path_is_file = self._invoke_main(command, ports)
                self.assertEqual((result, stdout, stderr), (expected, "", ""))
                self.assertEqual(parent.mock_calls, [getattr(mock.call, port_name)(*arguments)])
                path_is_file.assert_not_called()

    def test_command_parse_and_control_errors_preserve_exact_rejections(self):
        cases = (
            ("", "interactive sessions are not permitted"),
            ('"unterminated', "invalid command: No closing quotation"),
            (
                "onion-sentinel-pcap-intake unknown request",
                "unsupported intake control command",
            ),
        )
        for command, reason in cases:
            with self.subTest(command=command):
                parent, ports = self._dispatch_ports()
                with self.assertRaises(Rejected):
                    self._invoke_main(command, ports)
                self.assertEqual(parent.mock_calls, [mock.call.reject(reason)])

    def test_rsync_resolution_precedence_and_exec_argv_are_exact(self):
        parent, ports = self._dispatch_ports()
        result, stdout, stderr, path_is_file = self._invoke_main(
            "rsync --server . /synthetic/request",
            ports,
            installed=("/usr/local/bin/rsync",),
        )
        self.assertEqual((result, stdout, stderr), (127, "", ""))
        self.assertEqual(
            parent.mock_calls,
            [
                mock.call.validate_rsync(
                    ["rsync", "--server", ".", "/synthetic/request"]
                ),
                mock.call.execv(
                    "/usr/local/bin/rsync",
                    [
                        "/usr/local/bin/rsync",
                        "--server",
                        ".",
                        "/synthetic/request",
                    ],
                ),
            ],
        )
        self.assertEqual(
            path_is_file.mock_calls,
            [
                mock.call(Path("/opt/homebrew/bin/rsync")),
                mock.call(Path("/usr/local/bin/rsync")),
            ],
        )
        ports["which"].assert_not_called()

    def test_rsync_fallback_and_unavailable_boundaries_are_exact(self):
        parent, ports = self._dispatch_ports()
        ports["which"].return_value = "/synthetic/fallback-rsync"
        result, _, _, _ = self._invoke_main(
            "rsync --server . /synthetic/request", ports
        )
        self.assertEqual(result, 127)
        self.assertEqual(
            parent.mock_calls[-2:],
            [
                mock.call.which("rsync"),
                mock.call.execv(
                    "/synthetic/fallback-rsync",
                    [
                        "/synthetic/fallback-rsync",
                        "--server",
                        ".",
                        "/synthetic/request",
                    ],
                ),
            ],
        )

        parent, ports = self._dispatch_ports()
        with self.assertRaises(Rejected):
            self._invoke_main("rsync --server . /synthetic/request", ports)
        self.assertEqual(
            parent.mock_calls[-2:],
            [mock.call.which("rsync"), mock.call.reject("rsync is unavailable")],
        )
        ports["execv"].assert_not_called()


if __name__ == "__main__":
    unittest.main()
