"""Characterization for the bounded Software Inventory query-page transport."""
from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "n8n" / "bin" / "software_inventory_transport.py"


def load_module():
    dependency = str(MODULE_PATH.parent)
    if dependency not in sys.path:
        sys.path.insert(0, dependency)
    spec = importlib.util.spec_from_file_location(
        "software_inventory_query_page_target",
        MODULE_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load Software Inventory transport")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class SoftwareInventoryQueryPageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_module()

    def setUp(self) -> None:
        self.config = {
            "known_hosts": "/private/known_hosts",
            "connect_timeout_seconds": 17,
            "ssh_key": Path("/private/id_ed25519"),
            "port": 2222,
            "ssh_user": "collector",
            "host": "relay.internal",
            "max_response_bytes": 7654321,
            "max_stderr_bytes": 4321,
        }
        self.source = "zeek_software"
        self.window = {
            "start": "2026-08-11T12:00:00.000Z",
            "end": "2026-08-12T12:00:00.000Z",
        }
        self.after = {"product": "Example", "version": "1"}
        self.request = {
            "z": 1,
            "after": self.after,
            "window": {"end": "normalized-end", "start": "normalized-start"},
        }

    def expected_command(self) -> list[str]:
        return [
            "/usr/bin/ssh",
            "-T",
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "UserKnownHostsFile=/private/known_hosts",
            "-o",
            "ConnectTimeout=17",
            "-o",
            "ServerAliveInterval=15",
            "-o",
            "ServerAliveCountMax=3",
            "-i",
            "/private/id_ed25519",
            "-p",
            "2222",
            "collector@relay.internal",
        ]

    def test_success_preserves_call_order_command_encoding_and_validation(self) -> None:
        calls: list[tuple[object, ...]] = []
        completed = SimpleNamespace(
            returncode=0,
            stdout='{"ok":true}',
            stderr="unused",
        )
        expected = {"validated": True}

        def build(source, window, page_size, after):
            calls.append(("build", source, window, page_size, after))
            return self.request

        def run(command, **kwargs):
            calls.append(("run", command, kwargs))
            return completed

        def validate(payload, **kwargs):
            calls.append(("validate", payload, kwargs))
            return expected

        with (
            mock.patch.object(self.module, "build_request", side_effect=build),
            mock.patch.object(self.module, "run_bounded_command", side_effect=run),
            mock.patch.object(self.module, "validate_response", side_effect=validate),
        ):
            result = self.module.query_page(
                self.config,
                self.source,
                self.window,
                37,
                self.after,
                0.25,
            )

        self.assertIs(result, expected)
        self.assertEqual(
            calls,
            [
                ("build", self.source, self.window, 37, self.after),
                (
                    "run",
                    self.expected_command(),
                    {
                        "stdin_text": json.dumps(
                            self.request,
                            separators=(",", ":"),
                            sort_keys=True,
                        ),
                        "timeout_seconds": 1.0,
                        "max_stdout_bytes": 7654321,
                        "max_stderr_bytes": 4321,
                    },
                ),
                (
                    "validate",
                    {"ok": True},
                    {
                        "expected_source": self.source,
                        "expected_window": self.request["window"],
                        "requested_page_size": 37,
                        "previous_after": self.after,
                    },
                ),
            ],
        )

    def test_nonzero_exit_preserves_diagnostic_and_fallback_errors(self) -> None:
        for diagnostic, suffix in (
            ("bounded detail", "bounded detail"),
            ("", "no bounded diagnostic"),
        ):
            completed = SimpleNamespace(
                returncode=23,
                stdout="synthetic stdout",
                stderr="synthetic stderr",
            )
            with self.subTest(diagnostic=diagnostic):
                with (
                    mock.patch.object(
                        self.module,
                        "build_request",
                        return_value=self.request,
                    ),
                    mock.patch.object(
                        self.module,
                        "run_bounded_command",
                        return_value=completed,
                    ),
                    mock.patch.object(
                        self.module,
                        "relay_failure_diagnostic",
                        return_value=diagnostic,
                    ) as relay_diagnostic,
                    mock.patch.object(
                        self.module,
                        "validate_response",
                    ) as validate,
                ):
                    with self.assertRaisesRegex(
                        self.module.SoftwareInventoryError,
                        f"^software inventory relay returned 23: {suffix}$",
                    ):
                        self.module.query_page(
                            self.config,
                            self.source,
                            self.window,
                            37,
                            self.after,
                            9,
                        )
            relay_diagnostic.assert_called_once_with(
                "synthetic stdout",
                "synthetic stderr",
            )
            validate.assert_not_called()

    def test_invalid_json_preserves_public_error_and_decoder_cause(self) -> None:
        completed = SimpleNamespace(
            returncode=0,
            stdout="not-json",
            stderr="unused",
        )
        with (
            mock.patch.object(
                self.module,
                "build_request",
                return_value=self.request,
            ),
            mock.patch.object(
                self.module,
                "run_bounded_command",
                return_value=completed,
            ),
            mock.patch.object(self.module, "validate_response") as validate,
        ):
            with self.assertRaisesRegex(
                self.module.SoftwareInventoryError,
                "^software inventory relay returned invalid JSON$",
            ) as raised:
                self.module.query_page(
                    self.config,
                    self.source,
                    self.window,
                    37,
                    self.after,
                    9,
                )
        self.assertIsInstance(raised.exception.__cause__, json.JSONDecodeError)
        validate.assert_not_called()


if __name__ == "__main__":
    unittest.main()
