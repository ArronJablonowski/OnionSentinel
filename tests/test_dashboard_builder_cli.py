"""Characterization and admission tests for the dashboard builder CLI."""
from __future__ import annotations

import hashlib
import importlib.util
import inspect
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = ROOT / "onion-sentinel-dashboard" / "scripts"
BUILDER_PATH = SCRIPT_DIR / "build_soc_alerts_dashboard.py"
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

EXPECTED_HELP = """usage: build_soc_alerts_dashboard.py [-h]

Build and publish the Onion Sentinel SOC dashboard.

options:
  -h, --help  show this help message and exit
"""


def load_builder():
    spec = importlib.util.spec_from_file_location(
        "dashboard_builder_cli_test",
        BUILDER_PATH,
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def sha256_json(value: object) -> str:
    encoded = json.dumps(
        value,
        default=str,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class DashboardBuilderCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.builder = load_builder()

    def test_facade_namespace_and_main_signature_are_exact(self) -> None:
        names = sorted(
            name for name in dir(self.builder) if not name.startswith("__")
        )
        self.assertEqual(
            (len(names), sha256_json(names)),
            (480, "75c4d9372093624308e6a2e89b821fd7ba7a4d7bee1e3bd5a355ebb8d54324bd"),
        )
        signature = str(inspect.signature(self.builder.main))
        self.assertEqual(
            (signature, hashlib.sha256(signature.encode("utf-8")).hexdigest()),
            (
                "() -> 'int'",
                "02679bd5daed5c118d1b717b87c82a8baa899c19863417657e07e83efbbf34fd",
            ),
        )

    def test_zero_argument_main_forwards_once_and_returns_exact_status(self) -> None:
        with mock.patch.object(
            self.builder._runtime,
            "main",
            return_value=17,
        ) as runtime_main:
            self.assertEqual(self.builder.main(), 17)
        runtime_main.assert_called_once_with()

    def test_cli_zero_arguments_preserve_publication_call_and_status(self) -> None:
        run_cli = getattr(self.builder, "__run_cli")
        with mock.patch.object(self.builder, "main", return_value=23) as main:
            self.assertEqual(run_cli([]), 23)
        main.assert_called_once_with()

    def test_cli_help_is_side_effect_free_before_runtime_main(self) -> None:
        run_cli = getattr(self.builder, "__run_cli")
        for argument in ("-h", "--help"):
            with self.subTest(argument=argument), mock.patch.object(
                self.builder,
                "main",
            ) as main, mock.patch("sys.stdout") as stdout, mock.patch(
                "sys.stderr"
            ) as stderr:
                self.assertEqual(run_cli([argument]), 0)
            main.assert_not_called()
            stdout.write.assert_called_once_with(EXPECTED_HELP)
            stderr.write.assert_not_called()

    def test_cli_invalid_arguments_fail_closed_before_runtime_main(self) -> None:
        run_cli = getattr(self.builder, "__run_cli")
        with mock.patch.object(self.builder, "main") as main, mock.patch(
            "sys.stdout"
        ) as stdout, mock.patch("sys.stderr") as stderr:
            self.assertEqual(
                run_cli(["--output", "/tmp/candidate"]),
                2,
            )
        main.assert_not_called()
        stdout.write.assert_not_called()
        self.assertEqual(
            [call.args[0] for call in stderr.write.call_args_list],
            [
                "usage: build_soc_alerts_dashboard.py [-h]\n",
                "build_soc_alerts_dashboard.py: error: unrecognized arguments: "
                "--output /tmp/candidate\n",
            ],
        )

    def test_cli_subprocess_help_and_invalid_arguments_create_no_output(self) -> None:
        cases = (
            (["--help"], 0, EXPECTED_HELP, ""),
            (
                ["--unknown"],
                2,
                "",
                "usage: build_soc_alerts_dashboard.py [-h]\n"
                "build_soc_alerts_dashboard.py: error: unrecognized arguments: "
                "--unknown\n",
            ),
        )
        for arguments, status, stdout, stderr in cases:
            with self.subTest(arguments=arguments), tempfile.TemporaryDirectory() as home:
                environment = dict(os.environ)
                environment["HOME"] = home
                environment["PYTHONDONTWRITEBYTECODE"] = "1"
                result = subprocess.run(
                    [sys.executable, str(BUILDER_PATH), *arguments],
                    check=False,
                    capture_output=True,
                    env=environment,
                    text=True,
                    timeout=10,
                )
                self.assertEqual(result.returncode, status)
                self.assertEqual(result.stdout, stdout)
                self.assertEqual(result.stderr, stderr)
                self.assertFalse((Path(home) / "SOC Alerts Web").exists())


if __name__ == "__main__":
    unittest.main()
