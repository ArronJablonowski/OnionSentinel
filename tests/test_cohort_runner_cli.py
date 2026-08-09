#!/usr/bin/env python3
"""Tests for the thin cohort-runner CLI compatibility entry point."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import stat
import subprocess
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
OPERATIONS = ROOT / "operations"
CLI_PATH = OPERATIONS / "run-incident-harness-cohort.py"
if str(OPERATIONS) not in sys.path:
    sys.path.insert(0, str(OPERATIONS))

import cohort_runner_service  # noqa: E402
import cohort_runner_cli  # noqa: E402


class CohortRunnerCliTests(unittest.TestCase):
    def test_historical_cli_path_is_executable(self) -> None:
        mode = stat.S_IMODE(CLI_PATH.stat().st_mode)
        self.assertTrue(mode & stat.S_IXUSR)

    def test_cli_delegates_parser_and_main_to_service(self) -> None:
        spec = importlib.util.spec_from_file_location("cohort_runner_cli", CLI_PATH)
        assert spec and spec.loader
        cli = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cli)
        self.assertIs(cli.build_parser, cohort_runner_service.build_parser)
        self.assertIs(cli.main, cohort_runner_service.main)

    def test_service_delegates_cli_policy_to_adapter(self) -> None:
        self.assertIs(
            cohort_runner_service.build_cli_parser,
            cohort_runner_cli.build_parser,
        )
        self.assertIs(cohort_runner_service.run_cli, cohort_runner_cli.main)

    def test_monitor_nonterminal_exit_status_is_preserved(self) -> None:
        monitor = mock.Mock(return_value=({"state": "monitoring"}, False))
        unused = mock.Mock()
        operations = cohort_runner_cli.CohortCliOperations(
            freeze_cohort=unused,
            freeze_cohort_from_rows=unused,
            queue_cohort=unused,
            monitor_cohort=monitor,
            export_cohort=unused,
            handled_errors=(RuntimeError,),
        )
        parser = cohort_runner_cli.build_parser(
            "test parser", ["incident-responder", "soc-analyst"]
        )
        with mock.patch("builtins.print"):
            status = cohort_runner_cli.main(
                [
                    "monitor",
                    "--db",
                    "/tmp/alerts.sqlite3",
                    "--manifest",
                    "/tmp/cohort.json",
                ],
                parser=parser,
                operations=operations,
            )
        self.assertEqual(status, 3)
        monitor.assert_called_once()

    def test_historical_cli_path_preserves_help(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(CLI_PATH), "--help"],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=10,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("freeze-from-rows", completed.stdout)
        self.assertIn("queue", completed.stdout)
        self.assertIn("monitor", completed.stdout)
        self.assertIn("export", completed.stdout)


if __name__ == "__main__":
    unittest.main()
