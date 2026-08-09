#!/usr/bin/env python3
"""Tests for the thin cohort-runner CLI compatibility entry point."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import stat
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
OPERATIONS = ROOT / "operations"
CLI_PATH = OPERATIONS / "run-incident-harness-cohort.py"
if str(OPERATIONS) not in sys.path:
    sys.path.insert(0, str(OPERATIONS))

import cohort_runner_service  # noqa: E402


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
