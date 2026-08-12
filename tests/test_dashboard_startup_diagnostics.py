#!/usr/bin/env python3
"""Contracts for bounded dashboard subprocess startup diagnostics."""

from __future__ import annotations

import io
import unittest

from tests.dashboard_startup_diagnostics import startup_failure_diagnostic


class _Process:
    def __init__(self, returncode: int | None) -> None:
        self.returncode = returncode

    def poll(self) -> int | None:
        return self.returncode


class DashboardStartupDiagnosticsTests(unittest.TestCase):
    def test_reports_live_process_and_last_probe_when_log_is_empty(self) -> None:
        diagnostic = startup_failure_diagnostic(
            _Process(None),
            io.StringIO(""),
            last_probe="ConnectionRefusedError: synthetic refusal",
        )

        self.assertIn("process_state=running", diagnostic)
        self.assertIn("returncode=none", diagnostic)
        self.assertIn(
            "last_probe=ConnectionRefusedError: synthetic refusal",
            diagnostic,
        )
        self.assertIn("output=<empty>", diagnostic)

    def test_reports_exited_process_and_bounds_probe_and_terminal_output(
        self,
    ) -> None:
        diagnostic = startup_failure_diagnostic(
            _Process(17),
            io.StringIO("prefix\n" + ("x" * 20_000) + "\nterminal"),
            last_probe="p" * 2_000,
        )

        self.assertIn("process_state=exited", diagnostic)
        self.assertIn("returncode=17", diagnostic)
        self.assertIn("<truncated>", diagnostic)
        self.assertNotIn("prefix", diagnostic)
        self.assertTrue(diagnostic.endswith("terminal"))
        self.assertLess(len(diagnostic), 9_000)


if __name__ == "__main__":
    unittest.main()
