#!/usr/bin/env python3
"""Clean-interpreter coverage for controlled scheduler module loading."""
from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEDULER_BIN = REPO_ROOT / "n8n" / "bin"


class SchedulerImportlibCompatibilityTest(unittest.TestCase):
    def test_job_compat_loads_importlib_util_in_a_clean_interpreter(self) -> None:
        script = (
            "import importlib, sys; "
            f"sys.path.insert(0, {str(SCHEDULER_BIN)!r}); "
            "import scheduler_job_compat; "
            "assert hasattr(importlib, 'util')"
        )
        result = subprocess.run(
            [sys.executable, "-I", "-c", script],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
