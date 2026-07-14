#!/usr/bin/env python3
"""Regression checks for the relay SSD health monitor."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "relay" / "app" / "storage_health.py"


def load_module():
    spec = importlib.util.spec_from_file_location("storage_health", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class RelayStorageHealthTest(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()

    def run_check(self, smart: dict, source: str = "/dev/sda1") -> tuple[int, dict]:
        findmnt = subprocess.CompletedProcess(
            "findmnt", 0, json.dumps({"filesystems": [{"source": source}]}), ""
        )
        smartctl = subprocess.CompletedProcess("smartctl", 0, json.dumps(smart), "")
        output = io.StringIO()
        usage = type("Usage", (), {
            "total": 1024**4, "used": 100 * 1024**3, "free": 924 * 1024**3
        })()
        with (
            mock.patch.object(self.module, "run", side_effect=[findmnt, smartctl]),
            mock.patch.object(self.module.shutil, "disk_usage", return_value=usage),
            contextlib.redirect_stdout(output),
        ):
            rc = self.module.main()
        return rc, json.loads(output.getvalue())

    def test_healthy_external_ssd_passes(self) -> None:
        rc, result = self.run_check({
            "smart_status": {"passed": True},
            "temperature": {"current": 36},
            "nvme_smart_health_information_log": {
                "critical_warning": 0, "media_errors": 0, "unsafe_shutdowns": 0
            },
        })
        self.assertEqual(rc, 0)
        self.assertTrue(result["ok"])

    def test_sd_card_fallback_and_media_error_fail(self) -> None:
        rc, result = self.run_check({
            "smart_status": {"passed": True},
            "temperature": {"current": 36},
            "nvme_smart_health_information_log": {
                "critical_warning": 0, "media_errors": 1, "unsafe_shutdowns": 0
            },
        }, source="/dev/mmcblk0p7")
        self.assertEqual(rc, 1)
        self.assertIn("SMART media errors are nonzero", result["failures"])
        self.assertTrue(any("SD card" in item for item in result["failures"]))


if __name__ == "__main__":
    unittest.main()
