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

    def run_check(self, smart: dict, source: str = "/dev/sda1", root_used_percent: int = 20) -> tuple[int, dict]:
        findmnt = subprocess.CompletedProcess(
            "findmnt", 0, json.dumps({"filesystems": [{"source": source}]}), ""
        )
        smartctl = subprocess.CompletedProcess("smartctl", 0, json.dumps(smart), "")
        output = io.StringIO()
        ssd_usage = type("Usage", (), {
            "total": 1024**4, "used": 100 * 1024**3, "free": 924 * 1024**3
        })()
        root_total = 32 * 1024**3
        root_used = root_total * root_used_percent // 100
        root_usage = type("Usage", (), {
            "total": root_total, "used": root_used, "free": root_total - root_used
        })()
        with (
            mock.patch.object(self.module, "run", side_effect=[findmnt, smartctl]),
            mock.patch.object(self.module.shutil, "disk_usage", side_effect=[root_usage, ssd_usage]),
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

    def test_root_sd_card_warns_before_hard_limit(self) -> None:
        rc, result = self.run_check({
            "smart_status": {"passed": True},
            "temperature": {"current": 36},
            "nvme_smart_health_information_log": {
                "critical_warning": 0, "media_errors": 0, "unsafe_shutdowns": 0
            },
        }, root_used_percent=76)
        self.assertEqual(rc, 1)
        self.assertTrue(any("root usage is at or above 75" in item for item in result["failures"]))

    def test_root_sd_card_hard_limit_is_explicit(self) -> None:
        rc, result = self.run_check({
            "smart_status": {"passed": True},
            "temperature": {"current": 36},
            "nvme_smart_health_information_log": {
                "critical_warning": 0, "media_errors": 0, "unsafe_shutdowns": 0
            },
        }, root_used_percent=81)
        self.assertEqual(rc, 1)
        self.assertTrue(any("hard limit" in item for item in result["failures"]))

    def test_environment_cannot_raise_disk_thresholds_above_policy(self) -> None:
        with mock.patch.dict(self.module.os.environ, {
            "RELAY_SSD_MAX_USED_PERCENT": "95",
            "RELAY_ROOT_HARD_USED_PERCENT": "95",
        }):
            reloaded = load_module()
        self.assertEqual(reloaded.MAX_USED_PERCENT, 75)
        self.assertEqual(reloaded.ROOT_HARD_USED_PERCENT, 80)


if __name__ == "__main__":
    unittest.main()
