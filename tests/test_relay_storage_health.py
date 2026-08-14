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

    def test_probe_order_and_malformed_json_fail_closed(self) -> None:
        findmnt = subprocess.CompletedProcess("findmnt", 0, "not-json", "")
        smartctl = subprocess.CompletedProcess("smartctl", 0, "not-json", "")
        root_usage = type("Usage", (), {
            "total": 32 * 1024**3,
            "used": 4 * 1024**3,
            "free": 28 * 1024**3,
        })()
        ssd_usage = type("Usage", (), {
            "total": 1024**4,
            "used": 100 * 1024**3,
            "free": 924 * 1024**3,
        })()
        output = io.StringIO()
        with (
            mock.patch.object(
                self.module,
                "run",
                side_effect=[findmnt, smartctl],
            ) as run,
            mock.patch.object(
                self.module.shutil,
                "disk_usage",
                side_effect=[root_usage, ssd_usage],
            ) as disk_usage,
            contextlib.redirect_stdout(output),
        ):
            rc = self.module.main()

        self.assertEqual(rc, 1)
        self.assertEqual(
            [call.args[0] for call in run.call_args_list],
            [
                ["/usr/bin/findmnt", "-J", "-T", str(self.module.MOUNT)],
                [
                    "/usr/bin/sudo",
                    "-n",
                    self.module.SMARTCTL,
                    "-a",
                    "-j",
                    self.module.DEVICE,
                ],
            ],
        )
        self.assertEqual(
            [call.args[0] for call in disk_usage.call_args_list],
            [self.module.ROOT_MOUNT, self.module.MOUNT],
        )
        result = json.loads(output.getvalue())
        self.assertEqual(result["failures"], [
            "relay SSD mount resolved to the SD card or an unknown source",
            "SMART query returned invalid JSON",
            "SMART overall health did not pass",
        ])

    def test_probe_errors_preserve_failure_order(self) -> None:
        findmnt = subprocess.CompletedProcess(
            "findmnt",
            0,
            '{"filesystems":[{"source":"/dev/sda1"}]}',
            "",
        )
        smartctl = subprocess.CompletedProcess("smartctl", 4, "", "")
        output = io.StringIO()
        with (
            mock.patch.object(
                self.module,
                "run",
                side_effect=[findmnt, smartctl],
            ),
            mock.patch.object(
                self.module.shutil,
                "disk_usage",
                side_effect=[
                    OSError("root unavailable"),
                    OSError("ssd unavailable"),
                ],
            ),
            contextlib.redirect_stdout(output),
        ):
            rc = self.module.main()

        self.assertEqual(rc, 1)
        self.assertEqual(json.loads(output.getvalue())["failures"], [
            "relay root usage check failed: root unavailable",
            "relay SSD usage check failed: ssd unavailable",
            "SMART query failed with exit 4",
        ])

    def test_invalid_smart_counter_retains_value_error(self) -> None:
        smart = {
            "smart_status": {"passed": True},
            "nvme_smart_health_information_log": {"media_errors": "bad"},
        }
        with self.assertRaisesRegex(ValueError, "invalid literal"):
            self.run_check(smart)


if __name__ == "__main__":
    unittest.main()
