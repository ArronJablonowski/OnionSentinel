#!/usr/bin/env python3
"""Projected disk admission regression tests."""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "n8n" / "bin" / "disk_capacity.py"


def load_module():
    spec = importlib.util.spec_from_file_location("disk_capacity_under_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class DiskCapacityTest(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()

    @staticmethod
    def usage(used_percent: int):
        total = 1000
        used = total * used_percent // 100
        return type("Usage", (), {"total": total, "used": used, "free": total - used})()

    def test_healthy_projected_work_passes(self) -> None:
        with mock.patch.object(self.module.shutil, "disk_usage", return_value=self.usage(50)):
            result = self.module.require_runtime_capacity(
                Path("/runtime"), 100, min_free_bytes=100,
            )
        self.assertEqual(result["projected_used_percent"], 60.0)

    def test_work_stops_at_start_threshold(self) -> None:
        with mock.patch.object(self.module.shutil, "disk_usage", return_value=self.usage(75)):
            with self.assertRaises(self.module.DiskCapacityError):
                self.module.require_runtime_capacity(Path("/runtime"), 0, min_free_bytes=0)

    def test_projected_work_cannot_cross_start_threshold(self) -> None:
        with mock.patch.object(self.module.shutil, "disk_usage", return_value=self.usage(70)):
            with self.assertRaises(self.module.DiskCapacityError):
                self.module.require_runtime_capacity(Path("/runtime"), 50, min_free_bytes=0)

    def test_hard_limit_has_distinct_failure(self) -> None:
        with mock.patch.object(self.module.shutil, "disk_usage", return_value=self.usage(80)):
            with self.assertRaisesRegex(self.module.DiskCapacityError, "hard limit"):
                self.module.require_runtime_capacity(Path("/runtime"), 0, min_free_bytes=0)

    def test_environment_cannot_raise_hard_limit_above_eighty_percent(self) -> None:
        with mock.patch.dict(
            self.module.os.environ,
            {"ONION_SENTINEL_DISK_HARD_MAX_USED_PERCENT": "95"},
        ):
            _start, hard, _reserve = self.module.runtime_policy()
        self.assertEqual(hard, 80.0)


if __name__ == "__main__":
    unittest.main()
