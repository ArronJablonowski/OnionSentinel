#!/usr/bin/env python3
"""Direct contracts for legacy portal health composition."""
from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_health_read_service import (  # noqa: E402
    compose_portal_health,
    inspect_scan_root,
)


class FailingRoot:
    def __str__(self):
        return "/private/failing"

    def exists(self):
        return True

    def is_dir(self):
        return True

    def glob(self, _pattern):
        raise PermissionError("denied")


class PortalHealthReadServiceTests(unittest.TestCase):
    def test_root_snapshot_counts_only_top_level_html_without_list_materialization(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "one.html").write_text("one")
            (root / "two.html").write_text("two")
            (root / "other.txt").write_text("other")
            nested = root / "nested"
            nested.mkdir()
            (nested / "three.html").write_text("three")
            result = inspect_scan_root(root)
        self.assertEqual(result["html_here"], 2)
        self.assertIsNone(result["error"])

    def test_root_errors_are_reported_without_failing_health(self) -> None:
        result = inspect_scan_root(FailingRoot())
        self.assertEqual(result["html_here"], 0)
        self.assertIn("PermissionError", result["error"])

    def test_health_schema_preserves_runtime_identity_fields(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            result = compose_portal_health(
                [object(), object()], [Path(raw)],
                local_address="10.77.7.225",
                generated_at="2026-08-07  18:00:00-06:00",
            )
        self.assertTrue(result["ok"])
        self.assertEqual(result["reports"], 2)
        self.assertEqual(result["ip"], "10.77.7.225")
        self.assertEqual(len(result["roots"]), 1)


if __name__ == "__main__":
    unittest.main()
