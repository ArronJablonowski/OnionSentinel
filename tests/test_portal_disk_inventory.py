"""Behavior contracts for local disk usage and cached inventory policy."""
from __future__ import annotations

import datetime as dt
from collections import namedtuple
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_disk_inventory import (  # noqa: E402
    DiskInventorySources,
    DiskScanOutcome,
    compose_local_disk_inventory,
    compose_local_disk_usage,
    parse_file_stat_lines,
    parse_size_path_lines,
)


class DiskInventoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.home = Path("/Users/test user")
        self.now = dt.datetime(2026, 8, 7, 20, tzinfo=dt.timezone.utc)
        self.cache = {"generated": 0.0, "dirs": [], "files": [], "warnings": []}
        self.directory_calls = 0
        self.file_calls = 0
        self.directory_outcome = DiskScanOutcome()
        self.file_outcome = DiskScanOutcome()

    def sources(self) -> DiskInventorySources:
        def directory_scan():
            self.directory_calls += 1
            if isinstance(self.directory_outcome, Exception):
                raise self.directory_outcome
            return self.directory_outcome

        def file_scan():
            self.file_calls += 1
            if isinstance(self.file_outcome, Exception):
                raise self.file_outcome
            return self.file_outcome

        return DiskInventorySources(
            home=self.home,
            cache=self.cache,
            now=lambda: self.now,
            directory_scan=directory_scan,
            file_scan=file_scan,
        )

    def test_parsers_skip_malformed_rows_and_preserve_paths_with_spaces(self) -> None:
        self.assertEqual(
            parse_size_path_lines("10 /one path\ninvalid\n3 /two", 1024),
            [
                {"size": 10240, "path": "/one path"},
                {"size": 3072, "path": "/two"},
            ],
        )
        self.assertEqual(
            parse_file_stat_lines("2 900 /file path\nbad row\n4 nope /bad"),
            [{"size": 1024, "logical_size": 900, "path": "/file path"}],
        )

    def test_fresh_inventory_excludes_home_sorts_directories_and_preserves_file_order(self) -> None:
        self.directory_outcome = DiskScanOutcome(
            stdout=(
                f"999 {self.home}\n20 /small\n100 /largest\n50 /middle\n"
            ),
            stderr="du warning one\ndu warning last\n",
        )
        self.file_outcome = DiskScanOutcome(
            stdout="8 1000 /first file\n4 500 /second\n",
            stderr="file warning\n",
        )

        directories, files, warnings, generated = compose_local_disk_inventory(
            self.sources(), limit=2
        )

        self.assertEqual([row["path"] for row in directories], ["/largest", "/middle"])
        self.assertEqual([row["path"] for row in files], ["/first file", "/second"])
        self.assertEqual(
            warnings,
            ["Directory scan warnings: du warning last", "File scan warnings: file warning"],
        )
        self.assertEqual(generated, self.now)
        self.assertEqual(self.cache["generated"], self.now.timestamp())

    def test_valid_cache_returns_copies_without_running_scans(self) -> None:
        generated = self.now.timestamp() - 100
        cached_dirs = [{"size": 1, "path": "/cached"}]
        self.cache.update(
            {
                "generated": generated,
                "dirs": cached_dirs,
                "files": [{"size": 2, "path": "/file"}],
                "warnings": ["cached warning"],
            }
        )

        directories, files, warnings, when = compose_local_disk_inventory(
            self.sources(), cache_seconds=600
        )

        self.assertEqual(self.directory_calls, 0)
        self.assertEqual(self.file_calls, 0)
        self.assertEqual(directories, cached_dirs)
        self.assertIsNot(directories, cached_dirs)
        self.assertEqual(files[0]["path"], "/file")
        self.assertEqual(warnings, ["cached warning"])
        self.assertEqual(when.timestamp(), generated)

    def test_timeouts_and_exceptions_produce_independent_stable_warnings(self) -> None:
        self.directory_outcome = DiskScanOutcome(timed_out=True)
        self.file_outcome = RuntimeError("find failed")

        directories, files, warnings, _when = compose_local_disk_inventory(
            self.sources()
        )

        self.assertEqual(directories, [])
        self.assertEqual(files, [])
        self.assertEqual(
            warnings,
            [
                "Directory scan timed out after 30 seconds; showing cached/empty directory data.",
                "File scan failed: find failed",
            ],
        )

    def test_disk_usage_projects_values_and_has_zero_fallback(self) -> None:
        Usage = namedtuple("Usage", "total used free")
        self.assertEqual(
            compose_local_disk_usage(self.home, lambda _path: Usage(100, 75, 25)),
            (25, 100, 25.0),
        )

        def fail(_path):
            raise OSError("unavailable")

        self.assertEqual(compose_local_disk_usage(self.home, fail), (0, 0, 0.0))


if __name__ == "__main__":
    unittest.main()
