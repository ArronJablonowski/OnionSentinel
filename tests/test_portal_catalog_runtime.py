from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_catalog_runtime import artifact_library_disk_usage  # noqa: E402


class ArtifactLibraryDiskUsageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def runtime(self, roots, skipped=()):
        skipped_paths = {Path(path).resolve() for path in skipped}
        return SimpleNamespace(
            SCAN_ROOTS=roots,
            os=os,
            Path=Path,
            should_skip_dir=lambda path: path.resolve() in skipped_paths,
        )

    @staticmethod
    def allocated_size(path: Path) -> int:
        metadata = path.resolve().stat()
        return int(getattr(metadata, "st_blocks", 0) or 0) * 512 or metadata.st_size

    def test_counts_files_prunes_directories_and_deduplicates_resolved_paths(self) -> None:
        library = self.root / "library"
        library.mkdir()
        included = library / "included.txt"
        included.write_bytes(b"included")
        skipped = library / "skip"
        skipped.mkdir()
        excluded = skipped / "excluded.txt"
        excluded.write_bytes(b"excluded")
        alias = self.root / "alias.txt"
        alias.symlink_to(included)

        total = artifact_library_disk_usage(
            self.runtime([library, included, alias], skipped=[skipped])
        )

        self.assertEqual(total, self.allocated_size(included))

    def test_missing_directory_and_dangling_symlink_are_ignored(self) -> None:
        dangling = self.root / "dangling"
        dangling.symlink_to(self.root / "missing-target")
        directory = self.root / "directory"
        directory.mkdir()
        nested = directory / "nested.txt"
        nested.write_bytes(b"nested")

        total = artifact_library_disk_usage(
            self.runtime([self.root / "missing", dangling, directory])
        )

        self.assertEqual(total, self.allocated_size(nested))


if __name__ == "__main__":
    unittest.main()
