import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "onion-sentinel-dashboard" / "scripts" / "atomic_io.py"
SPEC = importlib.util.spec_from_file_location("dashboard_atomic_io", MODULE)
assert SPEC and SPEC.loader
ATOMIC = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ATOMIC)


class AtomicPublicationTests(unittest.TestCase):
    def test_text_and_json_replace_complete_files_without_temp_residue(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            text_path = root / "index.html"
            text_path.write_text("old", encoding="utf-8")
            ATOMIC.atomic_write_text(text_path, "new dashboard")
            self.assertEqual(text_path.read_text(encoding="utf-8"), "new dashboard")

            json_path = root / "status.json"
            ATOMIC.atomic_write_json(json_path, {"ok": True, "count": 2})
            self.assertEqual(json.loads(json_path.read_text(encoding="utf-8")), {"count": 2, "ok": True})
            self.assertEqual(list(root.glob(".*.tmp")), [])

    def test_failed_replace_preserves_the_previous_complete_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "index.html"
            destination.write_text("known-good", encoding="utf-8")
            with mock.patch.object(ATOMIC.os, "replace", side_effect=OSError("simulated failure")):
                with self.assertRaises(OSError):
                    ATOMIC.atomic_write_text(destination, "partial-new")
            self.assertEqual(destination.read_text(encoding="utf-8"), "known-good")
            self.assertEqual(list(destination.parent.glob(".*.tmp")), [])


if __name__ == "__main__":
    unittest.main()
