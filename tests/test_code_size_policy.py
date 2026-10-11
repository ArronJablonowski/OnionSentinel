"""Physical source-line ceiling contracts; never exercise production services."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("code_size", ROOT / "operations/check-code-size.py")
SIZE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SIZE)


class CodeSizeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "example.py"
        self.policy = {"schema": "onion-sentinel-code-size-v1", "maximum_lines": 1000}

    def check(self):
        with mock.patch.object(SIZE, "repository_files", return_value=[self.source]):
            return SIZE.check(self.root, self.policy)

    def test_comments_and_blank_lines_count_and_exact_ceiling_passes(self):
        self.source.write_text("# comment\n\n" * 500)
        self.assertTrue(self.check()["ok"])
        self.source.write_text("# comment\n\n" * 500 + "pass\n")
        self.assertFalse(self.check()["ok"])

    def test_shebang_scripts_without_extensions_are_included(self):
        self.source = self.root / "export-evidence"
        self.source.write_text("#!/usr/bin/env python3\n" + "# comment\n" * 1000)
        self.assertFalse(self.check()["ok"])

    def test_frozen_allowance_fails_if_any_byte_changes(self):
        self.source.write_text("# frozen\n" * 1001)
        self.policy["frozen_exceptions"] = {"example.py": {
            "sha256": hashlib.sha256(self.source.read_bytes()).hexdigest(),
            "reason": "synthetic fixed-version fixture",
        }}
        self.assertTrue(self.check()["ok"])
        self.source.write_text("# changed\n" * 1001)
        self.assertFalse(self.check()["ok"])

    def test_policy_cannot_raise_ceiling(self):
        self.policy["maximum_lines"] = 1001
        with self.assertRaises(ValueError):
            self.check()

    def test_missing_frozen_file_fails_closed(self):
        self.policy["frozen_exceptions"] = {"missing.py": {}}
        self.source.write_text("pass\n")
        self.assertFalse(self.check()["ok"])

    def test_repository_obeys_physical_line_limit(self):
        policy = json.loads((ROOT / "operations/quality/code-size-policy.json").read_text())
        report = SIZE.check(ROOT, policy)
        self.assertTrue(report["ok"], report["violations"])


if __name__ == "__main__":
    unittest.main()
