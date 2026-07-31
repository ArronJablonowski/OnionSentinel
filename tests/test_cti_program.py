import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD_DIR = ROOT / "onion-sentinel-dashboard"
if DASHBOARD_DIR.is_dir():
    sys.path.insert(0, str(DASHBOARD_DIR))
else:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

import cti_program


class CTIProgramTests(unittest.TestCase):
    def test_missing_file_returns_governed_defaults_without_writing(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cti.json"
            program = cti_program.load_program(path)
            self.assertFalse(path.exists())
            self.assertEqual(program["schema_version"], 1)
            self.assertEqual(program["revision"], 0)
            self.assertGreaterEqual(len(program["sources"]), 5)
            self.assertGreaterEqual(len(program["technologies"]), 4)
            self.assertTrue(all(source["enabled"] for source in program["sources"]))

    def test_round_trip_is_atomic_owner_only_and_revisioned(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cti.json"
            initial = cti_program.load_program(path)
            saved = cti_program.save_program(
                {
                    "expected_revision": initial["revision"],
                    "sources": initial["sources"],
                    "technologies": initial["technologies"],
                },
                path,
            )
            self.assertEqual(saved["revision"], 1)
            self.assertTrue(saved["updated_at"].endswith("Z"))
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(cti_program.load_program(path), saved)
            self.assertFalse(any(path.parent.glob(".*.tmp")))

    def test_revision_conflict_does_not_overwrite_current_workspace(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cti.json"
            initial = cti_program.load_program(path)
            saved = cti_program.save_program(
                {
                    "expected_revision": 0,
                    "sources": initial["sources"],
                    "technologies": initial["technologies"],
                },
                path,
            )
            with self.assertRaises(cti_program.CTIProgramConflict):
                cti_program.save_program(
                    {
                        "expected_revision": 0,
                        "sources": [],
                        "technologies": [],
                    },
                    path,
                )
            self.assertEqual(cti_program.load_program(path), saved)

    def test_source_rejects_credential_urls_and_secret_values(self):
        program = cti_program.load_program(Path("/path/that/does/not/exist"))
        source = dict(program["sources"][0])
        source["endpoint"] = "https://user:secret@example.test/feed?token=secret"
        with self.assertRaisesRegex(cti_program.CTIProgramError, "without credentials"):
            cti_program.normalize_program(
                {"sources": [source], "technologies": []}
            )
        source["endpoint"] = "https://example.test/feed"
        source["credential_reference"] = "actual-secret-value"
        with self.assertRaisesRegex(cti_program.CTIProgramError, "environment-variable"):
            cti_program.normalize_program(
                {"sources": [source], "technologies": []}
            )

    def test_unknown_fields_and_duplicate_names_are_rejected(self):
        program = cti_program.load_program(Path("/path/that/does/not/exist"))
        first = dict(program["sources"][0])
        first["token"] = "must-not-be-stored"
        with self.assertRaisesRegex(cti_program.CTIProgramError, "unsupported fields"):
            cti_program.normalize_program({"sources": [first], "technologies": []})
        first.pop("token")
        second = dict(first)
        second["id"] = "different-id"
        with self.assertRaisesRegex(cti_program.CTIProgramError, "must be unique"):
            cti_program.normalize_program(
                {"sources": [first, second], "technologies": []}
            )

    def test_symlink_and_oversized_files_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            target = directory / "target.json"
            target.write_text("{}", encoding="utf-8")
            link = directory / "cti.json"
            link.symlink_to(target)
            with self.assertRaisesRegex(cti_program.CTIProgramError, "regular file"):
                cti_program.load_program(link)
            oversized = directory / "large.json"
            oversized.write_bytes(b" " * (cti_program.MAX_FILE_BYTES + 1))
            with self.assertRaisesRegex(cti_program.CTIProgramError, "exceeds"):
                cti_program.load_program(oversized)

    def test_public_response_declares_admin_and_secret_reference_contract(self):
        program = cti_program.load_program(Path("/path/that/does/not/exist"))
        response = cti_program.public_response(program)
        self.assertTrue(response["ok"])
        self.assertTrue(response["editing"]["requires_admin"])
        self.assertTrue(response["editing"]["credentials_are_references_only"])
        self.assertNotIn("actual-secret-value", json.dumps(response))


if __name__ == "__main__":
    unittest.main()
