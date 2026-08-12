import json
import hashlib
import inspect
import os
import stat
import subprocess
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
    def test_compatibility_namespace_metadata_and_signatures_are_stable(self):
        names = sorted(
            name
            for name in vars(cti_program)
            if not (name.startswith("__") and name.endswith("__"))
        )
        self.assertEqual(len(names), 54)
        self.assertEqual(
            hashlib.sha256("\n".join(names).encode("utf-8")).hexdigest(),
            "88b050afd39633fd98eb1cd1c5ac8c20bb66bf6245c096c95c9b54032ac02bc6",
        )
        metadata = [
            (
                name,
                type(value).__module__,
                type(value).__qualname__,
                getattr(value, "__module__", None),
                getattr(value, "__qualname__", None),
            )
            for name in names
            for value in (getattr(cti_program, name),)
        ]
        expected_metadata = {
            (3, 9): "4eb831578f531fabbf150848ff0ce8324324fb88cad5c8d3f87b418f61e64545",
            (3, 14): "24e177bc0cd11ff3318be595d4439c82124ea042b493cfcac94f268abd147cd6",
        }
        self.assertEqual(
            hashlib.sha256(
                json.dumps(metadata, separators=(",", ":")).encode("utf-8")
            ).hexdigest(),
            expected_metadata[sys.version_info[:2]],
        )
        self.assertIsNone(getattr(cti_program, "__all__", None))
        expected_signatures = {
            "_default_program": "() -> 'dict[str, object]'",
            "normalize_program": "(value: 'object', *, stored: 'bool' = False) -> 'dict[str, object]'",
            "load_program": "(path: 'Path | None' = None) -> 'dict[str, object]'",
            "save_program": "(payload: 'object', path: 'Path | None' = None) -> 'dict[str, object]'",
            "program_digest": "(program: 'dict[str, object]') -> 'str'",
            "public_response": "(program: 'dict[str, object]') -> 'dict[str, object]'",
        }
        self.assertEqual(
            {
                name: str(inspect.signature(getattr(cti_program, name)))
                for name in expected_signatures
            },
            expected_signatures,
        )

    def test_validation_failure_types_and_messages_are_stable(self):
        baseline = cti_program.load_program(Path("/path/that/does/not/exist"))
        source = dict(baseline["sources"][0])
        technology = dict(baseline["technologies"][0])
        cases = [
            (None, "CTI workspace must be a JSON object."),
            ({"unexpected": True}, "CTI workspace contains unsupported fields: unexpected."),
            ({"schema_version": 2}, "Unsupported CTI workspace schema version: 2."),
            ({"revision": True}, "revision must be a non-negative integer."),
            ({"sources": [source] * 101}, "sources must be a list with at most 100 entries."),
            (
                {"sources": [{**source, "enabled": "yes"}]},
                "sources[0].enabled must be true or false.",
            ),
            (
                {"sources": [{**source, "endpoint": "https://user:secret@example.test/feed"}]},
                "sources[0].endpoint must be an http(s) URL without credentials, query parameters, or fragments.",
            ),
            (
                {"sources": [{**source, "credential_reference": "literal-secret"}]},
                "sources[0].credential_reference must be an environment-variable name, not a credential value.",
            ),
            (
                {"technologies": [technology, dict(technology)]},
                "Technology ids and vendor/product pairs must be unique.",
            ),
        ]
        for payload, message in cases:
            with self.subTest(message=message):
                with self.assertRaises(cti_program.CTIProgramError) as raised:
                    cti_program.normalize_program(payload)
                self.assertEqual(str(raised.exception), message)

    def test_isolated_flat_dashboard_import_succeeds(self):
        command = (
            "import sys;sys.path.insert(0,sys.argv[1]);"
            "import cti_program;"
            "assert callable(cti_program.normalize_program);"
            "assert callable(cti_program.save_program)"
        )
        result = subprocess.run(
            [sys.executable, "-I", "-B", "-c", command, str(DASHBOARD_DIR)],
            text=True,
            capture_output=True,
            timeout=20,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

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
