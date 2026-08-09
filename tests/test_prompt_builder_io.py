#!/usr/bin/env python3
"""Direct contracts for bounded prompt-builder I/O helpers."""
from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))

from prompt_builder_io import (  # noqa: E402
    load_bounded_json_mapping,
    load_prompt_text,
    normalized_int,
    output_filename_timestamp,
    parse_json_mapping,
    read_bounded_bytes,
    safe_output_filename,
)


class PromptBuilderIoTests(unittest.TestCase):
    def test_output_names_preserve_legacy_projection_and_bounds(self):
        self.assertEqual(
            output_filename_timestamp("2026-08-08  12:34:56-06:00"),
            "20260808-123456-0600",
        )
        self.assertEqual(
            output_filename_timestamp("unexpected/time"),
            "unexpected-time",
        )
        self.assertEqual(safe_output_filename(""), "alert")
        self.assertEqual(
            safe_output_filename(r"a:b/c\d|e f"),
            "ab-c-d-e-f",
        )
        self.assertEqual(len(safe_output_filename("x" * 200)), 180)

    def test_json_mapping_parser_fails_soft(self):
        self.assertEqual(parse_json_mapping('{"answer": 42}'), {"answer": 42})
        self.assertEqual(parse_json_mapping("[1, 2]"), {})
        self.assertEqual(parse_json_mapping("{"), {})
        self.assertEqual(parse_json_mapping(None), {})

    def test_normalized_int_preserves_default_for_unusable_values(self):
        self.assertEqual(normalized_int("7"), 7)
        self.assertEqual(normalized_int(None, 4), 4)
        self.assertEqual(normalized_int("", 5), 5)
        self.assertEqual(normalized_int("invalid", 6), 6)

    def test_bounded_read_rejects_known_oversize_before_opening(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "artifact.bin"
            path.write_bytes(b"12345")

            with mock.patch.object(Path, "open") as open_file:
                with self.assertRaisesRegex(ValueError, "exceeds 4 byte limit"):
                    read_bounded_bytes(path, 4)

            open_file.assert_not_called()

    def test_bounded_read_detects_growth_after_stat(self):
        path = mock.Mock(spec=Path)
        path.name = "growing.json"
        path.stat.return_value.st_size = 2
        handle = mock.MagicMock()
        handle.__enter__.return_value.read.return_value = b"1234"
        path.open.return_value = handle

        with self.assertRaisesRegex(ValueError, "grew beyond 3 byte limit"):
            read_bounded_bytes(path, 3)

    def test_bounded_json_requires_utf8_object_root(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            valid = root / "valid.json"
            array = root / "array.json"
            invalid_utf8 = root / "invalid.json"
            valid.write_text('{"ok": true}', encoding="utf-8")
            array.write_text("[]", encoding="utf-8")
            invalid_utf8.write_bytes(b"\xff")

            self.assertEqual(load_bounded_json_mapping(valid, 1024), {"ok": True})
            with self.assertRaisesRegex(ValueError, "root must be an object"):
                load_bounded_json_mapping(array, 1024)
            with self.assertRaises(UnicodeDecodeError):
                load_bounded_json_mapping(invalid_utf8, 1024)

    def test_prompt_text_uses_trimmed_content_or_fallback(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            populated = root / "prompt.md"
            empty = root / "empty.md"
            missing = root / "missing.md"
            oversized = root / "oversized.md"
            populated.write_text("  Investigate carefully.  ", encoding="utf-8")
            empty.write_text("   ", encoding="utf-8")
            oversized.write_text("too long", encoding="utf-8")

            self.assertEqual(
                load_prompt_text(populated, 1024, "fallback"),
                "Investigate carefully.",
            )
            self.assertEqual(load_prompt_text(empty, 1024, "fallback"), "fallback")
            self.assertEqual(load_prompt_text(missing, 1024, "fallback"), "fallback")
            self.assertEqual(load_prompt_text(oversized, 2, "fallback"), "fallback")


if __name__ == "__main__":
    unittest.main()
