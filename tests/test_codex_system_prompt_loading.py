"""Characterize secure canonical Codex system-prompt loading."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from n8n.onion_sentinel.analysis.providers import codex


class CodexSystemPromptLoadingTests(unittest.TestCase):
    def test_reads_strict_utf8_strips_edges_and_preserves_interior(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            path = Path(temp_name) / "prompt.md"
            path.write_bytes("  canonical\nrole ☕  \n".encode("utf-8"))

            self.assertEqual(
                codex.load_canonical_system_prompt(path, "soc-analyst", 1024),
                "canonical\nrole ☕",
            )

    def test_missing_prompt_preserves_message_and_oserror_cause(self) -> None:
        path = Path("/private/tmp/onion-sentinel-definitely-missing-prompt")
        with self.assertRaisesRegex(
            SystemExit, "canonical incident-responder system prompt is unavailable"
        ) as raised:
            codex.load_canonical_system_prompt(path, "incident-responder", 1024)
        self.assertIsInstance(raised.exception.__cause__, OSError)

    def test_symlink_and_non_regular_paths_fail_before_open(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            target = root / "target.md"
            target.write_text("prompt", encoding="utf-8")
            link = root / "prompt-link.md"
            link.symlink_to(target)
            directory = root / "prompt-directory"
            directory.mkdir()

            for path in (link, directory):
                with self.subTest(path=path), mock.patch.object(
                    codex.os, "open", wraps=os.open
                ) as opened, self.assertRaisesRegex(
                    SystemExit,
                    "canonical role system prompt must be a regular file",
                ) as raised:
                    codex.load_canonical_system_prompt(path, "role", 1024)
                self.assertIsNone(raised.exception.__cause__)
                opened.assert_not_called()

    def test_preopen_and_streamed_byte_limits_use_the_exact_error(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            path = Path(temp_name) / "prompt.md"
            path.write_bytes(b"12345")
            with self.assertRaisesRegex(
                SystemExit, "canonical role system prompt exceeds its byte limit"
            ):
                codex.load_canonical_system_prompt(path, "role", 4)

            admitted = path.lstat()
            with mock.patch.object(
                codex.Path,
                "lstat",
                return_value=SimpleNamespace(
                    st_mode=admitted.st_mode,
                    st_size=4,
                    st_dev=admitted.st_dev,
                    st_ino=admitted.st_ino,
                ),
            ), self.assertRaisesRegex(
                SystemExit, "canonical role system prompt exceeds its byte limit"
            ):
                codex.load_canonical_system_prompt(path, "role", 4)

    def test_identity_drift_fails_closed_and_closes_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            path = Path(temp_name) / "prompt.md"
            path.write_text("prompt", encoding="utf-8")
            real_fstat = os.fstat
            real_close = os.close
            closed: list[int] = []

            def drifted_fstat(descriptor: int):
                current = real_fstat(descriptor)
                return SimpleNamespace(
                    st_mode=current.st_mode,
                    st_dev=current.st_dev,
                    st_ino=current.st_ino + 1,
                )

            def tracking_close(descriptor: int) -> None:
                closed.append(descriptor)
                real_close(descriptor)

            with mock.patch.object(codex.os, "fstat", side_effect=drifted_fstat), \
                    mock.patch.object(codex.os, "close", side_effect=tracking_close), \
                    self.assertRaisesRegex(
                        SystemExit,
                        "canonical role system prompt changed during admission",
                    ) as raised:
                codex.load_canonical_system_prompt(path, "role", 1024)
            self.assertIsNone(raised.exception.__cause__)
            self.assertEqual(len(closed), 1)

    def test_read_oserror_preserves_message_cause_and_closes_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            path = Path(temp_name) / "prompt.md"
            path.write_text("prompt", encoding="utf-8")
            real_close = os.close
            closed: list[int] = []

            def tracking_close(descriptor: int) -> None:
                closed.append(descriptor)
                real_close(descriptor)

            with mock.patch.object(
                codex.os, "read", side_effect=OSError("synthetic read failure")
            ), mock.patch.object(
                codex.os, "close", side_effect=tracking_close
            ), self.assertRaisesRegex(
                SystemExit, "canonical role system prompt could not be read"
            ) as raised:
                codex.load_canonical_system_prompt(path, "role", 1024)
            self.assertIsInstance(raised.exception.__cause__, OSError)
            self.assertEqual(len(closed), 1)

    def test_invalid_utf8_and_empty_content_preserve_exact_failures(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            path = Path(temp_name) / "prompt.md"
            for payload, message, cause_type in (
                (b"\xff", "canonical role system prompt is not valid UTF-8", UnicodeError),
                (b" \n\t", "canonical role system prompt is empty", type(None)),
            ):
                with self.subTest(payload=payload):
                    path.write_bytes(payload)
                    with self.assertRaisesRegex(SystemExit, message) as raised:
                        codex.load_canonical_system_prompt(path, "role", 1024)
                    if cause_type is type(None):
                        self.assertIsNone(raised.exception.__cause__)
                    else:
                        self.assertIsInstance(raised.exception.__cause__, cause_type)


if __name__ == "__main__":
    unittest.main()
