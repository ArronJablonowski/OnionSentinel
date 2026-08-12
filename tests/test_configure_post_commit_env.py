#!/usr/bin/env python3
"""Tests for the stdin-only post-commit runtime configurator."""
from __future__ import annotations

import copy
import importlib.util
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "n8n" / "bin" / "configure-post-commit-env.py"


def load_module():
    spec = importlib.util.spec_from_file_location("configure_post_commit_env", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ConfigurePostCommitEnvTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_module()

    def test_render_env_empty_input_appends_in_update_order(self) -> None:
        updates = {"BETA": "two", "ALPHA": "one"}
        original = copy.deepcopy(updates)

        rendered = self.module.render_env("", updates)

        self.assertEqual(rendered, "BETA=two\nALPHA=one\n")
        self.assertEqual(updates, original)

    def test_render_env_preserves_unrelated_lines_and_collapses_duplicates(self) -> None:
        existing = (
            "# comment\r\n"
            " ALPHA =old\r\n"
            "ALPHA=duplicate\r\n"
            "UNRELATED=value\r\n"
            "\r\n"
        )

        rendered = self.module.render_env(
            existing,
            {"ALPHA": "fresh", "BETA": "two"},
        )

        self.assertEqual(
            rendered,
            "# comment\nALPHA=fresh\nUNRELATED=value\n\nBETA=two\n",
        )

    def test_render_env_repairs_only_admitted_literal_newline_blocks(self) -> None:
        existing = (
            "BEFORE=keep\n"
            "\\nALPHA=old\\nBETA=old\\nignored-fragment\n"
            "AFTER=keep\n"
        )

        rendered = self.module.render_env(
            existing,
            {"ALPHA": "one", "BETA": "two"},
        )

        self.assertEqual(
            rendered,
            "BEFORE=keep\nAFTER=keep\n\nALPHA=one\nBETA=two\n",
        )

    def test_render_env_rejects_unsupported_literal_newline_exactly(self) -> None:
        cases = (
            "ALPHA=old\\nUNKNOWN=value\n",
            "plain\\nfragment\n",
            "\\n\n",
        )
        for existing in cases:
            with self.subTest(existing=existing):
                with self.assertRaisesRegex(
                    SystemExit,
                    r"^environment file contains an unsupported literal \\\\n sequence$",
                ):
                    self.module.render_env(existing, {"ALPHA": "one"})

    def test_render_env_normalizes_trailing_newlines_and_empty_updates(self) -> None:
        self.assertEqual(
            self.module.render_env("LINE=keep\n\n\n", {}),
            "LINE=keep\n",
        )
        self.assertEqual(
            self.module.render_env("\n\n", {"ALPHA": "one"}),
            "\n\nALPHA=one\n",
        )
        self.assertEqual(
            self.module.render_env("ALPHA=old", {"ALPHA": "one"}),
            "ALPHA=one\n",
        )

    def test_updates_atomically_without_echoing_token(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            env_file = Path(temp_dir) / ".env"
            env_file.write_text(
                "# keep this comment\nUNRELATED=value\nN8N_POST_COMMIT_URL=old\n",
                encoding="utf-8",
            )
            token = "synthetic-post-commit-token-value"
            result = subprocess.run(
                [str(SCRIPT), "--env-file", str(env_file)],
                input=f"{token}\n",
                text=True,
                capture_output=True,
                check=True,
            )
            content = env_file.read_text(encoding="utf-8")
            self.assertIn("# keep this comment", content)
            self.assertIn("UNRELATED=value", content)
            self.assertIn(f"N8N_POST_COMMIT_TOKEN={token}", content)
            self.assertEqual(content.count("N8N_POST_COMMIT_URL="), 1)
            self.assertNotIn(token, result.stdout)
            self.assertNotIn(token, result.stderr)
            self.assertEqual(stat.S_IMODE(os.stat(env_file).st_mode), 0o600)

    def test_rejects_short_token_without_modifying_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            env_file = Path(temp_dir) / ".env"
            env_file.write_text("UNCHANGED=yes\n", encoding="utf-8")
            result = subprocess.run(
                [str(SCRIPT), "--env-file", str(env_file)],
                input="short\n",
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(env_file.read_text(encoding="utf-8"), "UNCHANGED=yes\n")

    def test_repairs_legacy_literal_newline_block(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            env_file = Path(temp_dir) / ".env"
            env_file.write_text(
                "UNRELATED=value\n"
                "\\nN8N_POST_COMMIT_URL=old"
                "\\nN8N_POST_COMMIT_TOKEN=old-secret-value"
                "\\nN8N_POST_COMMIT_INTERVAL_MS=999"
                "\\n\n",
                encoding="utf-8",
            )
            token = "synthetic-post-commit-token-value"

            result = subprocess.run(
                [str(SCRIPT), "--env-file", str(env_file)],
                input=f"{token}\n",
                text=True,
                capture_output=True,
                check=True,
            )

            content = env_file.read_text(encoding="utf-8")
            self.assertNotIn("\\n", content)
            self.assertNotIn("old-secret-value", content)
            self.assertIn("UNRELATED=value", content)
            self.assertIn(f"N8N_POST_COMMIT_TOKEN={token}", content)
            self.assertEqual(content.count("N8N_POST_COMMIT_URL="), 1)
            self.assertNotIn(token, result.stdout)


if __name__ == "__main__":
    unittest.main()
