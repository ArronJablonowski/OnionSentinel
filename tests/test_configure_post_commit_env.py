#!/usr/bin/env python3
"""Tests for the stdin-only post-commit runtime configurator."""
from __future__ import annotations

import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "n8n" / "bin" / "configure-post-commit-env.py"


class ConfigurePostCommitEnvTest(unittest.TestCase):
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
