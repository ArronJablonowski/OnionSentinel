from __future__ import annotations

import hashlib
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCANNER = ROOT / "operations" / "secret-scan.zsh"


class RepositoryScanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        operations = self.root / "operations"
        operations.mkdir()
        shutil.copy2(SCANNER, operations / SCANNER.name)
        subprocess.run(["git", "init", "-q"], cwd=self.root, check=True)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _config(self, content: str = "model = 'local-test'\n") -> Path:
        path = self.root / ".codex" / "config.toml"
        path.parent.mkdir(exist_ok=True)
        path.write_text(content, encoding="utf-8")
        path.chmod(0o600)
        return path

    def _ignore_codex(self) -> None:
        exclude = self.root / ".git" / "info" / "exclude"
        exclude.write_text(".codex/\n", encoding="utf-8")

    def _run(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["zsh", "operations/secret-scan.zsh"],
            cwd=self.root,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_ignored_owner_only_local_config_is_approved_without_rewrite(self) -> None:
        self._ignore_codex()
        config = self._config()
        before = hashlib.sha256(config.read_bytes()).hexdigest()

        result = self._run()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(hashlib.sha256(config.read_bytes()).hexdigest(), before)
        self.assertEqual(stat.S_IMODE(config.stat().st_mode), 0o600)

    def test_tracked_codex_config_remains_forbidden(self) -> None:
        self._ignore_codex()
        config = self._config()
        subprocess.run(
            ["git", "add", "-f", str(config.relative_to(self.root))],
            cwd=self.root,
            check=True,
        )

        result = self._run()

        self.assertEqual(result.returncode, 1)
        self.assertIn("./.codex/config.toml", result.stdout)

    def test_unignored_or_non_owner_only_config_remains_forbidden(self) -> None:
        config = self._config()
        result = self._run()
        self.assertEqual(result.returncode, 1)
        self.assertIn("./.codex/config.toml", result.stdout)

        self._ignore_codex()
        config.chmod(0o640)
        result = self._run()
        self.assertEqual(result.returncode, 1)
        self.assertIn("./.codex/config.toml", result.stdout)

    def test_credential_pattern_inside_approved_path_still_fails_content_scan(self) -> None:
        self._ignore_codex()
        token = "gh" + "p_" + ("A" * 30)
        self._config(f"token = '{token}'\n")

        result = self._run()

        self.assertEqual(result.returncode, 1)
        self.assertIn("High-confidence secret-like content found", result.stderr)
        self.assertNotIn(token, result.stdout + result.stderr)

    def test_ignored_codex_symlink_remains_forbidden(self) -> None:
        self._ignore_codex()
        target = self.root / "outside-config.toml"
        target.write_text("model = 'local-test'\n", encoding="utf-8")
        target.chmod(0o600)
        config = self.root / ".codex" / "config.toml"
        config.parent.mkdir()
        os.symlink(target, config)

        result = self._run()

        self.assertEqual(result.returncode, 1)
        self.assertIn("./.codex/config.toml", result.stdout)


if __name__ == "__main__":
    unittest.main()
