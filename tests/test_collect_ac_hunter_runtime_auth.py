"""Characterization for the scheduled AC Hunter publisher auth boundary."""
from __future__ import annotations

import hashlib
import importlib.util
import inspect
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "n8n" / "bin" / "collect-ac-hunter.py"


def load_module():
    spec = importlib.util.spec_from_file_location("collect_ac_hunter_token", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


collector = load_module()


class AcHunterTokenCharacterization(unittest.TestCase):
    def test_public_surface_and_signature_are_exact(self) -> None:
        names = sorted(name for name in dir(collector) if not name.startswith("__"))
        encoded = json.dumps(names, separators=(",", ":"), sort_keys=True).encode()
        self.assertEqual(
            (len(names), hashlib.sha256(encoded).hexdigest()),
            (25, "83419d207b49783c50dda630c35bee3111e38d24191f4300a703de9c36fda87b"),
        )
        self.assertEqual(
            str(inspect.signature(collector.database_write_token)),
            "(path: 'Path') -> 'str'",
        )

    def owner_file(self, root: str, content: str) -> Path:
        path = Path(root) / ".env"
        path.write_text(content, encoding="utf-8")
        os.chmod(path, 0o600)
        return path

    def test_parser_ignores_noise_splits_once_strips_and_last_key_wins(self) -> None:
        first = "a" * 32
        expected = "b" * 32 + "=suffix"
        with tempfile.TemporaryDirectory() as root:
            path = self.owner_file(
                root,
                f"\n # comment\nmalformed\n ASSET_STORE_WRITE_TOKEN = {first}\n"
                f"ASSET_STORE_WRITE_TOKEN={expected}\nN8N_POST_COMMIT_TOKEN={'c' * 32}\n",
            )
            self.assertEqual(collector.database_write_token(path), expected)

    def test_empty_primary_token_falls_back_to_post_commit_token(self) -> None:
        fallback = "d" * 32
        with tempfile.TemporaryDirectory() as root:
            path = self.owner_file(
                root,
                f"ASSET_STORE_WRITE_TOKEN=\nN8N_POST_COMMIT_TOKEN={fallback}\n",
            )
            self.assertEqual(collector.database_write_token(path), fallback)

    def test_missing_and_short_tokens_have_the_exact_secret_safe_error(self) -> None:
        for content in ("OTHER=value\n", "ASSET_STORE_WRITE_TOKEN=short\n"):
            with self.subTest(content=content), tempfile.TemporaryDirectory() as root:
                path = self.owner_file(root, content)
                with self.assertRaisesRegex(
                    RuntimeError,
                    "^AC Hunter database write token is missing$",
                ):
                    collector.database_write_token(path)

    def test_owner_control_rejections_share_the_exact_safe_error(self) -> None:
        cases = (
            {"is_file": False},
            {"is_symlink": True},
            {"uid": os.geteuid() + 1},
            {"mode": 0o640},
            {"size": 1024 * 1024 + 1},
        )
        for changes in cases:
            path = mock.Mock()
            path.is_file.return_value = changes.get("is_file", True)
            path.is_symlink.return_value = changes.get("is_symlink", False)
            path.lstat.return_value = mock.Mock(
                st_uid=changes.get("uid", os.geteuid()),
                st_mode=changes.get("mode", 0o600),
                st_size=changes.get("size", 100),
            )
            with self.subTest(changes=changes):
                with self.assertRaisesRegex(
                    RuntimeError,
                    "^runtime environment file is not owner-controlled$",
                ):
                    collector.database_write_token(path)
            path.read_text.assert_not_called()

    def test_lstat_and_utf8_failures_propagate_without_secret_projection(self) -> None:
        denied = mock.Mock()
        denied.lstat.side_effect = PermissionError("denied")
        with self.assertRaises(PermissionError):
            collector.database_write_token(denied)
        with tempfile.TemporaryDirectory() as root:
            path = self.owner_file(root, "valid")
            path.write_bytes(b"\xff")
            os.chmod(path, 0o600)
            with self.assertRaises(UnicodeDecodeError):
                collector.database_write_token(path)


if __name__ == "__main__":
    unittest.main()
