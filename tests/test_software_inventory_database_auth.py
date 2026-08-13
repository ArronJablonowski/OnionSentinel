"""Characterization for Software Inventory database authentication isolation."""
from __future__ import annotations

import importlib.util
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "n8n" / "bin" / "software_inventory_transport.py"


def load_module():
    dependency = str(MODULE_PATH.parent)
    if dependency not in sys.path:
        sys.path.insert(0, dependency)
    spec = importlib.util.spec_from_file_location(
        "software_inventory_database_token_target",
        MODULE_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load Software Inventory transport")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class SoftwareInventoryDatabaseTokenTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_module()

    @staticmethod
    def owner_file(root: str, content: str) -> Path:
        path = Path(root) / ".env"
        path.write_text(content, encoding="utf-8")
        os.chmod(path, 0o600)
        return path

    def test_parser_ignores_noise_splits_once_strips_and_last_key_wins(self) -> None:
        first = "a" * 32
        expected = "b" * 32 + "=suffix"
        fallback = "c" * 32
        with tempfile.TemporaryDirectory() as root:
            path = self.owner_file(
                root,
                f"\n # comment\nmalformed\n ASSET_STORE_WRITE_TOKEN = {first}\n"
                f"ASSET_STORE_WRITE_TOKEN={expected}\n"
                f"N8N_POST_COMMIT_TOKEN={fallback}\n",
            )
            self.assertEqual(self.module.database_write_token(path), expected)

    def test_empty_primary_falls_back_and_exact_minimum_length_is_accepted(self) -> None:
        fallback = "d" * 32
        with tempfile.TemporaryDirectory() as root:
            path = self.owner_file(
                root,
                f"ASSET_STORE_WRITE_TOKEN=\nN8N_POST_COMMIT_TOKEN={fallback}\n",
            )
            self.assertEqual(self.module.database_write_token(path), fallback)

    def test_missing_and_short_tokens_have_the_exact_secret_safe_error(self) -> None:
        cases = (
            "OTHER=value\n",
            f"ASSET_STORE_WRITE_TOKEN={'x' * 31}\n",
            f"ASSET_STORE_WRITE_TOKEN=\nN8N_POST_COMMIT_TOKEN={'y' * 31}\n",
        )
        for content in cases:
            with self.subTest(case_length=len(content)):
                with tempfile.TemporaryDirectory() as root:
                    path = self.owner_file(root, content)
                    with self.assertRaisesRegex(
                        ValueError,
                        "^software inventory database write token is missing$",
                    ):
                        self.module.database_write_token(path)

    def test_owner_control_admission_call_order_is_exact(self) -> None:
        calls: list[tuple[object, ...]] = []

        class Metadata:
            @property
            def st_uid(self):
                calls.append(("st_uid",))
                return 501

            @property
            def st_mode(self):
                calls.append(("st_mode",))
                return stat.S_IFREG | 0o600

            @property
            def st_size(self):
                calls.append(("st_size",))
                return 100

        class PathDouble:
            def lstat(self):
                calls.append(("lstat",))
                return Metadata()

            def is_file(self):
                calls.append(("is_file",))
                return True

            def is_symlink(self):
                calls.append(("is_symlink",))
                return False

            def read_text(self, *, encoding: str):
                calls.append(("read_text", encoding))
                return f"ASSET_STORE_WRITE_TOKEN={'z' * 32}\n"

        def geteuid() -> int:
            calls.append(("geteuid",))
            return 501

        with mock.patch.object(self.module.os, "geteuid", side_effect=geteuid):
            token = self.module.database_write_token(PathDouble())

        self.assertEqual(token, "z" * 32)
        self.assertEqual(
            calls,
            [
                ("lstat",),
                ("is_file",),
                ("is_symlink",),
                ("st_uid",),
                ("geteuid",),
                ("st_mode",),
                ("st_size",),
                ("read_text", "utf-8"),
            ],
        )

    def test_owner_control_rejections_short_circuit_before_read(self) -> None:
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
                    ValueError,
                    "^runtime environment file is not owner-controlled$",
                ):
                    self.module.database_write_token(path)
            path.read_text.assert_not_called()

    def test_lstat_and_utf8_failures_propagate_without_token_projection(self) -> None:
        denied = mock.Mock()
        denied.lstat.side_effect = PermissionError("synthetic denied")
        with self.assertRaisesRegex(PermissionError, "^synthetic denied$"):
            self.module.database_write_token(denied)
        denied.is_file.assert_not_called()
        denied.read_text.assert_not_called()

        with tempfile.TemporaryDirectory() as root:
            path = self.owner_file(root, "placeholder")
            path.write_bytes(b"\xff")
            os.chmod(path, 0o600)
            with self.assertRaises(UnicodeDecodeError):
                self.module.database_write_token(path)


if __name__ == "__main__":
    unittest.main()
