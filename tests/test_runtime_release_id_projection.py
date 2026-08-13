from __future__ import annotations

import importlib.util
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "n8n" / "bin" / "set-runtime-release-id.py"


def load_module():
    spec = importlib.util.spec_from_file_location(
        "runtime_release_id_projection_target",
        SCRIPT,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load runtime release helper")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class RuntimeReleaseIdProjectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_module()

    def test_line_projection_and_newline_contract_are_exact(self) -> None:
        cases = [
            (
                b"A=1\r\nONION_SENTINEL_RELEASE_ID=old\r\nB=2",
                "A=1\nONION_SENTINEL_RELEASE_ID=release-1234\nB=2\n",
            ),
            (
                b"ONION_SENTINEL_RELEASE_ID=first\nKEEP=1\n"
                b" ONION_SENTINEL_RELEASE_ID =second\n",
                "ONION_SENTINEL_RELEASE_ID=release-1234\nKEEP=1\n",
            ),
            (b"A=1\n", "A=1\n\nONION_SENTINEL_RELEASE_ID=release-1234\n"),
            (b"A=1\n\n", "A=1\n\nONION_SENTINEL_RELEASE_ID=release-1234\n"),
            (b"", "ONION_SENTINEL_RELEASE_ID=release-1234\n"),
            (
                b"# ONION_SENTINEL_RELEASE_ID=comment\nA=1\n",
                "# ONION_SENTINEL_RELEASE_ID=comment\nA=1\n\n"
                "ONION_SENTINEL_RELEASE_ID=release-1234\n",
            ),
        ]
        for raw, expected in cases:
            with self.subTest(raw=raw):
                with tempfile.TemporaryDirectory() as temporary:
                    env_path = Path(temporary) / ".env"
                    env_path.write_bytes(raw)
                    self.module.set_runtime_release_id(
                        env_path,
                        "release-1234",
                    )
                    self.assertEqual(
                        env_path.read_text(encoding="utf-8"),
                        expected,
                    )
                    self.assertEqual(env_path.stat().st_mode & 0o777, 0o600)

    def test_validation_precedes_symlink_and_file_access(self) -> None:
        env_path = mock.Mock()
        with self.assertRaisesRegex(
            self.module.ReleaseIdError,
            "^release id must be 7..100 characters",
        ):
            self.module.set_runtime_release_id(env_path, "bad value")
        env_path.is_symlink.assert_not_called()
        env_path.read_bytes.assert_not_called()

    def test_symlink_rejection_precedes_read(self) -> None:
        env_path = mock.Mock()
        env_path.is_symlink.return_value = True
        with self.assertRaisesRegex(
            self.module.ReleaseIdError,
            r"^runtime \.env must not be a symbolic link$",
        ):
            self.module.set_runtime_release_id(env_path, "release-1234")
        env_path.read_bytes.assert_not_called()

    def test_read_size_and_utf8_errors_are_exact_and_side_effect_free(self) -> None:
        cases = [
            (OSError("synthetic read failure"), "could not read runtime .env: synthetic read failure", OSError),
            (b"x" * (self.module.MAX_ENV_BYTES + 1), "runtime .env exceeds its byte limit", None),
            (b"\xff", "runtime .env is not valid UTF-8", UnicodeDecodeError),
        ]
        for read_result, message, cause_type in cases:
            with self.subTest(message=message):
                env_path = mock.Mock()
                env_path.is_symlink.return_value = False
                if isinstance(read_result, BaseException):
                    env_path.read_bytes.side_effect = read_result
                else:
                    env_path.read_bytes.return_value = read_result
                with self.assertRaisesRegex(
                    self.module.ReleaseIdError,
                    f"^{re.escape(message)}$",
                ) as caught:
                    self.module.set_runtime_release_id(
                        env_path,
                        "release-1234",
                    )
                if cause_type is None:
                    self.assertIsNone(caught.exception.__cause__)
                else:
                    self.assertIsInstance(caught.exception.__cause__, cause_type)
                env_path.parent.mkdir.assert_not_called()

    def test_atomic_write_side_effect_order_and_arguments_are_exact(self) -> None:
        calls: list[tuple[object, ...]] = []
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            env_path = root / ".env"
            env_path.write_text("A=1\n", encoding="utf-8")
            temporary_path = root / ".env.synthetic"

            class Handle:
                name = str(temporary_path)

                def __enter__(self):
                    calls.append(("enter",))
                    return self

                def __exit__(self, *args):
                    calls.append(("exit",))

                def write(self, value: str) -> None:
                    calls.append(("write", value))

                def flush(self) -> None:
                    calls.append(("flush",))

                def fileno(self) -> int:
                    calls.append(("fileno",))
                    return 71

            def named_temporary_file(*args, **kwargs):
                calls.append(("named_temp", args, kwargs))
                return Handle()

            def fsync(fd: int) -> None:
                calls.append(("fsync", fd))

            def chmod(path: Path, mode: int) -> None:
                calls.append(("chmod", path, mode))

            def replace(source: Path, destination: Path) -> None:
                calls.append(("replace", source, destination))

            def unlink(*, missing_ok: bool = False) -> None:
                calls.append(("unlink", missing_ok))

            with (
                mock.patch.object(self.module.tempfile, "NamedTemporaryFile", side_effect=named_temporary_file),
                mock.patch.object(self.module.os, "fsync", side_effect=fsync),
                mock.patch.object(self.module.os, "chmod", side_effect=chmod),
                mock.patch.object(self.module.os, "replace", side_effect=replace),
                mock.patch.object(Path, "unlink", side_effect=unlink),
            ):
                self.module.set_runtime_release_id(env_path, "release-1234")

            self.assertEqual(
                calls,
                [
                    ("named_temp", ("w",), {
                        "encoding": "utf-8",
                        "dir": root,
                        "prefix": "..env.",
                        "delete": False,
                    }),
                    ("enter",),
                    ("write", "A=1\n\nONION_SENTINEL_RELEASE_ID=release-1234\n"),
                    ("flush",),
                    ("fileno",),
                    ("fsync", 71),
                    ("exit",),
                    ("chmod", temporary_path, 0o600),
                    ("replace", temporary_path, env_path),
                    ("unlink", True),
                ],
            )

    def test_failed_replace_still_unlinks_temporary_with_original_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            env_path = root / ".env"
            env_path.write_text("A=1\n", encoding="utf-8")
            original_named_temporary_file = tempfile.NamedTemporaryFile

            with (
                mock.patch.object(
                    self.module.tempfile,
                    "NamedTemporaryFile",
                    wraps=original_named_temporary_file,
                ),
                mock.patch.object(
                    self.module.os,
                    "replace",
                    side_effect=OSError("synthetic replace failure"),
                ),
            ):
                with self.assertRaisesRegex(OSError, "synthetic replace failure"):
                    self.module.set_runtime_release_id(
                        env_path,
                        "release-1234",
                    )
            self.assertEqual(env_path.read_text(encoding="utf-8"), "A=1\n")
            self.assertEqual(
                [path for path in root.iterdir() if path.name.startswith(".env.")],
                [],
            )


if __name__ == "__main__":
    unittest.main()
