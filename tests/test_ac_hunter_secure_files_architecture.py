from __future__ import annotations

import importlib.util
import inspect
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "onion-sentinel-dashboard"
CONFIG_PATH = DASHBOARD / "ac_hunter_config.py"
BASELINE = ROOT / "operations/quality/module-quality-baseline.json"


def load_config_module():
    spec = importlib.util.spec_from_file_location(
        "ac_hunter_secure_files_architecture", CONFIG_PATH
    )
    if spec is None or spec.loader is None:
        raise AssertionError("AC Hunter configuration owner could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class AcHunterSecureFilesArchitectureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.config = load_config_module()

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def private_file(
        self,
        name: str,
        content: bytes,
        *,
        mode: int = 0o600,
    ) -> Path:
        path = self.root / name
        path.write_bytes(content)
        path.chmod(mode)
        return path

    def outcome(
        self,
        path: Path,
        maximum_bytes: int,
        *,
        exact_mode: int = 0o600,
        allow_empty: bool = False,
    ) -> dict[str, object]:
        try:
            result = self.config._secure_file_bytes(
                path,
                maximum_bytes=maximum_bytes,
                exact_mode=exact_mode,
                allow_empty=allow_empty,
            )
        except Exception as exc:
            cause = exc.__cause__
            return {
                "status": "error",
                "type": type(exc).__name__,
                "message": str(exc),
                "cause": (
                    None
                    if cause is None
                    else [type(cause).__name__, str(cause)]
                ),
            }
        return {"status": "ok", "result": result}

    def assert_error(
        self,
        path: Path,
        maximum_bytes: int,
        message: str,
        *,
        cause: type[BaseException] | None = None,
        exact_mode: int = 0o600,
        allow_empty: bool = False,
    ) -> None:
        with self.assertRaises(self.config.AcHunterConfigurationError) as caught:
            self.config._secure_file_bytes(
                path,
                maximum_bytes=maximum_bytes,
                exact_mode=exact_mode,
                allow_empty=allow_empty,
            )
        self.assertEqual(str(caught.exception), message)
        if cause is None:
            self.assertIsNone(caught.exception.__cause__)
        else:
            self.assertIsInstance(caught.exception.__cause__, cause)

    def test_signature_current_debt_flags_and_bounded_read_trace_are_exact(
        self,
    ) -> None:
        self.assertEqual(
            str(inspect.signature(self.config._secure_file_bytes)),
            "(path: 'Path', *, maximum_bytes: 'int', exact_mode: 'int' = 384, "
            "allow_empty: 'bool' = False) -> 'bytes'",
        )
        baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
        self.assertEqual(
            baseline["functions"][
                "onion-sentinel-dashboard/ac_hunter_config.py::_secure_file_bytes"
            ],
            {"max_complexity": 20},
        )

        content = b"x" * 70_000
        path = self.private_file("trust.bin", content)
        original_open = os.open
        original_read = os.read
        opened_flags: list[int] = []
        requested_bytes: list[int] = []

        def tracked_open(value: str, flags: int) -> int:
            opened_flags.append(flags)
            return original_open(value, flags)

        def tracked_read(descriptor: int, size: int) -> bytes:
            requested_bytes.append(size)
            return original_read(descriptor, size)

        with mock.patch.object(os, "open", side_effect=tracked_open), mock.patch.object(
            os, "read", side_effect=tracked_read
        ):
            self.assertEqual(
                self.config._secure_file_bytes(path, maximum_bytes=len(content)),
                content,
            )
        self.assertEqual(requested_bytes, [65_536, 4_465, 1])
        self.assertEqual(len(opened_flags), 1)
        self.assertTrue(opened_flags[0] & os.O_RDONLY == os.O_RDONLY)
        if hasattr(os, "O_CLOEXEC"):
            self.assertTrue(opened_flags[0] & os.O_CLOEXEC)
        if hasattr(os, "O_NOFOLLOW"):
            self.assertTrue(opened_flags[0] & os.O_NOFOLLOW)

    def test_missing_lstat_and_owner_only_admission_are_exact(self) -> None:
        missing = self.root / "missing.json"
        self.assert_error(
            missing,
            100,
            "AC Hunter trust file is unavailable: missing.json",
            cause=FileNotFoundError,
        )
        with mock.patch.object(
            Path, "lstat", side_effect=PermissionError("lstat denied")
        ):
            self.assert_error(
                missing,
                100,
                "AC Hunter trust file is unavailable: missing.json",
                cause=PermissionError,
            )

        valid = self.private_file("valid.json", b"{}")
        link = self.root / "trust-link.json"
        link.symlink_to(valid)
        invalid_cases = [
            (link, 100, 0o600, False),
            (self.root, 100, 0o600, False),
            (self.private_file("public.json", b"{}", mode=0o644), 100, 0o600, False),
            (self.private_file("empty.json", b""), 100, 0o600, False),
            (valid, 1, 0o600, False),
            (valid, -1, 0o600, False),
        ]
        for candidate, maximum, mode, allow_empty in invalid_cases:
            with self.subTest(candidate=candidate.name, maximum=maximum):
                self.assert_error(
                    candidate,
                    maximum,
                    f"AC Hunter trust file failed owner-only validation: {candidate.name}",
                    exact_mode=mode,
                    allow_empty=allow_empty,
                )
        with mock.patch.object(os, "geteuid", return_value=os.geteuid() + 1):
            self.assert_error(
                valid,
                100,
                "AC Hunter trust file failed owner-only validation: valid.json",
            )

    def test_empty_and_custom_exact_mode_policy_is_exact(self) -> None:
        empty = self.private_file("empty.json", b"")
        requested: list[int] = []
        original_read = os.read

        def tracked_read(descriptor: int, size: int) -> bytes:
            requested.append(size)
            return original_read(descriptor, size)

        with mock.patch.object(os, "read", side_effect=tracked_read):
            self.assertEqual(
                self.config._secure_file_bytes(
                    empty, maximum_bytes=0, allow_empty=True
                ),
                b"",
            )
        self.assertEqual(requested, [1])

        group_readable = self.private_file("group.json", b"ok", mode=0o640)
        self.assertEqual(
            self.config._secure_file_bytes(
                group_readable, maximum_bytes=2, exact_mode=0o640
            ),
            b"ok",
        )
        self.assert_error(
            group_readable,
            2,
            "AC Hunter trust file failed owner-only validation: group.json",
        )

    def test_open_identity_race_and_descriptor_close_behavior_are_exact(self) -> None:
        path = self.private_file("trust.json", b"{}")
        with mock.patch.object(os, "open", side_effect=PermissionError("open denied")):
            self.assert_error(
                path,
                100,
                "AC Hunter trust file could not be read: trust.json",
                cause=PermissionError,
            )

        before = path.lstat()
        mutations = {
            "device": {"st_dev": before.st_dev + 1},
            "inode": {"st_ino": before.st_ino + 1},
            "owner": {"st_uid": before.st_uid + 1},
            "size": {"st_size": before.st_size + 1},
            "mode": {"st_mode": stat.S_IFREG | 0o640},
            "type": {"st_mode": stat.S_IFDIR | 0o600},
        }
        original_close = os.close
        for label, changes in mutations.items():
            values = {
                "st_dev": before.st_dev,
                "st_ino": before.st_ino,
                "st_uid": before.st_uid,
                "st_size": before.st_size,
                "st_mode": before.st_mode,
            }
            values.update(changes)
            closed: list[int] = []

            def tracked_close(descriptor: int) -> None:
                closed.append(descriptor)
                original_close(descriptor)

            with self.subTest(label=label), mock.patch.object(
                os, "fstat", return_value=SimpleNamespace(**values)
            ), mock.patch.object(os, "close", side_effect=tracked_close):
                self.assert_error(
                    path,
                    100,
                    "AC Hunter trust file changed while opening: trust.json",
                )
            self.assertEqual(len(closed), 1)

    def test_fstat_read_close_and_post_read_oversize_errors_are_exact(self) -> None:
        path = self.private_file("trust.json", b"{}")
        original_close = os.close

        with mock.patch.object(os, "fstat", side_effect=PermissionError("fstat denied")):
            self.assert_error(
                path,
                100,
                "AC Hunter trust file could not be read: trust.json",
                cause=PermissionError,
            )

        closed: list[int] = []

        def tracked_close(descriptor: int) -> None:
            closed.append(descriptor)
            original_close(descriptor)

        with mock.patch.object(os, "read", side_effect=PermissionError("read denied")), mock.patch.object(
            os, "close", side_effect=tracked_close
        ):
            self.assert_error(
                path,
                100,
                "AC Hunter trust file could not be read: trust.json",
                cause=PermissionError,
            )
        self.assertEqual(len(closed), 1)

        original_open = os.open
        opened: list[int] = []

        def tracked_open(value: str, flags: int) -> int:
            descriptor = original_open(value, flags)
            opened.append(descriptor)
            return descriptor

        try:
            with mock.patch.object(os, "open", side_effect=tracked_open), mock.patch.object(
                os, "close", side_effect=PermissionError("close denied")
            ):
                self.assert_error(
                    path,
                    100,
                    "AC Hunter trust file could not be read: trust.json",
                    cause=PermissionError,
                )
        finally:
            for descriptor in opened:
                original_close(descriptor)
        self.assertEqual(len(opened), 1)

        with mock.patch.object(os, "read", side_effect=[b"abc", b""]):
            self.assert_error(
                path,
                2,
                "AC Hunter trust file exceeds its byte limit: trust.json",
            )


if __name__ == "__main__":
    unittest.main()
