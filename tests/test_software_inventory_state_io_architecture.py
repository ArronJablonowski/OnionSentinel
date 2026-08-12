from __future__ import annotations

import hashlib
import inspect
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "onion-sentinel-dashboard"
if str(DASHBOARD) not in sys.path:
    sys.path.insert(0, str(DASHBOARD))

import software_inventory_state as inventory_state


class SoftwareInventoryStateIoArchitectureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def private_file(self, name: str, content: bytes) -> Path:
        path = self.root / name
        path.write_bytes(content)
        path.chmod(0o600)
        return path

    def assert_state_error(
        self,
        path: Path,
        maximum_bytes: int,
        message: str,
        *,
        cause: type[BaseException] | None = None,
    ) -> inventory_state.InventoryStateError:
        with self.assertRaises(inventory_state.InventoryStateError) as caught:
            inventory_state._read_bounded_regular_json(path, maximum_bytes)
        self.assertEqual(str(caught.exception), message)
        if cause is None:
            self.assertIsNone(caught.exception.__cause__)
        else:
            self.assertIsInstance(caught.exception.__cause__, cause)
        return caught.exception

    def test_private_signature_owner_budget_digest_flags_and_read_cap(self) -> None:
        self.assertEqual(
            str(inspect.signature(inventory_state._read_bounded_regular_json)),
            "(path: 'Path', maximum_bytes: 'int') -> 'tuple[dict, str]'",
        )
        self.assertLessEqual(
            len(
                (DASHBOARD / "software_inventory_state.py")
                .read_text()
                .splitlines()
            ),
            800,
        )
        io_path = DASHBOARD / "software_inventory_state_io.py"
        self.assertLessEqual(len(io_path.read_text().splitlines()), 600)
        self.assertNotIn(
            "from software_inventory_state import", io_path.read_text()
        )
        installer = (ROOT / "n8n/bin/install-macstudio-stack.zsh").read_text()
        self.assertIn(
            'software_inventory_state_io.py" "$DASHBOARD_RUNTIME_DIR/',
            installer,
        )
        content = b'{"value":1,"nested":{"ok":true}}'
        path = self.private_file("state.json", content)
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
            payload, digest = inventory_state._read_bounded_regular_json(
                path, len(content)
            )
        self.assertEqual(payload, {"value": 1, "nested": {"ok": True}})
        self.assertEqual(digest, hashlib.sha256(content).hexdigest())
        self.assertEqual(requested_bytes, [len(content) + 1, 1])
        self.assertEqual(len(opened_flags), 1)
        self.assertTrue(opened_flags[0] & os.O_RDONLY == os.O_RDONLY)
        if hasattr(os, "O_NOFOLLOW"):
            self.assertTrue(opened_flags[0] & os.O_NOFOLLOW)

    def test_missing_and_lstat_failure_classification_is_exact(self) -> None:
        missing = self.root / "missing.json"
        self.assert_state_error(
            missing,
            100,
            "Software Inventory has not been collected yet",
            cause=FileNotFoundError,
        )
        with mock.patch.object(
            Path, "lstat", side_effect=PermissionError("lstat denied")
        ):
            self.assert_state_error(
                missing,
                100,
                "Software Inventory state is unavailable",
                cause=PermissionError,
            )

    def test_identity_owner_mode_and_size_admission_order_is_exact(self) -> None:
        valid = self.private_file("valid.json", b"{}")
        link = self.root / "state-link.json"
        link.symlink_to(valid)
        self.assert_state_error(
            link,
            100,
            "Software Inventory state is not a regular file",
        )
        self.assert_state_error(
            self.root,
            100,
            "Software Inventory state is not a regular file",
        )
        with mock.patch.object(os, "getuid", return_value=os.getuid() + 1):
            self.assert_state_error(
                valid,
                100,
                "Software Inventory state has an unexpected owner",
            )
        valid.chmod(0o620)
        self.assert_state_error(
            valid,
            100,
            "Software Inventory state is writable by another user",
        )
        valid.chmod(0o600)
        empty = self.private_file("empty.json", b"")
        self.assert_state_error(
            empty,
            100,
            "Software Inventory state exceeds its size boundary",
        )
        self.assert_state_error(
            valid,
            1,
            "Software Inventory state exceeds its size boundary",
        )
        self.assert_state_error(
            valid,
            -1,
            "Software Inventory state exceeds its size boundary",
        )

    def test_open_and_identity_race_errors_are_exact_and_close_descriptor(self) -> None:
        path = self.private_file("state.json", b"{}")
        with mock.patch.object(os, "open", side_effect=PermissionError("open denied")):
            self.assert_state_error(
                path,
                100,
                "Software Inventory state could not be read",
                cause=PermissionError,
            )

        before = path.lstat()
        changed = SimpleNamespace(
            st_dev=before.st_dev + 1,
            st_ino=before.st_ino,
            st_mode=before.st_mode,
            st_size=before.st_size,
        )
        original_close = os.close
        closed: list[int] = []

        def tracked_close(descriptor: int) -> None:
            closed.append(descriptor)
            original_close(descriptor)

        with mock.patch.object(os, "fstat", return_value=changed), mock.patch.object(
            os, "close", side_effect=tracked_close
        ):
            self.assert_state_error(
                path,
                100,
                "Software Inventory state changed while opening",
            )
        self.assertEqual(len(closed), 1)

    def test_read_and_close_errors_are_wrapped_and_descriptors_are_bounded(self) -> None:
        path = self.private_file("state.json", b"{}")
        original_close = os.close
        closed: list[int] = []

        def tracked_close(descriptor: int) -> None:
            closed.append(descriptor)
            original_close(descriptor)

        with mock.patch.object(os, "read", side_effect=PermissionError("read denied")), mock.patch.object(
            os, "close", side_effect=tracked_close
        ):
            self.assert_state_error(
                path,
                100,
                "Software Inventory state could not be read",
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
                self.assert_state_error(
                    path,
                    100,
                    "Software Inventory state could not be read",
                    cause=PermissionError,
                )
        finally:
            for descriptor in opened:
                original_close(descriptor)
        self.assertEqual(len(opened), 1)

    def test_decode_json_and_root_object_failures_are_exact(self) -> None:
        invalid_utf8 = self.private_file("invalid-utf8.json", b"\xff")
        self.assert_state_error(
            invalid_utf8,
            100,
            "Software Inventory state is not valid JSON",
            cause=UnicodeDecodeError,
        )
        invalid_json = self.private_file("invalid-json.json", b"{")
        self.assert_state_error(
            invalid_json,
            100,
            "Software Inventory state is not valid JSON",
            cause=json.JSONDecodeError,
        )
        array_root = self.private_file("array.json", b"[]")
        self.assert_state_error(
            array_root,
            100,
            "Software Inventory state must be an object",
        )


if __name__ == "__main__":
    unittest.main()
