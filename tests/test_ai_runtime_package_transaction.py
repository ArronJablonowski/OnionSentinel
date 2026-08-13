"""Characterize atomic AI runtime package installation and recovery."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
INSTALLER_PATH = ROOT / "n8n/bin/install-ai-runtime-package.py"
SPEC = importlib.util.spec_from_file_location(
    "ai_runtime_package_transaction", INSTALLER_PATH
)
installer = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(installer)


class AiRuntimePackageTransactionTests(unittest.TestCase):
    def _tree(self, root: Path, *, destination_exists: bool = True):
        source = root / "source/onion_sentinel"
        source.mkdir(parents=True)
        (source / "__init__.py").write_text("VALUE = 'new'\n", encoding="utf-8")
        (source / "module.py").write_text("VALUE = 2\n", encoding="utf-8")
        destination = root / "runtime/onion_sentinel"
        destination.parent.mkdir(parents=True)
        if destination_exists:
            destination.mkdir()
            (destination / "release.txt").write_text("known-good", encoding="utf-8")
        return source, destination

    def _lightweight_validation(self, events: list[object]):
        def validate(staged: Path) -> None:
            events.append(("validate", staged.name, (staged / "module.py").exists()))

        def remove(staged: Path) -> None:
            events.append(("remove_bytecode", staged.name))

        return (
            mock.patch.object(installer, "validate_staged_package", side_effect=validate),
            mock.patch.object(
                installer,
                "remove_validation_bytecode",
                side_effect=remove,
            ),
        )

    def test_existing_destination_success_preserves_transaction_order(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, destination = self._tree(root)
            events: list[object] = []
            original_copytree = shutil.copytree
            original_rename = type(root).rename
            original_rmtree = shutil.rmtree

            def copytree(source_path, destination_path, *args, **kwargs):
                events.append(("copytree", Path(source_path).name, Path(destination_path).name))
                return original_copytree(source_path, destination_path, *args, **kwargs)

            def rename(path, target):
                events.append(("rename", path.name, Path(target).name))
                return original_rename(path, target)

            def rmtree(path, *args, **kwargs):
                events.append(("rmtree", Path(path).name, kwargs.get("ignore_errors", False)))
                return original_rmtree(path, *args, **kwargs)

            validate_patch, remove_patch = self._lightweight_validation(events)
            with (
                mock.patch.object(installer.os, "getpid", return_value=4242),
                mock.patch.object(installer.shutil, "copytree", side_effect=copytree),
                mock.patch.object(type(root), "rename", new=rename),
                mock.patch.object(installer.shutil, "rmtree", side_effect=rmtree),
                validate_patch,
                remove_patch,
            ):
                installer.install_package(source, destination)

            self.assertEqual((destination / "__init__.py").read_text(), "VALUE = 'new'\n")
            self.assertFalse((destination / "release.txt").exists())
            self.assertEqual(
                events,
                [
                    ("copytree", "onion_sentinel", "onion_sentinel"),
                    ("validate", "onion_sentinel", True),
                    ("remove_bytecode", "onion_sentinel"),
                    ("rename", "onion_sentinel", ".onion-sentinel-package-backup.4242"),
                    ("rename", "onion_sentinel", "onion_sentinel"),
                    ("rmtree", ".onion-sentinel-package-backup.4242", False),
                    ("rmtree", mock.ANY, True),
                ],
            )
            self.assertTrue(str(events[-1][1]).startswith(".onion-sentinel-package."))
            self.assertEqual(list(destination.parent.glob(".*package*")), [])

    def test_absent_destination_publishes_without_backup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, destination = self._tree(root, destination_exists=False)
            events: list[object] = []
            original_rename = type(root).rename

            def rename(path, target):
                events.append((path.name, Path(target).name))
                return original_rename(path, target)

            validate_patch, remove_patch = self._lightweight_validation([])
            with (
                mock.patch.object(installer.os, "getpid", return_value=4242),
                mock.patch.object(type(root), "rename", new=rename),
                validate_patch,
                remove_patch,
            ):
                installer.install_package(source, destination)

            self.assertTrue((destination / "module.py").is_file())
            self.assertEqual(events, [("onion_sentinel", "onion_sentinel")])
            self.assertEqual(list(destination.parent.glob(".*package*")), [])

    def test_backup_collision_occurs_after_staged_validation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, destination = self._tree(root)
            backup = destination.parent / ".onion-sentinel-package-backup.4242"
            backup.mkdir()
            (backup / "owner.txt").write_text("preexisting", encoding="utf-8")
            events: list[object] = []
            validate_patch, remove_patch = self._lightweight_validation(events)
            with (
                mock.patch.object(installer.os, "getpid", return_value=4242),
                validate_patch,
                remove_patch,
                self.assertRaisesRegex(RuntimeError, "backup path already exists"),
            ):
                installer.install_package(source, destination)

            self.assertEqual(events[0][0], "validate")
            self.assertEqual(events[1][0], "remove_bytecode")
            self.assertEqual((destination / "release.txt").read_text(), "known-good")
            self.assertEqual((backup / "owner.txt").read_text(), "preexisting")
            self.assertEqual(
                [path for path in destination.parent.glob(".*package*") if path != backup],
                [],
            )

    def test_failed_promotion_restores_known_good_destination(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, destination = self._tree(root)
            original_rename = type(root).rename
            rename_events: list[tuple[str, str]] = []

            def rename(path, target):
                rename_events.append((path.name, Path(target).name))
                if path.parent.name.startswith(".onion-sentinel-package."):
                    raise OSError("synthetic promotion failure")
                return original_rename(path, target)

            validate_patch, remove_patch = self._lightweight_validation([])
            with (
                mock.patch.object(installer.os, "getpid", return_value=4242),
                mock.patch.object(type(root), "rename", new=rename),
                validate_patch,
                remove_patch,
                self.assertRaisesRegex(OSError, "synthetic promotion failure"),
            ):
                installer.install_package(source, destination)

            self.assertEqual(
                rename_events,
                [
                    ("onion_sentinel", ".onion-sentinel-package-backup.4242"),
                    ("onion_sentinel", "onion_sentinel"),
                    (".onion-sentinel-package-backup.4242", "onion_sentinel"),
                ],
            )
            self.assertEqual((destination / "release.txt").read_text(), "known-good")
            self.assertEqual(list(destination.parent.glob(".*package*")), [])

    def test_finally_retries_a_failed_inner_restore(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, destination = self._tree(root)
            original_rename = type(root).rename
            restore_attempts = 0

            def rename(path, target):
                nonlocal restore_attempts
                if path.parent.name.startswith(".onion-sentinel-package."):
                    raise OSError("promotion failure")
                if path.name.startswith(".onion-sentinel-package-backup."):
                    restore_attempts += 1
                    if restore_attempts == 1:
                        raise OSError("first restore failure")
                return original_rename(path, target)

            validate_patch, remove_patch = self._lightweight_validation([])
            with (
                mock.patch.object(installer.os, "getpid", return_value=4242),
                mock.patch.object(type(root), "rename", new=rename),
                validate_patch,
                remove_patch,
                self.assertRaisesRegex(OSError, "first restore failure"),
            ):
                installer.install_package(source, destination)

            self.assertEqual(restore_attempts, 2)
            self.assertEqual((destination / "release.txt").read_text(), "known-good")
            self.assertEqual(list(destination.parent.glob(".*package*")), [])

    def test_invalid_source_precedes_invalid_destination(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source/onion_sentinel"
            source.mkdir(parents=True)
            destination = root / "runtime/not-the-package"
            with self.assertRaisesRegex(RuntimeError, "source is incomplete"):
                installer.install_package(source, destination)
            self.assertFalse(destination.parent.exists())


if __name__ == "__main__":
    unittest.main()
