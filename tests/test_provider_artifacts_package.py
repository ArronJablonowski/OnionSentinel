from pathlib import Path
import os
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))

from onion_sentinel.analysis.providers import artifacts  # noqa: E402


class ArtifactError(RuntimeError):
    pass


class ProviderArtifactsPackageTests(unittest.TestCase):
    def test_reads_owner_only_bounded_json_object(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "auth.json"
            path.write_text('{"provider":"openai-codex"}', encoding="utf-8")
            path.chmod(0o600)
            self.assertEqual(
                artifacts.read_json_object(
                    path,
                    max_bytes=1024,
                    label="provider artifact",
                    required_mode=0o600,
                    error_type=ArtifactError,
                ),
                {"provider": "openai-codex"},
            )

    def test_rejects_missing_symlink_wrong_mode_and_oversize(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            missing = root / "missing.json"
            with self.assertRaisesRegex(ArtifactError, "is missing"):
                artifacts.read_json_object(
                    missing,
                    max_bytes=10,
                    label="artifact",
                    error_type=ArtifactError,
                )

            target = root / "target.json"
            target.write_text("{}", encoding="utf-8")
            target.chmod(0o600)
            linked = root / "linked.json"
            linked.symlink_to(target)
            with self.assertRaisesRegex(ArtifactError, "regular file"):
                artifacts.read_json_object(
                    linked,
                    max_bytes=10,
                    label="artifact",
                    error_type=ArtifactError,
                )

            target.chmod(0o640)
            with self.assertRaisesRegex(ArtifactError, "mode 0600"):
                artifacts.read_json_object(
                    target,
                    max_bytes=10,
                    label="artifact",
                    required_mode=0o600,
                    error_type=ArtifactError,
                )

            target.chmod(0o600)
            target.write_text('{"too":"large"}', encoding="utf-8")
            with self.assertRaisesRegex(ArtifactError, "size limit"):
                artifacts.read_json_object(
                    target,
                    max_bytes=4,
                    label="artifact",
                    error_type=ArtifactError,
                )

    def test_rejects_invalid_utf8_json_and_nonobject_roots(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "artifact.json"
            for raw, message in (
                (b"\xff", "not valid JSON"),
                (b"{", "not valid JSON"),
                (b"[]", "root must be an object"),
            ):
                path.write_bytes(raw)
                with self.subTest(raw=raw), self.assertRaisesRegex(
                    ArtifactError, message,
                ):
                    artifacts.read_json_object(
                        path,
                        max_bytes=32,
                        label="artifact",
                        error_type=ArtifactError,
                    )

    def test_rejects_descriptor_identity_change(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "artifact.json"
            path.write_text("{}", encoding="utf-8")
            admitted = path.lstat()
            changed = os.stat_result((
                admitted.st_mode,
                admitted.st_ino + 1,
                admitted.st_dev,
                admitted.st_nlink,
                admitted.st_uid,
                admitted.st_gid,
                admitted.st_size,
                admitted.st_atime,
                admitted.st_mtime,
                admitted.st_ctime,
            ))
            with (
                mock.patch.object(artifacts.os, "fstat", return_value=changed),
                self.assertRaisesRegex(ArtifactError, "changed during admission"),
            ):
                artifacts.read_json_object(
                    path,
                    max_bytes=32,
                    label="artifact",
                    error_type=ArtifactError,
                )


if __name__ == "__main__":
    unittest.main()
