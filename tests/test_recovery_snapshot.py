#!/usr/bin/env python3
"""Authenticated hourly alert-store repair snapshot contract."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "n8n" / "bin" / "recovery_snapshot.py"
SECRET = b"fixture-repair-snapshot-secret-with-at-least-32-bytes"


def load_module():
    spec = importlib.util.spec_from_file_location("recovery_snapshot", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError("recovery snapshot module is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class RecoverySnapshotTests(unittest.TestCase):
    def test_create_and_restore_are_authenticated_and_plaintext_free(self) -> None:
        module = load_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "alerts.sqlite3.backup.tmp"
            encrypted = root / "alerts.sqlite3.20260815.backup.enc"
            metadata = root / "alerts.sqlite3.20260815.backup.json"
            restored = root / "restored.sqlite3"
            payload = b"SQLite fixture payload\x00" * 1024
            source.write_bytes(payload)
            source.chmod(0o600)
            encryption = module.RecoveryEncryption(
                SECRET,
                openssl="/usr/bin/openssl",
            )

            result = module.create_snapshot(
                source,
                encrypted,
                metadata,
                encryption=encryption,
                created_at="2026-08-15T10:00:00+00:00",
            )
            restored_result = module.restore_snapshot(
                encrypted,
                metadata,
                restored,
                encryption=encryption,
            )

            self.assertEqual(restored.read_bytes(), payload)
            self.assertNotEqual(encrypted.read_bytes(), payload)
            self.assertEqual(result["format"], module.SNAPSHOT_FORMAT)
            self.assertEqual(result["artifact"], encrypted.name)
            self.assertEqual(restored_result["plaintext_bytes"], len(payload))
            self.assertEqual(metadata.stat().st_mode & 0o777, 0o600)
            self.assertEqual(encrypted.stat().st_mode & 0o777, 0o600)
            self.assertNotIn(SECRET.decode(), metadata.read_text(encoding="utf-8"))

    def test_tamper_and_metadata_mismatch_fail_before_restore_publication(self) -> None:
        module = load_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "alerts.sqlite3.backup.tmp"
            encrypted = root / "alerts.sqlite3.20260815.backup.enc"
            metadata = root / "alerts.sqlite3.20260815.backup.json"
            source.write_bytes(b"sensitive alert evidence" * 256)
            source.chmod(0o600)
            encryption = module.RecoveryEncryption(
                SECRET,
                openssl="/usr/bin/openssl",
            )
            module.create_snapshot(
                source,
                encrypted,
                metadata,
                encryption=encryption,
                created_at="2026-08-15T10:00:00+00:00",
            )

            tampered = bytearray(encrypted.read_bytes())
            tampered[len(tampered) // 2] ^= 1
            encrypted.write_bytes(tampered)
            encrypted.chmod(0o600)
            output = root / "tampered.sqlite3"
            with self.assertRaisesRegex(
                RuntimeError,
                "ciphertext validation failed|authentication failed",
            ):
                module.restore_snapshot(
                    encrypted,
                    metadata,
                    output,
                    encryption=encryption,
                )
            self.assertFalse(output.exists())

            manifest = json.loads(metadata.read_text(encoding="utf-8"))
            manifest["artifact"] = "different.backup.enc"
            metadata.write_text(json.dumps(manifest), encoding="utf-8")
            metadata.chmod(0o600)
            with self.assertRaisesRegex(RuntimeError, "metadata artifact"):
                module.restore_snapshot(
                    encrypted,
                    metadata,
                    root / "mismatched.sqlite3",
                    encryption=encryption,
                )

    def test_failed_metadata_publication_removes_ciphertext(self) -> None:
        module = load_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "alerts.sqlite3.backup.tmp"
            encrypted = root / "alerts.sqlite3.20260815.backup.enc"
            metadata = root / "occupied.backup.json"
            source.write_bytes(b"payload" * 1024)
            source.chmod(0o600)
            metadata.write_text("occupied", encoding="utf-8")
            metadata.chmod(0o600)
            encryption = module.RecoveryEncryption(
                SECRET,
                openssl="/usr/bin/openssl",
            )

            with self.assertRaisesRegex(RuntimeError, "metadata already exists"):
                module.create_snapshot(
                    source,
                    encrypted,
                    metadata,
                    encryption=encryption,
                    created_at="2026-08-15T10:00:00+00:00",
                )

            self.assertFalse(encrypted.exists())
            self.assertEqual(metadata.read_text(encoding="utf-8"), "occupied")

    def test_restore_rejects_a_different_key_generation_before_decryption(self) -> None:
        module = load_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "alerts.sqlite3.backup.tmp"
            encrypted = root / "alerts.sqlite3.20260815.backup.enc"
            metadata = root / "alerts.sqlite3.20260815.backup.json"
            source.write_bytes(b"payload" * 1024)
            source.chmod(0o600)
            writer = module.RecoveryEncryption(
                SECRET,
                openssl="/usr/bin/openssl",
                key_id="generation-v1",
            )
            reader = module.RecoveryEncryption(
                SECRET,
                openssl="/usr/bin/openssl",
                key_id="generation-v2",
            )
            module.create_snapshot(
                source,
                encrypted,
                metadata,
                encryption=writer,
            )

            output = root / "restored.sqlite3"
            with self.assertRaisesRegex(RuntimeError, "key generation"):
                module.restore_snapshot(
                    encrypted,
                    metadata,
                    output,
                    encryption=reader,
                )
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
