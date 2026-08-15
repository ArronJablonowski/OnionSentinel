"""Authenticated, credential-isolated recovery artifact encryption."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "n8n" / "bin" / "recovery_encryption.py"
SECRET = b"fixture-recovery-secret-with-at-least-32-bytes"


def load_module():
    spec = importlib.util.spec_from_file_location("recovery_encryption", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError("recovery encryption module is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class RecoveryEncryptionTests(unittest.TestCase):
    def test_binary_round_trip_is_authenticated_and_metadata_is_secret_free(self) -> None:
        module = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "database.dump"
            encrypted = root / "database.dump.enc"
            restored = root / "database-restored.dump"
            payload = b"\x00database payload\xff" * 2048
            source.write_bytes(payload)
            owner = module.RecoveryEncryption(SECRET, openssl="/usr/bin/openssl")
            metadata = owner.encrypt_file(source, encrypted)
            result = owner.decrypt_file(
                encrypted,
                restored,
                expected_plaintext_sha256=metadata["plaintext_sha256"],
            )
            self.assertEqual(restored.read_bytes(), payload)
            self.assertNotEqual(encrypted.read_bytes(), payload)
            self.assertEqual(result["plaintext_bytes"], len(payload))
            self.assertEqual(metadata["scheme"], module.ENCRYPTION_SCHEME)
            self.assertNotIn(SECRET.decode(), repr(metadata))

    def test_wrong_key_and_tampering_fail_before_plaintext_publication(self) -> None:
        module = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "alerts.sqlite3"
            encrypted = root / "alerts.sqlite3.enc"
            source.write_bytes(b"sensitive evidence" * 256)
            owner = module.RecoveryEncryption(SECRET, openssl="/usr/bin/openssl")
            metadata = owner.encrypt_file(source, encrypted)
            for label, candidate in (
                ("wrong-key", encrypted),
                ("tampered", root / "tampered.enc"),
            ):
                if label == "tampered":
                    data = bytearray(encrypted.read_bytes())
                    data[len(data) // 2] ^= 1
                    candidate.write_bytes(data)
                    decryptor = owner
                else:
                    decryptor = module.RecoveryEncryption(
                        b"different-fixture-recovery-secret-at-least-32-bytes",
                        openssl="/usr/bin/openssl",
                    )
                output = root / f"{label}.sqlite3"
                with self.assertRaisesRegex(RuntimeError, "authentication failed"):
                    decryptor.decrypt_file(
                        candidate,
                        output,
                        expected_plaintext_sha256=metadata["plaintext_sha256"],
                    )
                self.assertFalse(output.exists())

    def test_secret_and_file_admission_fail_closed(self) -> None:
        module = load_module()
        with self.assertRaisesRegex(ValueError, "at least 32 bytes"):
            module.RecoveryEncryption(b"short", openssl="/usr/bin/openssl")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            real = root / "real"
            real.write_bytes(b"payload")
            linked = root / "linked"
            linked.symlink_to(real)
            owner = module.RecoveryEncryption(SECRET, openssl="/usr/bin/openssl")
            with self.assertRaisesRegex(RuntimeError, "regular owner-only file"):
                owner.encrypt_file(linked, root / "linked.enc")

    def test_keychain_lookup_is_bounded_and_never_reports_command_output(self) -> None:
        module = load_module()
        completed = subprocess.CompletedProcess(
            args=[], returncode=45, stdout=b"must-not-appear", stderr=b"also-secret"
        )
        with mock.patch.object(module.subprocess, "run", return_value=completed) as run:
            with self.assertRaisesRegex(
                RuntimeError,
                "recovery encryption key is unavailable",
            ) as failure:
                module.RecoveryEncryption.from_keychain(
                    service="fixture.service",
                    account="fixture-account",
                    security="/usr/bin/security",
                    openssl="/usr/bin/openssl",
                )
        self.assertNotIn("must-not-appear", str(failure.exception))
        self.assertNotIn("also-secret", str(failure.exception))
        self.assertEqual(
            run.call_args.args[0],
            [
                "/usr/bin/security", "find-generic-password", "-w",
                "-s", "fixture.service", "-a", "fixture-account",
            ],
        )
        self.assertEqual(run.call_args.kwargs["timeout"], 15)


if __name__ == "__main__":
    unittest.main()
