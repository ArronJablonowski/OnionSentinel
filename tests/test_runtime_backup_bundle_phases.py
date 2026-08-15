"""Characterization for atomic runtime recovery-bundle orchestration."""
from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
import inspect
import json
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BACKUP_PATH = ROOT / "n8n" / "bin" / "backup-onion-sentinel-runtime.py"
STAMP = "20260812T000000-0600"
REAL_DATETIME = dt.datetime


def load_backup_module():
    spec = importlib.util.spec_from_file_location(
        "runtime_backup_bundle_phases",
        BACKUP_PATH,
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


backup = load_backup_module()


class FixedDatetime:
    @classmethod
    def now(cls) -> dt.datetime:
        return REAL_DATETIME(
            2026,
            8,
            12,
            0,
            0,
            0,
            tzinfo=dt.timezone(dt.timedelta(hours=-6)),
        )


class FakeEncryption:
    descriptor = {
        "scheme": "fixture-authenticated-encryption-v1",
        "key_source": "test-only",
        "authenticated": True,
    }

    def __init__(self, events: list[tuple[object, ...]]):
        self.events = events

    def encrypt_file(self, source: Path, destination: Path) -> dict[str, object]:
        self.events.append(("encrypt", source.name, destination.name))
        plaintext = source.read_bytes()
        ciphertext = b"encrypted:" + plaintext
        destination.write_bytes(ciphertext)
        destination.chmod(0o600)
        return {
            "scheme": self.descriptor["scheme"],
            "bytes": len(ciphertext),
            "sha256": hashlib.sha256(ciphertext).hexdigest(),
            "plaintext_bytes": len(plaintext),
            "plaintext_sha256": hashlib.sha256(plaintext).hexdigest(),
        }


def sqlite_result(rows: int) -> dict[str, object]:
    return {
        "rows": rows,
        "quick_check": "ok",
        "journal_mode": "delete",
        "foreign_key_check_rows": 0,
        "restore_drill": {
            "quick_check": "ok",
            "foreign_key_check_rows": 0,
            "rows": rows,
        },
    }


class RuntimeBackupBundlePhaseTests(unittest.TestCase):
    def test_surface_and_signature_are_exact(self) -> None:
        names = sorted(name for name in dir(backup) if not name.startswith("__"))
        encoded = json.dumps(names, separators=(",", ":"), sort_keys=True).encode()
        self.assertEqual(
            (len(names), hashlib.sha256(encoded).hexdigest()),
            (30, "ac78e85dc0aaf678660a08a4c83d66b5c5698c348a9bbb1320148e3aa3d1558c"),
        )
        self.assertEqual(
            str(inspect.signature(backup.create_bundle)),
            "(stack_dir: 'Path', backup_root: 'Path', docker: 'str', *, encryption: 'RecoveryEncryption') -> 'Path'",
        )

    def test_complete_bundle_order_manifest_hashes_and_modes_are_exact(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stack = root / "stack"
            data = stack / "alert_store_data"
            data.mkdir(parents=True)
            backup_root = root / "backups"
            backup_root.mkdir()
            alert_source = data / "alerts.sqlite3"
            harness_source = data / "investigation-harness.sqlite3"
            alert_source.write_bytes(b"a" * 101)
            harness_source.write_bytes(b"h" * 203)
            (stack / ".env").write_text(
                "ALERT_STORE_POSTGRES_SHADOW_ENABLED=1\n",
                encoding="utf-8",
            )
            events: list[tuple[object, ...]] = []

            def require_capacity(
                path: Path,
                estimated_bytes: int,
                *,
                label: str,
            ) -> None:
                events.append(("capacity", path, estimated_bytes, label))

            def backup_sqlite_database(
                source: Path,
                destination: Path,
                *,
                required_tables: tuple[str, ...],
                count_table: str,
            ) -> dict[str, object]:
                events.append(
                    (
                        "sqlite",
                        source,
                        destination,
                        required_tables,
                        count_table,
                    )
                )
                payload = b"alert-snapshot" if source == alert_source else b"harness-snapshot"
                destination.write_bytes(payload)
                return sqlite_result(3 if source == alert_source else 2)

            def postgres_dump(docker: str, destination: Path) -> None:
                events.append(("postgres", docker, destination))
                destination.write_bytes(b"n8n-dump")

            def postgres_dump_container(
                docker: str,
                destination: Path,
                container: str,
            ) -> None:
                events.append(("shadow", docker, destination, container))
                destination.write_bytes(b"shadow-dump")

            def archive_runtime_secrets(
                stack_dir: Path,
                destination: Path,
            ) -> list[str]:
                events.append(("archive", stack_dir, destination))
                destination.write_bytes(b"runtime-archive")
                return [".env", "config"]

            with mock.patch.object(
                backup.dt,
                "datetime",
                FixedDatetime,
            ), mock.patch.object(
                backup,
                "require_runtime_capacity",
                side_effect=require_capacity,
            ), mock.patch.object(
                backup,
                "backup_sqlite_database",
                side_effect=backup_sqlite_database,
            ), mock.patch.object(
                backup,
                "postgres_dump",
                side_effect=postgres_dump,
            ), mock.patch.object(
                backup,
                "postgres_dump_container",
                side_effect=postgres_dump_container,
            ), mock.patch.object(
                backup,
                "archive_runtime_secrets",
                side_effect=archive_runtime_secrets,
            ):
                bundle = backup.create_bundle(
                    stack,
                    backup_root,
                    "/fake/docker",
                    encryption=FakeEncryption(events),
                )

            self.assertEqual(bundle, backup_root / STAMP)
            self.assertTrue(bundle.is_dir())
            self.assertFalse((backup_root / f".staging-{STAMP}").exists())
            self.assertEqual(stat.S_IMODE(bundle.stat().st_mode), 0o700)
            manifest = json.loads((bundle / "manifest.json").read_text())
            self.assertEqual(manifest["created_at"], "2026-08-12  00:00:00-06:00")
            self.assertEqual(manifest["alert_rows"], 3)
            self.assertEqual(manifest["harness_runs"], 2)
            self.assertEqual(manifest["runtime_paths"], [".env", "config"])
            self.assertEqual(manifest["encryption"], FakeEncryption.descriptor)
            self.assertEqual(
                manifest["postgres"],
                {
                    "n8n": {"present": True, "container": "n8n-postgres"},
                    "alert_store_shadow": {
                        "present": True,
                        "container": "onion-sentinel-alert-store-postgres",
                    },
                },
            )
            plaintext_files = {
                "alerts.sqlite3": b"alert-snapshot",
                "investigation-harness.sqlite3": b"harness-snapshot",
                "n8n-postgres.dump": b"n8n-dump",
                "alert-store-postgres.dump": b"shadow-dump",
                "runtime-secrets.tar.gz": b"runtime-archive",
            }
            expected_files = {f"{name}.enc" for name in plaintext_files}
            self.assertEqual(set(manifest["files"]), expected_files)
            for name, plaintext in plaintext_files.items():
                encrypted_name = f"{name}.enc"
                payload = b"encrypted:" + plaintext
                path = bundle / encrypted_name
                self.assertEqual(path.read_bytes(), payload)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertEqual(
                    manifest["files"][encrypted_name],
                    {
                        "scheme": "fixture-authenticated-encryption-v1",
                        "bytes": len(payload),
                        "sha256": hashlib.sha256(payload).hexdigest(),
                        "plaintext_name": name,
                        "plaintext_bytes": len(plaintext),
                        "plaintext_sha256": hashlib.sha256(plaintext).hexdigest(),
                    },
                )
                self.assertFalse((bundle / name).exists())
            self.assertEqual(stat.S_IMODE((bundle / "manifest.json").stat().st_mode), 0o600)
            self.assertEqual(
                events,
                [
                    ("capacity", backup_root, 2 * 1024**3, "runtime recovery backup"),
                    (
                        "sqlite",
                        alert_source,
                        backup_root / f".staging-{STAMP}/alerts.sqlite3",
                        ("alerts", "alert_group_summary"),
                        "alerts",
                    ),
                    (
                        "sqlite",
                        harness_source,
                        backup_root / f".staging-{STAMP}/investigation-harness.sqlite3",
                        (
                            "harness_metadata",
                            "harness_runs",
                            "harness_events",
                            "harness_evidence",
                            "harness_hypotheses",
                            "harness_decisions",
                            "harness_model_calls",
                            "harness_tool_calls",
                            "harness_budget_reservations",
                        ),
                        "harness_runs",
                    ),
                    (
                        "postgres",
                        "/fake/docker",
                        backup_root / f".staging-{STAMP}/n8n-postgres.dump",
                    ),
                    (
                        "shadow",
                        "/fake/docker",
                        backup_root / f".staging-{STAMP}/alert-store-postgres.dump",
                        "onion-sentinel-alert-store-postgres",
                    ),
                    (
                        "archive",
                        stack,
                        backup_root / f".staging-{STAMP}/runtime-secrets.tar.gz",
                    ),
                    ("encrypt", "alert-store-postgres.dump", "alert-store-postgres.dump.enc"),
                    ("encrypt", "alerts.sqlite3", "alerts.sqlite3.enc"),
                    ("encrypt", "investigation-harness.sqlite3", "investigation-harness.sqlite3.enc"),
                    ("encrypt", "n8n-postgres.dump", "n8n-postgres.dump.enc"),
                    ("encrypt", "runtime-secrets.tar.gz", "runtime-secrets.tar.gz.enc"),
                ],
            )

    def test_capacity_failure_precedes_staging_and_all_backup_work(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stack = root / "stack"
            data = stack / "alert_store_data"
            data.mkdir(parents=True)
            (data / "alerts.sqlite3").write_bytes(b"source")
            backup_root = root / "backups"
            backup_root.mkdir()
            with mock.patch.object(
                backup,
                "require_runtime_capacity",
                side_effect=RuntimeError("capacity denied"),
            ), mock.patch.object(
                backup,
                "backup_sqlite_database",
            ) as sqlite_backup:
                with self.assertRaisesRegex(RuntimeError, "capacity denied"):
                    backup.create_bundle(
                        stack,
                        backup_root,
                        "/fake/docker",
                        encryption=FakeEncryption([]),
                    )

            self.assertEqual(list(backup_root.iterdir()), [])
            sqlite_backup.assert_not_called()

    def test_failed_bundle_removes_staging_and_preserves_original_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stack = root / "stack"
            data = stack / "alert_store_data"
            data.mkdir(parents=True)
            source = data / "alerts.sqlite3"
            source.write_bytes(b"source")
            backup_root = root / "backups"
            backup_root.mkdir()

            def backup_sqlite_database(
                _source: Path,
                destination: Path,
                **_kwargs: object,
            ) -> dict[str, object]:
                destination.write_bytes(b"partial-snapshot")
                return sqlite_result(1)

            with mock.patch.object(
                backup.dt,
                "datetime",
                FixedDatetime,
            ), mock.patch.object(
                backup,
                "require_runtime_capacity",
            ), mock.patch.object(
                backup,
                "backup_sqlite_database",
                side_effect=backup_sqlite_database,
            ), mock.patch.object(
                backup,
                "postgres_dump",
                side_effect=RuntimeError("dump failed"),
            ), mock.patch.object(
                backup,
                "archive_runtime_secrets",
            ) as archive:
                with self.assertRaisesRegex(RuntimeError, "dump failed"):
                    backup.create_bundle(
                        stack,
                        backup_root,
                        "/fake/docker",
                        encryption=FakeEncryption([]),
                    )

            self.assertFalse((backup_root / f".staging-{STAMP}").exists())
            self.assertFalse((backup_root / STAMP).exists())
            self.assertEqual(list(backup_root.iterdir()), [])
            archive.assert_not_called()


if __name__ == "__main__":
    unittest.main()
