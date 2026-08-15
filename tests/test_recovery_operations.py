import datetime as dt
from contextlib import closing
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import tarfile
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
RECOVERY_SECRET = b"fixture-recovery-secret-with-at-least-32-bytes"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RecoveryOperationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.soak = load_module("soak_report", ROOT / "n8n/bin/report-production-soak.py")
        cls.backup = load_module(
            "runtime_backup",
            ROOT / "n8n/bin/backup-onion-sentinel-runtime.py",
        )
        cls.restore = load_module("restore_drill", ROOT / "n8n/bin/run-recovery-restore-drill.py")

    def sample(self, when: dt.datetime, ok: bool = True):
        return {
            "generated_at": when.isoformat().replace("T", "  "),
            "ok": ok,
            "failures": [] if ok else ["test failure"],
            "signals": {"heartbeat_age_seconds": 60, "disk_used_percent": 50},
            "soak": {"healthy_since": "2026-07-14  00:00:00+00:00"},
        }

    def encrypted_bundle_manifest(
        self,
        bundle: Path,
        plaintext_names: tuple[str, ...],
    ) -> dict[str, object]:
        files: dict[str, dict[str, object]] = {}
        for plaintext_name in plaintext_names:
            encrypted_name = f"{plaintext_name}.enc"
            plaintext = f"fixture:{plaintext_name}".encode()
            payload = b"encrypted-fixture:" + plaintext
            path = bundle / encrypted_name
            path.write_bytes(payload)
            os.chmod(path, 0o600)
            files[encrypted_name] = {
                "scheme": self.restore.ENCRYPTION_SCHEME,
                "bytes": len(payload),
                "sha256": self.restore.sha256_file(path),
                "plaintext_name": plaintext_name,
                "plaintext_bytes": len(plaintext),
                "plaintext_sha256": hashlib.sha256(plaintext).hexdigest(),
            }
        return {
            "encryption": {
                "scheme": self.restore.ENCRYPTION_SCHEME,
                "pbkdf2_iterations": self.restore.PBKDF2_ITERATIONS,
                "authenticated": True,
                "key_source": "injected",
                "key_id": "injected",
            },
            "files": files,
        }

    def test_complete_dense_soak_passes(self):
        start = dt.datetime(2026, 7, 14, tzinfo=dt.timezone.utc)
        samples = [self.sample(start + dt.timedelta(minutes=5 * index)) for index in range(49 * 12 + 1)]
        summary = self.soak.summarize(samples)
        self.assertEqual(summary["status"], "passed")
        self.assertTrue(summary["qualified"])

    def test_incomplete_soak_is_in_progress(self):
        start = dt.datetime(2026, 7, 14, tzinfo=dt.timezone.utc)
        summary = self.soak.summarize([self.sample(start), self.sample(start + dt.timedelta(hours=1))])
        self.assertEqual(summary["status"], "in_progress")
        self.assertFalse(summary["qualified"])

    def test_failure_prevents_qualification(self):
        start = dt.datetime(2026, 7, 14, tzinfo=dt.timezone.utc)
        samples = [self.sample(start), self.sample(start + dt.timedelta(hours=49), ok=False)]
        summary = self.soak.summarize(samples)
        self.assertEqual(summary["status"], "failed")

    def test_sqlite_restore_validation_uses_read_only_copy(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "alerts.sqlite3"
            with closing(sqlite3.connect(source)) as conn:
                with conn:
                    conn.execute("CREATE TABLE alerts (id TEXT)")
                    conn.execute("CREATE TABLE alert_group_summary (id TEXT)")
                    conn.execute("INSERT INTO alerts VALUES ('one')")
                    conn.execute("INSERT INTO alert_group_summary VALUES ('group')")
            restore_dir = root / "restore"
            restore_dir.mkdir()
            result = self.restore.validate_sqlite(source, restore_dir)
            self.assertEqual(result["quick_check"], "ok")
            self.assertEqual(result["alert_rows"], 1)

    def test_newest_bundle_ignores_newer_unrelated_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            eligible = root / "recovery-20260804T220000Z"
            eligible.mkdir()
            (eligible / "manifest.json").write_text("{}", encoding="utf-8")
            (root / "zzz-unrelated-cutover").mkdir()
            self.assertEqual(self.restore.newest_bundle(root), eligible)

    def test_newest_bundle_ignores_symlinked_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            external_manifest = root / "external-manifest.json"
            external_manifest.write_text("{}", encoding="utf-8")
            candidate = root / "recovery-20260804T230000Z"
            candidate.mkdir()
            (candidate / "manifest.json").symlink_to(external_manifest)
            with self.assertRaisesRegex(
                RuntimeError,
                "no eligible recovery bundle",
            ):
                self.restore.newest_bundle(root)

    def test_newest_bundle_requires_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "recovery-20260804T230000Z").mkdir()
            with self.assertRaisesRegex(
                RuntimeError,
                "no eligible recovery bundle",
            ):
                self.restore.newest_bundle(root)

    def test_optional_harness_restore_validates_integrity_and_schema(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "investigation-harness.sqlite3"
            required_tables = (
                "harness_metadata",
                "harness_runs",
                "harness_events",
                "harness_evidence",
                "harness_hypotheses",
                "harness_decisions",
                "harness_model_calls",
                "harness_tool_calls",
                "harness_budget_reservations",
            )
            with closing(sqlite3.connect(source)) as conn:
                with conn:
                    for table in required_tables:
                        if table == "harness_metadata":
                            conn.execute(
                                """
                                CREATE TABLE harness_metadata (
                                    key TEXT PRIMARY KEY,
                                    value TEXT
                                )
                                """
                            )
                        elif table == "harness_runs":
                            conn.execute(
                                "CREATE TABLE harness_runs (run_id TEXT)"
                            )
                        else:
                            conn.execute(f"CREATE TABLE {table} (id TEXT)")
                    conn.execute(
                        "INSERT INTO harness_metadata VALUES ('schema_version', '4')"
                    )
                    conn.execute("INSERT INTO harness_runs VALUES ('run-1')")
            restore_dir = root / "restore"
            restore_dir.mkdir()
            result = self.restore.validate_harness_sqlite(
                source,
                restore_dir,
            )
            self.assertEqual(result["quick_check"], "ok")
            self.assertEqual(result["foreign_key_check_rows"], 0)
            self.assertEqual(result["run_rows"], 1)
            self.assertEqual(result["schema_version"], 4)

    def test_bundle_harness_manifest_must_match_optional_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp)
            os.chmod(bundle, 0o700)
            names = (
                "alerts.sqlite3",
                "n8n-postgres.dump",
                "runtime-secrets.tar.gz",
            )
            manifest = self.encrypted_bundle_manifest(bundle, names)
            manifest_path = bundle / "manifest.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        **manifest,
                        "sqlite": {
                            "investigation_harness": {"present": True}
                        },
                    }
                )
            )
            os.chmod(manifest_path, 0o600)
            with self.assertRaisesRegex(
                RuntimeError,
                "harness manifest",
            ):
                self.restore.verify_bundle(bundle)

    def test_bundle_shadow_postgres_manifest_must_match_optional_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp)
            os.chmod(bundle, 0o700)
            names = (
                "alerts.sqlite3",
                "n8n-postgres.dump",
                "runtime-secrets.tar.gz",
            )
            manifest = self.encrypted_bundle_manifest(bundle, names)
            manifest_path = bundle / "manifest.json"
            manifest_path.write_text(json.dumps({
                **manifest,
                "sqlite": {
                    "investigation_harness": {"present": False},
                },
                "postgres": {
                    "alert_store_shadow": {"present": True},
                },
            }))
            os.chmod(manifest_path, 0o600)
            with self.assertRaisesRegex(
                RuntimeError,
                "alert-store PostgreSQL manifest",
            ):
                self.restore.verify_bundle(bundle)

    def test_shadow_postgres_flag_is_exact(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = Path(tmp) / ".env"
            env.write_text(
                "ALERT_STORE_POSTGRES_SHADOW_ENABLED=10\n",
                encoding="utf-8",
            )
            self.assertFalse(self.backup.env_flag(
                env,
                "ALERT_STORE_POSTGRES_SHADOW_ENABLED",
            ))
            env.write_text(
                "ALERT_STORE_POSTGRES_SHADOW_ENABLED=1\n",
                encoding="utf-8",
            )
            self.assertTrue(self.backup.env_flag(
                env,
                "ALERT_STORE_POSTGRES_SHADOW_ENABLED",
            ))

    def test_wal_harness_bundle_round_trips_without_sqlite_sidecars(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stack = root / "stack"
            data = stack / "alert_store_data"
            data.mkdir(parents=True)
            (stack / "n8n_data").mkdir()
            (stack / "n8n_data" / "config").write_text(
                "{}",
                encoding="utf-8",
            )
            (stack / ".env").write_text(
                "ONION_SENTINEL_RELEASE_ID=" + ("a" * 40) + "\n",
                encoding="utf-8",
            )

            with closing(sqlite3.connect(data / "alerts.sqlite3")) as conn:
                with conn:
                    conn.execute("CREATE TABLE alerts (id TEXT)")
                    conn.execute("CREATE TABLE alert_group_summary (id TEXT)")
                    conn.execute("INSERT INTO alerts VALUES ('alert-1')")

            harness_tables = (
                "harness_metadata",
                "harness_runs",
                "harness_events",
                "harness_evidence",
                "harness_hypotheses",
                "harness_decisions",
                "harness_model_calls",
                "harness_tool_calls",
                "harness_budget_reservations",
            )
            harness_path = data / "investigation-harness.sqlite3"
            with closing(sqlite3.connect(harness_path)) as writer:
                self.assertEqual(
                    writer.execute("PRAGMA journal_mode = WAL").fetchone()[0],
                    "wal",
                )
                with writer:
                    for table in harness_tables:
                        if table == "harness_metadata":
                            writer.execute(
                                """
                                CREATE TABLE harness_metadata (
                                    key TEXT PRIMARY KEY,
                                    value TEXT
                                )
                                """
                            )
                        elif table == "harness_runs":
                            writer.execute(
                                "CREATE TABLE harness_runs (run_id TEXT)"
                            )
                        else:
                            writer.execute(f"CREATE TABLE {table} (id TEXT)")
                    writer.execute(
                        "INSERT INTO harness_metadata VALUES "
                        "('schema_version', '4')"
                    )
                    writer.execute(
                        "INSERT INTO harness_runs VALUES ('run-1')"
                    )
                self.assertTrue(Path(f"{harness_path}-wal").is_file())

                backup_root = root / "backups"
                backup_root.mkdir()
                with mock.patch.object(
                    self.backup,
                    "require_runtime_capacity",
                ), mock.patch.object(
                    self.backup,
                    "postgres_dump",
                    side_effect=lambda _docker, destination: (
                        destination.write_bytes(b"fake-postgres-dump")
                    ),
                ):
                    bundle = self.backup.create_bundle(
                        stack,
                        backup_root,
                        "/fake/docker",
                        encryption=self.backup.RecoveryEncryption(
                            RECOVERY_SECRET,
                            openssl="/usr/bin/openssl",
                        ),
                    )

            self.assertFalse(
                (bundle / "investigation-harness.sqlite3-wal").exists()
            )
            self.assertFalse(
                (bundle / "investigation-harness.sqlite3-shm").exists()
            )
            manifest = self.restore.verify_bundle(bundle)
            self.assertEqual(
                manifest["sqlite"]["investigation_harness"]["journal_mode"],
                "delete",
            )

            restore_root = root / "restore"
            restore_root.mkdir(mode=0o700)
            payloads = self.restore.decrypt_bundle_files(
                bundle,
                manifest,
                restore_root,
                self.restore.RecoveryEncryption(
                    RECOVERY_SECRET,
                    openssl="/usr/bin/openssl",
                ),
            )
            alert_result = self.restore.validate_sqlite(
                payloads["alerts.sqlite3"],
                restore_root,
            )
            harness_result = self.restore.validate_harness_sqlite(
                payloads["investigation-harness.sqlite3"],
                restore_root,
            )
            archive_result = self.restore.validate_runtime_archive(
                payloads["runtime-secrets.tar.gz"]
            )
            self.assertEqual(alert_result["quick_check"], "ok")
            self.assertEqual(alert_result["alert_rows"], 1)
            self.assertEqual(harness_result["quick_check"], "ok")
            self.assertEqual(harness_result["run_rows"], 1)
            self.assertIn(".env", archive_result["required_paths"])

    def test_runtime_archive_requires_n8n_encryption_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "runtime.tar.gz"
            env = Path(tmp) / ".env"
            config = Path(tmp) / "config"
            env.write_text("PLACEHOLDER=value\n")
            config.write_text("{}")
            with tarfile.open(archive, "w:gz") as stream:
                stream.add(env, arcname=".env")
                stream.add(config, arcname="n8n_data/config")
            result = self.restore.validate_runtime_archive(archive)
            self.assertEqual(result["member_count"], 2)

    def test_runtime_archive_preserves_audit_chain_but_never_sessions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stack = root / "stack"
            (stack / "n8n_data").mkdir(parents=True)
            (stack / "logs").mkdir()
            (stack / "admin-state").mkdir()
            (stack / ".env").write_text("PLACEHOLDER=value\n")
            (stack / "n8n_data/config").write_text("{}")
            (stack / "logs/onion-sentinel-admin-audit.jsonl").write_text(
                '{"schema":"audit-fixture"}\n'
            )
            os.chmod(
                stack / "logs/onion-sentinel-admin-audit.jsonl",
                0o600,
            )
            (stack / "admin-state/.admin_sessions.json").write_text("{}")
            (stack / "admin-state/.human_sessions.json").write_text("{}")
            archive = root / "runtime-secrets.tar.gz"

            included = self.backup.archive_runtime_secrets(stack, archive)
            with tarfile.open(archive, "r:gz") as stream:
                names = set(stream.getnames())

            self.assertIn(
                "logs/onion-sentinel-admin-audit.jsonl",
                included,
            )
            self.assertIn("logs/onion-sentinel-admin-audit.jsonl", names)
            self.assertNotIn("admin-state", included)
            self.assertFalse(any("session" in name for name in names))
            validation = self.restore.validate_runtime_archive(archive)
            self.assertTrue(validation["audit_chain_present"])

    def test_runtime_archive_rejects_session_resurrection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "runtime.tar.gz"
            required = {
                ".env": "PLACEHOLDER=value\n",
                "n8n_data/config": "{}",
                "admin-state/.human_sessions.json": "{}",
            }
            with tarfile.open(archive, "w:gz") as stream:
                for name, content in required.items():
                    path = root / name.replace("/", "-")
                    path.write_text(content)
                    stream.add(path, arcname=name)
            with self.assertRaisesRegex(RuntimeError, "session state"):
                self.restore.validate_runtime_archive(archive)


if __name__ == "__main__":
    unittest.main()
