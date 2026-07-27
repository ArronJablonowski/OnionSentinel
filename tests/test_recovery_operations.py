import datetime as dt
from contextlib import closing
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RecoveryOperationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.soak = load_module("soak_report", ROOT / "n8n/bin/report-production-soak.py")
        cls.restore = load_module("restore_drill", ROOT / "n8n/bin/run-recovery-restore-drill.py")

    def sample(self, when: dt.datetime, ok: bool = True):
        return {
            "generated_at": when.isoformat().replace("T", "  "),
            "ok": ok,
            "failures": [] if ok else ["test failure"],
            "signals": {"heartbeat_age_seconds": 60, "disk_used_percent": 50},
            "soak": {"healthy_since": "2026-07-14  00:00:00+00:00"},
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
            for name in (
                "alerts.sqlite3",
                "n8n-postgres.dump",
                "runtime-secrets.tar.gz",
            ):
                (bundle / name).write_bytes(b"fixture")
                os.chmod(bundle / name, 0o600)
            files = {
                name: {"sha256": self.restore.sha256_file(bundle / name)}
                for name in (
                    "alerts.sqlite3",
                    "n8n-postgres.dump",
                    "runtime-secrets.tar.gz",
                )
            }
            manifest_path = bundle / "manifest.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "files": files,
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


if __name__ == "__main__":
    unittest.main()
