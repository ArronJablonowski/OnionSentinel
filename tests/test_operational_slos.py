import datetime as dt
from contextlib import closing
import importlib.util
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class OperationalSloTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.slo = load_module("operational_slos", ROOT / "n8n/bin/evaluate-operational-slos.py")
        cls.backup = load_module("runtime_backup", ROOT / "n8n/bin/backup-onion-sentinel-runtime.py")

    def test_healthy_snapshot_passes(self):
        now = dt.datetime(2026, 7, 14, 18, tzinfo=dt.timezone.utc)
        metrics = {"metrics": {"process": {"ingest_errors": 0}, "oldest_pending_job_seconds": 0,
                               "oldest_pending_jobs": [], "oldest_pending_pcap_seconds": 0}}
        health = {"summary": {"latest": {"timestamp_utc": "2026-07-14T17:55:00Z"}}, "pcap": {"warning_count": 0}}
        failures, snapshot = self.slo.evaluate(metrics, health, now=now, disk_used_percent=55, sqlite_backup_age=60, postgres_backup_age=60, previous_ingest_errors=0)
        self.assertEqual(failures, [])
        self.assertTrue(snapshot["ok"])

    def test_stale_or_regressed_signals_fail(self):
        now = dt.datetime(2026, 7, 14, 18, tzinfo=dt.timezone.utc)
        metrics = {"metrics": {"process": {"ingest_errors": 3}, "oldest_pending_job_seconds": 901, "oldest_pending_pcap_seconds": 3601}}
        health = {"summary": {"latest": {"timestamp_utc": "2026-07-14T17:00:00Z"}}, "pcap": {"warning_count": 1}}
        failures, _ = self.slo.evaluate(metrics, health, now=now, disk_used_percent=90, sqlite_backup_age=None, postgres_backup_age=None, previous_ingest_errors=1)
        self.assertGreaterEqual(len(failures), 8)

    def test_mac_disk_alerts_at_seventy_five_percent(self):
        now = dt.datetime(2026, 7, 14, 18, tzinfo=dt.timezone.utc)
        metrics = {"metrics": {"process": {"ingest_errors": 0}, "oldest_pending_job_seconds": 0,
                               "oldest_pending_jobs": [], "oldest_pending_pcap_seconds": 0}}
        health = {"summary": {"latest": {"timestamp_utc": "2026-07-14T17:55:00Z"}}, "pcap": {"warning_count": 0}}
        failures, snapshot = self.slo.evaluate(
            metrics, health, now=now, disk_used_percent=75,
            sqlite_backup_age=60, postgres_backup_age=60, previous_ingest_errors=0,
        )
        self.assertIn("Mac runtime disk is 75.0% used", failures)
        self.assertEqual(snapshot["signals"]["disk_hard_limit_percent"], 80)

    def test_known_pipeline_backlog_is_admitted_before_disk_ceiling(self):
        now = dt.datetime(2026, 7, 14, 18, tzinfo=dt.timezone.utc)
        metrics = {"metrics": {
            "process": {"ingest_errors": 0},
            "oldest_pending_job_seconds": 0,
            "oldest_pending_jobs": [],
            "oldest_pending_pcap_seconds": 0,
            "pipeline": {
                "disk": {
                    "known_pipeline_backlog_bytes": 50,
                    "projected_used_percent_with_known_backlog": 76.2,
                },
                "stages": [{
                    "stage": "pcap_transfer", "pending": 2, "processing": 1,
                    "oldest_pending_seconds": 120, "backlog_bytes_known": 50,
                    "backlog_bytes_unknown_items": 0, "drain_eta_seconds": 300,
                    "byte_drain_eta_seconds": 240, "throughput": {"1h": {"completed": 5}},
                }],
            },
        }}
        health = {"summary": {"latest": {"timestamp_utc": "2026-07-14T17:55:00Z"}}, "pcap": {"warning_count": 0}}
        failures, snapshot = self.slo.evaluate(
            metrics, health, now=now, disk_used_percent=70,
            sqlite_backup_age=60, postgres_backup_age=60, previous_ingest_errors=0,
        )
        self.assertIn("known pipeline backlog projects Mac runtime disk to 76.2% used", failures)
        self.assertEqual(snapshot["signals"]["pipeline_stages"]["pcap_transfer"]["drain_eta_seconds"], 300)

    def test_pcap_blocked_ai_uses_sixty_minute_deadline(self):
        now = dt.datetime(2026, 7, 14, 18, tzinfo=dt.timezone.utc)
        metrics = {"metrics": {
            "process": {"ingest_errors": 0},
            "oldest_pending_job_seconds": 1800,
            "oldest_pending_jobs": [
                {"job_type": "ai_analysis", "seconds": 1800},
                {"job_type": "public_enrichment", "seconds": 60},
            ],
            "oldest_pending_pcap_seconds": 1800,
        }}
        health = {"summary": {"latest": {"timestamp_utc": "2026-07-14T17:55:00Z"}}, "pcap": {"warning_count": 0}}
        failures, snapshot = self.slo.evaluate(metrics, health, now=now, disk_used_percent=55,
                                               sqlite_backup_age=60, postgres_backup_age=60,
                                               previous_ingest_errors=0)
        self.assertEqual(failures, [])
        self.assertEqual(snapshot["signals"]["oldest_pending_ai_job_seconds"], 1800)

    def test_fresh_active_pcap_transfer_suppresses_raw_backlog_age_failure(self):
        now = dt.datetime(2026, 7, 14, 18, tzinfo=dt.timezone.utc)
        metrics = {"metrics": {
            "process": {"ingest_errors": 0},
            "oldest_pending_job_seconds": 0,
            "oldest_pending_jobs": [],
            "oldest_pending_pcap_seconds": 4 * 60 * 60,
        }}
        health = {
            "summary": {"latest": {"timestamp_utc": "2026-07-14T17:55:00Z"}},
            "pcap": {
                "warning_count": 0,
                "active_transfers": [{"request_id": "pcap-large", "progress_at": "2026-07-14T17:59:30Z"}],
            },
        }

        failures, snapshot = self.slo.evaluate(
            metrics,
            health,
            now=now,
            disk_used_percent=55,
            sqlite_backup_age=60,
            postgres_backup_age=60,
            previous_ingest_errors=0,
        )

        self.assertNotIn("PCAP backlog exceeds 60 minutes", failures)
        self.assertEqual(snapshot["signals"]["active_pcap_transfer_count"], 1)

    def test_recent_serial_pcap_completion_suppresses_handoff_backlog_failure(self):
        now = dt.datetime(2026, 7, 14, 18, tzinfo=dt.timezone.utc)
        metrics = {"metrics": {
            "process": {"ingest_errors": 0},
            "oldest_pending_job_seconds": 0,
            "oldest_pending_jobs": [],
            "oldest_pending_pcap_seconds": 4 * 60 * 60,
        }}
        health = {
            "summary": {"latest": {"timestamp_utc": "2026-07-14T17:55:00Z"}},
            "pcap": {
                "warning_count": 0,
                "active_transfers": [],
                "queue_progressing": True,
                "last_progress_age_seconds": 75,
            },
        }

        failures, snapshot = self.slo.evaluate(
            metrics,
            health,
            now=now,
            disk_used_percent=55,
            sqlite_backup_age=60,
            postgres_backup_age=60,
            previous_ingest_errors=0,
        )

        self.assertNotIn("PCAP backlog exceeds 60 minutes", failures)
        self.assertTrue(snapshot["signals"]["pcap_queue_progressing"])
        self.assertEqual(snapshot["signals"]["pcap_last_progress_age_seconds"], 75)

    def test_enrichment_keeps_fifteen_minute_deadline(self):
        now = dt.datetime(2026, 7, 14, 18, tzinfo=dt.timezone.utc)
        metrics = {"metrics": {
            "process": {"ingest_errors": 0},
            "oldest_pending_job_seconds": 901,
            "oldest_pending_jobs": [{"job_type": "public_enrichment", "seconds": 901}],
            "oldest_pending_pcap_seconds": 0,
        }}
        health = {"summary": {"latest": {"timestamp_utc": "2026-07-14T17:55:00Z"}}, "pcap": {"warning_count": 0}}
        failures, _ = self.slo.evaluate(metrics, health, now=now, disk_used_percent=55,
                                        sqlite_backup_age=60, postgres_backup_age=60,
                                        previous_ingest_errors=0)
        self.assertIn("enrichment job backlog exceeds 15 minutes", failures)

    def test_pending_ai_requires_recent_forward_progress(self):
        now = dt.datetime(2026, 7, 14, 18, tzinfo=dt.timezone.utc)
        metrics = {"metrics": {
            "process": {"ingest_errors": 0},
            "durable_jobs": [{"job_type": "ai_analysis", "status": "pending", "count": 4}],
            "oldest_pending_job_seconds": 7200,
            "oldest_pending_jobs": [{"job_type": "ai_analysis", "seconds": 7200}],
            "latest_completed_jobs": [{"job_type": "ai_analysis", "seconds": 120}],
            "oldest_pending_pcap_seconds": 0,
        }}
        health = {"summary": {"latest": {"timestamp_utc": "2026-07-14T17:55:00Z"}}, "pcap": {"warning_count": 0}}
        failures, _ = self.slo.evaluate(metrics, health, now=now, disk_used_percent=55,
                                        sqlite_backup_age=60, postgres_backup_age=60,
                                        previous_ingest_errors=0)
        self.assertEqual(failures, [])

        metrics["metrics"]["latest_completed_jobs"][0]["seconds"] = 1801
        failures, _ = self.slo.evaluate(metrics, health, now=now, disk_used_percent=55,
                                        sqlite_backup_age=60, postgres_backup_age=60,
                                        previous_ingest_errors=0)
        self.assertIn("AI analysis has pending work but no completion within 30 minutes", failures)

    def test_active_ai_processing_uses_processing_age(self):
        now = dt.datetime(2026, 7, 14, 18, tzinfo=dt.timezone.utc)
        metrics = {"metrics": {
            "process": {"ingest_errors": 0},
            "durable_jobs": [
                {"job_type": "ai_analysis", "status": "pending", "count": 4},
                {"job_type": "ai_analysis", "status": "processing", "count": 1},
            ],
            "oldest_pending_jobs": [{"job_type": "ai_analysis", "seconds": 7200}],
            "oldest_processing_jobs": [{"job_type": "ai_analysis", "seconds": 600}],
            "latest_completed_jobs": [{"job_type": "ai_analysis", "seconds": 3600}],
            "oldest_pending_pcap_seconds": 0,
        }}
        health = {"summary": {"latest": {"timestamp_utc": "2026-07-14T17:55:00Z"}}, "pcap": {"warning_count": 0}}
        failures, snapshot = self.slo.evaluate(metrics, health, now=now, disk_used_percent=55,
                                               sqlite_backup_age=60, postgres_backup_age=60,
                                               previous_ingest_errors=0)
        self.assertEqual(failures, [])
        self.assertEqual(snapshot["signals"]["processing_ai_job_count"], 1)

        metrics["metrics"]["oldest_processing_jobs"][0]["seconds"] = 901
        failures, _ = self.slo.evaluate(metrics, health, now=now, disk_used_percent=55,
                                        sqlite_backup_age=60, postgres_backup_age=60,
                                        previous_ingest_errors=0)
        self.assertIn("AI analysis has been processing without state progress for 15 minutes", failures)

    def test_soak_clock_continues_only_while_healthy(self):
        now = dt.datetime(2026, 7, 16, 18, tzinfo=dt.timezone.utc)
        state = self.slo.update_soak_state({"healthy_since": "2026-07-14  17:00:00+00:00"}, [], now)
        self.assertTrue(state["qualified_48h"])
        self.assertEqual(state["healthy_elapsed_seconds"], 49 * 60 * 60)
        failed = self.slo.update_soak_state({"healthy_since": state["healthy_since"]}, ["stale"], now)
        self.assertIsNone(failed["healthy_since"])

    def test_slo_history_is_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            history = Path(tmp) / "history.jsonl"
            for value in range(5):
                self.slo.append_bounded_history(history, {"value": value}, keep=3)
            self.assertEqual(len(history.read_text().splitlines()), 3)
            self.assertIn('"value":4', history.read_text())

    def test_sqlite_backup_is_restorable(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source.sqlite3"
            destination = Path(tmp) / "backup.sqlite3"
            import sqlite3
            with closing(sqlite3.connect(source)) as conn:
                with conn:
                    conn.execute("CREATE TABLE alerts (id TEXT)")
                    conn.executemany("INSERT INTO alerts VALUES (?)", [("a",), ("b",)])
            self.assertEqual(self.backup.backup_sqlite(source, destination), 2)
            with closing(sqlite3.connect(destination)) as conn:
                self.assertEqual(conn.execute("PRAGMA quick_check").fetchone()[0], "ok")

    def test_runtime_archive_only_contains_declared_recovery_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "config").mkdir()
            (root / "config/settings.json").write_text("{}")
            (root / ".env").write_text("PLACEHOLDER=value\n")
            (root / "unrelated-live-data.log").write_text("must not be archived")
            archive = root / "runtime.tar.gz"
            included = self.backup.archive_runtime_secrets(root, archive)
            self.assertEqual(included, [".env", "config"])
            import tarfile
            with tarfile.open(archive) as stream:
                names = stream.getnames()
            self.assertNotIn("unrelated-live-data.log", names)


if __name__ == "__main__":
    unittest.main()
