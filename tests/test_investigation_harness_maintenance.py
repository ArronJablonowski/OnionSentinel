from __future__ import annotations

from contextlib import closing
import datetime as dt
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


HARNESS = load_module(
    "harness_maintenance_test_runtime",
    ROOT / "n8n/bin/onion_sentinel_harness.py",
)
MAINTENANCE = load_module(
    "harness_maintenance_test_module",
    ROOT / "n8n/bin/maintain-investigation-harness.py",
)


class InvestigationHarnessMaintenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.db = self.root / "alert_store_data/investigation-harness.sqlite3"
        self.now = dt.datetime(2026, 7, 25, 12, tzinfo=dt.timezone.utc)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def add_run(
        self,
        run_id: str,
        *,
        terminal: bool,
        age_days: int = 0,
    ) -> None:
        store = HARNESS.HarnessStore(self.db)
        envelope = HARNESS.JobEnvelope.from_prompt(
            run_id=run_id,
            prompt_package={
                "alert": {"alert_id": f"alert-{run_id}"},
                "group_id": f"group-{run_id}",
                "evidence_reference_contract": {"references": []},
            },
            role=HARNESS.AgentRole.SOC_ANALYST.value,
            assigned_route="codex-cli:gpt-5.6-sol:high",
            configuration={"reviewer_route": ""},
            source_revision="1" * 40,
            policy_version="1.0.0",
        )
        store.start_run(envelope, HARNESS.HarnessPolicy.disabled_default())
        if terminal:
            store.finish(run_id, status=HARNESS.RunStatus.SUCCEEDED.value)
        when = MAINTENANCE.timestamp_text(
            self.now - dt.timedelta(days=age_days)
        )
        with HARNESS._connect(self.db) as connection:
            connection.execute(
                """
                UPDATE harness_runs
                SET started_at = ?, updated_at = ?,
                    completed_at = CASE
                      WHEN status = 'succeeded' THEN ?
                      ELSE completed_at
                    END
                WHERE run_id = ?
                """,
                (when, when, when, run_id),
            )

    def make_alert_store_job(
        self,
        run_id: str,
        *,
        status: str,
        job_type: str = "ai_analysis",
    ) -> Path:
        alert_db = self.root / "alert_store_data/alerts.sqlite3"
        with closing(sqlite3.connect(alert_db)) as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS durable_jobs (
                  id INTEGER PRIMARY KEY,
                  job_type TEXT NOT NULL,
                  dedupe_key TEXT NOT NULL,
                  status TEXT NOT NULL,
                  attempt_count INTEGER NOT NULL DEFAULT 0,
                  updated_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                INSERT INTO durable_jobs (
                  job_type, dedupe_key, status, attempt_count, updated_at
                ) VALUES (?, ?, ?, 1, ?)
                """,
                (
                    job_type,
                    f"group-{run_id}",
                    status,
                    MAINTENANCE.timestamp_text(self.now),
                ),
            )
            connection.commit()
        os.chmod(alert_db, 0o600)
        return alert_db

    def worker_locks(self) -> tuple[Path, Path]:
        return (
            self.root / "run/ai-analysis-ollama-worker.lock",
            self.root / "run/ai-analysis-cli-worker.lock",
        )

    @staticmethod
    def digest(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def make_verified_backup(
        self,
        *,
        required_run_ids: tuple[str, ...] = (),
    ) -> dict:
        backup_root = self.root / "recovery_backups"
        bundle = backup_root / "20260725T120000+0000"
        bundle.mkdir(parents=True, mode=0o700)
        os.chmod(backup_root, 0o700)
        os.chmod(bundle, 0o700)
        snapshot = bundle / "investigation-harness.sqlite3"
        with closing(sqlite3.connect(self.db)) as source, closing(
            sqlite3.connect(snapshot)
        ) as destination:
            source.backup(destination)
        os.chmod(snapshot, 0o600)
        with closing(sqlite3.connect(snapshot)) as connection:
            runs = int(
                connection.execute(
                    "SELECT COUNT(*) FROM harness_runs"
                ).fetchone()[0]
            )
        manifest = {
            "created_at": "2026-07-25  12:00:00+00:00",
            "harness_runs": runs,
            "sqlite": {
                "investigation_harness": {
                    "present": True,
                    "rows": runs,
                }
            },
            "files": {
                "investigation-harness.sqlite3": {
                    "bytes": snapshot.stat().st_size,
                    "sha256": self.digest(snapshot),
                }
            },
        }
        manifest_path = bundle / "manifest.json"
        manifest_path.write_text(json.dumps(manifest))
        os.chmod(manifest_path, 0o600)
        return MAINTENANCE.verify_recent_harness_backup(
            backup_root,
            now=self.now,
            max_age_seconds=26 * 60 * 60,
            required_run_ids=required_run_ids,
        )

    def maintenance(self, *, apply: bool, backup: dict | None = None, **overrides):
        arguments = {
            "now": self.now,
            "retention_days": 30,
            "max_terminal_runs": 100,
            "min_terminal_runs": 0,
            "max_delete_runs": 100,
            "max_live_bytes": 64 * 1024**2,
            "incremental_vacuum_pages": 16,
            "apply": apply,
            "backup": backup,
        }
        arguments.update(overrides)
        return MAINTENANCE.maintain_database(self.db, **arguments)

    def test_absent_database_is_not_created(self) -> None:
        result = self.maintenance(apply=True)
        self.assertEqual(result["status"], "absent")
        self.assertFalse(self.db.exists())

    def test_cli_absent_database_writes_private_success_report(self) -> None:
        report_path = self.root / "logs/maintenance.json"
        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "n8n/bin/maintain-investigation-harness.py"),
                "--stack-dir",
                str(self.root),
                "--report",
                str(report_path),
            ],
            cwd=self.root,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertTrue(payload["ok"])
        self.assertEqual(report["status"], "absent")
        self.assertFalse(report["database_present"])
        self.assertEqual(report_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(report_path.parent.stat().st_mode & 0o777, 0o700)

    def test_cli_invalid_policy_writes_blocked_report_and_returns_two(self) -> None:
        report_path = self.root / "logs/maintenance.json"
        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "n8n/bin/maintain-investigation-harness.py"),
                "--stack-dir",
                str(self.root),
                "--report",
                str(report_path),
                "--retention-days",
                "0",
            ],
            cwd=self.root,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 2, completed.stderr)
        payload = json.loads(completed.stdout)
        report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertFalse(payload["ok"])
        self.assertEqual(report["status"], "blocked")
        self.assertIn("retention days must be between", report["error"])

    def test_harness_runtime_load_is_cached_and_cwd_independent(self) -> None:
        original_cwd = Path.cwd()
        try:
            os.chdir(self.root)
            first = MAINTENANCE.load_harness_runtime()
            second = MAINTENANCE.load_harness_runtime()
        finally:
            os.chdir(original_cwd)
        self.assertIs(first, second)
        self.assertTrue(hasattr(first, "HarnessStore"))

    def test_new_database_uses_incremental_auto_vacuum(self) -> None:
        self.add_run("run-current", terminal=False)
        with closing(sqlite3.connect(self.db)) as connection:
            self.assertEqual(connection.execute("PRAGMA auto_vacuum").fetchone()[0], 2)
        self.assertEqual(self.db.stat().st_mode & 0o777, 0o600)

    def test_dry_run_is_non_mutating_and_active_run_is_never_selected(self) -> None:
        self.add_run("run-old", terminal=True, age_days=60)
        self.add_run("run-active", terminal=False, age_days=60)
        before = self.db.read_bytes()
        result = self.maintenance(apply=False)
        self.assertEqual(result["candidates"]["selected"], 1)
        self.assertEqual(result["deleted_runs"], 0)
        self.assertEqual(self.db.read_bytes(), before)
        with closing(sqlite3.connect(self.db)) as connection:
            statuses = dict(
                connection.execute(
                    "SELECT run_id, status FROM harness_runs"
                ).fetchall()
            )
        self.assertEqual(statuses["run-active"], "running")

    def test_apply_requires_backup_then_deletes_only_terminal_trace(self) -> None:
        self.add_run("run-old", terminal=True, age_days=60)
        self.add_run("run-active", terminal=False, age_days=60)
        with self.assertRaisesRegex(
            MAINTENANCE.MaintenanceError,
            "verified harness backup",
        ):
            self.maintenance(apply=True)

        backup = self.make_verified_backup(required_run_ids=("run-old",))
        result = self.maintenance(apply=True, backup=backup)
        self.assertEqual(result["deleted_runs"], 1)
        self.assertEqual(result["after"]["quick_check"], "ok")
        self.assertEqual(result["after"]["foreign_key_check_rows"], 0)
        with closing(sqlite3.connect(self.db)) as connection:
            rows = connection.execute(
                "SELECT run_id, status FROM harness_runs"
            ).fetchall()
        self.assertEqual(rows, [("run-active", "running")])

    def test_count_retention_and_delete_batch_are_bounded(self) -> None:
        for index in range(7):
            self.add_run(
                f"run-{index}",
                terminal=True,
                age_days=index,
            )
        result = self.maintenance(
            apply=False,
            max_terminal_runs=3,
            max_delete_runs=2,
        )
        self.assertEqual(result["candidates"]["terminal_overflow"], 4)
        self.assertEqual(result["candidates"]["selected"], 2)

    def test_backup_verifier_rejects_hash_mismatch_and_stale_bundle(self) -> None:
        self.add_run("run-backup", terminal=True)
        backup = self.make_verified_backup()
        self.assertTrue(backup["verified"])
        bundle = self.root / "recovery_backups/20260725T120000+0000"
        snapshot = bundle / "investigation-harness.sqlite3"
        with snapshot.open("ab") as stream:
            stream.write(b"tampered")
        with self.assertRaisesRegex(
            MAINTENANCE.MaintenanceError,
            "no recent hash-verified",
        ):
            MAINTENANCE.verify_recent_harness_backup(
                self.root / "recovery_backups",
                now=self.now,
                max_age_seconds=26 * 60 * 60,
            )

    def test_backup_verifier_rejects_future_bundle_timestamp(self) -> None:
        self.add_run("run-backup", terminal=True)
        self.make_verified_backup()
        manifest_path = (
            self.root
            / "recovery_backups/20260725T120000+0000/manifest.json"
        )
        manifest = json.loads(manifest_path.read_text())
        manifest["created_at"] = "2026-07-26  12:00:00+00:00"
        manifest_path.write_text(json.dumps(manifest))
        os.chmod(manifest_path, 0o600)
        with self.assertRaisesRegex(
            MAINTENANCE.MaintenanceError,
            "no recent hash-verified",
        ):
            MAINTENANCE.verify_recent_harness_backup(
                self.root / "recovery_backups",
                now=self.now,
                max_age_seconds=26 * 60 * 60,
            )

    def test_backup_verifier_rejects_non_private_manifest(self) -> None:
        self.add_run("run-backup", terminal=True)
        self.make_verified_backup()
        manifest_path = (
            self.root
            / "recovery_backups/20260725T120000+0000/manifest.json"
        )
        os.chmod(manifest_path, 0o640)
        with self.assertRaisesRegex(
            MAINTENANCE.MaintenanceError,
            "no recent hash-verified",
        ):
            MAINTENANCE.verify_recent_harness_backup(
                self.root / "recovery_backups",
                now=self.now,
                max_age_seconds=26 * 60 * 60,
            )

    def test_backup_verifier_rejects_symlink_snapshot(self) -> None:
        self.add_run("run-backup", terminal=True)
        self.make_verified_backup()
        bundle = self.root / "recovery_backups/20260725T120000+0000"
        snapshot = bundle / "investigation-harness.sqlite3"
        target = bundle / "unexpected-target.sqlite3"
        snapshot.rename(target)
        snapshot.symlink_to(target)
        with self.assertRaisesRegex(
            MAINTENANCE.MaintenanceError,
            "no recent hash-verified",
        ):
            MAINTENANCE.verify_recent_harness_backup(
                self.root / "recovery_backups",
                now=self.now,
                max_age_seconds=26 * 60 * 60,
            )

    def test_backup_must_contain_candidate_in_terminal_state(self) -> None:
        self.add_run("run-later-terminal", terminal=False)
        self.make_verified_backup()
        store = HARNESS.HarnessStore(self.db)
        store.finish(
            "run-later-terminal",
            status=HARNESS.RunStatus.SUCCEEDED.value,
        )
        with self.assertRaisesRegex(
            MAINTENANCE.MaintenanceError,
            "no recent hash-verified",
        ):
            MAINTENANCE.verify_recent_harness_backup(
                self.root / "recovery_backups",
                now=self.now,
                max_age_seconds=26 * 60 * 60,
                required_run_ids=("run-later-terminal",),
            )

    def test_backup_candidate_event_chain_must_be_valid(self) -> None:
        self.add_run("run-chain", terminal=True)
        self.make_verified_backup()
        bundle = self.root / "recovery_backups/20260725T120000+0000"
        snapshot = bundle / "investigation-harness.sqlite3"
        with closing(sqlite3.connect(snapshot)) as connection:
            with connection:
                connection.execute(
                    """
                    UPDATE harness_events
                    SET payload_json = '{"tampered":true}'
                    WHERE run_id = ? AND sequence = 1
                    """,
                    ("run-chain",),
                )
        os.chmod(snapshot, 0o600)
        manifest_path = bundle / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["files"]["investigation-harness.sqlite3"]["sha256"] = (
            self.digest(snapshot)
        )
        manifest["files"]["investigation-harness.sqlite3"]["bytes"] = (
            snapshot.stat().st_size
        )
        manifest_path.write_text(json.dumps(manifest))
        os.chmod(manifest_path, 0o600)
        with self.assertRaisesRegex(
            MAINTENANCE.MaintenanceError,
            "no recent hash-verified",
        ):
            MAINTENANCE.verify_recent_harness_backup(
                self.root / "recovery_backups",
                now=self.now,
                max_age_seconds=26 * 60 * 60,
                required_run_ids=("run-chain",),
            )

    def test_symlink_database_is_rejected(self) -> None:
        target = self.root / "target.sqlite3"
        target.write_bytes(b"")
        self.db.parent.mkdir(parents=True)
        self.db.symlink_to(target)
        with self.assertRaisesRegex(
            MAINTENANCE.MaintenanceError,
            "must not be a symlink",
        ):
            self.maintenance(apply=False)

    def test_stale_run_is_hash_chain_reconciled_after_durable_retry(self) -> None:
        self.add_run("run-crashed", terminal=False, age_days=1)
        self.add_run("run-successor", terminal=True)
        with HARNESS._connect(self.db) as connection:
            connection.execute(
                """
                UPDATE harness_runs
                SET correlation_id = 'group-run-crashed',
                    case_id = (SELECT case_id FROM harness_runs
                               WHERE run_id = 'run-crashed'),
                    started_at = ?, updated_at = ?, completed_at = ?
                WHERE run_id = 'run-successor'
                """,
                (
                    MAINTENANCE.timestamp_text(
                        self.now - dt.timedelta(hours=1)
                    ),
                    MAINTENANCE.timestamp_text(self.now),
                    MAINTENANCE.timestamp_text(self.now),
                ),
            )
        alert_db = self.make_alert_store_job(
            "run-crashed", status="completed"
        )
        result = MAINTENANCE.reconcile_stale_running_runs(
            self.db,
            alert_db,
            worker_lock_paths=self.worker_locks(),
            now=self.now,
            stale_running_seconds=3600,
            limit=10,
            apply=True,
        )
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["reconciled"], 1)
        store = HARNESS.HarnessStore(self.db)
        snapshot = store.snapshot("run-crashed")
        self.assertEqual(snapshot["status"], "failed")
        summary = json.loads(snapshot["summary_json"])
        self.assertEqual(summary["durable_status"], "completed")
        self.assertEqual(summary["successor_run_id"], "run-successor")
        with HARNESS._connect(self.db) as connection:
            self.assertTrue(
                MAINTENANCE.verify_event_chains(
                    connection,
                    ("run-crashed",),
                )
            )

    def test_processing_durable_owner_is_never_reconciled(self) -> None:
        self.add_run("run-active", terminal=False, age_days=1)
        alert_db = self.make_alert_store_job(
            "run-active", status="processing"
        )
        result = MAINTENANCE.reconcile_stale_running_runs(
            self.db,
            alert_db,
            worker_lock_paths=self.worker_locks(),
            now=self.now,
            stale_running_seconds=3600,
            limit=10,
            apply=True,
        )
        self.assertEqual(result["reconciled"], 0)
        self.assertEqual(
            HARNESS.HarnessStore(self.db).snapshot("run-active")["status"],
            "running",
        )

    def test_read_only_alert_store_may_be_group_world_readable(self) -> None:
        self.add_run("run-readable", terminal=False, age_days=1)
        alert_db = self.make_alert_store_job(
            "run-readable", status="completed"
        )
        os.chmod(alert_db, 0o644)
        result = MAINTENANCE.reconcile_stale_running_runs(
            self.db,
            alert_db,
            worker_lock_paths=self.worker_locks(),
            now=self.now,
            stale_running_seconds=3600,
            limit=10,
            apply=False,
        )
        self.assertEqual(result["selected"], 1)

    def test_active_worker_lock_blocks_stale_run_reconciliation(self) -> None:
        self.add_run("run-locked", terminal=False, age_days=1)
        alert_db = self.make_alert_store_job(
            "run-locked", status="pending"
        )
        first_lock, second_lock = self.worker_locks()
        first_lock.parent.mkdir(parents=True)
        with first_lock.open("a+") as held:
            fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = MAINTENANCE.reconcile_stale_running_runs(
                self.db,
                alert_db,
                worker_lock_paths=(first_lock, second_lock),
                now=self.now,
                stale_running_seconds=3600,
                limit=10,
                apply=True,
            )
        self.assertEqual(result["status"], "active-worker")
        self.assertEqual(
            HARNESS.HarnessStore(self.db).snapshot("run-locked")["status"],
            "running",
        )


if __name__ == "__main__":
    unittest.main()
