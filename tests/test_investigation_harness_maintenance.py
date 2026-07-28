from __future__ import annotations

from contextlib import closing
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sqlite3
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


if __name__ == "__main__":
    unittest.main()
