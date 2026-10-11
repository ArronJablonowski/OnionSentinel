from __future__ import annotations

from operational_slos_fixtures import (
    Path,
    ROOT,
    closing,
    dt,
    importlib,
    io,
    json,
    load_module,
    mock,
    shutil,
    sqlite3,
    subprocess,
    sys,
    tempfile,
    unittest,
)

class OperationalSloTestsPendingAiRequiresRecentForwardProgressCases:
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


    def test_fresh_ai_job_after_idle_period_does_not_page(self):
        now = dt.datetime(2030, 1, 15, 8, 41, 44, tzinfo=dt.timezone.utc)
        metrics = {"metrics": {
            "process": {"ingest_errors": 0},
            "durable_jobs": [{"job_type": "ai_analysis", "status": "pending", "count": 1}],
            "oldest_pending_jobs": [{"job_type": "ai_analysis", "seconds": 33}],
            "latest_completed_jobs": [{"job_type": "ai_analysis", "seconds": 3544}],
            "oldest_pending_pcap_seconds": 0,
        }}
        health = {"summary": {"latest": {"timestamp_utc": "2030-01-15T08:40:00Z"}},
                  "pcap": {"warning_count": 0}}

        failures, snapshot = self.slo.evaluate(
            metrics, health, now=now, disk_used_percent=55,
            sqlite_backup_age=60, postgres_backup_age=60, previous_ingest_errors=0,
        )

        self.assertEqual(failures, [])
        self.assertEqual(snapshot["signals"]["oldest_pending_ai_job_seconds"], 33)


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


    def test_incident_response_backlog_is_part_of_the_soak_gate(self):
        now = dt.datetime(2026, 7, 14, 18, tzinfo=dt.timezone.utc)
        metrics = {"metrics": {
            "process": {"ingest_errors": 0},
            "durable_jobs": [
                {"job_type": "incident_response_analysis", "status": "pending", "count": 30},
            ],
            "oldest_pending_jobs": [
                {"job_type": "incident_response_analysis", "seconds": 1900},
            ],
            "latest_completed_jobs": [
                {"job_type": "incident_response_analysis", "seconds": 1900},
            ],
            "oldest_pending_pcap_seconds": 0,
        }}
        health = {"summary": {"latest": {"timestamp_utc": "2026-07-14T17:55:00Z"}},
                  "pcap": {"warning_count": 0}}
        failures, snapshot = self.slo.evaluate(
            metrics, health, now=now, disk_used_percent=55,
            sqlite_backup_age=60, postgres_backup_age=60,
            previous_ingest_errors=0,
        )
        self.assertIn(
            "incident-response analysis has pending work but no completion within 30 minutes",
            failures,
        )
        self.assertEqual(
            snapshot["signals"]["pending_incident_response_job_count"], 30,
        )


    def test_material_combined_queue_growth_degrades_the_soak(self):
        now = dt.datetime(2026, 7, 14, 18, tzinfo=dt.timezone.utc)
        metrics = {"metrics": {
            "process": {"ingest_errors": 0},
            "durable_jobs": [
                {"job_type": "ai_analysis", "status": "pending", "count": 30},
                {"job_type": "incident_response_analysis", "status": "pending", "count": 30},
            ],
            "oldest_pending_jobs": [
                {"job_type": "ai_analysis", "seconds": 60},
                {"job_type": "incident_response_analysis", "seconds": 60},
            ],
            "oldest_pending_pcap_seconds": 0,
        }}
        health = {"summary": {"latest": {"timestamp_utc": "2026-07-14T17:55:00Z"}},
                  "pcap": {"warning_count": 0}}
        failures, snapshot = self.slo.evaluate(
            metrics, health, now=now, disk_used_percent=55,
            sqlite_backup_age=60, postgres_backup_age=60,
            previous_ingest_errors=0,
            previous_pending_job_counts={
                "ai_analysis": 20,
                "incident_response_analysis": 20,
            },
        )
        self.assertEqual(failures, [])
        self.assertIn(
            "combined AI and incident-response queues are growing faster than the bounded soak gate",
            snapshot["advisories"],
        )


    def test_soak_clock_continues_only_while_healthy(self):
        now = dt.datetime(2026, 7, 16, 18, tzinfo=dt.timezone.utc)
        state = self.slo.update_soak_state({"healthy_since": "2026-07-14  17:00:00+00:00"}, [], now)
        self.assertTrue(state["qualified_48h"])
        self.assertEqual(state["healthy_elapsed_seconds"], 49 * 60 * 60)
        failed = self.slo.update_soak_state({"healthy_since": state["healthy_since"]}, ["stale"], now)
        self.assertIsNone(failed["healthy_since"])


    def test_sqlite_backup_slo_uses_encrypted_snapshot_commit_metadata(self):
        source = (ROOT / "n8n/bin/evaluate-operational-slos.py").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            'args.stack_dir / "alert_store_backups", "*.backup.json", now',
            source,
        )
        self.assertNotIn(
            'args.stack_dir / "alert_store_backups", "*.backup", now',
            source,
        )


    def test_backup_age_ignores_symlinked_commit_metadata(self):
        now = dt.datetime(2026, 8, 15, 10, tzinfo=dt.timezone.utc)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            external = root / "external.backup.json"
            external.write_text("{}", encoding="utf-8")
            directory = root / "backups"
            directory.mkdir()
            (directory / "linked.backup.json").symlink_to(external)
            self.assertIsNone(
                self.slo.newest_file_age(directory, "*.backup.json", now)
            )


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
            with closing(sqlite3.connect(source)) as conn:
                with conn:
                    conn.execute("CREATE TABLE alerts (id TEXT)")
                    conn.executemany("INSERT INTO alerts VALUES (?)", [("a",), ("b",)])
            self.assertEqual(self.backup.backup_sqlite(source, destination), 2)
            with closing(sqlite3.connect(destination)) as conn:
                self.assertEqual(conn.execute("PRAGMA quick_check").fetchone()[0], "ok")


    def test_harness_sqlite_backup_runs_logical_restore_drill(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "harness.sqlite3"
            destination = Path(tmp) / "harness.backup.sqlite3"
            with closing(sqlite3.connect(source)) as conn:
                with conn:
                    conn.execute("PRAGMA foreign_keys = ON")
                    conn.execute(
                        "CREATE TABLE harness_runs (run_id TEXT PRIMARY KEY)"
                    )
                    conn.execute(
                        """
                        CREATE TABLE harness_events (
                            run_id TEXT REFERENCES harness_runs(run_id)
                                ON DELETE CASCADE,
                            sequence INTEGER
                        )
                        """
                    )
                    conn.execute("INSERT INTO harness_runs VALUES ('run-1')")
                    conn.execute("INSERT INTO harness_events VALUES ('run-1', 1)")
            result = self.backup.backup_sqlite_database(
                source,
                destination,
                required_tables=("harness_runs", "harness_events"),
                count_table="harness_runs",
            )
            self.assertEqual(result["rows"], 1)
            self.assertEqual(result["quick_check"], "ok")
            self.assertEqual(result["restore_drill"]["quick_check"], "ok")
            self.assertEqual(result["foreign_key_check_rows"], 0)


    def test_create_bundle_includes_optional_harness_snapshot_and_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stack = root / "stack"
            backup_root = root / "backups"
            data = stack / "alert_store_data"
            data.mkdir(parents=True)
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
            with closing(
                sqlite3.connect(data / "investigation-harness.sqlite3")
            ) as conn:
                with conn:
                    for table in harness_tables:
                        if table == "harness_runs":
                            conn.execute(
                                "CREATE TABLE harness_runs (run_id TEXT)"
                            )
                        elif table == "harness_metadata":
                            conn.execute(
                                """
                                CREATE TABLE harness_metadata (
                                    key TEXT,
                                    value TEXT
                                )
                                """
                            )
                        else:
                            conn.execute(f"CREATE TABLE {table} (id TEXT)")
                    conn.execute("INSERT INTO harness_runs VALUES ('run-1')")
            backup_root.mkdir()
            with mock.patch.object(
                self.backup,
                "require_runtime_capacity",
            ), mock.patch.object(
                self.backup,
                "postgres_dump",
                side_effect=lambda _docker, destination: destination.write_bytes(
                    b"fake-postgres-dump"
                ),
            ):
                bundle = self.backup.create_bundle(
                    stack,
                    backup_root,
                    "/fake/docker",
                    encryption=self.backup.RecoveryEncryption(
                        b"fixture-recovery-secret-with-at-least-32-bytes",
                        openssl="/usr/bin/openssl",
                    ),
                )
            manifest = json.loads((bundle / "manifest.json").read_text())
            self.assertTrue(
                (bundle / "investigation-harness.sqlite3.enc").is_file()
            )
            self.assertEqual(manifest["harness_runs"], 1)
            self.assertTrue(
                manifest["sqlite"]["investigation_harness"]["present"]
            )
            self.assertEqual(
                manifest["sqlite"]["investigation_harness"]["restore_drill"][
                    "rows"
                ],
                1,
            )


    def test_create_bundle_remains_compatible_when_harness_is_absent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stack = root / "stack"
            backup_root = root / "backups"
            data = stack / "alert_store_data"
            data.mkdir(parents=True)
            with closing(sqlite3.connect(data / "alerts.sqlite3")) as conn:
                with conn:
                    conn.execute("CREATE TABLE alerts (id TEXT)")
                    conn.execute("CREATE TABLE alert_group_summary (id TEXT)")
            backup_root.mkdir()
            with mock.patch.object(
                self.backup,
                "require_runtime_capacity",
            ), mock.patch.object(
                self.backup,
                "postgres_dump",
                side_effect=lambda _docker, destination: destination.write_bytes(
                    b"fake-postgres-dump"
                ),
            ):
                bundle = self.backup.create_bundle(
                    stack,
                    backup_root,
                    "/fake/docker",
                    encryption=self.backup.RecoveryEncryption(
                        b"fixture-recovery-secret-with-at-least-32-bytes",
                        openssl="/usr/bin/openssl",
                    ),
                )
            manifest = json.loads((bundle / "manifest.json").read_text())
            self.assertFalse(
                manifest["sqlite"]["investigation_harness"]["present"]
            )
            self.assertFalse(
                (bundle / "investigation-harness.sqlite3").exists()
            )


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


