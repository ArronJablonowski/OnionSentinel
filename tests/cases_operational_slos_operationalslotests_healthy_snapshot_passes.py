from __future__ import annotations

from installer_source_fixture import read_installer_source

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

class OperationalSloTestsHealthySnapshotPassesCases:
    def test_healthy_snapshot_passes(self):
        now = dt.datetime(2026, 7, 14, 18, tzinfo=dt.timezone.utc)
        metrics = {"metrics": {"process": {"ingest_errors": 0}, "oldest_pending_job_seconds": 0,
                               "oldest_pending_jobs": [], "oldest_pending_pcap_seconds": 0}}
        health = {"summary": {"latest": {"timestamp_utc": "2026-07-14T17:55:00Z"}}, "pcap": {"warning_count": 0}}
        failures, snapshot = self.slo.evaluate(metrics, health, now=now, disk_used_percent=55, sqlite_backup_age=60, postgres_backup_age=60, previous_ingest_errors=0)
        self.assertEqual(failures, [])
        self.assertTrue(snapshot["ok"])


    def test_enabled_shadow_requires_fresh_recovery_dump(self):
        now = dt.datetime(2026, 7, 14, 18, tzinfo=dt.timezone.utc)
        metrics = {"metrics": {"process": {"ingest_errors": 0},
                               "oldest_pending_job_seconds": 0,
                               "oldest_pending_jobs": [],
                               "oldest_pending_pcap_seconds": 0}}
        health = {"summary": {"latest": {
            "timestamp_utc": "2026-07-14T17:55:00Z"
        }}, "pcap": {"warning_count": 0}}
        failures, snapshot = self.slo.evaluate(
            metrics,
            health,
            now=now,
            disk_used_percent=55,
            sqlite_backup_age=60,
            postgres_backup_age=60,
            previous_ingest_errors=0,
            alert_store_postgres_shadow_enabled=True,
            alert_store_postgres_backup_age=None,
        )
        self.assertIn(
            "verified alert-store PostgreSQL shadow backup is missing or "
            "older than 26 hours",
            failures,
        )
        self.assertTrue(
            snapshot["signals"]["alert_store_postgres_shadow_enabled"]
        )


    def test_probe_timeout_is_bounded_without_traceback(self):
        with mock.patch.object(
            self.slo.urllib.request,
            "urlopen",
            side_effect=TimeoutError("timed out"),
        ) as urlopen, mock.patch.object(self.slo.time, "sleep"):
            with self.assertRaisesRegex(self.slo.ProbeError, "metrics probe unavailable"):
                self.slo.fetch_json("http://127.0.0.1:8787/metrics", "metrics")
        self.assertEqual(urlopen.call_count, 2)


    def test_probe_retries_one_transient_timeout(self):
        response = io.BytesIO(b'{"ok":true}')
        with mock.patch.object(
            self.slo.urllib.request,
            "urlopen",
            side_effect=[TimeoutError("timed out"), response],
        ) as urlopen, mock.patch.object(self.slo.time, "sleep") as sleep:
            payload = self.slo.fetch_json("http://127.0.0.1:8787/metrics", "metrics")

        self.assertEqual(payload, {"ok": True})
        self.assertEqual(urlopen.call_count, 2)
        sleep.assert_called_once_with(self.slo.DEFAULT_PROBE_RETRY_DELAY_SECONDS)


    def test_probe_does_not_retry_invalid_json_contract(self):
        response = io.BytesIO(b'not-json')
        with mock.patch.object(self.slo.urllib.request, "urlopen", return_value=response) as urlopen:
            with self.assertRaisesRegex(self.slo.ProbeError, "BoundedHttpError"):
                self.slo.fetch_json("http://127.0.0.1:8787/metrics", "metrics")
        self.assertEqual(urlopen.call_count, 1)


    def test_installer_deploys_and_validates_operational_slo_policy(self):
        installer = read_installer_source(ROOT / "n8n/bin/install-macstudio-stack.zsh")
        self.assertIn(
            'cp "$REPO_DIR/n8n/bin/operational_slo_policy.py" '
            '"$STACK_DIR/bin/operational_slo_policy.py"',
            installer,
        )
        self.assertIn(
            'cp "$REPO_DIR/n8n/bin/operational_slo_primitives.py" '
            '"$STACK_DIR/bin/operational_slo_primitives.py"',
            installer,
        )
        self.assertIn(
            'cp "$REPO_DIR/n8n/bin/operational_slo_resilience_policy.py" '
            '"$STACK_DIR/bin/operational_slo_resilience_policy.py"',
            installer,
        )
        self.assertIn(
            'cp "$REPO_DIR/n8n/bin/operational_slo_queue_policy.py" '
            '"$STACK_DIR/bin/operational_slo_queue_policy.py"',
            installer,
        )
        self.assertIn(
            'cp "$REPO_DIR/n8n/bin/operational_slo_state.py" '
            '"$STACK_DIR/bin/operational_slo_state.py"',
            installer,
        )
        self.assertIn(
            'bin_dir / "evaluate-operational-slos.py"',
            installer,
        )


    def test_flat_bin_evaluator_starts_in_isolated_python(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory)
            for name in (
                "bounded_http.py",
                "operational_slo_primitives.py",
                "operational_slo_queue_policy.py",
                "operational_slo_resilience_policy.py",
                "operational_slo_policy.py",
                "operational_slo_state.py",
                "sqlite_backup_recovery_gate.py",
                "evaluate-operational-slos.py",
            ):
                shutil.copy2(ROOT / "n8n/bin" / name, runtime / name)
            result = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    str(runtime / "evaluate-operational-slos.py"),
                    "--help",
                ],
                text=True,
                capture_output=True,
                timeout=10,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--stack-dir", result.stdout)


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


    def test_harness_maintenance_disk_accounting_is_exposed(self):
        now = dt.datetime(2026, 7, 14, 18, tzinfo=dt.timezone.utc)
        metrics = {
            "metrics": {
                "process": {"ingest_errors": 0},
                "oldest_pending_job_seconds": 0,
                "oldest_pending_jobs": [],
                "oldest_pending_pcap_seconds": 0,
            }
        }
        health = {
            "summary": {
                "latest": {"timestamp_utc": "2026-07-14T17:55:00Z"}
            },
            "pcap": {"warning_count": 0},
        }
        maintenance = {
            "generated_at": "2026-07-14T17:50:00Z",
            "status": "ok",
            "follow_up_required": False,
            "policy": {"max_live_bytes": 2 * 1024**3},
            "checkpoint": {"busy": 0},
            "after": {
                "quick_check": "ok",
                "foreign_key_check_rows": 0,
                "live_page_bytes": 12_345,
                "allocated_disk_bytes": 16_384,
                "reclaimable_page_bytes": 4_039,
                "run_counts": {"terminal": 20, "active": 1},
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
            harness_database_present=True,
            harness_maintenance=maintenance,
        )
        self.assertEqual(failures, [])
        signal = snapshot["signals"]["investigation_harness"]
        self.assertEqual(signal["live_page_bytes"], 12_345)
        self.assertEqual(signal["terminal_runs"], 20)
        self.assertEqual(signal["maintenance_status"], "ok")


    def test_missing_harness_maintenance_report_fails_slo(self):
        now = dt.datetime(2026, 7, 14, 18, tzinfo=dt.timezone.utc)
        metrics = {
            "metrics": {
                "process": {"ingest_errors": 0},
                "oldest_pending_job_seconds": 0,
                "oldest_pending_jobs": [],
                "oldest_pending_pcap_seconds": 0,
            }
        }
        health = {
            "summary": {
                "latest": {"timestamp_utc": "2026-07-14T17:55:00Z"}
            },
            "pcap": {"warning_count": 0},
        }
        failures, _ = self.slo.evaluate(
            metrics,
            health,
            now=now,
            disk_used_percent=55,
            sqlite_backup_age=60,
            postgres_backup_age=60,
            previous_ingest_errors=0,
            harness_database_present=True,
            harness_maintenance=None,
        )
        self.assertIn(
            "investigation harness maintenance report is missing or older "
            "than 2 hours",
            failures,
        )
        self.assertIn(
            "investigation harness maintenance is not healthy (missing)",
            failures,
        )


    def test_evaluation_artifact_maintenance_is_projected_into_slo(self):
        now = dt.datetime(2026, 7, 14, 18, tzinfo=dt.timezone.utc)
        metrics = {"metrics": {
            "process": {"ingest_errors": 0},
            "oldest_pending_job_seconds": 0,
            "oldest_pending_jobs": [],
            "oldest_pending_pcap_seconds": 0,
        }}
        health = {
            "summary": {"latest": {"timestamp_utc": "2026-07-14T17:55:00Z"}},
            "pcap": {"warning_count": 0},
        }
        report = {
            "schema": "onion-sentinel-evaluation-artifact-maintenance-v1",
            "generated_at": "2026-07-14T17:50:00Z",
            "status": "warning",
            "inventory": {
                "run_directories": 7,
                "run_bytes": 12345,
                "sealed_runs": 6,
                "unsealed_runs": 1,
            },
            "cleanup": {
                "temporary_candidates": 2,
                "run_directory_candidates": 1,
                "report_file_candidates": 3,
            },
            "storage": {
                "local": {
                    "used_percent": 66.0,
                    "warning_percent": 65,
                    "failure_percent": 75,
                },
                "encrypted": {
                    "configured": True,
                    "used_percent": 71.0,
                    "warning_percent": 70,
                    "failure_percent": 85,
                },
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
            evaluation_artifact_root_present=True,
            evaluation_artifact_maintenance=report,
        )
        self.assertEqual(failures, [])
        self.assertIn(
            "evaluation artifact maintenance has capacity warnings",
            snapshot["advisories"],
        )
        signal = snapshot["signals"]["evaluation_artifacts"]
        self.assertEqual(signal["run_directories"], 7)
        self.assertEqual(signal["run_bytes"], 12345)
        self.assertTrue(signal["encrypted_configured"])
        self.assertEqual(signal["encrypted_failure_percent"], 85)


    def test_missing_evaluation_artifact_report_fails_when_root_exists(self):
        now = dt.datetime(2026, 7, 14, 18, tzinfo=dt.timezone.utc)
        metrics = {"metrics": {
            "process": {"ingest_errors": 0},
            "oldest_pending_job_seconds": 0,
            "oldest_pending_jobs": [],
            "oldest_pending_pcap_seconds": 0,
        }}
        health = {
            "summary": {"latest": {"timestamp_utc": "2026-07-14T17:55:00Z"}},
            "pcap": {"warning_count": 0},
        }
        failures, _ = self.slo.evaluate(
            metrics,
            health,
            now=now,
            disk_used_percent=55,
            sqlite_backup_age=60,
            postgres_backup_age=60,
            previous_ingest_errors=0,
            evaluation_artifact_root_present=True,
            evaluation_artifact_maintenance=None,
        )
        self.assertIn(
            "evaluation artifact maintenance report is missing or older than 2 hours",
            failures,
        )
        self.assertIn(
            "evaluation artifact maintenance is not healthy (missing)", failures
        )


    def test_invalid_or_future_evaluation_artifact_report_fails_closed(self):
        now = dt.datetime(2026, 7, 14, 18, tzinfo=dt.timezone.utc)
        metrics = {"metrics": {
            "process": {"ingest_errors": 0},
            "oldest_pending_job_seconds": 0,
            "oldest_pending_jobs": [],
            "oldest_pending_pcap_seconds": 0,
        }}
        health = {
            "summary": {"latest": {"timestamp_utc": "2026-07-14T17:55:00Z"}},
            "pcap": {"warning_count": 0},
        }
        failures, snapshot = self.slo.evaluate(
            metrics,
            health,
            now=now,
            disk_used_percent=55,
            sqlite_backup_age=60,
            postgres_backup_age=60,
            previous_ingest_errors=0,
            evaluation_artifact_root_present=True,
            evaluation_artifact_maintenance={
                "schema": "wrong-schema",
                "generated_at": "2026-07-15T18:00:00Z",
                "status": "unexpected",
                "inventory": {"run_directories": "not-an-integer"},
            },
        )
        self.assertIn(
            "evaluation artifact maintenance report schema is invalid", failures
        )
        self.assertIn(
            "evaluation artifact maintenance report is missing or older than 2 hours",
            failures,
        )
        self.assertIn(
            "evaluation artifact maintenance status is invalid (unexpected)", failures
        )
        self.assertEqual(
            snapshot["signals"]["evaluation_artifacts"]["run_directories"], 0
        )


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


    def test_fresh_capture_protection_hold_is_degraded_not_failed(self):
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
                "capture_protection": {
                    "active": True,
                    "state": "capture_protection_hold",
                    "reason": "Zeek capture loss exceeds threshold",
                    "report_age_seconds": 30,
                },
            },
        }

        failures, snapshot = self.slo.evaluate(
            metrics, health, now=now, disk_used_percent=55,
            sqlite_backup_age=60, postgres_backup_age=60, previous_ingest_errors=0,
        )

        self.assertEqual(failures, [])
        self.assertEqual(snapshot["status"], "degraded")
        self.assertTrue(snapshot["advisories"])
        self.assertTrue(snapshot["signals"]["pcap_workflow_operational"])


    def test_brief_capture_telemetry_rollover_gap_is_inside_grace(self):
        now = dt.datetime(2026, 7, 14, 18, tzinfo=dt.timezone.utc)
        metrics = {"metrics": {
            "process": {"ingest_errors": 0},
            "oldest_pending_job_seconds": 0,
            "oldest_pending_jobs": [],
            "oldest_pending_pcap_seconds": 0,
        }}
        health = {
            "summary": {"latest": {"timestamp_utc": "2026-07-14T17:59:30Z"}},
            "pcap": {
                "warning_count": 0,
                "capture_protection": {
                    "active": True,
                    "state": "capture_protection_hold",
                    "reason": "telemetry_unavailable",
                    "report_age_seconds": 30,
                },
            },
        }

        failures, snapshot = self.slo.evaluate(
            metrics, health, now=now, disk_used_percent=55,
            sqlite_backup_age=60, postgres_backup_age=60,
            previous_ingest_errors=0,
            previous_capture_telemetry_unavailable_since=(now - dt.timedelta(seconds=90)).isoformat(),
        )

        self.assertEqual(failures, [])
        self.assertEqual(snapshot["status"], "healthy")
        self.assertEqual(snapshot["advisories"], [])
        self.assertEqual(
            snapshot["signals"]["pcap_capture_telemetry_unavailable_age_seconds"],
            90,
        )


    def test_sustained_capture_telemetry_gap_degrades_soak(self):
        now = dt.datetime(2026, 7, 14, 18, tzinfo=dt.timezone.utc)
        metrics = {"metrics": {
            "process": {"ingest_errors": 0},
            "oldest_pending_job_seconds": 0,
            "oldest_pending_jobs": [],
            "oldest_pending_pcap_seconds": 0,
        }}
        health = {
            "summary": {"latest": {"timestamp_utc": "2026-07-14T17:59:30Z"}},
            "pcap": {
                "warning_count": 0,
                "capture_protection": {
                    "active": True,
                    "state": "capture_protection_hold",
                    "reason": "telemetry_unavailable",
                    "report_age_seconds": 30,
                },
            },
        }

        failures, snapshot = self.slo.evaluate(
            metrics, health, now=now, disk_used_percent=55,
            sqlite_backup_age=60, postgres_backup_age=60,
            previous_ingest_errors=0,
            previous_capture_telemetry_unavailable_since=(now - dt.timedelta(seconds=181)).isoformat(),
        )

        self.assertEqual(failures, [])
        self.assertEqual(snapshot["status"], "degraded")
        self.assertIn(
            "PCAP capture-protection hold: telemetry_unavailable",
            snapshot["advisories"],
        )


    def test_fresh_software_inventory_is_healthy(self):
        now = dt.datetime(2026, 8, 6, 13, tzinfo=dt.timezone.utc)
        failures, snapshot = self.slo.evaluate(
            {"metrics": {"process": {"ingest_errors": 0}}},
            {"summary": {"latest": {"timestamp_utc": "2026-08-06T12:59:30Z"}}},
            now=now,
            disk_used_percent=55,
            sqlite_backup_age=60,
            postgres_backup_age=60,
            previous_ingest_errors=0,
            software_inventory_health={
                "enabled": True,
                "available": True,
                "records": 1478,
                "updated_at": "2026-08-06T12:00:00Z",
            },
        )

        self.assertEqual(failures, [])
        self.assertEqual(
            snapshot["signals"]["software_inventory_updated_age_seconds"],
            3600,
        )


    def test_stale_software_inventory_fails_soak(self):
        now = dt.datetime(2026, 8, 6, 13, tzinfo=dt.timezone.utc)
        failures, snapshot = self.slo.evaluate(
            {"metrics": {"process": {"ingest_errors": 0}}},
            {"summary": {"latest": {"timestamp_utc": "2026-08-06T12:59:30Z"}}},
            now=now,
            disk_used_percent=55,
            sqlite_backup_age=60,
            postgres_backup_age=60,
            previous_ingest_errors=0,
            software_inventory_health={
                "enabled": True,
                "available": True,
                "records": 1478,
                "updated_at": "2026-08-06T09:59:59Z",
            },
        )

        self.assertIn("Software Inventory snapshot is stale", failures[0])
        self.assertEqual(
            snapshot["signals"]["software_inventory_record_count"],
            1478,
        )


    def test_expired_osquery_source_fails_even_when_snapshot_is_fresh(self):
        now = dt.datetime(2026, 8, 6, 13, tzinfo=dt.timezone.utc)
        failures, snapshot = self.slo.evaluate(
            {"metrics": {"process": {"ingest_errors": 0}}},
            {"summary": {"latest": {"timestamp_utc": "2026-08-06T12:59:30Z"}}},
            now=now,
            disk_used_percent=55,
            sqlite_backup_age=60,
            postgres_backup_age=60,
            previous_ingest_errors=0,
            software_inventory_health={
                "enabled": True,
                "available": True,
                "records": 1486,
                "updated_at": "2026-08-06T12:59:00Z",
                "source_statuses": {
                    "osquery_apps": {
                        "status": "ok",
                        "freshness": "expired",
                        "returned": 1106,
                    },
                    "zeek_software": {
                        "status": "ok",
                        "freshness": "fresh",
                        "returned": 203,
                    },
                },
            },
        )

        self.assertIn(
            "Software Inventory OSQuery endpoint evidence is expired",
            failures,
        )
        self.assertEqual(
            snapshot["signals"]["software_inventory_source_statuses"]
            ["osquery_apps"]["freshness"],
            "expired",
        )


    def test_empty_osquery_source_is_an_advisory(self):
        now = dt.datetime(2026, 8, 6, 13, tzinfo=dt.timezone.utc)
        failures, snapshot = self.slo.evaluate(
            {"metrics": {"process": {"ingest_errors": 0}}},
            {"summary": {"latest": {"timestamp_utc": "2026-08-06T12:59:30Z"}}},
            now=now,
            disk_used_percent=55,
            sqlite_backup_age=60,
            postgres_backup_age=60,
            previous_ingest_errors=0,
            software_inventory_health={
                "enabled": True,
                "available": True,
                "records": 300,
                "updated_at": "2026-08-06T12:59:00Z",
                "source_statuses": {
                    "osquery_apps": {
                        "status": "ok",
                        "freshness": "empty",
                        "returned": 0,
                    },
                },
            },
        )

        self.assertEqual(failures, [])
        self.assertIn(
            "Software Inventory has no OSQuery endpoint evidence",
            snapshot["advisories"],
        )


    def test_inactive_capture_protection_does_not_hide_stale_backlog(self):
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
                "capture_protection": {
                    "active": False,
                    "state": "capture_protection_hold",
                    "report_age_seconds": 600,
                },
            },
        }

        failures, snapshot = self.slo.evaluate(
            metrics, health, now=now, disk_used_percent=55,
            sqlite_backup_age=60, postgres_backup_age=60, previous_ingest_errors=0,
        )

        self.assertIn("PCAP backlog exceeds 60 minutes", failures)
        self.assertEqual(snapshot["status"], "failed")


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
