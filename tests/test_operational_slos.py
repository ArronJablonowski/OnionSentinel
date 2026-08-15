import datetime as dt
from contextlib import closing
import importlib.util
import io
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


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
        installer = (
            ROOT / "n8n/bin/install-macstudio-stack.zsh"
        ).read_text(encoding="utf-8")
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


if __name__ == "__main__":
    unittest.main()
