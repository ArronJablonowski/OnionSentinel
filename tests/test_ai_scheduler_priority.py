#!/usr/bin/env python3
"""Regression checks for local AI alert scheduler queue ordering."""
from __future__ import annotations

import importlib.util
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEDULER_PATH = REPO_ROOT / "n8n" / "bin" / "auto-run-ai-analysis.py"


def load_scheduler():
    spec = importlib.util.spec_from_file_location("auto_run_ai_analysis", SCHEDULER_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class AiSchedulerPriorityTest(unittest.TestCase):
    def setUp(self) -> None:
        self.scheduler = load_scheduler()
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.execute(
            """
            CREATE TABLE alerts (
                alert_id TEXT PRIMARY KEY,
                first_seen TEXT,
                last_seen TEXT,
                timestamp TEXT,
                rule_name TEXT,
                source_ip TEXT,
                destination_ip TEXT,
                triage_level TEXT,
                triage_score INTEGER,
                filter_status TEXT,
                routing TEXT,
                suppression_key TEXT
            )
            """
        )
        self.conn.execute(
            """
            CREATE TABLE alert_group_summary (
                group_id TEXT PRIMARY KEY
            )
            """
        )
        self.conn.execute(
            """
            CREATE TABLE alert_group_alias (
                legacy_group_id TEXT PRIMARY KEY,
                stable_group_id TEXT NOT NULL
            )
            """
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            self.args = SimpleNamespace(
                levels="critical,high,medium,low,informational",
                hours=87600,
                include_tests=True,
                analysis_dir=Path(tmpdir),
            )

    def tearDown(self) -> None:
        self.conn.close()

    def insert_alert(
        self,
        alert_id: str,
        severity: str,
        last_seen: str,
        score: int = 80,
        rule_name: str | None = None,
        source_ip: str | None = None,
        destination_ip: str | None = None,
    ) -> None:
        self.conn.execute(
            """
            INSERT INTO alerts (
                alert_id, first_seen, last_seen, timestamp, rule_name, source_ip,
                destination_ip, triage_level, triage_score, filter_status, routing,
                suppression_key
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'accepted', 'analyst-review', NULL)
            """,
            (
                alert_id,
                last_seen,
                last_seen,
                last_seen,
                rule_name or f"{severity} test detection {alert_id}",
                source_ip or f"192.0.2.{len(alert_id)}",
                destination_ip or f"198.51.100.{len(alert_id)}",
                severity,
                score,
            ),
        )

    def test_drains_each_severity_newest_first_before_lower_severity(self) -> None:
        self.insert_alert("medium-newest", "medium", "2026-07-03  00:50:00Z", 90)
        self.insert_alert("high-newer-than-critical", "high", "2026-07-03  00:55:00Z", 90)
        self.insert_alert("critical-old", "critical", "2026-07-03  00:10:00Z", 70)
        self.insert_alert("critical-new", "critical", "2026-07-03  00:20:00Z", 60)
        self.insert_alert("low-newest", "low", "2026-07-03  01:00:00Z", 100)
        self.conn.commit()

        selected_groups: set[str] = set()
        selected_ids: list[str] = []
        for _ in range(5):
            selected = self.scheduler.select_next_alert(self.conn, self.args, set(), selected_groups)
            self.assertIsNotNone(selected)
            selected_ids.append(selected["alert_id"])
            selected_groups.add(self.scheduler.alert_group_key(selected))

        self.assertEqual(
            selected_ids,
            [
                "critical-new",
                "critical-old",
                "high-newer-than-critical",
                "medium-newest",
                "low-newest",
            ],
        )

    def test_orphaned_pending_jobs_are_reconciled_without_touching_active_groups(self) -> None:
        self.insert_alert(
            "active-alert",
            "high",
            "2026-07-03  01:00:00Z",
            rule_name="Active detection",
            source_ip="192.0.2.10",
            destination_ip="198.51.100.10",
        )
        active_row = self.conn.execute("SELECT * FROM alerts WHERE alert_id = 'active-alert'").fetchone()
        active_id = self.scheduler.alert_group_id(self.scheduler.alert_group_key(active_row))
        self.conn.execute("INSERT INTO alert_group_summary (group_id) VALUES (?)", (active_id,))
        self.conn.execute(
            """
            CREATE TABLE durable_jobs (
                job_type TEXT NOT NULL,
                dedupe_key TEXT NOT NULL,
                status TEXT NOT NULL
            )
            """
        )
        self.conn.executemany(
            "INSERT INTO durable_jobs (job_type, dedupe_key, status) VALUES ('ai_analysis', ?, 'pending')",
            [(active_id,), ("orphaned-group-id",)],
        )
        self.conn.commit()

        orphaned = self.scheduler.orphaned_pending_ai_job_ids(self.conn)

        self.assertEqual(orphaned, {"orphaned-group-id"})

    def test_stable_queue_identity_remains_active_through_legacy_alias(self) -> None:
        self.conn.execute("INSERT INTO alert_group_summary (group_id) VALUES ('legacy-group')")
        self.conn.execute(
            "INSERT INTO alert_group_alias (legacy_group_id, stable_group_id) VALUES (?, ?)",
            ("legacy-group", "stable-group"),
        )
        self.conn.execute(
            """
            CREATE TABLE durable_jobs (
                job_type TEXT NOT NULL,
                dedupe_key TEXT NOT NULL,
                status TEXT NOT NULL
            )
            """
        )
        self.conn.executemany(
            "INSERT INTO durable_jobs (job_type, dedupe_key, status) VALUES ('ai_analysis', ?, 'pending')",
            [("stable-group",), ("orphaned-group",)],
        )
        self.conn.commit()

        orphaned = self.scheduler.orphaned_pending_ai_job_ids(self.conn)

        self.assertEqual(orphaned, {"orphaned-group"})

    def test_selected_alert_preserves_stable_queue_identity(self) -> None:
        self.conn.execute("ALTER TABLE alerts ADD COLUMN stable_group_id TEXT")
        self.insert_alert(
            "stable-alert",
            "high",
            "2026-07-03  01:00:00Z",
            rule_name="Stable identity detection",
        )
        self.conn.execute(
            "UPDATE alerts SET stable_group_id = ? WHERE alert_id = ?",
            ("stable-v2-group", "stable-alert"),
        )
        self.conn.commit()

        selected = self.scheduler.select_next_alert(self.conn, self.args, set(), set())

        self.assertIsNotNone(selected)
        self.assertEqual(selected["stable_group_id"], "stable-v2-group")

    def test_pending_durable_intent_forces_reanalysis_of_current_artifact(self) -> None:
        self.insert_alert(
            "durable-rerun-alert",
            "high",
            "2026-07-03  01:00:00Z",
            rule_name="Durable rerun detection",
            source_ip="192.0.2.20",
            destination_ip="198.51.100.20",
        )
        row = self.conn.execute("SELECT * FROM alerts WHERE alert_id = ?", ("durable-rerun-alert",)).fetchone()
        group_id = self.scheduler.alert_group_id(self.scheduler.alert_group_key(row))
        self.conn.execute(
            """
            CREATE TABLE durable_jobs (
                job_type TEXT NOT NULL,
                dedupe_key TEXT NOT NULL,
                status TEXT NOT NULL,
                processing_started_at TEXT,
                rerun_requested INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        self.conn.execute(
            "INSERT INTO durable_jobs (job_type, dedupe_key, status) VALUES ('ai_analysis', ?, 'pending')",
            (group_id,),
        )
        self.conn.commit()
        with tempfile.TemporaryDirectory() as tmpdir:
            analysis_dir = Path(tmpdir)
            (analysis_dir / "current-local-ai-analysis.json").write_text(
                json.dumps({"alert_id": "durable-rerun-alert"}),
                encoding="utf-8",
            )
            self.args.analysis_dir = analysis_dir
            analyzed = self.scheduler.analyzed_alert_ids(analysis_dir)
            selected = self.scheduler.select_next_alert(self.conn, self.args, analyzed, set())

        self.assertIsNotNone(selected)
        self.assertEqual(selected["alert_id"], "durable-rerun-alert")

    def test_artifact_reconciliation_does_not_erase_fresh_pending_intent(self) -> None:
        self.conn.execute(
            """
            CREATE TABLE durable_jobs (
                job_type TEXT NOT NULL,
                dedupe_key TEXT NOT NULL,
                status TEXT NOT NULL,
                processing_started_at TEXT,
                rerun_requested INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        self.conn.executemany(
            """
            INSERT INTO durable_jobs (
                job_type, dedupe_key, status, processing_started_at, rerun_requested
            ) VALUES ('ai_analysis', ?, 'pending', ?, ?)
            """,
            [
                ("fresh-evidence", None, 0),
                ("missed-completion-callback", "2026-07-03  00:00:00Z", 0),
                ("latched-rerun", "2026-07-03  00:00:00Z", 1),
            ],
        )
        self.conn.commit()

        reconciled = self.scheduler.reconcilable_completed_ai_job_ids(
            self.conn,
            {"fresh-evidence", "missed-completion-callback", "latched-rerun"},
        )

        self.assertEqual(reconciled, {"missed-completion-callback"})

    def test_duplicate_groups_use_newest_representative_before_next_group(self) -> None:
        for alert_id, last_seen in (
            ("critical-dup-old", "2026-07-03  00:10:00Z"),
            ("critical-dup-new", "2026-07-03  00:30:00Z"),
        ):
            self.insert_alert(
                alert_id,
                "critical",
                last_seen,
                rule_name="same critical duplicate group",
                source_ip="192.0.2.44",
                destination_ip="198.51.100.44",
            )
        self.insert_alert("critical-other", "critical", "2026-07-03  00:20:00Z")
        self.insert_alert("high-newer", "high", "2026-07-03  01:00:00Z")
        self.conn.commit()

        selected_groups: set[str] = set()
        first = self.scheduler.select_next_alert(self.conn, self.args, set(), selected_groups)
        self.assertIsNotNone(first)
        selected_groups.add(first["queue_group_key"])
        second = self.scheduler.select_next_alert(self.conn, self.args, set(), selected_groups)
        self.assertIsNotNone(second)

        self.assertEqual(first["alert_id"], "critical-dup-new")
        self.assertEqual(second["alert_id"], "critical-other")

    def test_newer_pcap_evidence_marks_existing_ai_analysis_stale(self) -> None:
        self.insert_alert("medium-with-pcap", "medium", "2026-07-03  00:50:00Z", 90)
        self.conn.commit()
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            analysis_dir = root / "ai-analysis"
            pcap_dir = root / "pcap-analysis"
            analysis_dir.mkdir()
            pcap_dir.mkdir()
            ai_path = analysis_dir / "old-local-ai-analysis.json"
            pcap_path = pcap_dir / "new-pcap-analysis.json"
            ai_path.write_text(json.dumps({"alert_id": "medium-with-pcap"}), encoding="utf-8")
            pcap_path.write_text(
                json.dumps({"request": {"alert_id": "medium-with-pcap"}}),
                encoding="utf-8",
            )
            os.utime(ai_path, (100, 100))
            os.utime(pcap_path, (200, 200))

            analyzed = self.scheduler.analyzed_alert_ids(analysis_dir, pcap_dir)
            selected = self.scheduler.select_next_alert(self.conn, self.args, analyzed, set())

        self.assertNotIn("medium-with-pcap", analyzed)
        self.assertIsNotNone(selected)
        self.assertEqual(selected["alert_id"], "medium-with-pcap")

    def test_newer_group_pcap_evidence_marks_duplicate_group_ai_stale(self) -> None:
        for alert_id, last_seen in (
            ("medium-dup-old", "2026-07-03  00:40:00Z"),
            ("medium-dup-new", "2026-07-03  00:50:00Z"),
        ):
            self.insert_alert(
                alert_id,
                "medium",
                last_seen,
                rule_name="same medium duplicate group",
                source_ip="192.0.2.55",
                destination_ip="198.51.100.55",
            )
        self.conn.commit()
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            analysis_dir = root / "ai-analysis"
            pcap_dir = root / "pcap-analysis"
            analysis_dir.mkdir()
            pcap_dir.mkdir()
            ai_path = analysis_dir / "old-member-local-ai-analysis.json"
            pcap_path = pcap_dir / "new-group-pcap-analysis.json"
            ai_path.write_text(json.dumps({"alert_id": "medium-dup-old"}), encoding="utf-8")
            newest = self.conn.execute("SELECT * FROM alerts WHERE alert_id = ?", ("medium-dup-new",)).fetchone()
            group_id = self.scheduler.alert_group_id(self.scheduler.alert_group_key(newest))
            pcap_path.write_text(
                json.dumps({"request": {"alert_id": "medium-dup-new", "group_id": group_id}}),
                encoding="utf-8",
            )
            os.utime(ai_path, (100, 100))
            os.utime(pcap_path, (200, 200))
            self.args.analysis_dir = analysis_dir
            self.args.pcap_analysis_dir = pcap_dir

            analyzed = self.scheduler.analyzed_alert_ids(analysis_dir, pcap_dir)
            selected = self.scheduler.select_next_alert(self.conn, self.args, analyzed, set())

        self.assertIn("medium-dup-old", analyzed)
        self.assertIsNotNone(selected)
        self.assertEqual(selected["alert_id"], "medium-dup-new")

    def test_newer_group_prompt_marks_duplicate_group_ai_stale(self) -> None:
        for alert_id, last_seen in (
            ("medium-manual-old", "2026-07-03  00:40:00Z"),
            ("medium-manual-new", "2026-07-03  00:50:00Z"),
        ):
            self.insert_alert(
                alert_id,
                "medium",
                last_seen,
                rule_name="same manually requeued duplicate group",
                source_ip="192.0.2.66",
                destination_ip="198.51.100.66",
            )
        self.conn.commit()
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            analysis_dir = root / "ai-analysis"
            prompt_dir = root / "ai-prompts"
            analysis_dir.mkdir()
            prompt_dir.mkdir()
            ai_path = analysis_dir / "old-member-local-ai-analysis.json"
            prompt_path = prompt_dir / "new-group-ai-prompt.json"
            ai_path.write_text(json.dumps({"alert_id": "medium-manual-old"}), encoding="utf-8")
            prompt_path.write_text(
                json.dumps(
                    {
                        "alert": {
                            "alert_id": "medium-manual-new",
                            "triage_level": "medium",
                            "rule_name": "same manually requeued duplicate group",
                            "source_ip": "192.0.2.66",
                            "destination_ip": "198.51.100.66",
                            "filter_status": "accepted",
                        }
                    }
                ),
                encoding="utf-8",
            )
            os.utime(ai_path, (100, 100))
            os.utime(prompt_path, (200, 200))
            self.args.analysis_dir = analysis_dir
            self.args.prompt_dir = prompt_dir

            analyzed = self.scheduler.analyzed_alert_ids(analysis_dir, prompt_dir=prompt_dir)
            selected = self.scheduler.select_next_alert(self.conn, self.args, analyzed, set())

        self.assertIn("medium-manual-old", analyzed)
        self.assertIsNotNone(selected)
        self.assertEqual(selected["alert_id"], "medium-manual-new")

    def test_manual_prompt_can_select_duplicate_status_representative(self) -> None:
        self.insert_alert(
            "medium-duplicate-manual",
            "medium",
            "2026-07-03  00:50:00Z",
            rule_name="manually requeued duplicate representative",
            source_ip="192.0.2.77",
            destination_ip="198.51.100.77",
        )
        self.conn.execute(
            "UPDATE alerts SET filter_status = 'duplicate' WHERE alert_id = ?",
            ("medium-duplicate-manual",),
        )
        self.conn.commit()
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            analysis_dir = root / "ai-analysis"
            prompt_dir = root / "ai-prompts"
            analysis_dir.mkdir()
            prompt_dir.mkdir()
            prompt_path = prompt_dir / "manual-duplicate-ai-prompt.json"
            prompt_path.write_text(
                json.dumps(
                    {
                        "alert": {
                            "alert_id": "medium-duplicate-manual",
                            "triage_level": "medium",
                            "rule_name": "manually requeued duplicate representative",
                            "source_ip": "192.0.2.77",
                            "destination_ip": "198.51.100.77",
                            "filter_status": "duplicate",
                        }
                    }
                ),
                encoding="utf-8",
            )
            os.utime(prompt_path, (200, 200))
            self.args.analysis_dir = analysis_dir
            self.args.prompt_dir = prompt_dir

            selected = self.scheduler.select_next_alert(self.conn, self.args, set(), set())

        self.assertIsNotNone(selected)
        self.assertEqual(selected["alert_id"], "medium-duplicate-manual")

    def test_manual_prompt_overrides_automatic_queue_filters(self) -> None:
        self.insert_alert(
            "manual-any-state-alert",
            "low",
            "2020-01-01  00:00:00Z",
            rule_name="manually queued regardless of state",
            source_ip="192.0.2.88",
            destination_ip="198.51.100.88",
        )
        self.conn.execute(
            "UPDATE alerts SET filter_status = 'suppressed' WHERE alert_id = ?",
            ("manual-any-state-alert",),
        )
        self.conn.commit()
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            analysis_dir = root / "ai-analysis"
            prompt_dir = root / "ai-prompts"
            analysis_dir.mkdir()
            prompt_dir.mkdir()
            prompt_path = prompt_dir / "manual-any-state-ai-prompt.json"
            prompt_path.write_text(
                json.dumps(
                    {
                        "alert": {
                            "alert_id": "manual-any-state-alert",
                            "triage_level": "low",
                            "rule_name": "manually queued regardless of state",
                            "source_ip": "192.0.2.88",
                            "destination_ip": "198.51.100.88",
                            "filter_status": "suppressed",
                        }
                    }
                ),
                encoding="utf-8",
            )
            os.utime(prompt_path, (200, 200))
            self.args.analysis_dir = analysis_dir
            self.args.prompt_dir = prompt_dir
            self.args.hours = 1
            self.args.levels = "critical"

            selected = self.scheduler.select_next_alert(self.conn, self.args, set(), set())

        self.assertIsNotNone(selected)
        self.assertEqual(selected["alert_id"], "manual-any-state-alert")

    def test_manual_prompt_is_selected_before_automatic_backlog(self) -> None:
        self.insert_alert("automatic-critical-backlog", "critical", "2026-07-03  00:50:00Z", 90)
        self.insert_alert(
            "manual-low-skipped-alert",
            "low",
            "2026-07-03  00:40:00Z",
            rule_name="manual skipped detection",
            source_ip="192.0.2.89",
            destination_ip="198.51.100.89",
        )
        self.conn.execute(
            "UPDATE alerts SET filter_status = 'duplicate' WHERE alert_id = ?",
            ("manual-low-skipped-alert",),
        )
        self.conn.commit()
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            analysis_dir = root / "ai-analysis"
            prompt_dir = root / "ai-prompts"
            analysis_dir.mkdir()
            prompt_dir.mkdir()
            prompt_path = prompt_dir / "manual-low-skipped-ai-prompt.json"
            prompt_path.write_text(
                json.dumps(
                    {
                        "alert": {
                            "alert_id": "manual-low-skipped-alert",
                            "triage_level": "low",
                            "rule_name": "manual skipped detection",
                            "source_ip": "192.0.2.89",
                            "destination_ip": "198.51.100.89",
                            "filter_status": "duplicate",
                        }
                    }
                ),
                encoding="utf-8",
            )
            os.utime(prompt_path, (200, 200))
            self.args.analysis_dir = analysis_dir
            self.args.prompt_dir = prompt_dir

            selected = self.scheduler.select_next_alert(self.conn, self.args, set(), set())

        self.assertIsNotNone(selected)
        self.assertEqual(selected["alert_id"], "manual-low-skipped-alert")

    def test_newer_group_pcap_evidence_rebuilds_stale_prompt_package(self) -> None:
        self.insert_alert("medium-with-stale-prompt", "medium", "2026-07-03  00:50:00Z", 90)
        self.conn.commit()
        selected = self.scheduler.select_next_alert(self.conn, self.args, set(), set())
        self.assertIsNotNone(selected)
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            prompt_dir = root / "ai-prompts"
            pcap_dir = root / "pcap-analysis"
            prompt_dir.mkdir()
            pcap_dir.mkdir()
            prompt_path = prompt_dir / "old-ai-prompt.json"
            pcap_path = pcap_dir / "new-pcap-analysis.json"
            prompt_path.write_text(
                json.dumps({"alert": {"alert_id": "medium-with-stale-prompt"}}),
                encoding="utf-8",
            )
            group_id = self.scheduler.alert_group_id(selected["queue_group_key"])
            pcap_path.write_text(
                json.dumps({"request": {"alert_id": "medium-with-stale-prompt", "group_id": group_id}}),
                encoding="utf-8",
            )
            os.utime(prompt_path, (100, 100))
            os.utime(pcap_path, (200, 200))

            reusable = self.scheduler.reusable_prompt_for_alert(prompt_dir, selected, pcap_dir)

        self.assertIsNone(reusable)

    def test_completed_analysis_group_ids_prefers_stable_group_id(self) -> None:
        self.conn.execute("ALTER TABLE alerts ADD COLUMN stable_group_id TEXT")
        self.insert_alert(
            "analyzed-stable-group",
            "medium",
            "2026-07-03  00:50:00Z",
            rule_name="stable analyzed group",
        )
        self.conn.execute(
            "UPDATE alerts SET stable_group_id = ? WHERE alert_id = ?",
            ("stable-group-id", "analyzed-stable-group"),
        )
        self.conn.commit()
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            analysis_dir = root / "ai-analysis"
            pcap_dir = root / "pcap-analysis"
            prompt_dir = root / "ai-prompts"
            analysis_dir.mkdir()
            pcap_dir.mkdir()
            prompt_dir.mkdir()
            (analysis_dir / "current-local-ai-analysis.json").write_text(
                json.dumps({"alert_id": "analyzed-stable-group"}),
                encoding="utf-8",
            )
            analyzed = self.scheduler.analyzed_alert_ids(analysis_dir, pcap_dir, prompt_dir)
            group_ids = self.scheduler.completed_analysis_group_ids(
                self.conn,
                analyzed,
                analysis_dir,
                pcap_dir,
                prompt_dir,
            )

        self.assertEqual(group_ids, {"stable-group-id"})


if __name__ == "__main__":
    unittest.main()
