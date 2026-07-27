#!/usr/bin/env python3
"""Regression checks for local AI alert scheduler queue ordering."""
from __future__ import annotations

import importlib.util
import io
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


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
        self.tempdir = tempfile.TemporaryDirectory()
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
        self.args = SimpleNamespace(
            levels="critical,high,medium,low,informational",
            hours=87600,
            include_tests=True,
            analysis_dir=Path(self.tempdir.name),
            provider_lane="any",
            ai_settings_file=Path(self.tempdir.name) / "ai_model_settings.json",
        )

    def tearDown(self) -> None:
        self.conn.close()
        self.tempdir.cleanup()

    def test_deterministic_context_and_prompt_size_failures_are_not_retried(self) -> None:
        for detail in (
            "Codex CLI analysis failed: model context window exhausted",
            "prompt package remains above 1048576 bytes after deterministic compaction",
            "command stderr exceeded the 1048576-byte limit",
            "Codex CLI analysis failed: provider authentication failed",
            "Codex CLI analysis failed: configured model is unavailable or unauthorized",
            "incident reanalysis claim did not return its server-authoritative job identity",
            "incident reanalysis lease identity did not match its server-bound attempt",
        ):
            self.assertFalse(self.scheduler.ai_failure_is_retryable(detail))

        for detail in (
            "prompt builder failed rc=1",
            "Codex CLI analysis failed: provider rate or usage limit reached",
            "Codex CLI analysis failed: provider connection closed unexpectedly",
        ):
            self.assertTrue(self.scheduler.ai_failure_is_retryable(detail))

    def test_failure_status_contract_marks_deterministic_failure_non_retryable(self) -> None:
        response = io.BytesIO(b'{"ok":true}')
        response.status = 200
        with mock.patch.object(
            self.scheduler.urllib.request,
            "urlopen",
            return_value=response,
        ) as urlopen:
            reported = self.scheduler.report_ai_job_status(
                "http://127.0.0.1:8787",
                "stable-group",
                "failed",
                "model context window exhausted",
                "lease-token",
                job_type="incident_response_analysis",
                retryable=False,
            )

        self.assertTrue(reported)
        request = urlopen.call_args.args[0]
        payload = json.loads(request.data.decode("utf-8"))
        self.assertIs(payload["retryable"], False)
        self.assertEqual(payload["error"], "model context window exhausted")

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

    def enable_indexed_scheduler(self) -> None:
        self.conn.execute("ALTER TABLE alerts ADD COLUMN stable_group_id TEXT")
        self.conn.execute("ALTER TABLE alerts ADD COLUMN stable_group_key TEXT")
        self.conn.execute(
            """
            CREATE TABLE durable_jobs (
                id INTEGER PRIMARY KEY,
                job_type TEXT NOT NULL,
                dedupe_key TEXT NOT NULL,
                status TEXT NOT NULL,
                payload_json TEXT NOT NULL DEFAULT '{}',
                priority INTEGER NOT NULL DEFAULT 0,
                attempt_count INTEGER NOT NULL DEFAULT 0,
                max_attempts INTEGER NOT NULL DEFAULT 8,
                next_attempt_at TEXT NOT NULL,
                processing_started_at TEXT,
                rerun_requested INTEGER NOT NULL DEFAULT 0,
                requested_at TEXT NOT NULL
            )
            """
        )
        self.conn.execute(
            """
            CREATE TABLE ai_analysis_runs (
                id INTEGER PRIMARY KEY,
                group_id TEXT NOT NULL,
                alert_id TEXT,
                generated_at TEXT NOT NULL
            )
            """
        )

    def set_stable_group(self, alert_id: str, group_id: str) -> None:
        self.conn.execute(
            "UPDATE alerts SET stable_group_id = ?, stable_group_key = ? WHERE alert_id = ?",
            (group_id, f"key:{group_id}", alert_id),
        )

    def insert_indexed_job(
        self,
        group_id: str,
        *,
        payload: dict | None = None,
        job_type: str = "ai_analysis",
        status: str = "pending",
        next_attempt_at: str = "2020-01-01  00:00:00Z",
        processing_started_at: str | None = None,
        rerun_requested: int = 0,
    ) -> None:
        self.conn.execute(
            """
            INSERT INTO durable_jobs (
                job_type, dedupe_key, status, payload_json, priority,
                attempt_count, max_attempts, next_attempt_at,
                processing_started_at, rerun_requested, requested_at
            ) VALUES (?, ?, ?, ?, 0, 0, 8, ?, ?, ?, ?)
            """,
            (
                job_type,
                group_id,
                status,
                json.dumps(payload or {}),
                next_attempt_at,
                processing_started_at,
                rerun_requested,
                next_attempt_at,
            ),
        )

    def run_indexed_worker_once(
        self,
        *,
        severity: str,
        payload: dict | None = None,
        claimed_payload: dict | None = None,
        job_type: str = "ai_analysis",
        analysis_threshold: str = "medium",
    ) -> dict[str, object]:
        """Run one indexed job through main() with inference boundaries mocked."""
        self.enable_indexed_scheduler()
        alert_id = f"{job_type}-{severity}-threshold-alert"
        group_id = f"{job_type}-{severity}-threshold-group"
        self.insert_alert(alert_id, severity, "2026-07-24  12:00:00Z", 80)
        self.set_stable_group(alert_id, group_id)
        self.insert_indexed_job(
            group_id,
            payload=payload,
            job_type=job_type,
        )
        self.conn.commit()

        root = Path(self.tempdir.name)
        db_path = root / "alerts.sqlite3"
        disk_conn = sqlite3.connect(db_path)
        try:
            self.conn.backup(disk_conn)
        finally:
            disk_conn.close()

        settings_path = root / "ai_model_settings.json"
        settings_path.write_text(
            json.dumps(
                {
                    "soc_analyst_analysis_min_severity": analysis_threshold,
                }
            ),
            encoding="utf-8",
        )
        args = SimpleNamespace(
            db=db_path,
            prompt_dir=root / "prompts",
            analysis_dir=root / "analysis",
            pcap_analysis_dir=root / "pcap-analysis",
            incident_evidence_dir=root / "incident-evidence",
            incident_evidence_config=root / "incident-evidence.json",
            ai_settings_file=settings_path,
            provider_lane="any",
            lock_file=root / "worker.lock",
            wake_file=root / "worker.wake",
            levels="critical,high,medium,low,informational",
            hours=87600,
            max_per_run=1,
            related_limit=8,
            correlation_limit=8,
            correlation_min_score=15,
            model=None,
            timeout=30,
            max_prompt_bytes=1024 * 1024,
            portal_wake_file=root / "portal.wake",
            no_portal_refresh=True,
            alert_store_url="http://127.0.0.1:8787",
            include_tests=True,
            dry_run=False,
        )

        def status_transition(
            _base_url: str,
            _group_id: str,
            status: str,
            _error: str = "",
            _lease_token: str = "",
            *,
            lease_token: str = "",
            job_type: str = "ai_analysis",
        ) -> bool | str:
            del lease_token
            if status != "processing":
                return True
            authoritative_payload = dict(
                claimed_payload if claimed_payload is not None else (payload or {})
            )
            authoritative_payload.setdefault("alert_id", alert_id)
            authoritative_payload.setdefault("group_id", group_id)
            return self.scheduler.ClaimedAiLease(
                "threshold-test-lease",
                job_payload=authoritative_payload,
                resolved_key=group_id,
                reanalysis_attempt_id=(
                    self.scheduler.job_reanalysis_attempt_id(
                        authoritative_payload,
                        "threshold-test-lease",
                    )
                    if job_type == "incident_response_analysis"
                    else ""
                ),
            )

        prompt_path = root / "prompt.json"
        incident_evidence_path = root / "incident-evidence.json"
        completed_process = SimpleNamespace(returncode=0, stdout="", stderr="")
        with (
            mock.patch.object(self.scheduler, "parse_args", return_value=args),
            mock.patch.object(self.scheduler, "require_runtime_capacity"),
            mock.patch.object(self.scheduler, "consume_wake_marker"),
            mock.patch.object(self.scheduler, "flush_deferred_analysis_results"),
            mock.patch.object(self.scheduler, "reconcile_worker_state", return_value=0),
            mock.patch.object(
                self.scheduler,
                "report_ai_job_status",
                side_effect=status_transition,
            ) as report_status,
            mock.patch.object(
                self.scheduler,
                "collect_incident_evidence",
                return_value=incident_evidence_path,
            ) as collect_incident_evidence,
            mock.patch.object(
                self.scheduler,
                "build_prompt",
                return_value=prompt_path,
            ) as build_prompt,
            mock.patch.object(
                self.scheduler,
                "run_analysis",
                return_value=completed_process,
            ) as run_analysis,
            mock.patch.object(self.scheduler, "signal_dashboard_refresh"),
        ):
            return_code = self.scheduler.main()

        return {
            "return_code": return_code,
            "report_status": report_status,
            "collect_incident_evidence": collect_incident_evidence,
            "build_prompt": build_prompt,
            "run_analysis": run_analysis,
            "group_id": group_id,
        }

    def test_missing_analysis_threshold_preserves_all_severity_behavior(self) -> None:
        self.args.ai_settings_file.write_text(
            json.dumps({"soc_analyst_pcap_min_severity": "medium"}),
            encoding="utf-8",
        )

        levels = self.scheduler.configured_analysis_levels(
            self.args.ai_settings_file,
            self.args.levels,
        )

        self.assertEqual(
            levels,
            ["critical", "high", "medium", "low", "informational"],
        )

    def test_analysis_watchdog_allows_bounded_multi_turn_investigation(self) -> None:
        args = SimpleNamespace(
            analysis_dir=Path(self.tempdir.name),
            timeout=240,
            alert_store_url="http://127.0.0.1:8767",
            ai_settings_file=Path(self.tempdir.name) / "ai_model_settings.json",
            model="",
        )
        completed = SimpleNamespace(returncode=0, stdout="", stderr="")
        with mock.patch.object(
            self.scheduler,
            "run_command",
            return_value=completed,
        ) as run_command:
            result = self.scheduler.run_analysis(
                Path(self.tempdir.name) / "prompt.json",
                args,
            )

        self.assertIs(result, completed)
        self.assertEqual(
            run_command.call_args.kwargs["timeout_seconds"],
            (args.timeout * 5) + 300,
        )

    def test_pending_automatic_low_job_is_retired_without_inference_at_medium(self) -> None:
        result = self.run_indexed_worker_once(severity="low")

        self.assertEqual(result["return_code"], 0)
        result["collect_incident_evidence"].assert_not_called()
        result["build_prompt"].assert_not_called()
        result["run_analysis"].assert_not_called()
        transitions = [
            (
                call.args[2],
                call.kwargs.get("lease_token", ""),
                call.kwargs.get("job_type"),
            )
            for call in result["report_status"].call_args_list
        ]
        self.assertEqual(
            transitions,
            [
                ("processing", "", "ai_analysis"),
                ("completed", "threshold-test-lease", "ai_analysis"),
            ],
        )

    def test_automatic_medium_job_runs_at_medium_threshold(self) -> None:
        result = self.run_indexed_worker_once(severity="medium")

        self.assertEqual(result["return_code"], 0)
        result["build_prompt"].assert_called_once()
        result["run_analysis"].assert_called_once()
        self.assertEqual(
            result["run_analysis"].call_args.kwargs["reanalysis_attempt_id"],
            "",
        )

    def test_manual_analyze_low_job_bypasses_medium_threshold(self) -> None:
        result = self.run_indexed_worker_once(
            severity="low",
            payload={"manual_reanalysis": True},
        )

        self.assertEqual(result["return_code"], 0)
        result["build_prompt"].assert_called_once()
        result["run_analysis"].assert_called_once()

    def test_incident_responder_low_job_bypasses_medium_threshold(self) -> None:
        result = self.run_indexed_worker_once(
            severity="low",
            payload={
                "agent_role": "incident-responder",
                "manual_reanalysis": True,
                "reanalysis_run_id": "irr-11111111-1111-1111-1111-111111111111",
                "case_id": "ir-threshold-test",
            },
            job_type="incident_response_analysis",
        )

        self.assertEqual(result["return_code"], 0)
        result["collect_incident_evidence"].assert_called_once()
        result["build_prompt"].assert_called_once()
        result["run_analysis"].assert_called_once()
        self.assertEqual(
            result["run_analysis"].call_args.kwargs["reanalysis_attempt_id"],
            self.scheduler.incident_reanalysis_attempt_id("threshold-test-lease"),
        )

    def test_normal_incident_escalation_does_not_receive_reanalysis_attempt_id(
        self,
    ) -> None:
        result = self.run_indexed_worker_once(
            severity="low",
            payload={"agent_role": "incident-responder"},
            job_type="incident_response_analysis",
        )

        self.assertEqual(result["return_code"], 0)
        result["run_analysis"].assert_called_once()
        self.assertEqual(
            result["run_analysis"].call_args.kwargs["reanalysis_attempt_id"],
            "",
        )

    def test_legacy_manual_incident_escalation_without_run_id_runs_unbound(
        self,
    ) -> None:
        """Old escalation rows used manual_reanalysis without a run ledger."""
        result = self.run_indexed_worker_once(
            severity="low",
            payload={
                "agent_role": "incident-responder",
                "case_id": "ir-legacy-escalation",
                "manual_reanalysis": True,
            },
            job_type="incident_response_analysis",
        )

        self.assertEqual(result["return_code"], 0)
        result["collect_incident_evidence"].assert_called_once()
        result["build_prompt"].assert_called_once()
        result["run_analysis"].assert_called_once()
        self.assertEqual(
            result["run_analysis"].call_args.kwargs["reanalysis_attempt_id"],
            "",
        )

    def test_incident_worker_uses_claim_identity_when_payload_changes_preclaim(
        self,
    ) -> None:
        selected_payload = {
            "agent_role": "incident-responder",
            "manual_reanalysis": True,
            "reanalysis_run_id": "irr-11111111-1111-1111-1111-111111111111",
            "case_id": "ir-selected-run",
            "alert_id": "selected-alert",
        }
        claimed_payload = {
            "agent_role": "incident-responder",
            "manual_reanalysis": True,
            "reanalysis_run_id": "irr-22222222-2222-2222-2222-222222222222",
            "case_id": "ir-replacement-run",
            "alert_id": "replacement-alert",
        }

        result = self.run_indexed_worker_once(
            severity="critical",
            payload=selected_payload,
            claimed_payload=claimed_payload,
            job_type="incident_response_analysis",
        )

        self.assertEqual(result["return_code"], 0)
        self.assertEqual(
            result["collect_incident_evidence"].call_args.args[0],
            "replacement-alert",
        )
        self.assertEqual(
            result["build_prompt"].call_args.args[0],
            "replacement-alert",
        )
        self.assertEqual(
            result["build_prompt"].call_args.args[2]["reanalysis_run_id"],
            claimed_payload["reanalysis_run_id"],
        )
        self.assertEqual(
            result["run_analysis"].call_args.kwargs["reanalysis_attempt_id"],
            self.scheduler.incident_reanalysis_attempt_id(
                "threshold-test-lease"
            ),
        )

    def test_indexed_provider_lanes_claim_only_assigned_agent_roles(self) -> None:
        self.enable_indexed_scheduler()
        self.insert_alert("soc-alert", "high", "2026-07-19  11:00:00Z", 90)
        self.insert_alert("ir-alert", "high", "2026-07-19  10:00:00Z", 90)
        self.set_stable_group("soc-alert", "soc-group")
        self.set_stable_group("ir-alert", "ir-group")
        self.insert_indexed_job(
            "soc-group",
            payload={"agent_role": "soc-analyst"},
        )
        self.insert_indexed_job(
            "ir-group",
            payload={"agent_role": "incident-responder"},
            job_type="incident_response_analysis",
        )
        self.args.ai_settings_file.write_text(
            json.dumps(
                {
                    "codex_cli_models": [
                        {
                            "model": "gpt-5.6-sol",
                            "reasoning_effort": "high",
                            "enabled": True,
                        }
                    ],
                    "agent_models": {
                        "soc-analyst": "ollama:local-model",
                        "incident-responder": "codex-cli:gpt-5.6-sol:high",
                    }
                }
            ),
            encoding="utf-8",
        )
        self.conn.commit()

        self.args.provider_lane = "cli"
        cli_selected = self.scheduler.select_next_alert_indexed(self.conn, self.args)
        self.args.provider_lane = "ollama"
        ollama_selected = self.scheduler.select_next_alert_indexed(self.conn, self.args)

        self.assertEqual(cli_selected["alert_id"], "ir-alert")
        self.assertEqual(ollama_selected["alert_id"], "soc-alert")

    def test_cli_lane_rejects_malformed_or_disabled_exact_routes(self) -> None:
        settings_path = self.args.ai_settings_file
        for route, roster in (
            (
                "codex-cli:gpt-5.6-sol:ultra",
                [{"model": "gpt-5.6-sol", "reasoning_effort": "high", "enabled": True}],
            ),
            (
                "codex-cli:gpt-5.6-sol:high",
                [{"model": "gpt-5.6-sol", "reasoning_effort": "high", "enabled": False}],
            ),
            (
                "codex-cli:not allowed:high",
                [{"model": "not allowed", "reasoning_effort": "high", "enabled": True}],
            ),
            (
                "codex-cli:gpt-9-unknown:high",
                [{"model": "gpt-9-unknown", "reasoning_effort": "high", "enabled": True}],
            ),
        ):
            with self.subTest(route=route, roster=roster):
                settings_path.write_text(
                    json.dumps(
                        {
                            "codex_cli_models": roster,
                            "agent_models": {"soc-analyst": route},
                        }
                    ),
                    encoding="utf-8",
                )
                self.assertEqual(self.scheduler.cli_agent_roles(settings_path), set())

    def test_cli_lane_includes_enabled_hermes_but_not_openclaw(self) -> None:
        self.args.ai_settings_file.write_text(
            json.dumps(
                {
                    "codex_cli_models": [],
                    "hermes_agent_enabled": True,
                    "hermes_agent_model": "gpt-5.6-sol",
                    "hermes_agent_reasoning_effort": "medium",
                    "openclaw_enabled": True,
                    "openclaw_model": "openai/gpt-5.6-terra",
                    "openclaw_reasoning_effort": "high",
                    "agent_models": {
                        "soc-analyst": "hermes-agent:gpt-5.6-sol:medium",
                        "incident-responder": "openclaw:openai/gpt-5.6-terra:high",
                    },
                }
            ),
            encoding="utf-8",
        )

        self.assertEqual(
            self.scheduler.cli_agent_roles(self.args.ai_settings_file),
            {"soc-analyst"},
        )

    def test_cli_lane_rejects_unsupported_hermes_reasoning_effort(self) -> None:
        self.args.ai_settings_file.write_text(
            json.dumps(
                {
                    "codex_cli_models": [],
                    "hermes_agent_enabled": True,
                    "hermes_agent_model": "gpt-5.6-sol",
                    "hermes_agent_reasoning_effort": "xhigh",
                    "agent_models": {
                        "soc-analyst": "hermes-agent:gpt-5.6-sol:xhigh",
                    },
                }
            ),
            encoding="utf-8",
        )

        self.assertEqual(
            self.scheduler.cli_agent_roles(self.args.ai_settings_file),
            set(),
        )

    def test_local_openclaw_route_stays_out_of_hosted_cli_lane(self) -> None:
        self.args.ai_settings_file.write_text(
            json.dumps(
                {
                    "codex_cli_models": [],
                    "hermes_agent_enabled": False,
                    "openclaw_enabled": True,
                    "openclaw_model": "ollama/gemma4:26b-mlx",
                    "openclaw_reasoning_effort": "medium",
                    "agent_models": {
                        "soc-analyst": "openclaw:ollama/gemma4:26b-mlx:medium",
                    },
                }
            ),
            encoding="utf-8",
        )

        self.assertEqual(
            self.scheduler.cli_agent_roles(self.args.ai_settings_file),
            set(),
        )

    def test_unsupported_openclaw_routes_never_enter_hosted_cli_lane(self) -> None:
        for model in ("local/gpt-oss:20b", "lmstudio/gpt-oss:20b"):
            route = f"openclaw:{model}:medium"
            with self.subTest(model=model):
                self.args.ai_settings_file.write_text(
                    json.dumps(
                        {
                            "codex_cli_models": [],
                            "hermes_agent_enabled": False,
                            "openclaw_enabled": True,
                            "openclaw_model": model,
                            "openclaw_reasoning_effort": "medium",
                            "agent_models": {"soc-analyst": route},
                        }
                    ),
                    encoding="utf-8",
                )

                self.assertEqual(
                    self.scheduler.cli_agent_roles(
                        self.args.ai_settings_file
                    ),
                    set(),
                )

    def test_disabled_harnesses_never_enter_hosted_cli_lane(self) -> None:
        self.args.ai_settings_file.write_text(
            json.dumps(
                {
                    "codex_cli_models": [],
                    "hermes_agent_enabled": False,
                    "hermes_agent_model": "gpt-5.6-sol",
                    "hermes_agent_reasoning_effort": "xhigh",
                    "openclaw_enabled": False,
                    "openclaw_model": "openai/gpt-5.6-terra",
                    "openclaw_reasoning_effort": "high",
                    "agent_models": {
                        "soc-analyst": "hermes-agent:gpt-5.6-sol:xhigh",
                        "incident-responder": "openclaw:openai/gpt-5.6-terra:high",
                    },
                }
            ),
            encoding="utf-8",
        )

        self.assertEqual(
            self.scheduler.cli_agent_roles(self.args.ai_settings_file),
            set(),
        )

    def test_analysis_child_uses_scheduler_settings_and_prompt_limit(self) -> None:
        settings_path = Path(self.tempdir.name) / "custom-ai-settings.json"
        args = SimpleNamespace(
            analysis_dir=Path(self.tempdir.name) / "analysis",
            timeout=600,
            max_prompt_bytes=1024 * 1024,
            alert_store_url="http://127.0.0.1:8787",
            ai_settings_file=settings_path,
            model=None,
        )

        command = self.scheduler.analysis_command(
            Path(self.tempdir.name) / "prompt.json",
            args,
            reanalysis_attempt_id="ira-" + ("a" * 40),
        )

        self.assertEqual(
            command[command.index("--ai-settings-file") + 1],
            str(settings_path),
        )
        self.assertEqual(
            command[command.index("--max-prompt-bytes") + 1],
            str(1024 * 1024),
        )
        self.assertEqual(
            command[command.index("--reanalysis-attempt-id") + 1],
            "ira-" + ("a" * 40),
        )

    def test_indexed_contract_rejects_partial_schema(self) -> None:
        self.conn.execute("ALTER TABLE alerts ADD COLUMN stable_group_id TEXT")
        self.conn.execute("ALTER TABLE alerts ADD COLUMN stable_group_key TEXT")
        self.conn.execute("CREATE TABLE durable_jobs (id INTEGER)")
        self.conn.execute("CREATE TABLE ai_analysis_runs (id INTEGER)")

        self.assertFalse(self.scheduler.indexed_scheduler_available(self.conn))

    def test_indexed_manual_rerun_preempts_backlog_and_prior_analysis(self) -> None:
        self.enable_indexed_scheduler()
        self.insert_alert("manual-low", "low", "2020-01-01  00:00:00Z", 10)
        self.insert_alert("automatic-critical", "critical", "2026-07-19  11:00:00Z", 99)
        self.set_stable_group("manual-low", "manual-group")
        self.set_stable_group("automatic-critical", "critical-group")
        self.conn.execute(
            "UPDATE alerts SET filter_status = 'suppressed' WHERE alert_id = 'manual-low'"
        )
        self.conn.execute(
            "INSERT INTO ai_analysis_runs (group_id, alert_id, generated_at) VALUES (?, ?, ?)",
            ("manual-group", "manual-low", "2026-07-19  10:00:00Z"),
        )
        self.insert_indexed_job("manual-group", payload={"manual_reanalysis": True})
        self.args.hours = 1
        self.args.levels = "critical"
        self.conn.commit()

        selected = self.scheduler.select_next_alert_indexed(self.conn, self.args)

        self.assertIsNotNone(selected)
        self.assertEqual(selected["alert_id"], "manual-low")
        self.assertEqual(selected["request_bucket"], 0)

    def test_indexed_pending_rerun_is_not_hidden_by_prior_selection(self) -> None:
        self.enable_indexed_scheduler()
        self.insert_alert("rerun-alert", "high", "2026-07-19  11:00:00Z", 90)
        self.set_stable_group("rerun-alert", "rerun-group")
        self.insert_indexed_job("rerun-group", payload={"manual_reanalysis": True})
        self.conn.commit()

        selected = self.scheduler.select_next_alert_indexed(
            self.conn,
            self.args,
            {"rerun-group"},
        )

        self.assertIsNotNone(selected)
        self.assertEqual(selected["alert_id"], "rerun-alert")

    def test_indexed_controlled_run_selects_only_exact_stable_group(self) -> None:
        self.enable_indexed_scheduler()
        target_group = "0123456789abcdefabcd"
        other_group = "fedcba9876543210abcd"
        self.insert_alert("target-low", "low", "2026-07-19  10:00:00Z", 10)
        self.insert_alert(
            "other-critical",
            "critical",
            "2026-07-19  11:00:00Z",
            100,
        )
        self.set_stable_group("target-low", target_group)
        self.set_stable_group("other-critical", other_group)
        self.insert_indexed_job(
            target_group,
            payload={"manual_reanalysis": True},
        )
        self.insert_indexed_job(
            other_group,
            payload={"manual_reanalysis": True},
        )
        self.args.only_group_id = target_group
        self.conn.commit()

        selected = self.scheduler.select_next_alert_indexed(self.conn, self.args)

        self.assertIsNotNone(selected)
        self.assertEqual(selected["stable_group_id"], target_group)
        self.assertEqual(selected["alert_id"], "target-low")

    def test_controlled_run_rejects_malformed_stable_group(self) -> None:
        self.enable_indexed_scheduler()
        self.args.only_group_id = "not-a-stable-group"

        with self.assertRaisesRegex(SystemExit, "one exact 20-hex"):
            self.scheduler.select_next_alert_indexed(self.conn, self.args)

    def test_indexed_queue_preserves_severity_and_due_time(self) -> None:
        self.enable_indexed_scheduler()
        self.insert_alert("critical-old", "critical", "2026-07-19  09:00:00Z", 50)
        self.insert_alert("high-new", "high", "2026-07-19  11:00:00Z", 100)
        self.insert_alert("future-manual", "low", "2026-07-19  11:30:00Z", 100)
        for alert_id, group_id in (
            ("critical-old", "critical-group"),
            ("high-new", "high-group"),
            ("future-manual", "future-group"),
        ):
            self.set_stable_group(alert_id, group_id)
        self.insert_indexed_job("critical-group")
        self.insert_indexed_job("high-group")
        self.insert_indexed_job(
            "future-group",
            payload={"manual_reanalysis": True},
            next_attempt_at="2999-01-01  00:00:00Z",
        )
        self.conn.commit()

        first = self.scheduler.select_next_alert_indexed(self.conn, self.args)
        self.conn.execute(
            "UPDATE durable_jobs SET status = 'completed' WHERE dedupe_key = ?",
            ("critical-group",),
        )
        self.conn.commit()
        second = self.scheduler.select_next_alert_indexed(
            self.conn, self.args, {"critical-group"},
        )

        self.assertEqual(first["alert_id"], "critical-old")
        self.assertEqual(second["alert_id"], "high-new")

    def test_indexed_reconciliation_requires_current_run_and_no_rerun(self) -> None:
        self.enable_indexed_scheduler()
        for alert_id, group_id in (
            ("current", "current-group"),
            ("stale", "stale-group"),
            ("rerun", "rerun-group"),
        ):
            self.insert_alert(alert_id, "high", "2026-07-19  11:00:00Z")
            self.set_stable_group(alert_id, group_id)
        self.insert_indexed_job(
            "current-group", processing_started_at="2026-07-19  10:00:00Z",
        )
        self.insert_indexed_job(
            "stale-group", processing_started_at="2026-07-19  10:00:00Z",
        )
        self.insert_indexed_job(
            "rerun-group", processing_started_at="2026-07-19  10:00:00Z", rerun_requested=1,
        )
        self.insert_indexed_job(
            "orphan-group", processing_started_at="2026-07-19  10:00:00Z",
        )
        self.conn.executemany(
            "INSERT INTO ai_analysis_runs (group_id, generated_at) VALUES (?, ?)",
            [
                ("current-group", "2026-07-19  10:01:00Z"),
                ("stale-group", "2026-07-19  09:59:00Z"),
                ("rerun-group", "2026-07-19  10:01:00Z"),
            ],
        )
        self.conn.commit()

        reconciled = self.scheduler.indexed_reconcilable_ai_job_ids(self.conn)

        self.assertEqual(reconciled, {"current-group", "orphan-group"})

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
