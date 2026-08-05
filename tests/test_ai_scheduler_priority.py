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
DEPLOYED_RELEASE = "d" * 40
PRIMARY_ROUTE = "codex-cli:gpt-5.5:high"
REVIEWER_ROUTE = "codex-cli:gpt-5.6-sol:xhigh"
CONTROLLED_ROUTE_FIELDS = {
    "expected_assigned_route": PRIMARY_ROUTE,
    "expected_reviewer_route": REVIEWER_ROUTE,
    "reviewer_required": True,
}


def write_controlled_route_fixture(runtime: Path, home: Path) -> Path:
    """Create a synthetic exact Relay route without live credential material."""
    ssh_dir = home / ".ssh"
    ssh_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    ssh_dir.chmod(0o700)
    ssh_key = ssh_dir / "onion-sentinel-incident-evidence_ed25519"
    known_hosts = runtime / "relay_known_hosts"
    ssh_key.write_text("synthetic-private-key-fixture\n", encoding="utf-8")
    known_hosts.write_text("synthetic-known-host-fixture\n", encoding="utf-8")
    ssh_key.chmod(0o600)
    known_hosts.chmod(0o600)
    route = runtime / "incident-evidence.json"
    route.write_text(
        json.dumps(
            {
                "investigation_query_contract": (
                    "onion-sentinel-investigation-pivots-v2"
                ),
                "host": "10.88.8.8",
                "ssh_user": "aj",
                "ssh_key": str(ssh_key),
                "known_hosts": str(known_hosts),
                "connect_timeout_seconds": 20,
                "timeout_seconds": 420,
                "max_response_bytes": 8 * 1024 * 1024,
                "max_stderr_bytes": 256 * 1024,
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    route.chmod(0o600)
    return route


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
            "InvestigationQueryError: investigation query prompt projection exceeds its cumulative byte budget",
            "command stderr exceeded the 1048576-byte limit",
            "Codex CLI analysis failed: provider authentication failed",
            "Codex CLI analysis failed: configured model is unavailable or unauthorized",
            "incident reanalysis claim did not return its server-authoritative job identity",
            "incident reanalysis lease identity did not match its server-bound attempt",
            "durable AI claim job identity is invalid",
            "durable AI claim group identity is invalid",
            "durable AI claim alert identity is invalid",
            "controlled AI run requires a durable AI job claim",
            "controlled AI run identity arguments are incomplete",
            "controlled AI claim group identity did not match --only-group-id",
            "controlled AI claim alert identity did not match --only-alert-id",
            "controlled AI claim dispatch identity did not match --only-dispatch-id",
            "controlled AI claim release_id did not match the deployed runtime",
        ):
            self.assertFalse(self.scheduler.ai_failure_is_retryable(detail))

        for detail in (
            "prompt builder failed rc=1",
            "durable AI claim did not return its server-authoritative job identity",
            "Codex CLI analysis failed: provider rate or usage limit reached",
            "Codex CLI analysis failed: provider connection closed unexpectedly",
        ):
            self.assertTrue(self.scheduler.ai_failure_is_retryable(detail))

    def test_controlled_run_arguments_require_complete_frozen_identity(self) -> None:
        group_id = "0123456789abcdefabcd"
        alert_id = ".ds-logs-suricata.alerts-so-2026.07.24-000001:alert-1"
        stable_group_key = "v2|frozen-group-key"
        dispatch_id = "a" * 64

        with mock.patch(
            "sys.argv",
            [
                str(SCHEDULER_PATH),
                "--only-group-id",
                group_id,
                "--only-alert-id",
                alert_id,
                "--only-stable-group-key",
                stable_group_key,
                "--only-dispatch-id",
                dispatch_id,
            ],
        ):
            args = self.scheduler.parse_args()

        self.assertEqual(args.only_group_id, group_id)
        self.assertEqual(args.only_alert_id, alert_id)
        self.assertEqual(args.only_stable_group_key, stable_group_key)
        self.assertEqual(args.only_dispatch_id, dispatch_id)

        incomplete = (
            ("--only-group-id", group_id),
            ("--only-alert-id", alert_id),
            ("--only-dispatch-id", dispatch_id),
            (
                "--only-group-id",
                group_id,
                "--only-alert-id",
                alert_id,
            ),
            (
                "--only-group-id",
                group_id,
                "--only-dispatch-id",
                dispatch_id,
            ),
            (
                "--only-alert-id",
                alert_id,
                "--only-dispatch-id",
                dispatch_id,
            ),
        )
        for cli_args in incomplete:
            with self.subTest(cli_args=cli_args), mock.patch(
                "sys.argv",
                [str(SCHEDULER_PATH), *cli_args],
            ), mock.patch("sys.stderr", io.StringIO()):
                with self.assertRaises(SystemExit):
                    self.scheduler.parse_args()

    def test_maintenance_drain_marker_requires_owner_only_regular_file(self) -> None:
        marker = Path(self.tempdir.name) / "maintenance-drain"
        self.assertEqual(
            self.scheduler.maintenance_drain_active(marker),
            (False, ""),
        )

        marker.write_text("operator maintenance\n", encoding="utf-8")
        marker.chmod(0o600)
        active, detail = self.scheduler.maintenance_drain_active(marker)
        self.assertTrue(active)
        self.assertEqual(detail, "maintenance drain requested")

        marker.chmod(0o644)
        active, detail = self.scheduler.maintenance_drain_active(marker)
        self.assertTrue(active)
        self.assertIn("not owner-only", detail)

        marker.unlink()
        marker.mkdir()
        active, detail = self.scheduler.maintenance_drain_active(marker)
        self.assertTrue(active)
        self.assertIn("not a regular file", detail)

    def test_drain_file_cli_override_is_parsed(self) -> None:
        marker = Path(self.tempdir.name) / "custom-maintenance-drain"
        with mock.patch(
            "sys.argv",
            [str(SCHEDULER_PATH), "--drain-file", str(marker)],
        ):
            args = self.scheduler.parse_args()
        self.assertEqual(args.drain_file, marker)

    def test_maintenance_drain_exits_before_controlled_token_or_database(self) -> None:
        marker = Path(self.tempdir.name) / "maintenance-drain"
        marker.write_text("deployment\n", encoding="utf-8")
        marker.chmod(0o600)
        args = SimpleNamespace(drain_file=marker)
        with mock.patch.object(
            self.scheduler,
            "parse_args",
            return_value=args,
        ), mock.patch.object(
            self.scheduler,
            "controlled_evaluation_runtime",
            side_effect=AssertionError("drain must precede controlled token use"),
        ), mock.patch("sys.stdout", io.StringIO()) as stdout:
            self.assertEqual(self.scheduler.main(), 0)
        self.assertIn("no additional AI work will be claimed", stdout.getvalue())

    def test_controlled_run_arguments_reject_unbounded_or_noncanonical_ids(
        self,
    ) -> None:
        group_id = "0123456789abcdefabcd"
        stable_group_key = "v2|frozen-group-key"
        valid_dispatch_id = "a" * 64
        invalid_id_sets = (
            ("alert/with/path", valid_dispatch_id),
            ("a" * 257, valid_dispatch_id),
            ("valid-alert", "A" * 64),
            ("valid-alert", "a" * 63),
        )

        for alert_id, dispatch_id in invalid_id_sets:
            with self.subTest(
                alert_id=alert_id,
                dispatch_id=dispatch_id,
            ), mock.patch(
                "sys.argv",
                [
                    str(SCHEDULER_PATH),
                    "--only-group-id",
                    group_id,
                    "--only-alert-id",
                    alert_id,
                    "--only-stable-group-key",
                    stable_group_key,
                    "--only-dispatch-id",
                    dispatch_id,
                ],
            ), mock.patch("sys.stderr", io.StringIO()):
                with self.assertRaises(SystemExit):
                    self.scheduler.parse_args()

        with mock.patch(
            "sys.argv",
            [
                str(SCHEDULER_PATH),
                "--only-group-id",
                group_id,
                "--only-alert-id",
                "valid-alert",
                "--only-stable-group-key",
                "x" * 2049,
                "--only-dispatch-id",
                valid_dispatch_id,
            ],
        ), mock.patch("sys.stderr", io.StringIO()):
            with self.assertRaises(SystemExit):
                self.scheduler.parse_args()

    def test_controlled_stable_group_key_uses_utf8_bytes_and_rejects_nul(
        self,
    ) -> None:
        group_id = "0123456789abcdefabcd"
        alert_id = "valid-alert"
        dispatch_id = "a" * 64
        exact_multibyte_key = "\u00e9" * 1024
        self.assertEqual(len(exact_multibyte_key.encode("utf-8")), 2048)
        self.assertTrue(
            self.scheduler.valid_controlled_stable_group_key(
                exact_multibyte_key
            )
        )

        with mock.patch(
            "sys.argv",
            [
                str(SCHEDULER_PATH),
                "--only-group-id",
                group_id,
                "--only-alert-id",
                alert_id,
                "--only-stable-group-key",
                exact_multibyte_key,
                "--only-dispatch-id",
                dispatch_id,
            ],
        ):
            args = self.scheduler.parse_args()
        self.assertEqual(args.only_stable_group_key, exact_multibyte_key)

        invalid_keys = (
            "\u00e9" * 1025,
            "v2|bad\x00group",
            "\ud800",
        )
        for invalid_key in invalid_keys:
            with self.subTest(invalid_key=repr(invalid_key)):
                self.assertFalse(
                    self.scheduler.valid_controlled_stable_group_key(
                        invalid_key
                    )
                )
                with mock.patch(
                    "sys.argv",
                    [
                        str(SCHEDULER_PATH),
                        "--only-group-id",
                        group_id,
                        "--only-alert-id",
                        alert_id,
                        "--only-stable-group-key",
                        invalid_key,
                        "--only-dispatch-id",
                        dispatch_id,
                    ],
                ), mock.patch("sys.stderr", io.StringIO()):
                    with self.assertRaises(SystemExit):
                        self.scheduler.parse_args()

    def test_runtime_release_attestation_uses_literal_env_file_fallback(
        self,
    ) -> None:
        env_path = Path(self.tempdir.name) / ".env"
        env_path.write_text(
            "# runtime metadata\n"
            f"ONION_SENTINEL_RELEASE_ID={DEPLOYED_RELEASE}\n",
            encoding="utf-8",
        )

        self.assertEqual(
            self.scheduler.current_runtime_release_id(
                environ={},
                env_path=env_path,
            ),
            DEPLOYED_RELEASE,
        )
        self.assertEqual(
            self.scheduler.current_runtime_release_id(
                environ={"ONION_SENTINEL_RELEASE_ID": "e" * 40},
                env_path=env_path,
            ),
            "e" * 40,
        )
        self.assertEqual(
            self.scheduler.current_runtime_release_id(
                environ={"ONION_SENTINEL_RELEASE_ID": ""},
                env_path=env_path,
            ),
            "",
        )
        env_path.write_text(
            f"ONION_SENTINEL_RELEASE_ID={DEPLOYED_RELEASE}\n"
            f"ONION_SENTINEL_RELEASE_ID={'e' * 40}\n",
            encoding="utf-8",
        )
        self.assertEqual(
            self.scheduler.current_runtime_release_id(
                environ={},
                env_path=env_path,
            ),
            "",
        )

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

    def test_processing_status_returns_server_bound_ai_claim(self) -> None:
        response = io.BytesIO(
            json.dumps(
                {
                    "ok": True,
                    "lease_token": "claim-lease",
                    "dedupe_key": "outer-group",
                    "claim": {
                        "job_id": 41,
                        "job_type": "ai_analysis",
                        "dedupe_key": "claimed-group",
                        "payload": {
                            "group_id": "claimed-group",
                            "alert_id": "claimed-alert",
                        },
                    },
                }
            ).encode("utf-8")
        )
        response.status = 200
        with mock.patch.object(
            self.scheduler.urllib.request,
            "urlopen",
            return_value=response,
        ) as urlopen:
            claimed = self.scheduler.report_ai_job_status(
                "http://127.0.0.1:8787",
                "requested-group",
                "processing",
                expected_job_id=41,
                expected_representative_alert_id="claimed-alert",
                expected_dispatch_id="a" * 64,
                expected_stable_group_key="v2|claimed-group",
                **CONTROLLED_ROUTE_FIELDS,
            )

        self.assertIsInstance(claimed, self.scheduler.ClaimedAiLease)
        self.assertEqual(claimed, "claim-lease")
        self.assertEqual(claimed.job_type, "ai_analysis")
        self.assertEqual(claimed.resolved_key, "claimed-group")
        self.assertEqual(claimed.job_id, 41)
        self.assertEqual(
            claimed.job_payload,
            {
                "group_id": "claimed-group",
                "alert_id": "claimed-alert",
            },
        )
        request_payload = json.loads(
            urlopen.call_args.args[0].data.decode("utf-8")
        )
        self.assertEqual(request_payload["expected_job_id"], 41)
        self.assertEqual(
            request_payload["expected_representative_alert_id"],
            "claimed-alert",
        )
        self.assertEqual(
            request_payload["expected_stable_group_key"],
            "v2|claimed-group",
        )
        self.assertEqual(
            request_payload["expected_assigned_route"],
            PRIMARY_ROUTE,
        )
        self.assertEqual(
            request_payload["expected_reviewer_route"],
            REVIEWER_ROUTE,
        )
        self.assertIs(request_payload["reviewer_required"], True)

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
        priority: int = 0,
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
            ) VALUES (?, ?, ?, ?, ?, 0, 8, ?, ?, ?, ?)
            """,
            (
                job_type,
                group_id,
                status,
                json.dumps(payload or {}),
                priority,
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
        claimed_payload_available: bool = True,
        claim_available: bool = True,
        claimed_job_type: str | None = None,
        claimed_resolved_key: str | None = None,
        register_claimed_alert: bool = True,
        job_type: str = "ai_analysis",
        analysis_threshold: str = "medium",
        only_group_id: str = "",
        only_alert_id: str = "",
        only_stable_group_key: str = "",
        only_dispatch_id: str = "",
        current_alert_group_key: str | None = None,
        controlled_evaluation: bool | None = None,
        build_prompt_error: BaseException | None = None,
        analysis_process: object | None = None,
    ) -> dict[str, object]:
        """Run one indexed job through main() with inference boundaries mocked."""
        if controlled_evaluation is None:
            controlled_evaluation = bool(only_group_id)
        self.enable_indexed_scheduler()
        alert_id = f"{job_type}-{severity}-threshold-alert"
        group_id = only_group_id or f"{job_type}-{severity}-threshold-group"
        frozen_group_key = (
            only_stable_group_key
            or (f"key:{group_id}" if only_group_id else "")
        )
        queued_payload = dict(payload or {})
        if only_group_id:
            controlled_agent_role = (
                "incident-responder"
                if job_type == "incident_response_analysis"
                else "soc-analyst"
            )
            queued_payload.setdefault("alert_id", alert_id)
            queued_payload.setdefault("representative_alert_id", alert_id)
            queued_payload.setdefault("group_id", group_id)
            queued_payload.setdefault("stable_group_id", group_id)
            queued_payload.setdefault("stable_group_key", frozen_group_key)
            queued_payload.setdefault("dispatch_id", only_dispatch_id)
            queued_payload.setdefault("release_id", DEPLOYED_RELEASE)
            queued_payload.setdefault("agent_role", controlled_agent_role)
            for field, value in CONTROLLED_ROUTE_FIELDS.items():
                queued_payload.setdefault(field, value)
        self.insert_alert(alert_id, severity, "2026-07-24  12:00:00Z", 80)
        self.set_stable_group(alert_id, group_id)
        if current_alert_group_key is not None:
            self.conn.execute(
                "UPDATE alerts SET stable_group_key = ? WHERE alert_id = ?",
                (current_alert_group_key, alert_id),
            )
        self.insert_indexed_job(
            group_id,
            payload=queued_payload,
            job_type=job_type,
        )
        if claimed_payload and register_claimed_alert:
            claimed_alert_ids = {
                str(claimed_payload.get(field) or "").strip()
                for field in ("alert_id", "representative_alert_id")
                if str(claimed_payload.get(field) or "").strip()
            }
            for claimed_alert_id in claimed_alert_ids:
                if claimed_alert_id == alert_id:
                    continue
                self.insert_alert(
                    claimed_alert_id,
                    severity,
                    "2026-07-24  12:00:01Z",
                    80,
                )
                self.set_stable_group(claimed_alert_id, group_id)
        self.conn.commit()

        root = Path(self.tempdir.name).resolve()
        controlled_home = root / "controlled-home"
        controlled_runtime = (
            controlled_home
            / "n8n-local"
            / "harness-evaluations"
            / "scheduler-test"
        )
        if controlled_evaluation:
            controlled_runtime.mkdir(parents=True, mode=0o700)
            controlled_runtime.parent.chmod(0o700)
            controlled_runtime.chmod(0o700)
        worker_root = controlled_runtime if controlled_evaluation else root
        runtime_directories = {
            name: worker_root / name
            for name in (
                "prompts",
                "analysis",
                "prior-analysis",
                "pcap-analysis",
                "rollups",
                "agent-memory",
                "incident-evidence",
                "investigation-pivots",
                "tmp",
            )
        }
        for path in runtime_directories.values():
            path.mkdir(mode=0o700, exist_ok=True)
            path.chmod(0o700)
        db_path = worker_root / "alerts.sqlite3"
        disk_conn = sqlite3.connect(db_path)
        try:
            self.conn.backup(disk_conn)
        finally:
            disk_conn.close()
        db_path.chmod(0o600)

        settings_path = worker_root / "ai_model_settings.json"
        settings = {
            "soc_analyst_analysis_min_severity": analysis_threshold,
        }
        if controlled_evaluation:
            controlled_agent_role = (
                "incident-responder"
                if job_type == "incident_response_analysis"
                else "soc-analyst"
            )
            settings.update(
                {
                    "agent_models": {
                        controlled_agent_role: PRIMARY_ROUTE,
                    },
                    "agent_second_opinion_models": {
                        controlled_agent_role: REVIEWER_ROUTE,
                    },
                    "codex_cli_models": [
                        {
                            "model": "gpt-5.5",
                            "reasoning_effort": "high",
                            "enabled": True,
                        },
                        {
                            "model": "gpt-5.6-sol",
                            "reasoning_effort": "xhigh",
                            "enabled": True,
                        },
                    ],
                }
            )
        settings_path.write_text(
            json.dumps(settings),
            encoding="utf-8",
        )
        settings_path.chmod(0o600)
        harness_policy_path = worker_root / "investigation_harness_policy.json"
        harness_policy_path.write_text("{}\n", encoding="utf-8")
        harness_policy_path.chmod(0o600)
        detection_playbooks_path = worker_root / "detection_playbooks.json"
        detection_playbooks_path.write_text("{}\n", encoding="utf-8")
        detection_playbooks_path.chmod(0o600)
        investigation_skills_path = worker_root / "investigation_skills.json"
        investigation_skills_path.write_text("{}\n", encoding="utf-8")
        investigation_skills_path.chmod(0o600)
        shared_memory_path = worker_root / "shared-agent-memory.md"
        shared_memory_path.write_text("\n", encoding="utf-8")
        shared_memory_path.chmod(0o600)
        asset_inventory_path = worker_root / "asset-inventory.json"
        asset_inventory_path.write_text("{}\n", encoding="utf-8")
        asset_inventory_path.chmod(0o600)
        live_osquery_path = worker_root / "live-osquery.json"
        live_osquery_path.write_text(
            '{"enabled":false}\n',
            encoding="utf-8",
        )
        live_osquery_path.chmod(0o600)
        disagreement_prompt_path = worker_root / "disagreement.md"
        disagreement_prompt_path.write_text("\n", encoding="utf-8")
        disagreement_prompt_path.chmod(0o600)
        for role_name in ("soc_analyst", "incident_responder"):
            for suffix in ("system_prompt.md", "second_opinion_prompt.md"):
                prompt = worker_root / f"{role_name}_{suffix}"
                prompt.write_text("\n", encoding="utf-8")
                prompt.chmod(0o600)
        for role_name in ("soc-analyst", "incident-responder"):
            memory = runtime_directories["agent-memory"] / f"{role_name}-memory.md"
            memory.write_text("\n", encoding="utf-8")
            memory.chmod(0o600)
        relay_config_path = write_controlled_route_fixture(
            worker_root,
            controlled_home,
        )
        args = SimpleNamespace(
            db=db_path,
            prompt_dir=runtime_directories["prompts"],
            analysis_dir=runtime_directories["analysis"],
            prior_analysis_dir=runtime_directories["prior-analysis"],
            pcap_analysis_dir=runtime_directories["pcap-analysis"],
            rollup_dir=runtime_directories["rollups"],
            agent_memory_dir=runtime_directories["agent-memory"],
            shared_memory_file=shared_memory_path,
            asset_inventory_file=asset_inventory_path,
            incident_evidence_dir=runtime_directories["incident-evidence"],
            incident_evidence_config=relay_config_path,
            investigation_pivot_dir=runtime_directories[
                "investigation-pivots"
            ],
            live_osquery_config=live_osquery_path,
            disagreement_adjudicator_prompt_file=disagreement_prompt_path,
            ai_settings_file=settings_path,
            investigation_harness_policy=harness_policy_path,
            detection_playbooks=detection_playbooks_path,
            investigation_skills=investigation_skills_path,
            provider_lane="any",
            lock_file=worker_root / "worker.lock",
            wake_file=worker_root / "worker.wake",
            levels="critical,high,medium,low,informational",
            hours=87600,
            max_per_run=1,
            only_group_id=only_group_id,
            only_alert_id=only_alert_id,
            only_stable_group_key=frozen_group_key,
            only_dispatch_id=only_dispatch_id,
            related_limit=8,
            correlation_limit=8,
            correlation_min_score=15,
            model=None,
            timeout=30,
            max_prompt_bytes=1024 * 1024,
            portal_wake_file=worker_root / "portal.wake",
            no_portal_refresh=True,
            alert_store_url=(
                "http://127.0.0.1:18787"
                if controlled_evaluation
                else "http://127.0.0.1:8787"
            ),
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
            retryable: bool = True,
            expected_job_id: int = 0,
            expected_representative_alert_id: str = "",
            expected_dispatch_id: str = "",
            expected_stable_group_key: str = "",
            expected_assigned_route: str = "",
            expected_reviewer_route: str = "",
            reviewer_required: bool = False,
        ) -> bool | str:
            del lease_token, retryable
            if status != "processing":
                return True
            if not claim_available:
                contention_conn = sqlite3.connect(db_path)
                try:
                    contention_conn.execute(
                        """
                        UPDATE durable_jobs
                        SET status = 'processing',
                            processing_started_at = ?
                        WHERE dedupe_key = ?
                        """,
                        ("2026-07-24  12:00:02Z", group_id),
                    )
                    contention_conn.commit()
                finally:
                    contention_conn.close()
                return False
            authoritative_payload = dict(
                claimed_payload
                if claimed_payload is not None
                else queued_payload
            )
            authoritative_payload.setdefault("alert_id", alert_id)
            authoritative_payload.setdefault("group_id", group_id)
            if only_group_id:
                authoritative_payload.setdefault(
                    "representative_alert_id",
                    queued_payload.get("representative_alert_id", alert_id),
                )
                authoritative_payload.setdefault("stable_group_id", group_id)
                authoritative_payload.setdefault(
                    "stable_group_key",
                    frozen_group_key,
                )
                authoritative_payload.setdefault(
                    "dispatch_id",
                    only_dispatch_id,
                )
                authoritative_payload.setdefault(
                    "release_id",
                    DEPLOYED_RELEASE,
                )
                authoritative_payload.setdefault(
                    "agent_role",
                    queued_payload["agent_role"],
                )
                authoritative_payload.setdefault(
                    "expected_assigned_route",
                    expected_assigned_route,
                )
                authoritative_payload.setdefault(
                    "expected_reviewer_route",
                    expected_reviewer_route,
                )
                authoritative_payload.setdefault(
                    "reviewer_required",
                    reviewer_required,
                )
            return self.scheduler.ClaimedAiLease(
                "threshold-test-lease",
                job_payload=(
                    authoritative_payload
                    if claimed_payload_available
                    else {}
                ),
                job_type=(
                    claimed_job_type
                    if claimed_job_type is not None
                    else job_type
                ),
                resolved_key=(
                    claimed_resolved_key
                    if claimed_resolved_key is not None
                    else group_id
                ),
                job_id=expected_job_id,
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
        completed_process = (
            analysis_process
            if analysis_process is not None
            else SimpleNamespace(
                returncode=0,
                stdout="",
                stderr="",
            )
        )
        worker_stderr = io.StringIO()
        worker_stdout = io.StringIO()
        worker_environment = {
            "ONION_SENTINEL_EVALUATION_MODE": (
                "1" if controlled_evaluation else "0"
            ),
            "ONION_SENTINEL_RELEASE_ID": DEPLOYED_RELEASE,
        }
        if controlled_evaluation:
            worker_environment.update(
                {
                    "ONION_SENTINEL_EVALUATION_RUNTIME_DIR": str(
                        controlled_runtime
                    ),
                    "ONION_SENTINEL_EVALUATION_FREEZE_MEMORY": "1",
                    "ONION_SENTINEL_EVALUATION_TOKEN": "f" * 64,
                    "TMPDIR": str(runtime_directories["tmp"]),
                }
            )
        with (
            mock.patch.object(self.scheduler, "parse_args", return_value=args),
            mock.patch.object(self.scheduler, "HOME", controlled_home),
            mock.patch.object(self.scheduler.tempfile, "tempdir", None),
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
                side_effect=build_prompt_error,
            ) as build_prompt,
            mock.patch.object(
                self.scheduler,
                "run_analysis",
                return_value=completed_process,
            ) as run_analysis,
            mock.patch.object(self.scheduler, "signal_dashboard_refresh"),
            mock.patch.object(self.scheduler.sys, "stderr", worker_stderr),
            mock.patch.object(self.scheduler.sys, "stdout", worker_stdout),
            mock.patch.dict(
                os.environ,
                worker_environment,
            ),
        ):
            return_code = self.scheduler.main()

        return {
            "return_code": return_code,
            "report_status": report_status,
            "collect_incident_evidence": collect_incident_evidence,
            "build_prompt": build_prompt,
            "run_analysis": run_analysis,
            "group_id": group_id,
            "stderr": worker_stderr.getvalue(),
            "stdout": worker_stdout.getvalue(),
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
            investigation_harness_policy=(
                Path(self.tempdir.name) / "investigation_harness_policy.json"
            ),
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

    def test_lost_durable_claim_is_logged_as_contention_not_failure(
        self,
    ) -> None:
        result = self.run_indexed_worker_once(
            severity="medium",
            claim_available=False,
        )

        self.assertEqual(result["return_code"], 0)
        result["build_prompt"].assert_not_called()
        result["run_analysis"].assert_not_called()
        self.assertEqual(
            [call.args[2] for call in result["report_status"].call_args_list],
            ["processing"],
        )
        self.assertIn("claim contention", result["stdout"])
        self.assertNotIn("failed", result["stderr"])

    def test_manual_analyze_low_job_bypasses_medium_threshold(self) -> None:
        result = self.run_indexed_worker_once(
            severity="low",
            payload={"manual_reanalysis": True},
        )

        self.assertEqual(result["return_code"], 0)
        result["build_prompt"].assert_called_once()
        result["run_analysis"].assert_called_once()

    def test_soc_worker_uses_coalesced_claim_payload_before_threshold_decision(
        self,
    ) -> None:
        result = self.run_indexed_worker_once(
            severity="low",
            payload={
                "manual_reanalysis": False,
                "related_limit": 8,
            },
            claimed_payload={
                "manual_reanalysis": True,
                "related_limit": 500,
            },
        )

        self.assertEqual(result["return_code"], 0)
        result["build_prompt"].assert_called_once()
        result["run_analysis"].assert_called_once()
        claimed = result["build_prompt"].call_args.args[2]
        self.assertIs(claimed["manual_reanalysis"], True)
        self.assertEqual(claimed["related_limit"], 500)

    def test_soc_worker_retires_coalesced_automatic_job_below_threshold(
        self,
    ) -> None:
        result = self.run_indexed_worker_once(
            severity="low",
            payload={"manual_reanalysis": True},
            claimed_payload={"manual_reanalysis": False},
        )

        self.assertEqual(result["return_code"], 0)
        result["build_prompt"].assert_not_called()
        result["run_analysis"].assert_not_called()
        self.assertEqual(
            [call.args[2] for call in result["report_status"].call_args_list],
            ["processing", "completed"],
        )

    def test_soc_worker_rejects_claim_with_mismatched_group_identity(
        self,
    ) -> None:
        result = self.run_indexed_worker_once(
            severity="critical",
            payload={"manual_reanalysis": True},
            claimed_payload={"manual_reanalysis": True},
            claimed_resolved_key="different-stable-group",
        )

        self.assertEqual(result["return_code"], 0)
        result["build_prompt"].assert_not_called()
        result["run_analysis"].assert_not_called()
        failed = result["report_status"].call_args_list[-1]
        self.assertEqual(failed.args[2], "failed")
        self.assertIn("group identity is invalid", failed.args[3])
        self.assertIs(failed.kwargs["retryable"], False)

    def test_payload_less_rolling_deploy_claim_remains_retryable(
        self,
    ) -> None:
        result = self.run_indexed_worker_once(
            severity="critical",
            payload={"manual_reanalysis": True},
            claimed_payload_available=False,
        )

        self.assertEqual(result["return_code"], 0)
        result["build_prompt"].assert_not_called()
        result["run_analysis"].assert_not_called()
        failed = result["report_status"].call_args_list[-1]
        self.assertEqual(failed.args[2], "failed")
        self.assertIn("server-authoritative job identity", failed.args[3])
        self.assertIs(failed.kwargs["retryable"], True)

    def test_soc_worker_rejects_claim_with_mismatched_job_identity(
        self,
    ) -> None:
        result = self.run_indexed_worker_once(
            severity="critical",
            payload={"manual_reanalysis": True},
            claimed_payload={"manual_reanalysis": True},
            claimed_job_type="incident_response_analysis",
        )

        self.assertEqual(result["return_code"], 0)
        result["build_prompt"].assert_not_called()
        result["run_analysis"].assert_not_called()
        failed = result["report_status"].call_args_list[-1]
        self.assertEqual(failed.args[2], "failed")
        self.assertIn("job identity is invalid", failed.args[3])
        self.assertIs(failed.kwargs["retryable"], False)

    def test_soc_worker_rejects_claim_with_unknown_alert_identity(
        self,
    ) -> None:
        result = self.run_indexed_worker_once(
            severity="critical",
            payload={"manual_reanalysis": True},
            claimed_payload={
                "manual_reanalysis": True,
                "alert_id": "not-in-alert-store",
            },
            register_claimed_alert=False,
        )

        self.assertEqual(result["return_code"], 0)
        result["build_prompt"].assert_not_called()
        result["run_analysis"].assert_not_called()
        failed = result["report_status"].call_args_list[-1]
        self.assertEqual(failed.args[2], "failed")
        self.assertIn("alert identity is invalid", failed.args[3])
        self.assertIs(failed.kwargs["retryable"], False)

    def test_controlled_worker_runs_only_for_exact_claim_identity(self) -> None:
        group_id = "0123456789abcdefabcd"
        alert_id = "ai_analysis-critical-threshold-alert"
        dispatch_id = "a" * 64

        result = self.run_indexed_worker_once(
            severity="critical",
            payload={
                "manual_reanalysis": True,
                "dispatch_id": dispatch_id,
            },
            only_group_id=group_id,
            only_alert_id=alert_id,
            only_dispatch_id=dispatch_id,
        )

        self.assertEqual(result["return_code"], 0)
        result["build_prompt"].assert_called_once()
        result["run_analysis"].assert_called_once()
        self.assertEqual(
            result["build_prompt"].call_args.args[0],
            alert_id,
        )

    def test_controlled_prompt_failure_returns_nonzero_and_requeues_owned_job(
        self,
    ) -> None:
        group_id = "1123456789abcdefabcd"
        alert_id = "ai_analysis-critical-threshold-alert"
        dispatch_id = "1" * 64

        result = self.run_indexed_worker_once(
            severity="critical",
            payload={
                "manual_reanalysis": True,
                "dispatch_id": dispatch_id,
            },
            only_group_id=group_id,
            only_alert_id=alert_id,
            only_dispatch_id=dispatch_id,
            build_prompt_error=RuntimeError("prompt builder failed rc=1"),
        )

        self.assertEqual(
            result["return_code"],
            self.scheduler.CONTROLLED_SELECTED_JOB_FAILURE_EXIT_CODE,
        )
        result["build_prompt"].assert_called_once()
        result["run_analysis"].assert_not_called()
        failed = result["report_status"].call_args_list[-1]
        self.assertEqual(failed.args[2], "failed")
        self.assertEqual(failed.args[3], "prompt builder failed rc=1")
        self.assertEqual(failed.args[4], "threshold-test-lease")
        self.assertIs(failed.kwargs["retryable"], True)
        self.assertIn('"controlled_evaluation": "selected_job_failed"', result["stderr"])
        self.assertIn(f'"stable_group_id": "{group_id}"', result["stderr"])

    def test_controlled_analysis_failure_returns_nonzero_after_retry_callback(
        self,
    ) -> None:
        group_id = "2123456789abcdefabcd"
        alert_id = "ai_analysis-critical-threshold-alert"
        dispatch_id = "2" * 64

        result = self.run_indexed_worker_once(
            severity="critical",
            payload={
                "manual_reanalysis": True,
                "dispatch_id": dispatch_id,
            },
            only_group_id=group_id,
            only_alert_id=alert_id,
            only_dispatch_id=dispatch_id,
            analysis_process=SimpleNamespace(
                returncode=7,
                stdout="",
                stderr="provider connection closed unexpectedly",
            ),
        )

        self.assertEqual(
            result["return_code"],
            self.scheduler.CONTROLLED_SELECTED_JOB_FAILURE_EXIT_CODE,
        )
        result["run_analysis"].assert_called_once()
        failed = result["report_status"].call_args_list[-1]
        self.assertEqual(failed.args[2], "failed")
        self.assertEqual(
            failed.args[3],
            "provider connection closed unexpectedly",
        )
        self.assertIs(failed.kwargs["retryable"], True)
        self.assertIn('"controlled_evaluation": "selected_job_failed"', result["stderr"])

    def test_production_prompt_failure_keeps_retry_and_scheduler_exit_semantics(
        self,
    ) -> None:
        result = self.run_indexed_worker_once(
            severity="critical",
            payload={"manual_reanalysis": True},
            build_prompt_error=RuntimeError("prompt builder failed rc=1"),
        )

        self.assertEqual(result["return_code"], 0)
        result["build_prompt"].assert_called_once()
        result["run_analysis"].assert_not_called()
        failed = result["report_status"].call_args_list[-1]
        self.assertEqual(failed.args[2], "failed")
        self.assertEqual(failed.args[3], "prompt builder failed rc=1")
        self.assertIs(failed.kwargs["retryable"], True)
        self.assertNotIn("selected_job_failed", result["stderr"])

    def test_controlled_worker_rejects_replaced_claim_alert_before_prompt(
        self,
    ) -> None:
        group_id = "0123456789abcdefabcd"
        expected_alert_id = "ai_analysis-critical-threshold-alert"
        dispatch_id = "b" * 64

        result = self.run_indexed_worker_once(
            severity="critical",
            payload={
                "manual_reanalysis": True,
                "dispatch_id": dispatch_id,
            },
            claimed_payload={
                "manual_reanalysis": True,
                "alert_id": "replacement-alert",
                "dispatch_id": dispatch_id,
            },
            only_group_id=group_id,
            only_alert_id=expected_alert_id,
            only_dispatch_id=dispatch_id,
        )

        self.assertEqual(
            result["return_code"],
            self.scheduler.CONTROLLED_SELECTED_JOB_FAILURE_EXIT_CODE,
        )
        result["collect_incident_evidence"].assert_not_called()
        result["build_prompt"].assert_not_called()
        result["run_analysis"].assert_not_called()
        released = result["report_status"].call_args_list[-1]
        self.assertEqual(released.args[2], "failed")
        self.assertIn("alert identity", released.args[3])
        self.assertIs(released.kwargs["retryable"], True)
        self.assertIn(
            '"controlled_evaluation": "selected_job_failed"',
            result["stderr"],
        )

    def test_controlled_incident_worker_rejects_dispatch_drift_before_evidence(
        self,
    ) -> None:
        group_id = "fedcba9876543210abcd"
        alert_id = "incident_response_analysis-critical-threshold-alert"
        expected_dispatch_id = "c" * 64

        result = self.run_indexed_worker_once(
            severity="critical",
            payload={
                "agent_role": "incident-responder",
                "manual_reanalysis": True,
                "dispatch_id": expected_dispatch_id,
            },
            claimed_payload={
                "agent_role": "incident-responder",
                "manual_reanalysis": True,
                "dispatch_id": "d" * 64,
            },
            job_type="incident_response_analysis",
            only_group_id=group_id,
            only_alert_id=alert_id,
            only_dispatch_id=expected_dispatch_id,
        )

        self.assertEqual(
            result["return_code"],
            self.scheduler.CONTROLLED_SELECTED_JOB_FAILURE_EXIT_CODE,
        )
        result["collect_incident_evidence"].assert_not_called()
        result["build_prompt"].assert_not_called()
        result["run_analysis"].assert_not_called()
        released = result["report_status"].call_args_list[-1]
        self.assertEqual(released.args[2], "failed")
        self.assertIn("dispatch identity did not match", released.args[3])
        self.assertIs(released.kwargs["retryable"], True)
        self.assertIn(
            '"controlled_evaluation": "selected_job_failed"',
            result["stderr"],
        )

    def test_controlled_worker_rejects_mismatched_candidate_without_claim(self) -> None:
        group_id = "abcdef0123456789abcd"
        alert_id = "ai_analysis-critical-threshold-alert"
        dispatch_id = "e" * 64
        result = self.run_indexed_worker_once(
            severity="critical",
            payload={
                "manual_reanalysis": True,
                "alert_id": "ordinary-replacement-alert",
                "dispatch_id": dispatch_id,
            },
            only_group_id=group_id,
            only_alert_id=alert_id,
            only_dispatch_id=dispatch_id,
        )

        self.assertEqual(result["return_code"], 0)
        result["report_status"].assert_not_called()
        result["collect_incident_evidence"].assert_not_called()
        result["build_prompt"].assert_not_called()
        result["run_analysis"].assert_not_called()
        self.assertNotIn("selected_job_failed", result["stderr"])

    def test_controlled_worker_rejects_release_mismatch_before_claim(self) -> None:
        group_id = "abcdef0123456789abcd"
        alert_id = "ai_analysis-critical-threshold-alert"
        dispatch_id = "9" * 64
        result = self.run_indexed_worker_once(
            severity="critical",
            payload={
                "manual_reanalysis": True,
                "dispatch_id": dispatch_id,
                "release_id": "e" * 40,
            },
            only_group_id=group_id,
            only_alert_id=alert_id,
            only_dispatch_id=dispatch_id,
        )

        self.assertEqual(result["return_code"], 0)
        result["report_status"].assert_not_called()
        result["collect_incident_evidence"].assert_not_called()
        result["build_prompt"].assert_not_called()
        result["run_analysis"].assert_not_called()
        self.assertNotIn("selected_job_failed", result["stderr"])

    def test_controlled_worker_releases_only_owned_lease_on_release_drift(
        self,
    ) -> None:
        group_id = "bbcdef0123456789abcd"
        alert_id = "ai_analysis-critical-threshold-alert"
        dispatch_id = "8" * 64
        result = self.run_indexed_worker_once(
            severity="critical",
            payload={
                "manual_reanalysis": True,
                "dispatch_id": dispatch_id,
            },
            claimed_payload={
                "manual_reanalysis": True,
                "dispatch_id": dispatch_id,
                "release_id": "e" * 40,
            },
            only_group_id=group_id,
            only_alert_id=alert_id,
            only_dispatch_id=dispatch_id,
        )

        self.assertEqual(
            result["return_code"],
            self.scheduler.CONTROLLED_SELECTED_JOB_FAILURE_EXIT_CODE,
        )
        result["build_prompt"].assert_not_called()
        result["run_analysis"].assert_not_called()
        released = result["report_status"].call_args_list[-1]
        self.assertEqual(released.args[2], "failed")
        self.assertIn("release_id did not match", released.args[3])
        self.assertIs(released.kwargs["retryable"], True)
        self.assertIn(
            '"controlled_evaluation": "selected_job_failed"',
            result["stderr"],
        )

    def test_controlled_worker_requeues_owned_lease_when_alert_key_drifts(
        self,
    ) -> None:
        group_id = "bcdef0123456789abcde"
        alert_id = "ai_analysis-critical-threshold-alert"
        dispatch_id = "f" * 64
        result = self.run_indexed_worker_once(
            severity="critical",
            payload={"manual_reanalysis": True, "dispatch_id": dispatch_id},
            only_group_id=group_id,
            only_alert_id=alert_id,
            only_dispatch_id=dispatch_id,
            current_alert_group_key="key:post-queue-drift",
        )

        self.assertEqual(
            result["return_code"],
            self.scheduler.CONTROLLED_SELECTED_JOB_FAILURE_EXIT_CODE,
        )
        result["build_prompt"].assert_not_called()
        result["run_analysis"].assert_not_called()
        released = result["report_status"].call_args_list[-1]
        self.assertEqual(released.args[2], "failed")
        self.assertIn("stable group key is invalid", released.args[3])
        self.assertIs(released.kwargs["retryable"], True)
        self.assertIn(
            '"controlled_evaluation": "selected_job_failed"',
            result["stderr"],
        )

    def test_worker_rejects_invalid_claimed_and_current_stable_group_key(
        self,
    ) -> None:
        invalid_key = "v2|bad\x00group"
        result = self.run_indexed_worker_once(
            severity="critical",
            payload={
                "manual_reanalysis": True,
                "stable_group_key": invalid_key,
            },
            claimed_payload={
                "manual_reanalysis": True,
                "stable_group_key": invalid_key,
            },
            current_alert_group_key=invalid_key,
        )

        self.assertEqual(result["return_code"], 0)
        result["build_prompt"].assert_not_called()
        result["run_analysis"].assert_not_called()
        released = result["report_status"].call_args_list[-1]
        self.assertEqual(released.args[2], "failed")
        self.assertIn("stable group key is invalid", released.args[3])

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
        harness_policy_path = (
            Path(self.tempdir.name) / "investigation-harness-policy.json"
        )
        args = SimpleNamespace(
            analysis_dir=Path(self.tempdir.name) / "analysis",
            timeout=600,
            max_prompt_bytes=1024 * 1024,
            alert_store_url="http://127.0.0.1:8787",
            ai_settings_file=settings_path,
            investigation_harness_policy=harness_policy_path,
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
            command[command.index("--investigation-harness-policy") + 1],
            str(harness_policy_path),
        )
        self.assertEqual(
            command[command.index("--max-prompt-bytes") + 1],
            str(1024 * 1024),
        )
        self.assertEqual(
            command[command.index("--reanalysis-attempt-id") + 1],
            "ira-" + ("a" * 40),
        )

    def test_cli_lane_reserves_follow_up_headroom_between_builder_and_runner(
        self,
    ) -> None:
        settings_path = Path(self.tempdir.name) / "custom-ai-settings.json"
        harness_policy_path = (
            Path(self.tempdir.name) / "investigation-harness-policy.json"
        )
        settings_path.write_text(
            json.dumps(
                {
                    "codex_cli_models": [
                        {
                            "model": "gpt-5.5",
                            "reasoning_effort": "high",
                            "enabled": True,
                        }
                    ],
                    "agent_models": {
                        "soc-analyst": "codex-cli:gpt-5.5:high",
                    },
                }
            ),
            encoding="utf-8",
        )
        args = SimpleNamespace(
            prompt_dir=Path(self.tempdir.name) / "prompts",
            related_limit=8,
            correlation_limit=8,
            correlation_min_score=15,
            include_tests=False,
            analysis_dir=Path(self.tempdir.name) / "analysis",
            timeout=600,
            max_prompt_bytes=1024 * 1024,
            alert_store_url="http://127.0.0.1:8787",
            ai_settings_file=settings_path,
            investigation_harness_policy=harness_policy_path,
            detection_playbooks=(
                Path(self.tempdir.name) / "detection-playbooks.json"
            ),
            provider_lane="cli",
            model=None,
        )
        args.prompt_dir.mkdir()
        prompt_path = args.prompt_dir / "prompt.json"
        prompt_path.write_text("{}", encoding="utf-8")

        self.assertEqual(
            self.scheduler.effective_prompt_package_limit(
                args,
                agent_role="soc-analyst",
            ),
            self.scheduler.CODEX_CLI_MAX_PROMPT_PACKAGE_BYTES,
        )
        self.assertEqual(
            self.scheduler.effective_initial_prompt_package_limit(
                args,
                agent_role="soc-analyst",
            ),
            self.scheduler.CODEX_CLI_INITIAL_PROMPT_PACKAGE_BYTES,
        )
        completed = SimpleNamespace(
            returncode=0,
            stdout=str(prompt_path) + "\n",
            stderr="",
        )
        with mock.patch.object(
            self.scheduler,
            "run_command",
            return_value=completed,
        ) as run:
            self.assertEqual(
                self.scheduler.build_prompt(
                    "synthetic-alert",
                    args,
                    {"agent_role": "soc-analyst"},
                ),
                prompt_path,
            )
        builder_command = run.call_args.args[0]
        self.assertEqual(
            builder_command[
                builder_command.index("--max-package-bytes") + 1
            ],
            str(self.scheduler.CODEX_CLI_INITIAL_PROMPT_PACKAGE_BYTES),
        )
        self.assertEqual(
            builder_command[
                builder_command.index("--detection-playbooks") + 1
            ],
            str(args.detection_playbooks),
        )
        prompt_path.write_bytes(
            b"x"
            * (
                self.scheduler.CODEX_CLI_INITIAL_PROMPT_PACKAGE_BYTES
                + 1
            )
        )
        with (
            mock.patch.object(
                self.scheduler,
                "run_command",
                return_value=completed,
            ),
            self.assertRaisesRegex(
                RuntimeError,
                "prompt package exceeded the "
                f"{self.scheduler.CODEX_CLI_INITIAL_PROMPT_PACKAGE_BYTES}-byte",
            ),
        ):
            self.scheduler.build_prompt(
                "synthetic-alert",
                args,
                {"agent_role": "soc-analyst"},
            )
        command = self.scheduler.analysis_command(
            Path(self.tempdir.name) / "prompt.json",
            args,
            agent_role="soc-analyst",
        )
        self.assertEqual(
            command[command.index("--max-prompt-bytes") + 1],
            str(self.scheduler.CODEX_CLI_MAX_PROMPT_PACKAGE_BYTES),
        )
        self.assertEqual(
            command[command.index("--investigation-harness-policy") + 1],
            str(harness_policy_path),
        )

    def test_local_lane_retains_operator_prompt_package_budget(self) -> None:
        args = SimpleNamespace(
            max_prompt_bytes=1024 * 1024,
            provider_lane="ollama",
            ai_settings_file=Path(self.tempdir.name) / "missing-settings.json",
        )

        self.assertEqual(
            self.scheduler.effective_prompt_package_limit(
                args,
                agent_role="soc-analyst",
            ),
            1024 * 1024,
        )

    def test_codex_second_opinion_also_clamps_prompt_package_budget(self) -> None:
        settings_path = Path(self.tempdir.name) / "reviewer-settings.json"
        settings_path.write_text(
            json.dumps(
                {
                    "agent_models": {
                        "soc-analyst": "ollama:local-primary",
                    },
                    "agent_second_opinion_models": {
                        "soc-analyst": "codex-cli:gpt-5.6-sol:xhigh",
                    },
                }
            ),
            encoding="utf-8",
        )
        args = SimpleNamespace(
            max_prompt_bytes=1024 * 1024,
            ai_settings_file=settings_path,
        )

        self.assertEqual(
            self.scheduler.effective_prompt_package_limit(
                args,
                agent_role="soc-analyst",
            ),
            self.scheduler.CODEX_CLI_MAX_PROMPT_PACKAGE_BYTES,
        )
        self.assertEqual(
            self.scheduler.effective_initial_prompt_package_limit(
                args,
                agent_role="soc-analyst",
            ),
            self.scheduler.CODEX_CLI_INITIAL_PROMPT_PACKAGE_BYTES,
        )

    def test_prompt_builder_and_runner_share_custom_role_prompt_directory(self) -> None:
        root = Path(self.tempdir.name)
        config_dir = root / "custom-config"
        config_dir.mkdir()
        settings_path = config_dir / "ai_model_settings.json"
        settings_path.write_text(
            json.dumps(
                {
                    "agent_models": {
                        "incident-responder": "codex-cli:gpt-5.5:high",
                    },
                }
            ),
            encoding="utf-8",
        )
        prompt_path = root / "prompts" / "prompt.json"
        prompt_path.parent.mkdir()
        prompt_path.write_text("{}", encoding="utf-8")
        args = SimpleNamespace(
            prompt_dir=prompt_path.parent,
            related_limit=8,
            correlation_limit=8,
            correlation_min_score=15,
            max_prompt_bytes=1024 * 1024,
            ai_settings_file=settings_path,
            detection_playbooks=root / "detection-playbooks.json",
            include_tests=False,
        )
        completed = SimpleNamespace(
            returncode=0,
            stdout=str(prompt_path) + "\n",
            stderr="",
        )

        with mock.patch.object(
            self.scheduler,
            "run_command",
            return_value=completed,
        ) as run:
            returned = self.scheduler.build_prompt(
                "synthetic-alert",
                args,
                {"agent_role": "incident-responder"},
            )

        command = run.call_args.args[0]
        self.assertEqual(returned, prompt_path)
        self.assertEqual(
            command[command.index("--system-prompt-file") + 1],
            str(
                self.scheduler.role_prompt_file(
                    config_dir,
                    "incident-responder",
                )
            ),
        )
        self.assertEqual(
            command[command.index("--second-opinion-prompt-file") + 1],
            str(
                self.scheduler.role_second_opinion_prompt_file(
                    config_dir,
                    "incident-responder",
                )
            ),
        )

    def test_hermes_only_route_keeps_its_separate_prompt_budget(self) -> None:
        settings_path = Path(self.tempdir.name) / "hermes-settings.json"
        settings_path.write_text(
            json.dumps(
                {
                    "agent_models": {
                        "soc-analyst": "hermes-agent:gpt-5.6-sol:medium",
                    },
                    "agent_second_opinion_models": {
                        "soc-analyst": "",
                    },
                }
            ),
            encoding="utf-8",
        )
        args = SimpleNamespace(
            max_prompt_bytes=1024 * 1024,
            ai_settings_file=settings_path,
        )

        self.assertEqual(
            self.scheduler.effective_prompt_package_limit(
                args,
                agent_role="soc-analyst",
            ),
            1024 * 1024,
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

    def test_indexed_queue_prevents_incident_role_from_starving_soc_analysis(
        self,
    ) -> None:
        self.enable_indexed_scheduler()
        self.insert_alert(
            "soc-medium",
            "medium",
            "2026-07-31  12:00:00-06:00",
            60,
        )
        self.insert_alert(
            "incident-medium",
            "medium",
            "2026-07-31  12:20:00-06:00",
            60,
        )
        self.set_stable_group("soc-medium", "soc-medium-group")
        self.set_stable_group("incident-medium", "incident-medium-group")
        self.insert_indexed_job(
            "soc-medium-group",
            payload={"agent_role": "soc-analyst"},
            priority=2,
            next_attempt_at="2026-07-31  12:00:00-06:00",
        )
        self.insert_indexed_job(
            "incident-medium-group",
            payload={"agent_role": "incident-responder"},
            job_type="incident_response_analysis",
            priority=102,
            next_attempt_at="2026-07-31  12:20:00-06:00",
        )
        self.conn.commit()

        with mock.patch.object(
            self.scheduler,
            "project_now_precise",
            return_value="2026-07-31  12:30:00-06:00",
        ):
            selected = self.scheduler.select_next_alert_indexed(
                self.conn,
                self.args,
            )

        self.assertIsNotNone(selected)
        self.assertEqual(selected["alert_id"], "soc-medium")
        self.assertEqual(selected["durable_job_type"], "ai_analysis")
        self.assertEqual(selected["fairness_bucket"], 0)

    def test_indexed_queue_keeps_severity_ahead_of_cross_role_age_fairness(
        self,
    ) -> None:
        self.enable_indexed_scheduler()
        self.insert_alert(
            "soc-medium-old",
            "medium",
            "2026-07-31  11:00:00-06:00",
            60,
        )
        self.insert_alert(
            "incident-critical-new",
            "critical",
            "2026-07-31  12:25:00-06:00",
            95,
        )
        self.set_stable_group("soc-medium-old", "soc-medium-old-group")
        self.set_stable_group(
            "incident-critical-new",
            "incident-critical-new-group",
        )
        self.insert_indexed_job(
            "soc-medium-old-group",
            payload={"agent_role": "soc-analyst"},
            next_attempt_at="2026-07-31  11:00:00-06:00",
        )
        self.insert_indexed_job(
            "incident-critical-new-group",
            payload={"agent_role": "incident-responder"},
            job_type="incident_response_analysis",
            next_attempt_at="2026-07-31  12:25:00-06:00",
        )
        self.conn.commit()

        with mock.patch.object(
            self.scheduler,
            "project_now_precise",
            return_value="2026-07-31  12:30:00-06:00",
        ):
            selected = self.scheduler.select_next_alert_indexed(
                self.conn,
                self.args,
            )

        self.assertIsNotNone(selected)
        self.assertEqual(selected["alert_id"], "incident-critical-new")
        self.assertEqual(
            selected["durable_job_type"],
            "incident_response_analysis",
        )

    def test_indexed_queue_uses_subsecond_due_clock(self) -> None:
        self.enable_indexed_scheduler()
        group_id = "0123456789abcdefabcd"
        self.insert_alert(
            "subsecond-alert",
            "high",
            "2026-07-28  02:24:29-06:00",
            90,
        )
        self.set_stable_group("subsecond-alert", group_id)
        self.insert_indexed_job(
            group_id,
            payload={"manual_reanalysis": True},
            next_attempt_at="2026-07-28  02:24:29.438-06:00",
        )
        self.conn.commit()

        with mock.patch.object(
            self.scheduler,
            "project_now_precise",
            return_value="2026-07-28  02:24:29.437-06:00",
        ):
            self.assertIsNone(
                self.scheduler.select_next_alert_indexed(
                    self.conn,
                    self.args,
                )
            )

        with mock.patch.object(
            self.scheduler,
            "project_now_precise",
            return_value="2026-07-28  02:24:29.500-06:00",
        ):
            selected = self.scheduler.select_next_alert_indexed(
                self.conn,
                self.args,
            )

        self.assertIsNotNone(selected)
        self.assertEqual(selected["alert_id"], "subsecond-alert")

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
