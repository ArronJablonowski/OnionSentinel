#!/usr/bin/env python3
"""End-to-end regression checks for immutable Incident Responder rerun lineage."""
from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
import json
import os
import socket
import sqlite3
import subprocess
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from contextlib import closing
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
ALERT_STORE_DIR = REPO_ROOT / "n8n" / "alert_store"
ALERT_STORE = ALERT_STORE_DIR / "alert_store.js"
SCORING_RULES = ALERT_STORE_DIR / "config" / "scoring_rules.json"
DEPLOYED_RELEASE = "d" * 40
PRIMARY_ROUTE = "codex-cli:gpt-5.5:high"
REVIEWER_ROUTE = "codex-cli:gpt-5.6-sol:xhigh"
CONTROLLED_ROUTE_FIELDS = {
    "expected_assigned_route": PRIMARY_ROUTE,
    "expected_reviewer_route": REVIEWER_ROUTE,
    "reviewer_required": True,
}
COHORT_MODULE_PATH = (
    REPO_ROOT / "operations" / "cohort_runner_service.py"
)
COHORT_SPEC = importlib.util.spec_from_file_location(
    "run_incident_harness_cohort_for_lineage_test",
    COHORT_MODULE_PATH,
)
assert COHORT_SPEC and COHORT_SPEC.loader
cohort = importlib.util.module_from_spec(COHORT_SPEC)
COHORT_SPEC.loader.exec_module(cohort)


def available_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def request_json(
    url: str,
    method: str = "GET",
    payload: dict | None = None,
) -> tuple[int, dict]:
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers={"Content-Type": "application/json"} if body else {},
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        try:
            return error.code, json.loads(error.read())
        finally:
            error.close()


class IncidentReanalysisLineageTests(unittest.TestCase):
    case_id = "ir-lineage-regression"
    alert_id = "synthetic-incident-lineage"
    group_id = "4f83e4cd0123456789ab"
    dashboard_group_id = "4f83e4cd0123"

    def setUp(self) -> None:
        if not (ALERT_STORE_DIR / "node_modules" / "sqlite3").exists():
            self.skipTest(
                "run npm ci in n8n/alert_store to install the locked sqlite3 dependency"
            )
        self.tempdir = tempfile.TemporaryDirectory(
            prefix="onion-sentinel-reanalysis-lineage-"
        )
        self.runtime = Path(self.tempdir.name)
        self.db_path = self.runtime / "alerts.sqlite3"
        self.port = available_port()
        self.process_log = tempfile.TemporaryFile(mode="w+t", encoding="utf-8")
        self.alert_store_env = {
            **os.environ,
            "ALERT_STORE_DB": str(self.db_path),
            "SCORING_RULES_PATH": str(SCORING_RULES),
            "ALERT_STORE_HOST": "127.0.0.1",
            "ALERT_STORE_PORT": str(self.port),
            "ALERT_STORE_BEACON_PATHS": str(self.runtime / "beacon.json"),
            "ALERT_STORE_BEACON_HISTORY_PATHS": str(
                self.runtime / "beacon-history.json"
            ),
            "ALERT_STORE_DISK_MIN_FREE_BYTES": "0",
            "ALERT_STORE_DISK_START_MAX_USED_PERCENT": "79.9",
            "ALERT_STORE_DISK_HARD_MAX_USED_PERCENT": "80",
            "TELEGRAM_OUTBOX_AUTOSTART": "0",
            "ENRICHMENT_WORKER_INTERVAL_MS": "600000",
            "PIPELINE_DISK_SAMPLE_INTERVAL_SECONDS": "3600",
            "AI_ANALYSIS_WAKE_PATH": str(
                self.runtime / "run" / "ai-analysis.wake"
            ),
            "PCAP_ANALYSIS_WAKE_PATH": str(
                self.runtime / "run" / "pcap-analysis.wake"
            ),
            "ONION_SENTINEL_RELEASE_ID": DEPLOYED_RELEASE,
        }
        self.base_url = f"http://127.0.0.1:{self.port}"
        self.start_alert_store()
        self.seed_incident()

    def start_alert_store(self) -> None:
        if hasattr(self, "process"):
            # The Node listener does not opt into immediate same-port reuse on
            # every supported platform. A restart regression only needs the
            # same database, so bind a fresh loopback port after shutdown.
            self.port = available_port()
            self.alert_store_env["ALERT_STORE_PORT"] = str(self.port)
            self.base_url = f"http://127.0.0.1:{self.port}"
        self.process = subprocess.Popen(
            ["node", str(ALERT_STORE)],
            cwd=ALERT_STORE_DIR,
            env=self.alert_store_env,
            stdout=self.process_log,
            stderr=subprocess.STDOUT,
            text=True,
        )
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            try:
                if request_json(f"{self.base_url}/health")[0] == 200:
                    break
            except (OSError, urllib.error.URLError):
                time.sleep(0.05)
        else:
            self.fail(f"alert-store did not become healthy: {self.process_output()}")

    def stop_alert_store(self) -> None:
        process = getattr(self, "process", None)
        if process is None or process.poll() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)

    def tearDown(self) -> None:
        self.stop_alert_store()
        if hasattr(self, "process_log"):
            self.process_log.close()
        if hasattr(self, "tempdir"):
            self.tempdir.cleanup()

    def process_output(self) -> str:
        self.process_log.flush()
        self.process_log.seek(0)
        return self.process_log.read()

    def seed_incident(self) -> None:
        timestamp = "2026-07-25  12:00:00-06:00"
        alert = {
            "alert_id": self.alert_id,
            "timestamp": timestamp,
            "rule_name": "Synthetic immutable lineage validation",
            "severity": 4,
            "severity_label": "critical",
            "source": {"ip": "192.0.2.10"},
            "destination": {"ip": "198.51.100.20"},
        }
        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            connection.execute(
                """
                INSERT INTO alerts (
                  alert_id, first_seen, last_seen, seen_count, timestamp,
                  rule_name, severity, severity_label, stable_group_key,
                  stable_group_id, alert_json
                ) VALUES (?, ?, ?, 1, ?, ?, 4, 'critical', ?, ?, ?)
                """,
                (
                    self.alert_id,
                    timestamp,
                    timestamp,
                    timestamp,
                    alert["rule_name"],
                    "synthetic-lineage-group",
                    self.group_id,
                    json.dumps(alert),
                ),
            )
            connection.execute(
                """
                INSERT INTO incident_response_cases (
                  case_id, group_id, dashboard_group_id,
                  representative_alert_id, status, agent_status,
                  escalated_at, updated_at, escalated_by, reason
                ) VALUES (?, ?, ?, ?, 'open', 'analyzed', ?, ?, 'unit-test', ?)
                """,
                (
                    self.case_id,
                    self.group_id,
                    self.dashboard_group_id,
                    self.alert_id,
                    timestamp,
                    timestamp,
                    "Validate overlapping rerun lineage",
                ),
            )
            connection.commit()

    def post(
        self,
        path: str,
        payload: dict,
        expected_status: int = 200,
    ) -> dict:
        status, result = request_json(
            f"{self.base_url}{path}",
            "POST",
            payload,
        )
        self.assertEqual(status, expected_status, result)
        return result

    @staticmethod
    def generated_at(offset_seconds: int = 0) -> str:
        value = dt.datetime.now().astimezone() + dt.timedelta(seconds=offset_seconds)
        return value.isoformat(timespec="microseconds").replace("T", "  ", 1)

    def analysis_payload(
        self,
        analysis_id: str,
        *,
        model: str,
        model_path: str,
        provider: str | None = None,
        reanalysis_attempt_id: str | None,
        analysis_started_at: str,
        generated_at: str,
    ) -> dict:
        return {
            "analysis_id": analysis_id,
            "alert_id": self.alert_id,
            "agent_role": "incident-responder",
            "reanalysis_attempt_id": reanalysis_attempt_id,
            "analysis_started_at": analysis_started_at,
            "generated_at": generated_at,
            "model": model,
            "model_path": model_path,
            "provider": provider,
            "artifact_path": f"/synthetic/{analysis_id}.json",
            "evidence_hash": "a" * 64,
            "response": {
                "detection_outcome": "true_positive_suspicious",
                "bluf": f"Synthetic result from {model}",
                "summary": "Regression fixture",
                "confidence": "high",
            },
            "correlation_candidates": [],
        }

    def run_case(self, run_id: str) -> sqlite3.Row:
        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                """
                SELECT * FROM incident_reanalysis_run_cases
                WHERE run_id = ? AND case_id = ?
                """,
                (run_id, self.case_id),
            ).fetchone()
        self.assertIsNotNone(row)
        return row

    def incident_case(self) -> sqlite3.Row:
        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                "SELECT * FROM incident_response_cases WHERE case_id = ?",
                (self.case_id,),
            ).fetchone()
        self.assertIsNotNone(row)
        return row

    def drift_representative_group(self, group_id: str) -> None:
        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            connection.execute(
                """
                UPDATE alerts
                SET stable_group_id = ?, stable_group_key = ?
                WHERE alert_id = ?
                """,
                (group_id, f"drifted-key:{group_id}", self.alert_id),
            )
            connection.commit()

    def seed_representative(
        self,
        alert_id: str,
        *,
        group_id: str | None = None,
        group_key: str = "synthetic-lineage-group",
    ) -> None:
        timestamp = "2026-07-25  12:01:00-06:00"
        stable_group_id = group_id or self.group_id
        alert = {
            "alert_id": alert_id,
            "timestamp": timestamp,
            "rule_name": "Synthetic immutable lineage validation",
            "severity": 4,
            "severity_label": "critical",
            "source": {"ip": "192.0.2.10"},
            "destination": {"ip": "198.51.100.20"},
        }
        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            connection.execute(
                """
                INSERT INTO alerts (
                  alert_id, first_seen, last_seen, seen_count, timestamp,
                  rule_name, severity, severity_label, stable_group_key,
                  stable_group_id, alert_json
                ) VALUES (?, ?, ?, 1, ?, ?, 4, 'critical', ?, ?, ?)
                """,
                (
                    alert_id,
                    timestamp,
                    timestamp,
                    timestamp,
                    alert["rule_name"],
                    group_key,
                    stable_group_id,
                    json.dumps(alert),
                ),
            )
            connection.commit()

    def mutation_snapshot(self) -> tuple:
        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            case = connection.execute(
                """
                SELECT group_id, representative_alert_id, agent_status,
                       updated_at
                FROM incident_response_cases WHERE case_id = ?
                """,
                (self.case_id,),
            ).fetchone()
            counts = tuple(
                connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                for table in (
                    "incident_reanalysis_runs",
                    "incident_reanalysis_run_cases",
                    "incident_response_events",
                    "durable_jobs",
                )
            )
        return tuple(case), counts

    def seed_failed_review(self, analysis_id: str, agent_role: str) -> None:
        generated_at = self.generated_at(-60)
        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            connection.execute(
                """
                INSERT INTO ai_analysis_runs (
                  analysis_id, group_id, alert_id, agent_role, generated_at,
                  model, model_path, detection_outcome, bluf, summary,
                  confidence, artifact_path, evidence_hash, response_json,
                  created_at
                ) VALUES (?, ?, ?, ?, ?, 'gpt-5.6-sol',
                          'frontier-codex-cli', 'true_positive_suspicious',
                          'Prior analysis', 'Prior analysis', 'medium',
                          '/synthetic/prior.json', ?, '{}', ?)
                """,
                (
                    analysis_id,
                    self.group_id,
                    self.alert_id,
                    agent_role,
                    generated_at,
                    "b" * 64,
                    generated_at,
                ),
            )
            connection.execute(
                """
                INSERT INTO ai_second_opinion_runs (
                  analysis_id, group_id, alert_id, agent_role, status,
                  reviewer_error, material_disagreement, generated_at,
                  created_at, updated_at
                ) VALUES (?, ?, ?, ?, 'failed',
                          'Required independent reviewer unavailable',
                          0, ?, ?, ?)
                """,
                (
                    analysis_id,
                    self.group_id,
                    self.alert_id,
                    agent_role,
                    generated_at,
                    generated_at,
                    generated_at,
                ),
            )
            if agent_role == "incident-responder":
                connection.execute(
                    """
                    UPDATE incident_response_cases
                    SET latest_analysis_id = ?, latest_model = 'gpt-5.6-sol',
                        latest_generated_at = ?
                    WHERE case_id = ?
                    """,
                    (analysis_id, generated_at, self.case_id),
                )
            connection.commit()

    def test_initial_escalation_is_not_claimed_as_case_bound_reanalysis(
        self,
    ) -> None:
        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            connection.execute(
                """
                INSERT INTO alert_group_summary (
                  group_id, group_key, representative_alert_id,
                  raw_alert_count, total_seen_count, updated_at
                ) VALUES (?, 'lineage-dashboard-group', ?, 1, 1, ?)
                """,
                (
                    self.dashboard_group_id,
                    self.alert_id,
                    self.generated_at(),
                ),
            )
            connection.commit()

        self.post(
            "/incidents/escalate",
            {
                "group_id": self.dashboard_group_id,
                "requested_by": "initial-escalation-test",
            },
            expected_status=202,
        )

        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            payload_json = connection.execute(
                """
                SELECT payload_json FROM durable_jobs
                WHERE job_type = 'incident_response_analysis'
                  AND dedupe_key = ?
                """,
                (self.group_id,),
            ).fetchone()[0]
        payload = json.loads(payload_json)
        self.assertIs(payload["manual_reanalysis"], False)
        self.assertNotIn("reanalysis_run_id", payload)

        claim = self.post(
            "/jobs/status",
            {
                "job_type": "incident_response_analysis",
                "dedupe_key": self.group_id,
                "status": "processing",
            },
        )
        self.assertIs(claim["claim"]["payload"]["manual_reanalysis"], False)
        self.assertIsNone(claim["claim"]["reanalysis_attempt_id"])

    def test_case_reanalysis_pins_and_persists_frozen_dispatch_identity(
        self,
    ) -> None:
        cohort_id = "newest-20-ir.2026_07_26"
        dispatch_id = "c" * 64
        frozen = self.post(
            "/incidents/reanalyze",
            {
                "case_id": self.case_id,
                "representative_alert_id": self.alert_id,
                "stable_group_id": self.group_id,
                "stable_group_key": "synthetic-lineage-group",
                "cohort_id": cohort_id,
                "dispatch_id": dispatch_id,
                "release_id": DEPLOYED_RELEASE,
                "requested_by": "frozen-lineage-test",
                **CONTROLLED_ROUTE_FIELDS,
            },
            expected_status=202,
        )
        self.assertEqual(frozen["representative_alert_id"], self.alert_id)
        self.assertEqual(frozen["stable_group_id"], self.group_id)
        self.assertEqual(
            frozen["stable_group_key"],
            "synthetic-lineage-group",
        )
        self.assertEqual(frozen["cohort_id"], cohort_id)
        self.assertEqual(frozen["dispatch_id"], dispatch_id)
        self.assertEqual(frozen["release_id"], DEPLOYED_RELEASE)

        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            payload_json = connection.execute(
                """
                SELECT payload_json FROM durable_jobs
                WHERE job_type = 'incident_response_analysis'
                  AND dedupe_key = ?
                """,
                (self.group_id,),
            ).fetchone()[0]
        durable_payload = json.loads(payload_json)
        self.assertEqual(durable_payload["alert_id"], self.alert_id)
        self.assertEqual(
            durable_payload["representative_alert_id"],
            self.alert_id,
        )
        self.assertEqual(durable_payload["group_id"], self.group_id)
        self.assertEqual(durable_payload["stable_group_id"], self.group_id)
        self.assertEqual(
            durable_payload["stable_group_key"],
            "synthetic-lineage-group",
        )
        self.assertEqual(durable_payload["cohort_id"], cohort_id)
        self.assertEqual(durable_payload["dispatch_id"], dispatch_id)
        self.assertEqual(durable_payload["release_id"], DEPLOYED_RELEASE)

        conflicts = (
            {
                "representative_alert_id": "different-alert",
                "stable_group_id": self.group_id,
                "stable_group_key": "synthetic-lineage-group",
                "cohort_id": cohort_id,
                "dispatch_id": "d" * 64,
                "release_id": DEPLOYED_RELEASE,
            },
            {
                "representative_alert_id": self.alert_id,
                "stable_group_id": "abcdef1234567890abcd",
                "stable_group_key": "synthetic-lineage-group",
                "cohort_id": cohort_id,
                "dispatch_id": "e" * 64,
                "release_id": DEPLOYED_RELEASE,
            },
            {
                "representative_alert_id": self.alert_id,
                "stable_group_id": self.group_id,
                "stable_group_key": "synthetic-lineage-group",
                "cohort_id": cohort_id,
                "release_id": DEPLOYED_RELEASE,
            },
            {
                "representative_alert_id": self.alert_id,
                "stable_group_id": self.group_id,
                "stable_group_key": "synthetic-lineage-group",
                "cohort_id": cohort_id,
                "dispatch_id": "f" * 64,
            },
            {
                "representative_alert_id": self.alert_id,
                "stable_group_id": self.group_id,
                "stable_group_key": "synthetic-lineage-group",
                "cohort_id": cohort_id,
                "dispatch_id": "0" * 64,
                "release_id": "e" * 40,
            },
        )
        for conflict in conflicts:
            with self.subTest(conflict=conflict):
                rejected = self.post(
                    "/incidents/reanalyze",
                    {"case_id": self.case_id, **conflict},
                    expected_status=409,
                )
                self.assertFalse(rejected["ok"])

        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            retained_json = connection.execute(
                """
                SELECT payload_json FROM durable_jobs
                WHERE job_type = 'incident_response_analysis'
                  AND dedupe_key = ?
                """,
                (self.group_id,),
            ).fetchone()[0]
        self.assertEqual(json.loads(retained_json), durable_payload)

    def test_controlled_reanalysis_rebinds_same_stable_representative(
        self,
    ) -> None:
        pinned_alert_id = "synthetic-incident-lineage-newest"
        self.seed_representative(pinned_alert_id)
        cohort_id = "newest-20-ir.representative-rotation"
        dispatch_id = "6" * 64

        accepted = self.post(
            "/incidents/reanalyze",
            {
                "case_id": self.case_id,
                "representative_alert_id": pinned_alert_id,
                "stable_group_id": self.group_id,
                "stable_group_key": "synthetic-lineage-group",
                "cohort_id": cohort_id,
                "dispatch_id": dispatch_id,
                "release_id": DEPLOYED_RELEASE,
                "requested_by": "frozen-rebind-test",
                **CONTROLLED_ROUTE_FIELDS,
            },
            expected_status=202,
        )

        case = self.incident_case()
        run_case = self.run_case(accepted["run_id"])
        self.assertEqual(case["group_id"], self.group_id)
        self.assertEqual(case["representative_alert_id"], pinned_alert_id)
        self.assertEqual(run_case["group_id"], self.group_id)
        self.assertEqual(run_case["representative_alert_id"], pinned_alert_id)
        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            durable_payload = json.loads(
                connection.execute(
                    """
                    SELECT payload_json FROM durable_jobs
                    WHERE job_type = 'incident_response_analysis'
                      AND dedupe_key = ?
                    """,
                    (self.group_id,),
                ).fetchone()[0]
            )
            event = connection.execute(
                """
                SELECT detail_json FROM incident_response_events
                WHERE case_id = ? AND event_type = 'reanalysis_basis_rebound'
                """,
                (self.case_id,),
            ).fetchone()
        self.assertEqual(durable_payload["case_id"], self.case_id)
        self.assertEqual(
            durable_payload["reanalysis_run_id"],
            accepted["run_id"],
        )
        self.assertEqual(durable_payload["alert_id"], pinned_alert_id)
        self.assertEqual(
            durable_payload["representative_alert_id"],
            pinned_alert_id,
        )
        self.assertEqual(durable_payload["release_id"], DEPLOYED_RELEASE)
        self.assertIsNotNone(event)
        event_detail = json.loads(event[0])
        self.assertEqual(
            event_detail["previous_representative_alert_id"],
            self.alert_id,
        )
        self.assertEqual(
            event_detail["representative_alert_id"],
            pinned_alert_id,
        )
        self.assertEqual(event_detail["cohort_id"], cohort_id)
        self.assertEqual(event_detail["dispatch_id"], dispatch_id)
        self.assertEqual(event_detail["release_id"], DEPLOYED_RELEASE)

    def test_controlled_reanalysis_canonicalizes_legacy_case_group(
        self,
    ) -> None:
        legacy_group_id = "3f83e4cd0123456789ab"
        pinned_alert_id = "synthetic-incident-lineage-canonical"
        self.seed_representative(pinned_alert_id)
        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            connection.execute(
                """
                INSERT INTO alert_group_alias (
                  legacy_group_id, stable_group_id, stable_group_key, updated_at
                ) VALUES (?, ?, 'synthetic-lineage-group', ?)
                """,
                (legacy_group_id, self.group_id, self.generated_at()),
            )
            connection.execute(
                """
                UPDATE incident_response_cases SET group_id = ?
                WHERE case_id = ?
                """,
                (legacy_group_id, self.case_id),
            )
            connection.execute(
                """
                INSERT INTO durable_jobs (
                  job_type, dedupe_key, payload_json, status, priority,
                  attempt_count, max_attempts, next_attempt_at, created_at,
                  updated_at, requested_at
                ) VALUES (
                  'incident_response_analysis', ?, ?, 'pending', 10,
                  0, 8, ?, ?, ?, ?
                )
                """,
                (
                    legacy_group_id,
                    json.dumps(
                        {
                            "case_id": self.case_id,
                            "alert_id": self.alert_id,
                            "group_id": legacy_group_id,
                            "manual_reanalysis": False,
                        }
                    ),
                    self.generated_at(),
                    self.generated_at(),
                    self.generated_at(),
                    self.generated_at(),
                ),
            )
            connection.commit()

        accepted = self.post(
            "/incidents/reanalyze",
            {
                "case_id": self.case_id,
                "representative_alert_id": pinned_alert_id,
                "stable_group_id": self.group_id,
                "stable_group_key": "synthetic-lineage-group",
                "cohort_id": "newest-20-ir.legacy-case",
                "dispatch_id": "7" * 64,
                "release_id": DEPLOYED_RELEASE,
                "requested_by": "legacy-case-rebind-test",
                **CONTROLLED_ROUTE_FIELDS,
            },
            expected_status=202,
        )

        case = self.incident_case()
        run_case = self.run_case(accepted["run_id"])
        self.assertEqual(case["group_id"], self.group_id)
        self.assertEqual(case["representative_alert_id"], pinned_alert_id)
        self.assertEqual(run_case["group_id"], self.group_id)
        self.assertEqual(run_case["representative_alert_id"], pinned_alert_id)
        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            old_job = connection.execute(
                """
                SELECT status FROM durable_jobs
                WHERE job_type = 'incident_response_analysis'
                  AND dedupe_key = ?
                """,
                (legacy_group_id,),
            ).fetchone()
            current_payload = json.loads(
                connection.execute(
                    """
                    SELECT payload_json FROM durable_jobs
                    WHERE job_type = 'incident_response_analysis'
                      AND dedupe_key = ?
                    """,
                    (self.group_id,),
                ).fetchone()[0]
            )
        self.assertEqual(old_job[0], "completed")
        self.assertEqual(current_payload["case_id"], self.case_id)
        self.assertEqual(current_payload["alert_id"], pinned_alert_id)
        self.assertEqual(
            current_payload["reanalysis_run_id"],
            accepted["run_id"],
        )

    def test_controlled_reanalysis_identity_rejections_are_read_only(
        self,
    ) -> None:
        wrong_group_id = "abcdef1234567890abcd"
        wrong_group_alert_id = "synthetic-incident-lineage-wrong-group"
        wrong_key_alert_id = "synthetic-incident-lineage-wrong-key"
        self.seed_representative(
            wrong_group_alert_id,
            group_id=wrong_group_id,
            group_key="wrong-stable-group",
        )
        self.seed_representative(
            wrong_key_alert_id,
            group_key="colliding-but-different-key",
        )
        conflicts = (
            ("missing-frozen-representative", "8"),
            (wrong_group_alert_id, "9"),
            (wrong_key_alert_id, "a"),
        )
        for representative_alert_id, dispatch_character in conflicts:
            with self.subTest(representative_alert_id=representative_alert_id):
                before = self.mutation_snapshot()
                rejected = self.post(
                    "/incidents/reanalyze",
                    {
                        "case_id": self.case_id,
                        "representative_alert_id": representative_alert_id,
                        "stable_group_id": self.group_id,
                        "stable_group_key": "synthetic-lineage-group",
                        "cohort_id": "newest-20-ir.invalid-rebind",
                        "dispatch_id": dispatch_character * 64,
                        "release_id": DEPLOYED_RELEASE,
                    },
                    expected_status=409,
                )
                self.assertFalse(rejected["ok"])
                self.assertEqual(self.mutation_snapshot(), before)

    def test_controlled_reanalysis_rejects_canonical_case_collision(
        self,
    ) -> None:
        legacy_group_id = "2f83e4cd0123456789ab"
        conflicting_case_id = "ir-canonical-conflict"
        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            connection.execute(
                """
                INSERT INTO alert_group_alias (
                  legacy_group_id, stable_group_id, stable_group_key, updated_at
                ) VALUES (?, ?, 'synthetic-lineage-group', ?)
                """,
                (legacy_group_id, self.group_id, self.generated_at()),
            )
            connection.execute(
                """
                INSERT INTO incident_response_cases (
                  case_id, group_id, dashboard_group_id,
                  representative_alert_id, status, agent_status,
                  escalated_at, updated_at, escalated_by, reason
                ) VALUES (?, ?, ?, ?, 'open', 'analyzed', ?, ?,
                          'unit-test', 'Canonical collision fixture')
                """,
                (
                    conflicting_case_id,
                    legacy_group_id,
                    self.dashboard_group_id,
                    self.alert_id,
                    self.generated_at(),
                    self.generated_at(),
                ),
            )
            connection.commit()
        before = self.mutation_snapshot()

        rejected = self.post(
            "/incidents/reanalyze",
            {
                "case_id": self.case_id,
                "representative_alert_id": self.alert_id,
                "stable_group_id": self.group_id,
                "stable_group_key": "synthetic-lineage-group",
                "cohort_id": "newest-20-ir.case-collision",
                "dispatch_id": "b" * 64,
                "release_id": DEPLOYED_RELEASE,
            },
            expected_status=409,
        )

        self.assertFalse(rejected["ok"])
        self.assertEqual(self.mutation_snapshot(), before)

    def test_controlled_reanalysis_rejects_processing_canonical_job_read_only(
        self,
    ) -> None:
        queued = self.post(
            "/incidents/reanalyze",
            {"case_id": self.case_id, "requested_by": "processing-fixture"},
            expected_status=202,
        )
        self.post(
            "/jobs/status",
            {
                "job_type": "incident_response_analysis",
                "dedupe_key": self.group_id,
                "status": "processing",
            },
        )
        before = self.mutation_snapshot()

        rejected = self.post(
            "/incidents/reanalyze",
            {
                "case_id": self.case_id,
                "representative_alert_id": self.alert_id,
                "stable_group_id": self.group_id,
                "stable_group_key": "synthetic-lineage-group",
                "cohort_id": "newest-20-ir.processing-canonical",
                "dispatch_id": "c" * 64,
                "release_id": DEPLOYED_RELEASE,
            },
            expected_status=409,
        )

        self.assertFalse(rejected["ok"])
        self.assertEqual(self.mutation_snapshot(), before)
        self.assertEqual(self.run_case(queued["run_id"])["status"], "running")

    def test_controlled_reanalysis_rejects_processing_legacy_job_read_only(
        self,
    ) -> None:
        legacy_group_id = "1f83e4cd0123456789ab"
        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            timestamp = self.generated_at()
            connection.execute(
                """
                INSERT INTO alert_group_alias (
                  legacy_group_id, stable_group_id, stable_group_key, updated_at
                ) VALUES (?, ?, 'synthetic-lineage-group', ?)
                """,
                (legacy_group_id, self.group_id, timestamp),
            )
            connection.execute(
                """
                UPDATE incident_response_cases SET group_id = ?
                WHERE case_id = ?
                """,
                (legacy_group_id, self.case_id),
            )
            connection.execute(
                """
                INSERT INTO durable_jobs (
                  job_type, dedupe_key, payload_json, status, priority,
                  attempt_count, max_attempts, next_attempt_at,
                  lease_expires_at, lease_token, processing_started_at,
                  created_at, updated_at, requested_at
                ) VALUES (
                  'incident_response_analysis', ?, ?, 'processing', 10,
                  1, 8, ?, '2099-01-01  00:00:00+00:00',
                  'legacy-processing-lease', ?, ?, ?, ?
                )
                """,
                (
                    legacy_group_id,
                    json.dumps(
                        {
                            "case_id": self.case_id,
                            "alert_id": self.alert_id,
                            "group_id": legacy_group_id,
                            "manual_reanalysis": False,
                        }
                    ),
                    timestamp,
                    timestamp,
                    timestamp,
                    timestamp,
                    timestamp,
                ),
            )
            connection.commit()
        before = self.mutation_snapshot()

        rejected = self.post(
            "/incidents/reanalyze",
            {
                "case_id": self.case_id,
                "representative_alert_id": self.alert_id,
                "stable_group_id": self.group_id,
                "stable_group_key": "synthetic-lineage-group",
                "cohort_id": "newest-20-ir.processing-legacy",
                "dispatch_id": "d" * 64,
                "release_id": DEPLOYED_RELEASE,
            },
            expected_status=409,
        )

        self.assertFalse(rejected["ok"])
        self.assertEqual(self.mutation_snapshot(), before)
        self.assertEqual(self.incident_case()["group_id"], legacy_group_id)

    def test_overlap_preserves_attempt_owner_and_result_lineage(self) -> None:
        first = self.post(
            "/incidents/reanalyze",
            {
                "case_id": self.case_id,
                "release_id": "spoofed-client-release",
                "requested_by": "lineage-test",
            },
            expected_status=202,
        )
        first_run = first["run_id"]
        self.assertEqual(first["release_id"], DEPLOYED_RELEASE)

        first_claim = self.post(
            "/jobs/status",
            {
                "job_type": "incident_response_analysis",
                "dedupe_key": self.group_id,
                "status": "processing",
            },
        )
        first_lease = first_claim["lease_token"]
        first_running = self.run_case(first_run)
        self.assertEqual(first_running["status"], "running")
        self.assertTrue(first_running["latest_attempt_id"])
        first_attempt_id = first_running["latest_attempt_id"]
        first_analysis_started_at = first_running["started_at"]

        second = self.post(
            "/incidents/reanalyze",
            {
                "case_id": self.case_id,
                "release_id": "another-spoofed-release",
                "requested_by": "lineage-test",
            },
            expected_status=202,
        )
        second_run = second["run_id"]
        self.assertEqual(second["release_id"], DEPLOYED_RELEASE)
        self.assertEqual(self.run_case(first_run)["status"], "running")
        self.assertEqual(self.run_case(second_run)["status"], "queued")

        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            payload_json, rerun_requested = connection.execute(
                """
                SELECT payload_json, rerun_requested FROM durable_jobs
                WHERE job_type = 'incident_response_analysis' AND dedupe_key = ?
                """,
                (self.group_id,),
            ).fetchone()
        self.assertEqual(json.loads(payload_json)["reanalysis_run_id"], second_run)
        self.assertEqual(rerun_requested, 1)

        rejected = self.post(
            "/analysis/result",
            self.analysis_payload(
                "lineage-spoofed-attempt",
                model="gpt-5.6-luna",
                model_path="frontier-codex-cli",
                reanalysis_attempt_id="ira-" + ("f" * 40),
                analysis_started_at=first_analysis_started_at,
                generated_at=self.generated_at(3),
            ),
            expected_status=409,
        )
        self.assertIn("does not match", rejected["reason"])
        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            spoofed = connection.execute(
                "SELECT 1 FROM ai_analysis_runs WHERE analysis_id = ?",
                ("lineage-spoofed-attempt",),
            ).fetchone()
        self.assertIsNone(spoofed)

        first_result = self.post(
            "/analysis/result",
            self.analysis_payload(
                "lineage-analysis-a",
                model="gpt-5.6-sol",
                model_path="frontier-codex-cli",
                reanalysis_attempt_id=first_attempt_id,
                analysis_started_at=first_analysis_started_at,
                generated_at=self.generated_at(5),
            ),
        )
        self.assertEqual(first_result["reanalysis_run_id"], first_run)
        self.assertFalse(first_result["reanalysis_authoritative"])
        first_completed = self.run_case(first_run)
        second_still_queued = self.run_case(second_run)
        self.assertEqual(first_completed["status"], "completed")
        self.assertEqual(first_completed["analysis_id"], "lineage-analysis-a")
        self.assertEqual(first_completed["executed_model"], "gpt-5.6-sol")
        self.assertEqual(first_completed["executed_provider"], "codex-cli")
        self.assertIsNone(second_still_queued["analysis_id"])
        self.assertEqual(second_still_queued["status"], "queued")
        queued_case = self.incident_case()
        self.assertEqual(queued_case["agent_status"], "queued")
        self.assertIsNone(queued_case["latest_analysis_id"])

        self.post(
            "/jobs/status",
            {
                "job_type": "incident_response_analysis",
                "dedupe_key": self.group_id,
                "status": "completed",
                "lease_token": first_lease,
            },
        )
        self.assertEqual(self.run_case(first_run)["status"], "completed")
        self.assertEqual(self.run_case(second_run)["status"], "queued")

        second_claim = self.post(
            "/jobs/status",
            {
                "job_type": "incident_response_analysis",
                "dedupe_key": self.group_id,
                "status": "processing",
            },
        )
        second_lease = second_claim["lease_token"]
        second_running = self.run_case(second_run)
        self.assertEqual(second_running["status"], "running")
        second_attempt_id = second_running["latest_attempt_id"]
        second_result = self.post(
            "/analysis/result",
            self.analysis_payload(
                "lineage-analysis-b",
                model="gemma4:31b",
                model_path="ollama",
                reanalysis_attempt_id=second_attempt_id,
                analysis_started_at=second_running["started_at"],
                generated_at=self.generated_at(10),
            ),
        )
        self.assertEqual(second_result["reanalysis_run_id"], second_run)
        self.post(
            "/jobs/status",
            {
                "job_type": "incident_response_analysis",
                "dedupe_key": self.group_id,
                "status": "completed",
                "lease_token": second_lease,
            },
        )

        first_final = self.run_case(first_run)
        second_final = self.run_case(second_run)
        self.assertEqual(first_final["analysis_id"], "lineage-analysis-a")
        self.assertEqual(first_final["executed_provider"], "codex-cli")
        self.assertEqual(second_final["analysis_id"], "lineage-analysis-b")
        self.assertEqual(second_final["executed_model"], "gemma4:31b")
        self.assertEqual(second_final["executed_provider"], "ollama")
        self.assertNotEqual(
            first_final["latest_attempt_id"],
            second_final["latest_attempt_id"],
        )

        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            attempts = connection.execute(
                """
                SELECT run_id, status, analysis_id, executed_model,
                       executed_provider
                FROM incident_reanalysis_attempts
                ORDER BY started_at ASC
                """
            ).fetchall()
            releases = connection.execute(
                """
                SELECT release_id FROM incident_reanalysis_runs
                WHERE run_id IN (?, ?) ORDER BY run_id
                """,
                (first_run, second_run),
            ).fetchall()
        self.assertEqual(
            {tuple(item) for item in attempts},
            {
                (
                    first_run,
                    "completed",
                    "lineage-analysis-a",
                    "gpt-5.6-sol",
                    "codex-cli",
                ),
                (
                    second_run,
                    "completed",
                    "lineage-analysis-b",
                    "gemma4:31b",
                    "ollama",
                ),
            },
        )
        self.assertEqual({item[0] for item in releases}, {DEPLOYED_RELEASE})

    def test_preclaim_overlap_returns_replacement_identity_with_lease(self) -> None:
        first = self.post(
            "/incidents/reanalyze",
            {"case_id": self.case_id, "requested_by": "preclaim-race"},
            expected_status=202,
        )
        second = self.post(
            "/incidents/reanalyze",
            {"case_id": self.case_id, "requested_by": "preclaim-race"},
            expected_status=202,
        )

        claim = self.post(
            "/jobs/status",
            {
                "job_type": "incident_response_analysis",
                "dedupe_key": self.group_id,
                "status": "processing",
            },
        )

        self.assertEqual(self.run_case(first["run_id"])["status"], "skipped")
        replacement = self.run_case(second["run_id"])
        self.assertEqual(replacement["status"], "running")
        self.assertEqual(
            claim["claim"]["payload"]["reanalysis_run_id"],
            second["run_id"],
        )
        self.assertEqual(claim["claim"]["case_id"], self.case_id)
        self.assertEqual(
            claim["claim"]["reanalysis_attempt_id"],
            replacement["latest_attempt_id"],
        )
        self.assertEqual(
            claim["claim"]["reanalysis_attempt_id"],
            "ira-"
            + hashlib.sha256(claim["lease_token"].encode("utf-8")).hexdigest()[:40],
        )
        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            attempts = connection.execute(
                "SELECT run_id FROM incident_reanalysis_attempts"
            ).fetchall()
        self.assertEqual(attempts, [(second["run_id"],)])

    def test_analysis_commit_ack_binds_raw_submission_and_stored_response(
        self,
    ) -> None:
        payload = self.analysis_payload(
            "commit-ack-binding-analysis",
            model="gpt-5.6-sol",
            model_path="frontier-codex-cli",
            provider="openai-codex",
            reanalysis_attempt_id=None,
            analysis_started_at="2026-07-25T18:00:00Z",
            generated_at="2026-07-25T18:00:01Z",
        )
        payload["response"]["observed_at"] = "2026-07-25T18:00:00Z"
        payload["response"]["summary"] = "Observed café traffic — reviewed."
        payload["response"]["confidence_score"] = 0.0000001
        payload["response"]["serialization_probe"] = {
            "observed_at": "2026-07-25T18:00:00Z",
            "\ue000": "private-use",
            "😀": "astral",
        }

        raw_body = json.dumps(
            payload,
            indent=2,
            sort_keys=False,
        ).encode("utf-8") + b"\n"
        request = urllib.request.Request(
            f"{self.base_url}/analysis/result",
            data=raw_body,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            self.assertEqual(response.status, 200)
            accepted = json.loads(response.read())

        self.assertEqual(accepted["analysis_id"], payload["analysis_id"])
        self.assertEqual(
            accepted["submission_sha256"],
            hashlib.sha256(raw_body).hexdigest(),
        )
        self.assertFalse(accepted.get("idempotent", False))

        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            stored_response_json = connection.execute(
                """
                SELECT response_json FROM ai_analysis_runs
                WHERE analysis_id = ?
                """,
                (payload["analysis_id"],),
            ).fetchone()[0]
        stored_response = json.loads(stored_response_json)
        expected_stored_digest = cohort.alert_store_response_sha256(
            stored_response_json
        )
        self.assertEqual(
            accepted["stored_response_sha256"],
            expected_stored_digest,
        )
        self.assertNotEqual(
            stored_response["observed_at"],
            payload["response"]["observed_at"],
        )

        replay_body = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        replay_request = urllib.request.Request(
            f"{self.base_url}/analysis/result",
            data=replay_body,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(replay_request, timeout=5) as response:
            self.assertEqual(response.status, 200)
            replay = json.loads(response.read())

        self.assertTrue(replay["idempotent"])
        self.assertEqual(replay["analysis_id"], payload["analysis_id"])
        self.assertEqual(
            replay["submission_sha256"],
            hashlib.sha256(replay_body).hexdigest(),
        )
        self.assertNotEqual(
            replay["submission_sha256"],
            accepted["submission_sha256"],
        )
        self.assertEqual(
            replay["stored_response_sha256"],
            expected_stored_digest,
        )

    def test_analysis_replay_is_read_only_and_provenance_is_immutable(self) -> None:
        rerun = self.post(
            "/incidents/reanalyze",
            {"case_id": self.case_id, "requested_by": "idempotency-test"},
            expected_status=202,
        )
        claim = self.post(
            "/jobs/status",
            {
                "job_type": "incident_response_analysis",
                "dedupe_key": self.group_id,
                "status": "processing",
            },
        )
        running = self.run_case(rerun["run_id"])
        payload = self.analysis_payload(
            "lineage-immutable-analysis",
            model="gpt-5.6-sol",
            model_path="hermes-agent",
            provider="openai-codex",
            reanalysis_attempt_id=running["latest_attempt_id"],
            analysis_started_at=running["started_at"],
            generated_at=self.generated_at(5),
        )
        accepted = self.post("/analysis/result", payload)
        self.assertFalse(accepted.get("idempotent", False))
        self.assertEqual(
            accepted["submission_sha256"],
            hashlib.sha256(
                json.dumps(payload).encode("utf-8")
            ).hexdigest(),
        )
        self.assertRegex(
            accepted["stored_response_sha256"],
            r"^[a-f0-9]{64}$",
        )
        self.assertEqual(
            accepted["analysis_id"],
            payload["analysis_id"],
        )
        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            event_count = connection.execute(
                """
                SELECT COUNT(*) FROM incident_response_events
                WHERE case_id = ? AND event_type = 'analysis_completed'
                """,
                (self.case_id,),
            ).fetchone()[0]

        replay = self.post("/analysis/result", payload)
        self.assertTrue(replay["idempotent"])
        self.assertEqual(
            replay["submission_sha256"],
            accepted["submission_sha256"],
        )
        self.assertEqual(
            replay["stored_response_sha256"],
            accepted["stored_response_sha256"],
        )
        mutated = json.loads(json.dumps(payload))
        mutated["model"] = "gpt-5.6-terra"
        rejected = self.post(
            "/analysis/result",
            mutated,
            expected_status=409,
        )
        self.assertIn("immutable fields", rejected["reason"])

        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            stored = connection.execute(
                """
                SELECT model, model_path FROM ai_analysis_runs
                WHERE analysis_id = 'lineage-immutable-analysis'
                """
            ).fetchone()
            attempt = connection.execute(
                """
                SELECT analysis_id, executed_model, executed_provider,
                       executed_model_path
                FROM incident_reanalysis_attempts
                WHERE attempt_id = ?
                """,
                (running["latest_attempt_id"],),
            ).fetchone()
            final_event_count = connection.execute(
                """
                SELECT COUNT(*) FROM incident_response_events
                WHERE case_id = ? AND event_type = 'analysis_completed'
                """,
                (self.case_id,),
            ).fetchone()[0]
        self.assertEqual(stored, ("gpt-5.6-sol", "hermes-agent"))
        self.assertEqual(
            attempt,
            (
                "lineage-immutable-analysis",
                "gpt-5.6-sol",
                "openai-codex",
                "hermes-agent",
            ),
        )
        self.assertEqual(final_event_count, event_count)
        self.assertEqual(
            self.incident_case()["latest_model"],
            "gpt-5.6-sol",
        )
        self.post(
            "/jobs/status",
            {
                "job_type": "incident_response_analysis",
                "dedupe_key": self.group_id,
                "status": "completed",
                "lease_token": claim["lease_token"],
            },
        )

    def test_result_bound_attempt_is_retired_during_startup_recovery(self) -> None:
        rerun = self.post(
            "/incidents/reanalyze",
            {"case_id": self.case_id, "requested_by": "crash-window-test"},
            expected_status=202,
        )
        self.post(
            "/jobs/status",
            {
                "job_type": "incident_response_analysis",
                "dedupe_key": self.group_id,
                "status": "processing",
            },
        )
        running = self.run_case(rerun["run_id"])
        self.post(
            "/analysis/result",
            self.analysis_payload(
                "lineage-crash-window",
                model="gpt-5.6-sol",
                model_path="frontier-codex-cli",
                reanalysis_attempt_id=running["latest_attempt_id"],
                analysis_started_at=running["started_at"],
                generated_at=self.generated_at(5),
            ),
        )

        self.stop_alert_store()
        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            connection.execute(
                """
                UPDATE durable_jobs
                SET lease_expires_at = '2000-01-01  00:00:00+00:00'
                WHERE job_type = 'incident_response_analysis'
                  AND dedupe_key = ?
                """,
                (self.group_id,),
            )
            connection.commit()
        self.start_alert_store()

        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            durable = connection.execute(
                """
                SELECT status, attempt_count FROM durable_jobs
                WHERE job_type = 'incident_response_analysis'
                  AND dedupe_key = ?
                """,
                (self.group_id,),
            ).fetchone()
            attempts = connection.execute(
                """
                SELECT COUNT(*), MIN(status), MAX(status)
                FROM incident_reanalysis_attempts
                """
            ).fetchone()
        self.assertEqual(durable[0], "completed")
        self.assertEqual(durable[1], 1)
        self.assertEqual(attempts, (1, "completed", "completed"))
        self.assertEqual(self.run_case(rerun["run_id"])["status"], "completed")
        self.post(
            "/jobs/status",
            {
                "job_type": "incident_response_analysis",
                "dedupe_key": self.group_id,
                "status": "processing",
            },
            expected_status=404,
        )

    def test_startup_recovery_reconciles_retry_and_terminal_expiry(self) -> None:
        rerun = self.post(
            "/incidents/reanalyze",
            {"case_id": self.case_id, "requested_by": "expiry-test"},
            expected_status=202,
        )
        first_claim = self.post(
            "/jobs/status",
            {
                "job_type": "incident_response_analysis",
                "dedupe_key": self.group_id,
                "status": "processing",
            },
        )
        first_attempt = self.run_case(rerun["run_id"])["latest_attempt_id"]

        self.stop_alert_store()
        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            connection.execute(
                """
                UPDATE durable_jobs
                SET lease_expires_at = '2000-01-01  00:00:00+00:00'
                WHERE job_type = 'incident_response_analysis'
                  AND dedupe_key = ?
                """,
                (self.group_id,),
            )
            connection.commit()
        self.start_alert_store()
        self.assertEqual(self.run_case(rerun["run_id"])["status"], "queued")
        self.assertEqual(self.incident_case()["agent_status"], "queued")
        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            first_status = connection.execute(
                """
                SELECT status FROM incident_reanalysis_attempts
                WHERE attempt_id = ?
                """,
                (first_attempt,),
            ).fetchone()[0]
            connection.execute(
                """
                UPDATE durable_jobs
                SET next_attempt_at = '2000-01-01  00:00:00+00:00'
                WHERE job_type = 'incident_response_analysis'
                  AND dedupe_key = ?
                """,
                (self.group_id,),
            )
            connection.commit()
        self.assertEqual(first_status, "failed")

        second_claim = self.post(
            "/jobs/status",
            {
                "job_type": "incident_response_analysis",
                "dedupe_key": self.group_id,
                "status": "processing",
            },
        )
        second_attempt = self.run_case(rerun["run_id"])["latest_attempt_id"]
        self.assertNotEqual(first_attempt, second_attempt)
        self.assertEqual(self.incident_case()["agent_status"], "analyzing")

        self.stop_alert_store()
        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            connection.execute(
                """
                UPDATE durable_jobs
                SET lease_expires_at = '2000-01-01  00:00:00+00:00',
                    attempt_count = max_attempts
                WHERE job_type = 'incident_response_analysis'
                  AND dedupe_key = ?
                """,
                (self.group_id,),
            )
            connection.commit()
        self.start_alert_store()

        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            durable_status = connection.execute(
                """
                SELECT status FROM durable_jobs
                WHERE job_type = 'incident_response_analysis'
                  AND dedupe_key = ?
                """,
                (self.group_id,),
            ).fetchone()[0]
            statuses = dict(
                connection.execute(
                    """
                    SELECT attempt_id, status
                    FROM incident_reanalysis_attempts
                    """
                ).fetchall()
            )
        self.assertEqual(durable_status, "failed")
        self.assertEqual(statuses[first_attempt], "failed")
        self.assertEqual(statuses[second_attempt], "failed")
        self.assertEqual(self.run_case(rerun["run_id"])["status"], "failed")
        self.assertEqual(self.incident_case()["agent_status"], "failed")
        self.assertTrue(first_claim["lease_token"])
        self.assertTrue(second_claim["lease_token"])

    def test_recovery_keeps_case_analyzing_for_replacement_lease(self) -> None:
        first = self.post(
            "/incidents/reanalyze",
            {"case_id": self.case_id, "requested_by": "replacement-recovery"},
            expected_status=202,
        )
        self.post(
            "/jobs/status",
            {
                "job_type": "incident_response_analysis",
                "dedupe_key": self.group_id,
                "status": "processing",
            },
        )
        first_attempt = self.run_case(first["run_id"])["latest_attempt_id"]
        second = self.post(
            "/incidents/reanalyze",
            {"case_id": self.case_id, "requested_by": "replacement-recovery"},
            expected_status=202,
        )
        replacement_token = "replacement-recovery-lease"
        replacement_attempt = (
            "ira-"
            + hashlib.sha256(replacement_token.encode("utf-8")).hexdigest()[:40]
        )
        replacement_started = self.generated_at()

        self.stop_alert_store()
        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            connection.execute(
                """
                UPDATE durable_jobs
                SET status = 'processing', lease_token = ?,
                    lease_expires_at = '2099-01-01  00:00:00+00:00',
                    processing_started_at = ?, attempt_count = 2,
                    rerun_requested = 0
                WHERE job_type = 'incident_response_analysis'
                  AND dedupe_key = ?
                """,
                (
                    replacement_token,
                    replacement_started,
                    self.group_id,
                ),
            )
            connection.execute(
                """
                INSERT INTO incident_reanalysis_attempts (
                  attempt_id, run_id, case_id, group_id,
                  durable_attempt_count, status, started_at, updated_at
                ) VALUES (?, ?, ?, ?, 2, 'running', ?, ?)
                """,
                (
                    replacement_attempt,
                    second["run_id"],
                    self.case_id,
                    self.group_id,
                    replacement_started,
                    replacement_started,
                ),
            )
            connection.execute(
                """
                UPDATE incident_reanalysis_run_cases
                SET status = 'running', latest_attempt_id = ?,
                    started_at = ?, updated_at = ?
                WHERE run_id = ? AND case_id = ?
                """,
                (
                    replacement_attempt,
                    replacement_started,
                    replacement_started,
                    second["run_id"],
                    self.case_id,
                ),
            )
            connection.execute(
                """
                UPDATE incident_response_cases
                SET agent_status = 'failed'
                WHERE case_id = ?
                """,
                (self.case_id,),
            )
            connection.commit()
        self.start_alert_store()

        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            statuses = dict(
                connection.execute(
                    """
                    SELECT attempt_id, status
                    FROM incident_reanalysis_attempts
                    """
                ).fetchall()
            )
        self.assertEqual(statuses[first_attempt], "failed")
        self.assertEqual(statuses[replacement_attempt], "running")
        self.assertEqual(self.run_case(first["run_id"])["status"], "failed")
        self.assertEqual(self.run_case(second["run_id"])["status"], "running")
        self.assertEqual(self.incident_case()["agent_status"], "analyzing")

    def test_stale_worker_result_cannot_attach_to_replacement_lease(self) -> None:
        first = self.post(
            "/incidents/reanalyze",
            {"case_id": self.case_id, "requested_by": "stale-worker-test"},
            expected_status=202,
        )
        first_run = first["run_id"]
        self.post(
            "/jobs/status",
            {
                "job_type": "incident_response_analysis",
                "dedupe_key": self.group_id,
                "status": "processing",
            },
        )
        first_running = self.run_case(first_run)
        first_started_at = first_running["started_at"]
        first_attempt_id = first_running["latest_attempt_id"]

        second = self.post(
            "/incidents/reanalyze",
            {"case_id": self.case_id, "requested_by": "stale-worker-test"},
            expected_status=202,
        )
        second_run = second["run_id"]
        # Model lease recovery without waiting for the production watchdog.
        # The queue payload already belongs to run B while run A's immutable
        # attempt remains in the ledger.
        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            connection.execute(
                """
                UPDATE durable_jobs
                SET status = 'pending', attempt_count = 0,
                    next_attempt_at = '2000-01-01  00:00:00+00:00',
                    lease_expires_at = NULL, lease_token = NULL,
                    processing_started_at = NULL, rerun_requested = 0
                WHERE job_type = 'incident_response_analysis' AND dedupe_key = ?
                """,
                (self.group_id,),
            )
            connection.commit()
        second_claim = self.post(
            "/jobs/status",
            {
                "job_type": "incident_response_analysis",
                "dedupe_key": self.group_id,
                "status": "processing",
            },
        )
        second_started_at = self.run_case(second_run)["started_at"]
        second_attempt_id = self.run_case(second_run)["latest_attempt_id"]
        self.assertEqual(self.run_case(first_run)["status"], "failed")
        self.assertEqual(self.run_case(second_run)["status"], "running")
        self.assertEqual(self.incident_case()["agent_status"], "analyzing")

        second_result = self.post(
            "/analysis/result",
            self.analysis_payload(
                "lineage-replacement-worker",
                model="gemma4:31b",
                model_path="ollama",
                reanalysis_attempt_id=second_attempt_id,
                analysis_started_at=second_started_at,
                generated_at=self.generated_at(60),
            ),
        )
        self.assertEqual(second_result["reanalysis_run_id"], second_run)
        self.post(
            "/jobs/status",
            {
                "job_type": "incident_response_analysis",
                "dedupe_key": self.group_id,
                "status": "completed",
                "lease_token": second_claim["lease_token"],
            },
        )
        self.assertEqual(
            self.incident_case()["latest_analysis_id"],
            "lineage-replacement-worker",
        )

        stale_result = self.post(
            "/analysis/result",
            self.analysis_payload(
                "lineage-stale-worker",
                model="gpt-5.6-terra",
                model_path="frontier-codex-cli",
                reanalysis_attempt_id=first_attempt_id,
                analysis_started_at=first_started_at,
                # A delayed stale result is newer by wall clock but must not
                # replace the case pointer owned by the replacement attempt.
                generated_at=self.generated_at(120),
            ),
        )
        self.assertEqual(stale_result["reanalysis_run_id"], first_run)
        self.assertFalse(stale_result["reanalysis_authoritative"])
        self.assertEqual(self.run_case(first_run)["analysis_id"], "lineage-stale-worker")
        self.assertEqual(
            self.run_case(second_run)["analysis_id"],
            "lineage-replacement-worker",
        )
        current_case = self.incident_case()
        self.assertEqual(
            current_case["latest_analysis_id"],
            "lineage-replacement-worker",
        )
        self.assertEqual(current_case["latest_model"], "gemma4:31b")

    def test_pending_identity_drift_retires_orphan_and_queues_current_group(
        self,
    ) -> None:
        first = self.post(
            "/incidents/reanalyze",
            {"case_id": self.case_id, "requested_by": "identity-drift"},
            expected_status=202,
        )
        new_group_id = "5f83e4cd0123456789abcdef"
        self.drift_representative_group(new_group_id)
        second = self.post(
            "/incidents/reanalyze",
            {"case_id": self.case_id, "requested_by": "identity-drift"},
            expected_status=202,
        )

        self.assertEqual(self.incident_case()["group_id"], new_group_id)
        self.assertEqual(self.run_case(first["run_id"])["status"], "skipped")
        second_case = self.run_case(second["run_id"])
        self.assertEqual(second_case["group_id"], new_group_id)
        self.assertEqual(second_case["status"], "queued")
        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            durable = connection.execute(
                """
                SELECT dedupe_key, status FROM durable_jobs
                WHERE job_type = 'incident_response_analysis'
                ORDER BY dedupe_key
                """
            ).fetchall()
            executable = connection.execute(
                """
                SELECT COUNT(*) FROM durable_jobs
                WHERE job_type = 'incident_response_analysis'
                  AND status IN ('pending', 'processing')
                """
            ).fetchone()[0]
        self.assertEqual(
            durable,
            [(self.group_id, "completed"), (new_group_id, "pending")],
        )
        self.assertEqual(executable, 1)

        claim = self.post(
            "/jobs/status",
            {
                "job_type": "incident_response_analysis",
                "dedupe_key": new_group_id,
                "status": "processing",
            },
        )
        self.assertEqual(
            claim["claim"]["payload"]["reanalysis_run_id"],
            second["run_id"],
        )

    def test_processing_identity_drift_allows_old_result_non_authoritatively(
        self,
    ) -> None:
        first = self.post(
            "/incidents/reanalyze",
            {"case_id": self.case_id, "requested_by": "processing-drift"},
            expected_status=202,
        )
        first_claim = self.post(
            "/jobs/status",
            {
                "job_type": "incident_response_analysis",
                "dedupe_key": self.group_id,
                "status": "processing",
            },
        )
        first_running = self.run_case(first["run_id"])
        new_group_id = "6f83e4cd0123456789abcdef"
        self.drift_representative_group(new_group_id)
        second = self.post(
            "/incidents/reanalyze",
            {"case_id": self.case_id, "requested_by": "processing-drift"},
            expected_status=202,
        )
        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            durable = connection.execute(
                """
                SELECT dedupe_key, status FROM durable_jobs
                WHERE job_type = 'incident_response_analysis'
                ORDER BY dedupe_key
                """
            ).fetchall()
        self.assertEqual(
            durable,
            [(self.group_id, "processing"), (new_group_id, "pending")],
        )

        old_result = self.post(
            "/analysis/result",
            self.analysis_payload(
                "lineage-old-identity-result",
                model="gpt-5.6-sol",
                model_path="frontier-codex-cli",
                reanalysis_attempt_id=first_running["latest_attempt_id"],
                analysis_started_at=first_running["started_at"],
                generated_at=self.generated_at(10),
            ),
        )
        self.assertEqual(old_result["reanalysis_run_id"], first["run_id"])
        self.assertFalse(old_result["reanalysis_authoritative"])
        self.assertEqual(self.incident_case()["agent_status"], "queued")
        self.assertIsNone(self.incident_case()["latest_analysis_id"])
        self.post(
            "/jobs/status",
            {
                "job_type": "incident_response_analysis",
                "dedupe_key": self.group_id,
                "status": "completed",
                "lease_token": first_claim["lease_token"],
            },
        )
        second_claim = self.post(
            "/jobs/status",
            {
                "job_type": "incident_response_analysis",
                "dedupe_key": new_group_id,
                "status": "processing",
            },
        )
        self.assertEqual(
            second_claim["claim"]["payload"]["reanalysis_run_id"],
            second["run_id"],
        )
        self.assertEqual(self.run_case(second["run_id"])["status"], "running")

    def test_expired_processing_identity_drift_retires_old_queue_owner(
        self,
    ) -> None:
        first = self.post(
            "/incidents/reanalyze",
            {"case_id": self.case_id, "requested_by": "expiry-drift"},
            expected_status=202,
        )
        self.post(
            "/jobs/status",
            {
                "job_type": "incident_response_analysis",
                "dedupe_key": self.group_id,
                "status": "processing",
            },
        )
        first_attempt = self.run_case(first["run_id"])["latest_attempt_id"]
        new_group_id = "8f83e4cd0123456789abcdef"
        self.drift_representative_group(new_group_id)
        second = self.post(
            "/incidents/reanalyze",
            {"case_id": self.case_id, "requested_by": "expiry-drift"},
            expected_status=202,
        )

        self.stop_alert_store()
        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            connection.execute(
                """
                UPDATE durable_jobs
                SET lease_expires_at = '2000-01-01  00:00:00+00:00'
                WHERE job_type = 'incident_response_analysis'
                  AND dedupe_key = ?
                """,
                (self.group_id,),
            )
            connection.commit()
        self.start_alert_store()

        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            durable = connection.execute(
                """
                SELECT dedupe_key, status FROM durable_jobs
                WHERE job_type = 'incident_response_analysis'
                ORDER BY dedupe_key
                """
            ).fetchall()
            attempt_status = connection.execute(
                """
                SELECT status FROM incident_reanalysis_attempts
                WHERE attempt_id = ?
                """,
                (first_attempt,),
            ).fetchone()[0]
            executable = connection.execute(
                """
                SELECT COUNT(*) FROM durable_jobs
                WHERE job_type = 'incident_response_analysis'
                  AND status IN ('pending', 'processing')
                """
            ).fetchone()[0]
        self.assertEqual(
            durable,
            [(self.group_id, "completed"), (new_group_id, "pending")],
        )
        self.assertEqual(attempt_status, "failed")
        self.assertEqual(self.run_case(first["run_id"])["status"], "failed")
        self.assertEqual(self.run_case(second["run_id"])["status"], "queued")
        self.assertEqual(self.incident_case()["agent_status"], "queued")
        self.assertEqual(executable, 1)

    def test_processing_drift_retires_coalesced_superseded_old_rerun(
        self,
    ) -> None:
        first = self.post(
            "/incidents/reanalyze",
            {"case_id": self.case_id, "requested_by": "coalesced-drift"},
            expected_status=202,
        )
        first_claim = self.post(
            "/jobs/status",
            {
                "job_type": "incident_response_analysis",
                "dedupe_key": self.group_id,
                "status": "processing",
            },
        )
        first_running = self.run_case(first["run_id"])
        coalesced = self.post(
            "/incidents/reanalyze",
            {"case_id": self.case_id, "requested_by": "coalesced-drift"},
            expected_status=202,
        )
        new_group_id = "9f83e4cd0123456789abcdef"
        self.drift_representative_group(new_group_id)
        current = self.post(
            "/incidents/reanalyze",
            {"case_id": self.case_id, "requested_by": "coalesced-drift"},
            expected_status=202,
        )
        self.assertEqual(self.run_case(coalesced["run_id"])["status"], "skipped")

        self.post(
            "/analysis/result",
            self.analysis_payload(
                "lineage-coalesced-old-worker",
                model="gpt-5.6-sol",
                model_path="frontier-codex-cli",
                reanalysis_attempt_id=first_running["latest_attempt_id"],
                analysis_started_at=first_running["started_at"],
                generated_at=self.generated_at(10),
            ),
        )
        self.post(
            "/jobs/status",
            {
                "job_type": "incident_response_analysis",
                "dedupe_key": self.group_id,
                "status": "completed",
                "lease_token": first_claim["lease_token"],
            },
        )

        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            durable = connection.execute(
                """
                SELECT dedupe_key, status FROM durable_jobs
                WHERE job_type = 'incident_response_analysis'
                ORDER BY dedupe_key
                """
            ).fetchall()
            executable = connection.execute(
                """
                SELECT COUNT(*) FROM durable_jobs
                WHERE job_type = 'incident_response_analysis'
                  AND status IN ('pending', 'processing')
                """
            ).fetchone()[0]
        self.assertEqual(
            durable,
            [(self.group_id, "completed"), (new_group_id, "pending")],
        )
        self.assertEqual(self.run_case(first["run_id"])["status"], "completed")
        self.assertEqual(self.run_case(current["run_id"])["status"], "queued")
        self.assertEqual(executable, 1)

    def test_identity_drift_preserves_resolution_and_suppression_review_guards(
        self,
    ) -> None:
        self.seed_failed_review(
            "lineage-prior-incident-review",
            "incident-responder",
        )
        self.seed_failed_review(
            "lineage-prior-soc-review",
            "soc-analyst",
        )
        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            connection.execute(
                """
                INSERT INTO alert_group_summary (
                  group_id, group_key, representative_alert_id,
                  raw_alert_count, total_seen_count, updated_at
                ) VALUES (?, 'lineage-dashboard-group', ?, 1, 1, ?)
                """,
                (
                    self.dashboard_group_id,
                    self.alert_id,
                    self.generated_at(),
                ),
            )
            connection.commit()
        new_group_id = "7f83e4cd0123456789abcdef"
        self.drift_representative_group(new_group_id)
        self.post(
            "/incidents/reanalyze",
            {"case_id": self.case_id, "requested_by": "review-drift"},
            expected_status=202,
        )

        resolution = self.post(
            "/incidents/status",
            {
                "case_id": self.case_id,
                "status": "resolved",
                "resolution_reason": "Should require adjudication",
                "updated_by": "unit-test",
            },
            expected_status=409,
        )
        self.assertIn("independent review", resolution["reason"])
        suppression = self.post(
            "/analyst-status",
            {
                "id": self.dashboard_group_id,
                "status": "suppressed",
                "reason": "Should require adjudication",
                "updated_by": "unit-test",
            },
            expected_status=409,
        )
        self.assertIn("independent review", suppression["reason"])
        self.assertEqual(self.incident_case()["status"], "open")

    def test_normal_incident_result_cannot_fallback_to_stale_reanalysis(self) -> None:
        rerun = self.post(
            "/incidents/reanalyze",
            {"case_id": self.case_id, "requested_by": "normal-ir-test"},
            expected_status=202,
        )
        run_id = rerun["run_id"]
        self.post(
            "/jobs/status",
            {
                "job_type": "incident_response_analysis",
                "dedupe_key": self.group_id,
                "status": "processing",
            },
        )
        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            connection.execute(
                """
                UPDATE durable_jobs
                SET payload_json = ?, status = 'pending', attempt_count = 0,
                    next_attempt_at = '2000-01-01  00:00:00+00:00',
                    lease_expires_at = NULL, lease_token = NULL,
                    processing_started_at = NULL, rerun_requested = 0
                WHERE job_type = 'incident_response_analysis' AND dedupe_key = ?
                """,
                (
                    json.dumps(
                        {
                            "agent_role": "incident-responder",
                            "case_id": self.case_id,
                            "alert_id": self.alert_id,
                            "group_id": self.group_id,
                            "manual_reanalysis": False,
                        }
                    ),
                    self.group_id,
                ),
            )
            connection.commit()
        normal_claim = self.post(
            "/jobs/status",
            {
                "job_type": "incident_response_analysis",
                "dedupe_key": self.group_id,
                "status": "processing",
            },
        )
        self.assertEqual(self.run_case(run_id)["status"], "failed")

        normal_result = self.post(
            "/analysis/result",
            self.analysis_payload(
                "lineage-normal-incident",
                model="gpt-5.6-sol",
                model_path="frontier-codex-cli",
                # New runners deliberately serialize null for normal IR jobs.
                reanalysis_attempt_id=None,
                analysis_started_at=self.generated_at(),
                generated_at=self.generated_at(5),
            ),
        )
        self.assertIsNone(normal_result["reanalysis_run_id"])
        stale_run = self.run_case(run_id)
        self.assertEqual(stale_run["status"], "failed")
        self.assertIsNone(stale_run["analysis_id"])
        self.post(
            "/jobs/status",
            {
                "job_type": "incident_response_analysis",
                "dedupe_key": self.group_id,
                "status": "completed",
                "lease_token": normal_claim["lease_token"],
            },
        )


if __name__ == "__main__":
    unittest.main()
