#!/usr/bin/env python3
"""Fail-closed contracts for the isolated harness-evaluation runtime.

These tests use only loopback listeners, temporary SQLite databases, and
owner-only temporary directories.  They deliberately never contact the live
Onion Sentinel or Security Onion services.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
import io
import json
import os
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from contextlib import closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
ALERT_STORE_DIR = ROOT / "n8n" / "alert_store"
ALERT_STORE = ALERT_STORE_DIR / "alert_store.js"
SCORING_RULES = ALERT_STORE_DIR / "config" / "scoring_rules.json"
DASHBOARD_SERVER = (
    ROOT / "onion-sentinel-dashboard" / "onion_sentinel_server.py"
)
BIN_DIR = ROOT / "n8n" / "bin"
RUNNER_PATH = BIN_DIR / "run-local-ai-analysis.py"
SCHEDULER_PATH = BIN_DIR / "auto-run-ai-analysis.py"
RELEASE_ID = "c" * 40
REPLACEMENT_RELEASE_ID = "f" * 40
EVALUATION_TOKEN = "9" * 64

CONTROLLED_CREDENTIAL_KEYS = {
    "TELEGRAM_BOT_TOKEN",
    "TELEGRAM_CHAT_ID",
    "N8N_POST_COMMIT_TOKEN",
    "ABUSEIPDB_API_KEY",
    "GREYNOISE_API_KEY",
    "OTX_API_KEY",
    "URLHAUS_AUTH_KEY",
    "VIRUSTOTAL_API_KEY",
    "URLSCAN_API_KEY",
    "GOOGLE_SAFE_BROWSING_API_KEY",
    "PHISHTANK_API_KEY",
    "MALWAREBAZAAR_AUTH_KEY",
    "THREATFOX_AUTH_KEY",
    "SHODAN_API_KEY",
    "CENSYS_API_ID",
    "CENSYS_API_SECRET",
    "CENSYS_API_TOKEN",
    "CENSYS_ORGANIZATION_ID",
    "NVD_API_KEY",
}


def available_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def sanitized_environment() -> dict[str, str]:
    environment = dict(os.environ)
    for key in CONTROLLED_CREDENTIAL_KEYS:
        environment.pop(key, None)
    for key in (
        "ONION_SENTINEL_EVALUATION_MODE",
        "ONION_SENTINEL_EVALUATION_RUNTIME_DIR",
        "ONION_SENTINEL_EVALUATION_FREEZE_MEMORY",
        "ONION_SENTINEL_EVALUATION_TOKEN",
    ):
        environment.pop(key, None)
    return environment


def request_json(
    url: str,
    method: str = "GET",
    payload: dict | None = None,
    *,
    timeout: float = 3,
    evaluation_token: str = EVALUATION_TOKEN,
    request_headers: dict[str, str] | None = None,
) -> tuple[int, dict]:
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"} if body is not None else {}
    headers.update(request_headers or {})
    if body is not None and evaluation_token:
        headers["X-Onion-Sentinel-Evaluation-Token"] = evaluation_token
    request = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers=headers,
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
            return (
                int(response.status),
                json.loads(raw) if raw else {},
            )
    except urllib.error.HTTPError as error:
        try:
            raw = error.read()
            return (
                int(error.code),
                json.loads(raw) if raw else {},
            )
        finally:
            error.close()


def request_json_bytes(
    url: str,
    payload: dict,
    *,
    timeout: float = 3,
    evaluation_token: str = EVALUATION_TOKEN,
) -> tuple[int, bytes]:
    body = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if evaluation_token:
        headers["X-Onion-Sentinel-Evaluation-Token"] = evaluation_token
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers=headers,
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return int(response.status), response.read()
    except urllib.error.HTTPError as error:
        try:
            return int(error.code), error.read()
        finally:
            error.close()


def request_status(
    url: str,
    method: str = "GET",
    *,
    timeout: float = 3,
) -> int:
    request = urllib.request.Request(url, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            response.read()
            return int(response.status)
    except urllib.error.HTTPError as error:
        try:
            error.read()
            return int(error.code)
        finally:
            error.close()


def raw_request_status(
    host: str,
    port: int,
    target: str,
    method: str = "GET",
    *,
    timeout: float = 3,
    evaluation_token: str = EVALUATION_TOKEN,
) -> int:
    body = b"{}" if method == "POST" else b""
    request = (
        f"{method} {target} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Connection: close\r\n"
        + (
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            + (
                "X-Onion-Sentinel-Evaluation-Token: "
                f"{evaluation_token}\r\n"
                if evaluation_token
                else ""
            )
            if body
            else ""
        )
        + "\r\n"
    ).encode("ascii") + body
    with socket.create_connection((host, port), timeout=timeout) as connection:
        connection.settimeout(timeout)
        connection.sendall(request)
        response = connection.recv(4096)
    status_line = response.split(b"\r\n", 1)[0].decode("ascii")
    return int(status_line.split(" ", 2)[1])


def process_output(log_file) -> str:
    log_file.flush()
    log_file.seek(0)
    return log_file.read()


def stop_process(process: subprocess.Popen, *, graceful: bool = True) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5 if graceful else 2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def load_python_module(name: str, path: Path):
    if str(BIN_DIR) not in sys.path:
        sys.path.insert(0, str(BIN_DIR))
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class ControlledAlertStoreTests(unittest.TestCase):
    """Exercise the service boundary against a fully initialized temp schema."""

    @classmethod
    def setUpClass(cls) -> None:
        if not (ALERT_STORE_DIR / "node_modules" / "sqlite3").is_dir():
            raise unittest.SkipTest(
                "run npm ci in n8n/alert_store to install sqlite3"
            )
        cls.template = tempfile.TemporaryDirectory(
            prefix="onion-sentinel-controlled-template-"
        )
        # macOS exposes /var through a /private/var symlink.  Controlled mode
        # intentionally rejects paths whose spelling is not already canonical.
        cls.template_root = Path(cls.template.name).resolve()
        cls.template_db = cls.template_root / "alerts.sqlite3"
        cls.template_rules = cls.template_root / "scoring_rules.json"
        shutil.copyfile(SCORING_RULES, cls.template_rules)
        cls.template_rules.chmod(0o600)
        cls._initialize_template_database()
        cls.scheduler = load_python_module(
            "controlled_evaluation_recovery_e2e",
            SCHEDULER_PATH,
        )
        cls.runner = load_python_module(
            "controlled_evaluation_result_spool_e2e",
            RUNNER_PATH,
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.template.cleanup()

    @classmethod
    def _initialize_template_database(cls) -> None:
        port = available_port()
        log_file = tempfile.TemporaryFile(mode="w+t", encoding="utf-8")
        environment = {
            **sanitized_environment(),
            "ONION_SENTINEL_EVALUATION_MODE": "0",
            "ONION_SENTINEL_RELEASE_ID": RELEASE_ID,
            "ALERT_STORE_DB": str(cls.template_db),
            "SCORING_RULES_PATH": str(cls.template_rules),
            "ALERT_STORE_HOST": "127.0.0.1",
            "ALERT_STORE_PORT": str(port),
            "ALERT_STORE_BEACON_PATHS": str(
                cls.template_root / "beacon.json"
            ),
            "ALERT_STORE_BEACON_HISTORY_PATHS": str(
                cls.template_root / "beacon-history.json"
            ),
            "ALERT_STORE_DISK_MIN_FREE_BYTES": "0",
            "ALERT_STORE_DISK_START_MAX_USED_PERCENT": "99.8",
            "ALERT_STORE_DISK_HARD_MAX_USED_PERCENT": "99.9",
            "TELEGRAM_OUTBOX_AUTOSTART": "0",
            "ENRICHMENT_WORKER_INTERVAL_MS": "600000",
            "N8N_POST_COMMIT_INTERVAL_MS": "600000",
            "DURABLE_JOB_RECOVERY_INTERVAL_MS": "600000",
            "PIPELINE_DISK_SAMPLE_INTERVAL_SECONDS": "3600",
            "AI_ANALYSIS_WAKE_PATH": str(
                cls.template_root / "run" / "ai-analysis.wake"
            ),
            "PCAP_ANALYSIS_WAKE_PATH": str(
                cls.template_root / "run" / "pcap-analysis.wake"
            ),
        }
        process = subprocess.Popen(
            ["node", str(ALERT_STORE)],
            cwd=ALERT_STORE_DIR,
            env=environment,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            text=True,
        )
        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    break
                try:
                    if request_json(
                        f"http://127.0.0.1:{port}/health"
                    )[0] == 200:
                        break
                except (OSError, urllib.error.URLError):
                    time.sleep(0.05)
            else:
                raise AssertionError(
                    "template alert-store did not become healthy: "
                    + process_output(log_file)
                )
            if process.poll() is not None:
                raise AssertionError(
                    "template alert-store exited early: "
                    + process_output(log_file)
                )
        finally:
            stop_process(process, graceful=False)
        with closing(
            sqlite3.connect(cls.template_db, timeout=5)
        ) as connection:
            connection.execute("PRAGMA journal_mode = DELETE")
            integrity = connection.execute(
                "PRAGMA integrity_check"
            ).fetchone()[0]
            if integrity != "ok":
                raise AssertionError(f"template SQLite integrity: {integrity}")
            connection.commit()
        cls.template_db.chmod(0o600)
        for suffix in ("-journal", "-wal", "-shm"):
            sidecar = Path(f"{cls.template_db}{suffix}")
            if sidecar.exists():
                raise AssertionError(
                    f"template retained SQLite recovery sidecar {sidecar}"
                )
        log_file.close()

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="onion-sentinel-controlled-alert-store-"
        )
        self.runtime = Path(self.temporary.name).resolve()
        self.db = self.runtime / "alerts.sqlite3"
        self.rules = self.runtime / "scoring_rules.json"
        shutil.copyfile(self.template_db, self.db)
        shutil.copyfile(self.template_rules, self.rules)
        self.db.chmod(0o600)
        self.rules.chmod(0o600)
        self.process: subprocess.Popen | None = None
        self.log_file = tempfile.TemporaryFile(
            mode="w+t",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        if self.process is not None:
            stop_process(self.process)
        self.log_file.close()
        self.temporary.cleanup()

    def controlled_environment(
        self,
        *,
        port: int | None = None,
        release_id: str = RELEASE_ID,
    ) -> dict[str, str]:
        return {
            **sanitized_environment(),
            "ONION_SENTINEL_EVALUATION_MODE": "1",
            "ONION_SENTINEL_RELEASE_ID": release_id,
            "ONION_SENTINEL_EVALUATION_TOKEN": EVALUATION_TOKEN,
            "ALERT_STORE_DB": str(self.db),
            "SCORING_RULES_PATH": str(self.rules),
            "ALERT_STORE_HOST": "127.0.0.1",
            "ALERT_STORE_PORT": str(port or available_port()),
            "ALERT_STORE_BEACON_PATHS": str(
                self.runtime / "beacon.json"
            ),
            "ALERT_STORE_BEACON_HISTORY_PATHS": str(
                self.runtime / "beacon-history.json"
            ),
            "AI_ANALYSIS_WAKE_PATH": str(
                self.runtime / "run" / "ai-analysis.wake"
            ),
            "PCAP_ANALYSIS_WAKE_PATH": str(
                self.runtime / "run" / "pcap-analysis.wake"
            ),
            "ALERT_STORE_DISK_MIN_FREE_BYTES": "0",
        }

    def assert_startup_rejected(
        self,
        environment: dict[str, str],
        message: str,
    ) -> None:
        result = subprocess.run(
            ["node", str(ALERT_STORE)],
            cwd=ALERT_STORE_DIR,
            env=environment,
            text=True,
            capture_output=True,
            timeout=8,
            check=False,
        )
        output = result.stdout + result.stderr
        self.assertNotEqual(result.returncode, 0, output)
        self.assertIn(message, output)

    def start_controlled(
        self,
        *,
        release_id: str = RELEASE_ID,
    ) -> tuple[int, dict]:
        port = available_port()
        self.process = subprocess.Popen(
            ["node", str(ALERT_STORE)],
            cwd=ALERT_STORE_DIR,
            env=self.controlled_environment(
                port=port,
                release_id=release_id,
            ),
            stdout=self.log_file,
            stderr=subprocess.STDOUT,
            text=True,
        )
        base_url = f"http://127.0.0.1:{port}"
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                break
            try:
                status, health = request_json(f"{base_url}/health")
                if status == 200:
                    self.base_url = base_url
                    return status, health
            except (OSError, urllib.error.URLError):
                time.sleep(0.05)
        self.fail(
            "controlled alert-store did not become healthy: "
            + process_output(self.log_file)
        )

    def start_production(self) -> tuple[int, dict]:
        port = available_port()
        environment = self.controlled_environment(port=port)
        environment.update({
            "ONION_SENTINEL_EVALUATION_MODE": "0",
            "TELEGRAM_OUTBOX_AUTOSTART": "0",
            "ENRICHMENT_WORKER_INTERVAL_MS": "600000",
            "N8N_POST_COMMIT_INTERVAL_MS": "600000",
            "DURABLE_JOB_RECOVERY_INTERVAL_MS": "600000",
            "PIPELINE_DISK_SAMPLE_INTERVAL_SECONDS": "3600",
        })
        self.process = subprocess.Popen(
            ["node", str(ALERT_STORE)],
            cwd=ALERT_STORE_DIR,
            env=environment,
            stdout=self.log_file,
            stderr=subprocess.STDOUT,
            text=True,
        )
        base_url = f"http://127.0.0.1:{port}"
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                break
            try:
                status, health = request_json(f"{base_url}/health")
                if status == 200:
                    self.base_url = base_url
                    return status, health
            except (OSError, urllib.error.URLError):
                time.sleep(0.05)
        self.fail(
            "production-mode alert-store did not become healthy: "
            + process_output(self.log_file)
        )

    def seed_controlled_job(
        self,
        *,
        group_id: str,
        alert_id: str,
        stable_group_key: str,
        dispatch_id: str,
        cohort_id: str = "controlled-cohort-11",
        agent_role: str | None = "soc-analyst",
    ) -> int:
        timestamp = "2020-01-01 00:00:00+00:00"
        job_payload = {
            "alert_id": alert_id,
            "representative_alert_id": alert_id,
            "group_id": group_id,
            "stable_group_id": group_id,
            "stable_group_key": stable_group_key,
            "cohort_id": cohort_id,
            "dispatch_id": dispatch_id,
            "release_id": RELEASE_ID,
        }
        if agent_role is not None:
            job_payload["agent_role"] = agent_role
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            connection.execute(
                """
                INSERT INTO alerts (
                    alert_id, first_seen, last_seen, alert_json,
                    stable_group_id, stable_group_key, triage_level,
                    filter_status
                ) VALUES (?, ?, ?, ?, ?, ?, 'medium', 'accepted')
                """,
                (
                    alert_id,
                    timestamp,
                    timestamp,
                    json.dumps({"alert_id": alert_id}),
                    group_id,
                    stable_group_key,
                ),
            )
            cursor = connection.execute(
                """
                INSERT INTO durable_jobs (
                    job_type, dedupe_key, payload_json, status, priority,
                    attempt_count, max_attempts, next_attempt_at, created_at,
                    updated_at, requested_at, rerun_requested
                ) VALUES (
                    'ai_analysis', ?, ?, 'pending', 100, 0, 8, ?, ?, ?, ?, 0
                )
                """,
                (
                    group_id,
                    json.dumps(job_payload, separators=(",", ":")),
                    timestamp,
                    timestamp,
                    timestamp,
                    timestamp,
                ),
            )
            connection.commit()
            return int(cursor.lastrowid)

    def seed_controlled_incident_case(
        self,
        *,
        case_id: str,
        group_id: str,
        alert_id: str,
        stable_group_key: str,
        prior_analysis_id: str = "",
    ) -> None:
        timestamp = "2020-01-01 00:00:00+00:00"
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            connection.execute(
                """
                INSERT INTO alerts (
                    alert_id, first_seen, last_seen, alert_json,
                    stable_group_id, stable_group_key, triage_level,
                    filter_status
                ) VALUES (?, ?, ?, ?, ?, ?, 'critical', 'accepted')
                """,
                (
                    alert_id,
                    timestamp,
                    timestamp,
                    json.dumps({"alert_id": alert_id}),
                    group_id,
                    stable_group_key,
                ),
            )
            connection.execute(
                """
                INSERT INTO incident_response_cases (
                    case_id, group_id, dashboard_group_id,
                    representative_alert_id, status, agent_status,
                    escalated_at, updated_at, escalated_by, reason
                ) VALUES (
                    ?, ?, ?, ?, 'open', 'analyzed', ?, ?,
                    'controlled-test', 'Controlled dispatch replay test'
                )
                """,
                (
                    case_id,
                    group_id,
                    group_id[:12],
                    alert_id,
                    timestamp,
                    timestamp,
                ),
            )
            if prior_analysis_id:
                connection.execute(
                    """
                    INSERT INTO ai_analysis_runs (
                        analysis_id, group_id, alert_id, agent_role,
                        generated_at, model, model_path, response_json,
                        created_at
                    ) VALUES (
                        ?, ?, ?, 'incident-responder', ?, 'prior-model',
                        'frontier-codex-cli', '{}', ?
                    )
                    """,
                    (
                        prior_analysis_id,
                        group_id,
                        alert_id,
                        timestamp,
                        timestamp,
                    ),
                )
                connection.execute(
                    """
                    UPDATE incident_response_cases
                    SET latest_analysis_id = ?, latest_model = 'prior-model',
                        latest_generated_at = ?
                    WHERE case_id = ?
                    """,
                    (prior_analysis_id, timestamp, case_id),
                )
            connection.commit()

    def complete_controlled_retirement_member_lifecycle(
        self,
        *,
        rank: int,
        cohort_id: str,
        dispatch_id: str,
    ) -> dict:
        group_id = f"{rank:02x}" * 10
        case_id = f"ir-controlled-retirement-completed-{rank}"
        alert_id = f"controlled-retirement-completed-alert-{rank}"
        stable_group_key = (
            f"v2|controlled|retirement-completed-{rank}"
        )
        analysis_id = f"controlled-retirement-analysis-{rank}"
        self.seed_controlled_incident_case(
            case_id=case_id,
            group_id=group_id,
            alert_id=alert_id,
            stable_group_key=stable_group_key,
        )
        status, accepted = request_json(
            f"{self.base_url}/incidents/reanalyze",
            "POST",
            {
                "case_id": case_id,
                "representative_alert_id": alert_id,
                "stable_group_id": group_id,
                "stable_group_key": stable_group_key,
                "cohort_id": cohort_id,
                "dispatch_id": dispatch_id,
                "release_id": RELEASE_ID,
                "requested_by": "controlled-retirement-test",
                "reason": (
                    "Complete a real controlled claim/result lifecycle."
                ),
            },
        )
        self.assertEqual(status, 202, accepted)
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            connection.row_factory = sqlite3.Row
            job = connection.execute(
                """
                SELECT * FROM durable_jobs
                WHERE job_type = 'incident_response_analysis'
                  AND dedupe_key = ?
                """,
                (group_id,),
            ).fetchone()
        self.assertIsNotNone(job)
        status, claim = request_json(
            f"{self.base_url}/jobs/status",
            "POST",
            {
                "job_type": "incident_response_analysis",
                "dedupe_key": group_id,
                "status": "processing",
                "error": "",
                "lease_token": "",
                "retryable": True,
                "expected_job_id": int(job["id"]),
                "expected_representative_alert_id": alert_id,
                "expected_dispatch_id": dispatch_id,
                "expected_stable_group_key": stable_group_key,
            },
        )
        self.assertEqual(status, 200, claim)
        result_payload = self.controlled_incident_result_payload(
            analysis_id=analysis_id,
            claim=claim,
        )
        status, indexed = request_json(
            f"{self.base_url}/analysis/result",
            "POST",
            result_payload,
        )
        self.assertEqual(status, 200, indexed)
        self.assertTrue(indexed["second_opinion_recorded"])
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            connection.row_factory = sqlite3.Row
            completed = connection.execute(
                "SELECT * FROM durable_jobs WHERE id = ?",
                (int(job["id"]),),
            ).fetchone()
        self.assertEqual(completed["status"], "completed")
        self.assertEqual(int(completed["attempt_count"]), 1)
        self.assertTrue(completed["processing_started_at"])
        return {
            "rank": rank,
            "dispatch_id": dispatch_id,
            "job_id": int(job["id"]),
            "run_id": accepted["run_id"],
            "analysis_id": analysis_id,
        }

    def prepare_failed_controlled_retirement(
        self,
        *,
        case_id: str = "ir-controlled-retirement",
        group_id: str = "81818181818181818181",
        alert_id: str = "controlled-retirement-alert",
        stable_group_key: str = "v2|controlled|retirement",
        cohort_id: str = "controlled-cohort-retirement",
        dispatch_id: str = "8" * 64,
        prior_analysis_id: str = "controlled-prior-ir-analysis",
        member_rank: int = 7,
        cohort_size: int = 20,
        retired_release_id: str = RELEASE_ID,
        replacement_release_id: str = REPLACEMENT_RELEASE_ID,
        retirement_reason: str = (
            "Retire the failed controlled evaluation before a fresh cohort."
        ),
    ) -> tuple[dict, dict]:
        self.seed_controlled_incident_case(
            case_id=case_id,
            group_id=group_id,
            alert_id=alert_id,
            stable_group_key=stable_group_key,
            prior_analysis_id=prior_analysis_id,
        )
        self.start_controlled(release_id=retired_release_id)
        dispatch = {
            "case_id": case_id,
            "representative_alert_id": alert_id,
            "stable_group_id": group_id,
            "stable_group_key": stable_group_key,
            "cohort_id": cohort_id,
            "dispatch_id": dispatch_id,
            "release_id": retired_release_id,
            "requested_by": "controlled-retirement-test",
            "reason": "Create one exact failed controlled attempt.",
        }
        status, accepted = request_json(
            f"{self.base_url}/incidents/reanalyze",
            "POST",
            dispatch,
        )
        self.assertEqual(status, 202, accepted)
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            connection.row_factory = sqlite3.Row
            job = connection.execute(
                """
                SELECT * FROM durable_jobs
                WHERE job_type = 'incident_response_analysis'
                  AND dedupe_key = ?
                """,
                (group_id,),
            ).fetchone()
        self.assertIsNotNone(job)
        status, claim = request_json(
            f"{self.base_url}/jobs/status",
            "POST",
            {
                "job_type": "incident_response_analysis",
                "dedupe_key": group_id,
                "status": "processing",
                "error": "",
                "lease_token": "",
                "retryable": True,
                "expected_job_id": int(job["id"]),
                "expected_representative_alert_id": alert_id,
                "expected_dispatch_id": dispatch_id,
                "expected_stable_group_key": stable_group_key,
            },
        )
        self.assertEqual(status, 200, claim)
        self.assertEqual(
            claim["claim"]["reanalysis_run_id"],
            accepted["run_id"],
        )
        status, failed = request_json(
            f"{self.base_url}/jobs/status",
            "POST",
            {
                "job_type": "incident_response_analysis",
                "dedupe_key": group_id,
                "status": "failed",
                "error": "Synthetic controlled worker failure.",
                "lease_token": claim["lease_token"],
                "retryable": True,
            },
        )
        self.assertEqual(status, 200, failed)
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            connection.row_factory = sqlite3.Row
            pending = connection.execute(
                "SELECT * FROM durable_jobs WHERE id = ?",
                (int(job["id"]),),
            ).fetchone()
        self.assertEqual(pending["status"], "pending")
        self.assertEqual(int(pending["attempt_count"]), 1)
        completed_members = [
            self.complete_controlled_retirement_member_lifecycle(
                rank=rank,
                cohort_id=cohort_id,
                dispatch_id=hashlib.sha256(
                    f"{cohort_id}:completed:{rank}".encode("utf-8")
                ).hexdigest(),
            )
            for rank in range(1, member_rank)
        ]
        absent_dispatch_ids = [
            hashlib.sha256(
                f"{cohort_id}:absent:{rank}".encode("utf-8")
            ).hexdigest()
            for rank in range(member_rank + 1, cohort_size + 1)
        ]
        stop_process(self.process)
        self.process = None
        self.start_controlled(
            release_id=replacement_release_id,
        )
        request = {
            "schema": (
                "onion-sentinel-controlled-evaluation-retirement-v1"
            ),
            "absent_dispatch_ids": absent_dispatch_ids,
            "case_id": case_id,
            "cohort_id": cohort_id,
            "cohort_size": cohort_size,
            "completed_dispatch_ids": [
                member["dispatch_id"] for member in completed_members
            ],
            "dispatch_id": dispatch_id,
            "expected_attempt_count": 1,
            "expected_attempt_id": claim["claim"][
                "reanalysis_attempt_id"
            ],
            "expected_job_payload_sha256": hashlib.sha256(
                str(pending["payload_json"]).encode("utf-8")
            ).hexdigest(),
            "expected_prior_analysis_id": prior_analysis_id,
            "failure_attestation_sha256": "a" * 64,
            "job_id": int(job["id"]),
            "manifest_sha256": "b" * 64,
            "member_rank": member_rank,
            "reanalysis_run_id": accepted["run_id"],
            "reason": retirement_reason,
            "replacement_release_id": replacement_release_id,
            "representative_alert_id": alert_id,
            "retired_release_id": retired_release_id,
            "stable_group_id": group_id,
            "stable_group_key": stable_group_key,
            "start_sha256": "d" * 64,
        }
        return request, {
            "accepted": accepted,
            "claim": claim,
            "completed_members": completed_members,
            "pending": dict(pending),
        }

    def claim_controlled_job(
        self,
        *,
        job_id: int,
        group_id: str,
        alert_id: str,
        stable_group_key: str,
        dispatch_id: str,
    ) -> tuple[int, dict]:
        return request_json(
            f"{self.base_url}/jobs/status",
            "POST",
            {
                "job_type": "ai_analysis",
                "dedupe_key": group_id,
                "status": "processing",
                "error": "",
                "lease_token": "",
                "retryable": True,
                "expected_job_id": job_id,
                "expected_representative_alert_id": alert_id,
                "expected_dispatch_id": dispatch_id,
                "expected_stable_group_key": stable_group_key,
            },
        )

    def controlled_result_payload(
        self,
        *,
        analysis_id: str,
        claim: dict,
    ) -> dict:
        claimed_job = claim["claim"]
        job_payload = claimed_job["payload"]
        identity = {
            "job_id": int(claimed_job["job_id"]),
            "job_type": "ai_analysis",
            "lease_token": claim["lease_token"],
            "cohort_id": job_payload["cohort_id"],
            "dispatch_id": job_payload["dispatch_id"],
            "representative_alert_id": (
                job_payload["representative_alert_id"]
            ),
            "stable_group_id": job_payload["stable_group_id"],
            "stable_group_key": job_payload["stable_group_key"],
            "agent_role": "soc-analyst",
            "reanalysis_attempt_id": "",
            "release_id": RELEASE_ID,
        }
        claim_digest = hashlib.sha256(
            json.dumps(
                identity,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
        ).hexdigest()
        response = {
            "detection_outcome": "Inconclusive",
            "bluf": "Controlled evaluation synthetic result.",
            "summary": "Synthetic result used only for lifecycle testing.",
            "confidence": "low",
            "_analysis_evaluation_memory_frozen": True,
            "_analysis_controlled_claim_sha256": claim_digest,
        }
        return {
            "analysis_id": analysis_id,
            "alert_id": identity["representative_alert_id"],
            "agent_role": "soc-analyst",
            "reanalysis_attempt_id": None,
            "generated_at": "2026-07-27 12:01:00+00:00",
            "model": "synthetic-controlled-model",
            "model_path": "frontier-codex-cli",
            "artifact_path": "/controlled/evaluation/result.json",
            "evidence_hash": "e" * 64,
            "response": response,
            "controlled_job": identity,
        }

    def controlled_incident_result_payload(
        self,
        *,
        analysis_id: str,
        claim: dict,
    ) -> dict:
        claimed_job = claim["claim"]
        job_payload = claimed_job["payload"]
        identity = {
            "job_id": int(claimed_job["job_id"]),
            "job_type": "incident_response_analysis",
            "lease_token": claim["lease_token"],
            "cohort_id": job_payload["cohort_id"],
            "dispatch_id": job_payload["dispatch_id"],
            "representative_alert_id": (
                job_payload["representative_alert_id"]
            ),
            "stable_group_id": job_payload["stable_group_id"],
            "stable_group_key": job_payload["stable_group_key"],
            "agent_role": "incident-responder",
            "reanalysis_attempt_id": claimed_job[
                "reanalysis_attempt_id"
            ],
            "release_id": RELEASE_ID,
        }
        claim_digest = hashlib.sha256(
            json.dumps(
                identity,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
        ).hexdigest()
        generated_at = dt.datetime.now(
            dt.timezone.utc
        ).isoformat()
        response = {
            "detection_outcome": "Inconclusive",
            "bluf": "Controlled incident lifecycle result.",
            "summary": (
                "Synthetic content with a real durable lifecycle."
            ),
            "confidence": "low",
            "_analysis_provider": "codex-cli",
            "_analysis_evaluation_memory_frozen": True,
            "_analysis_controlled_claim_sha256": claim_digest,
            "_second_opinion": {
                "trigger": "required",
                "status": "completed",
                "error": "",
                "runtime_seconds": 0.25,
                "response": {
                    "detection_outcome": "Inconclusive",
                    "confidence": "low",
                    "_analysis_model": (
                        "synthetic-controlled-reviewer"
                    ),
                    "_analysis_model_path": "frontier-codex-cli",
                },
                "comparison": {
                    "agreement": "agree",
                    "material_disagreement": False,
                    "disputed_fields": [],
                },
                "memory_writeback": {"accepted": 0},
            },
        }
        return {
            "analysis_id": analysis_id,
            "alert_id": identity["representative_alert_id"],
            "agent_role": "incident-responder",
            "reanalysis_attempt_id": identity[
                "reanalysis_attempt_id"
            ],
            "generated_at": generated_at,
            "model": "synthetic-controlled-primary",
            "provider": "codex-cli",
            "model_path": "frontier-codex-cli",
            "artifact_path": "/controlled/evaluation/result.json",
            "evidence_hash": "e" * 64,
            "response": response,
            "controlled_job": identity,
        }

    def test_startup_requires_every_explicit_runtime_field(self) -> None:
        for key in (
            "ALERT_STORE_DB",
            "ALERT_STORE_HOST",
            "ALERT_STORE_PORT",
            "SCORING_RULES_PATH",
            "ONION_SENTINEL_EVALUATION_TOKEN",
        ):
            with self.subTest(key=key):
                environment = self.controlled_environment()
                del environment[key]
                self.assert_startup_rejected(
                    environment,
                    "controlled evaluation requires loopback",
                )

    def test_startup_rejects_production_and_non_loopback_listeners(self) -> None:
        cases = (
            ("production-port", "127.0.0.1", "8787"),
            ("wildcard-host", "0.0.0.0", str(available_port())),
        )
        for label, host, port in cases:
            with self.subTest(case=label):
                environment = self.controlled_environment()
                environment["ALERT_STORE_HOST"] = host
                environment["ALERT_STORE_PORT"] = port
                self.assert_startup_rejected(
                    environment,
                    "controlled evaluation requires loopback",
                )

    def test_startup_rejects_sidecars_credentials_and_unsafe_database(self) -> None:
        sidecar = Path(f"{self.db}-journal")
        sidecar.write_bytes(b"")
        try:
            self.assert_startup_rejected(
                self.controlled_environment(),
                "controlled evaluation refuses database recovery sidecar",
            )
        finally:
            sidecar.unlink(missing_ok=True)

        for credential_key in (
            "TELEGRAM_BOT_TOKEN",
            "N8N_POST_COMMIT_TOKEN",
        ):
            with self.subTest(credential=credential_key):
                environment = self.controlled_environment()
                environment[credential_key] = "must-not-enter-evaluation"
                self.assert_startup_rejected(
                    environment,
                    "and no configured production credentials",
                )

        self.db.chmod(0o660)
        try:
            self.assert_startup_rejected(
                self.controlled_environment(),
                "database must be an owner-controlled regular file",
            )
        finally:
            self.db.chmod(0o600)

        linked_db = self.runtime / "linked.sqlite3"
        linked_db.symlink_to(self.db)
        environment = self.controlled_environment()
        environment["ALERT_STORE_DB"] = str(linked_db)
        self.assert_startup_rejected(
            environment,
            "database must be an owner-controlled regular file",
        )

    def test_startup_rejects_pre_idempotency_schema_and_index_drift(
        self,
    ) -> None:
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            connection.execute(
                "DROP INDEX "
                "idx_incident_reanalysis_runs_controlled_dispatch"
            )
            connection.execute(
                "ALTER TABLE incident_reanalysis_runs "
                "DROP COLUMN controlled_receipt_json"
            )
            connection.execute(
                "ALTER TABLE incident_reanalysis_runs "
                "DROP COLUMN controlled_dispatch_id"
            )
            connection.commit()
        self.assert_startup_rejected(
            self.controlled_environment(),
            (
                "controlled evaluation schema is missing "
                "incident_reanalysis_runs columns"
            ),
        )

        shutil.copy2(self.template_db, self.db)
        self.db.chmod(0o600)
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            connection.execute(
                "DROP INDEX "
                "idx_incident_reanalysis_runs_controlled_dispatch"
            )
            connection.commit()
        self.assert_startup_rejected(
            self.controlled_environment(),
            (
                "controlled evaluation schema is missing incident "
                "reanalysis dispatch uniqueness"
            ),
        )

    def test_health_route_allowlist_and_lifecycle_are_exact_and_read_only(
        self,
    ) -> None:
        before = hashlib.sha256(self.db.read_bytes()).hexdigest()
        _status, health = self.start_controlled()

        self.assertEqual(health["service"], "onion-sentinel-alert-store")
        self.assertEqual(health["release_id"], RELEASE_ID)
        self.assertTrue(health["controlled_evaluation"])
        self.assertTrue(health["evaluation_mode"])
        self.assertEqual(health["runtime_mode"], "controlled-evaluation")
        self.assertEqual(health["listen_host"], "127.0.0.1")
        self.assertEqual(health["listen_port"], int(self.base_url.rsplit(":", 1)[1]))
        self.assertTrue(health["accepting_requests"])
        self.assertEqual(health["active_writes"], 0)
        self.assertFalse(health["background_jobs_enabled"])
        self.assertFalse(health["outbound_network_enabled"])
        self.assertFalse(health["worker_wake_signaling_enabled"])
        self.assertEqual(
            health["route_allowlist"],
            sorted(
                [
                    "GET /health",
                    "POST /ai/request",
                    "POST /analysis/result",
                    "POST /controlled-evaluations/retire",
                    "POST /incidents/reanalyze",
                    "POST /jobs/status",
                ]
            ),
        )

        for method, route, payload in (
            ("GET", "/metrics", None),
            ("GET", "/analyst-status", None),
            ("POST", "/alert", {}),
            ("POST", "/enrich", {}),
            ("POST", "/incidents/reanalyze-all", {}),
            ("POST", "/rescore", {}),
        ):
            with self.subTest(method=method, route=route):
                status, response = request_json(
                    f"{self.base_url}{route}",
                    method,
                    payload,
                )
                self.assertEqual(status, 403)
                self.assertEqual(response["status"], "forbidden")

        for method, route, payload in (
            ("GET", "/health?unexpected=1", None),
            ("POST", "/analysis/result?unexpected=1", {}),
            ("POST", "/jobs/status?unexpected=1", {}),
        ):
            with self.subTest(query_route=route):
                status, response = request_json(
                    f"{self.base_url}{route}",
                    method,
                    payload,
                )
                self.assertEqual(status, 403)
                self.assertEqual(response["status"], "forbidden")

        stop_process(self.process)
        self.process = None
        self.assertEqual(
            hashlib.sha256(self.db.read_bytes()).hexdigest(),
            before,
        )
        for suffix in ("-journal", "-wal", "-shm"):
            self.assertFalse(Path(f"{self.db}{suffix}").exists())

    def test_unowned_job_transitions_and_unbound_results_are_rejected(self) -> None:
        before = hashlib.sha256(self.db.read_bytes()).hexdigest()
        self.start_controlled()
        group_id = "0123456789abcdefabcd"
        cases = (
            (
                "/jobs/status",
                {
                    "job_type": "ai_analysis",
                    "dedupe_key": group_id,
                    "status": "pending",
                    "lease_token": "",
                },
            ),
            (
                "/jobs/status",
                {
                    "job_type": "ai_analysis",
                    "dedupe_key": group_id,
                    "status": "processing",
                    "lease_token": "",
                },
            ),
            (
                "/jobs/status",
                {
                    "job_type": "ai_analysis",
                    "dedupe_key": group_id,
                    "status": "completed",
                    "lease_token": (
                        "11111111-1111-4111-8111-111111111111"
                    ),
                },
            ),
            ("/analysis/result", {}),
            (
                "/analysis/result",
                {
                    "analysis_id": "unbound-evaluation-result",
                    "controlled_job": {
                        "job_id": 1,
                        "job_type": "ai_analysis",
                    },
                },
            ),
        )
        for route, payload in cases:
            with self.subTest(route=route, status=payload.get("status")):
                status, response = request_json(
                    f"{self.base_url}{route}",
                    "POST",
                    payload,
                )
                self.assertEqual(status, 409, response)
                self.assertEqual(response["status"], "rejected")

        stop_process(self.process)
        self.process = None
        self.assertEqual(
            hashlib.sha256(self.db.read_bytes()).hexdigest(),
            before,
        )

    def test_controlled_mutations_require_the_ephemeral_token(self) -> None:
        self.start_controlled()
        before = hashlib.sha256(self.db.read_bytes()).hexdigest()
        payload = {
            "job_type": "ai_analysis",
            "dedupe_key": "0123456789abcdefabcd",
            "status": "processing",
            "lease_token": "",
        }
        for label, token in (
            ("missing", ""),
            ("wrong", "8" * 64),
        ):
            with self.subTest(label=label):
                status, response = request_json(
                    f"{self.base_url}/jobs/status",
                    "POST",
                    payload,
                    evaluation_token=token,
                )
                self.assertEqual(status, 403, response)
                self.assertEqual(
                    response["reason"],
                    "controlled evaluation authorization failed",
                )
        self.assertEqual(
            hashlib.sha256(self.db.read_bytes()).hexdigest(),
            before,
        )

    def test_controlled_retirement_is_exact_atomic_and_idempotent(
        self,
    ) -> None:
        unrelated_group = "91919191919191919191"
        unrelated_job_id = self.seed_controlled_job(
            group_id=unrelated_group,
            alert_id="controlled-retirement-unrelated-alert",
            stable_group_key="v2|controlled|retirement-unrelated",
            dispatch_id="9" * 64,
            cohort_id="controlled-retirement-unrelated",
        )
        retirement, context = (
            self.prepare_failed_controlled_retirement()
        )

        def logical_snapshot() -> tuple[str, ...]:
            with closing(
                sqlite3.connect(self.db, timeout=5)
            ) as connection:
                return tuple(connection.iterdump())

        def one(statement: str, values: tuple = ()) -> dict:
            with closing(
                sqlite3.connect(self.db, timeout=5)
            ) as connection:
                connection.row_factory = sqlite3.Row
                row = connection.execute(statement, values).fetchone()
                self.assertIsNotNone(row)
                return dict(row)

        unrelated_before = one(
            "SELECT * FROM durable_jobs WHERE id = ?",
            (unrelated_job_id,),
        )
        completed_before = [
            {
                "job": one(
                    "SELECT * FROM durable_jobs WHERE id = ?",
                    (member["job_id"],),
                ),
                "run": one(
                    """
                    SELECT * FROM incident_reanalysis_runs
                    WHERE run_id = ?
                    """,
                    (member["run_id"],),
                ),
                "analysis": one(
                    "SELECT * FROM ai_analysis_runs WHERE analysis_id = ?",
                    (member["analysis_id"],),
                ),
                "reviewer": one(
                    """
                    SELECT * FROM ai_second_opinion_runs
                    WHERE analysis_id = ?
                    """,
                    (member["analysis_id"],),
                ),
            }
            for member in context["completed_members"]
        ]
        before_rejection = logical_snapshot()
        wrong_identity = dict(retirement)
        wrong_identity["expected_job_payload_sha256"] = "e" * 64
        status, rejected = request_json(
            f"{self.base_url}/controlled-evaluations/retire",
            "POST",
            wrong_identity,
        )
        self.assertEqual(status, 409, rejected)
        self.assertEqual(rejected["status"], "rejected")
        self.assertEqual(logical_snapshot(), before_rejection)

        for label, token in (
            ("missing", ""),
            ("wrong", "8" * 64),
        ):
            with self.subTest(authentication=label):
                status, rejected = request_json(
                    (
                        f"{self.base_url}"
                        "/controlled-evaluations/retire"
                    ),
                    "POST",
                    retirement,
                    evaluation_token=token,
                )
                self.assertEqual(status, 403, rejected)
                self.assertEqual(
                    rejected["reason"],
                    "controlled evaluation authorization failed",
                )
        self.assertEqual(logical_snapshot(), before_rejection)

        status, receipt = request_json(
            f"{self.base_url}/controlled-evaluations/retire",
            "POST",
            retirement,
        )
        self.assertEqual(status, 200, receipt)
        self.assertTrue(receipt["ok"])
        self.assertEqual(receipt["status"], "retired")
        self.assertTrue(receipt["idempotent"])
        self.assertEqual(
            receipt["schema"],
            (
                "onion-sentinel-controlled-evaluation-"
                "retirement-receipt-v1"
            ),
        )
        self.assertEqual(receipt["identity"], retirement)
        self.assertEqual(receipt["case_agent_status"], "analyzed")
        self.assertEqual(receipt["security_onion_access"], "none")
        self.assertFalse(receipt["security_onion_writes_allowed"])
        self.assertEqual(receipt["model_invocations"], 0)
        self.assertFalse(receipt["worker_wake_signaled"])
        self.assertEqual(
            set(receipt),
            {
                "case_agent_status",
                "idempotent",
                "identity",
                "job_after_sha256",
                "job_before_sha256",
                "lineage_after_sha256",
                "lineage_before_sha256",
                "model_invocations",
                "ok",
                "receipt_sha256",
                "retired_at",
                "retirement_id",
                "schema",
                "security_onion_access",
                "security_onion_writes_allowed",
                "skip_reason",
                "status",
                "target_after",
                "target_before",
                "worker_wake_signaled",
            },
        )
        self.assertRegex(
            receipt["lineage_before_sha256"],
            r"^[a-f0-9]{64}$",
        )
        self.assertRegex(
            receipt["lineage_after_sha256"],
            r"^[a-f0-9]{64}$",
        )
        self.assertNotEqual(
            receipt["lineage_before_sha256"],
            receipt["lineage_after_sha256"],
        )
        target_before = receipt["target_before"]
        target_after = receipt["target_after"]
        self.assertEqual(target_before["state"], "pending")
        self.assertEqual(target_after["state"], "retired")
        self.assertTrue(
            target_before["job"]["processing_started_at"]
        )
        self.assertTrue(target_before["attempt"]["started_at"])
        self.assertTrue(target_before["attempt"]["completed_at"])
        self.assertIsNone(
            target_after["job"]["processing_started_at"]
        )
        self.assertIsNone(
            target_after["failure"]["job"]["raw_sha256"]
        )
        self.assertIsNone(
            target_after["failure"]["run_case"]["raw_sha256"]
        )
        self.assertEqual(
            target_before["failure"]["attempt"]["raw_sha256"],
            target_after["failure"]["attempt"]["raw_sha256"],
        )
        self.assertEqual(
            target_before["failure"]["job"]["normalized_sha256"],
            target_before["failure"]["run_case"][
                "normalized_sha256"
            ],
        )
        self.assertEqual(
            target_before["failure"]["job"]["normalized_sha256"],
            target_before["failure"]["attempt"]["normalized_sha256"],
        )
        unsigned = dict(receipt)
        embedded = unsigned.pop("receipt_sha256")
        canonical = json.dumps(
            unsigned,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        self.assertEqual(
            embedded,
            hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        )

        job = one(
            "SELECT * FROM durable_jobs WHERE id = ?",
            (retirement["job_id"],),
        )
        self.assertEqual(job["status"], "completed")
        self.assertEqual(int(job["attempt_count"]), 1)
        self.assertIsNone(job["lease_token"])
        self.assertIsNone(job["lease_expires_at"])
        self.assertIsNone(job["last_error"])
        self.assertIsNone(job["processing_started_at"])
        self.assertEqual(int(job["rerun_requested"]), 0)
        self.assertEqual(job["completed_at"], receipt["retired_at"])
        self.assertEqual(
            job["last_completed_at"],
            receipt["retired_at"],
        )
        self.assertEqual(job["updated_at"], receipt["retired_at"])

        run = one(
            "SELECT * FROM incident_reanalysis_runs WHERE run_id = ?",
            (retirement["reanalysis_run_id"],),
        )
        self.assertEqual(run["status"], "partial")
        self.assertIsNotNone(run["completed_at"])
        run_case = one(
            """
            SELECT * FROM incident_reanalysis_run_cases
            WHERE run_id = ? AND case_id = ?
            """,
            (
                retirement["reanalysis_run_id"],
                retirement["case_id"],
            ),
        )
        self.assertEqual(run_case["status"], "skipped")
        self.assertEqual(
            run_case["skip_reason"],
            receipt["skip_reason"],
        )
        self.assertIsNone(run_case["latest_error"])
        self.assertIsNone(run_case["analysis_id"])
        attempt = one(
            """
            SELECT * FROM incident_reanalysis_attempts
            WHERE attempt_id = ?
            """,
            (retirement["expected_attempt_id"],),
        )
        self.assertEqual(attempt["status"], "failed")
        self.assertEqual(
            int(attempt["durable_attempt_count"]),
            retirement["expected_attempt_count"],
        )
        self.assertIsNone(attempt["analysis_id"])
        incident = one(
            "SELECT * FROM incident_response_cases WHERE case_id = ?",
            (retirement["case_id"],),
        )
        self.assertEqual(incident["agent_status"], "analyzed")
        self.assertEqual(
            incident["latest_analysis_id"],
            retirement["expected_prior_analysis_id"],
        )
        self.assertIsNone(incident["latest_error"])
        event = one(
            """
            SELECT COUNT(*) AS count
            FROM incident_response_events
            WHERE case_id = ?
              AND event_type = 'controlled_evaluation_retired'
            """,
            (retirement["case_id"],),
        )
        self.assertEqual(int(event["count"]), 1)
        self.assertEqual(
            one(
                "SELECT * FROM durable_jobs WHERE id = ?",
                (unrelated_job_id,),
            ),
            unrelated_before,
        )
        completed_after = [
            {
                "job": one(
                    "SELECT * FROM durable_jobs WHERE id = ?",
                    (member["job_id"],),
                ),
                "run": one(
                    """
                    SELECT * FROM incident_reanalysis_runs
                    WHERE run_id = ?
                    """,
                    (member["run_id"],),
                ),
                "analysis": one(
                    "SELECT * FROM ai_analysis_runs WHERE analysis_id = ?",
                    (member["analysis_id"],),
                ),
                "reviewer": one(
                    """
                    SELECT * FROM ai_second_opinion_runs
                    WHERE analysis_id = ?
                    """,
                    (member["analysis_id"],),
                ),
            }
            for member in context["completed_members"]
        ]
        self.assertEqual(completed_after, completed_before)
        after_first = logical_snapshot()

        status, replay = request_json(
            f"{self.base_url}/controlled-evaluations/retire",
            "POST",
            retirement,
        )
        self.assertEqual(status, 200, replay)
        self.assertEqual(replay, receipt)
        self.assertEqual(logical_snapshot(), after_first)

        conflict = dict(retirement)
        conflict["reason"] = (
            "A changed reason cannot reuse the retired lineage identity."
        )
        status, rejected = request_json(
            f"{self.base_url}/controlled-evaluations/retire",
            "POST",
            conflict,
        )
        self.assertEqual(status, 409, rejected)
        self.assertEqual(rejected["status"], "rejected")
        self.assertEqual(logical_snapshot(), after_first)
        self.assertEqual(
            context["claim"]["claim"]["reanalysis_attempt_id"],
            retirement["expected_attempt_id"],
        )

    def test_controlled_retirement_rank_one_replays_exact_scalars_and_bytes(
        self,
    ) -> None:
        reason = (
            "Retire rank one after failure observed at "
            "2026-07-28T12:34:56Z without rewriting this timestamp."
        )
        retirement, _ = self.prepare_failed_controlled_retirement(
            cohort_id="controlled-retirement-rank-one",
            dispatch_id=hashlib.sha256(b"retirement-rank-one").hexdigest(),
            prior_analysis_id="",
            member_rank=1,
            cohort_size=20,
            retirement_reason=reason,
        )
        endpoint = (
            f"{self.base_url}/controlled-evaluations/retire"
        )
        status, first_bytes = request_json_bytes(
            endpoint,
            retirement,
        )
        self.assertEqual(status, 200, first_bytes)
        first = json.loads(first_bytes)
        self.assertEqual(
            first_bytes,
            json.dumps(
                first,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8"),
        )
        self.assertEqual(
            first["identity"]["expected_prior_analysis_id"],
            "",
        )
        self.assertEqual(first["identity"]["reason"], reason)
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            after_first = tuple(connection.iterdump())
            stored = connection.execute(
                """
                SELECT detail_json FROM incident_response_events
                WHERE case_id = ?
                  AND event_type = 'controlled_evaluation_retired'
                """,
                (retirement["case_id"],),
            ).fetchone()[0]
        self.assertEqual(stored.encode("utf-8"), first_bytes)
        stop_process(self.process)
        self.process = None
        self.start_controlled(
            release_id=REPLACEMENT_RELEASE_ID,
        )
        endpoint = (
            f"{self.base_url}/controlled-evaluations/retire"
        )
        status, replay_bytes = request_json_bytes(
            endpoint,
            retirement,
        )
        self.assertEqual(status, 200, replay_bytes)
        self.assertEqual(replay_bytes, first_bytes)
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            self.assertEqual(tuple(connection.iterdump()), after_first)

    def test_controlled_retirement_supports_same_release_recovery(
        self,
    ) -> None:
        retirement, _ = self.prepare_failed_controlled_retirement(
            cohort_id="controlled-retirement-same-release",
            dispatch_id=hashlib.sha256(
                b"retirement-same-release"
            ).hexdigest(),
            prior_analysis_id="",
            member_rank=1,
            cohort_size=1,
            retired_release_id=REPLACEMENT_RELEASE_ID,
            replacement_release_id=REPLACEMENT_RELEASE_ID,
        )
        status, receipt = request_json(
            f"{self.base_url}/controlled-evaluations/retire",
            "POST",
            retirement,
        )
        self.assertEqual(status, 200, receipt)
        self.assertEqual(
            receipt["identity"]["retired_release_id"],
            REPLACEMENT_RELEASE_ID,
        )
        self.assertEqual(
            receipt["identity"]["replacement_release_id"],
            REPLACEMENT_RELEASE_ID,
        )
        status, replay = request_json(
            f"{self.base_url}/controlled-evaluations/retire",
            "POST",
            retirement,
        )
        self.assertEqual(status, 200, replay)
        self.assertEqual(replay, receipt)

    def test_controlled_retirement_rank_twenty_is_generic(
        self,
    ) -> None:
        retirement, context = self.prepare_failed_controlled_retirement(
            cohort_id="controlled-retirement-rank-twenty",
            dispatch_id=hashlib.sha256(
                b"retirement-rank-twenty"
            ).hexdigest(),
            member_rank=20,
            cohort_size=20,
        )
        self.assertEqual(len(context["completed_members"]), 19)
        self.assertEqual(retirement["absent_dispatch_ids"], [])
        status, receipt = request_json(
            f"{self.base_url}/controlled-evaluations/retire",
            "POST",
            retirement,
        )
        self.assertEqual(status, 200, receipt)
        self.assertEqual(receipt["identity"]["member_rank"], 20)
        self.assertEqual(receipt["target_before"]["state"], "pending")
        self.assertEqual(receipt["target_after"]["state"], "retired")
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            job = connection.execute(
                "SELECT status FROM durable_jobs WHERE id = ?",
                (retirement["job_id"],),
            ).fetchone()
        self.assertEqual(job[0], "completed")

    def test_controlled_retirement_replay_rejects_noncanonical_store(
        self,
    ) -> None:
        retirement, _ = self.prepare_failed_controlled_retirement(
            cohort_id="controlled-retirement-noncanonical-replay",
            dispatch_id=hashlib.sha256(
                b"retirement-noncanonical-replay"
            ).hexdigest(),
            member_rank=1,
            cohort_size=1,
        )
        status, receipt = request_json(
            f"{self.base_url}/controlled-evaluations/retire",
            "POST",
            retirement,
        )
        self.assertEqual(status, 200, receipt)
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            connection.execute(
                """
                UPDATE incident_response_events
                SET detail_json = ?
                WHERE case_id = ?
                  AND event_type = 'controlled_evaluation_retired'
                """,
                (
                    json.dumps(receipt, ensure_ascii=False),
                    retirement["case_id"],
                ),
            )
            connection.commit()
            before = tuple(connection.iterdump())
        status, rejected = request_json(
            f"{self.base_url}/controlled-evaluations/retire",
            "POST",
            retirement,
        )
        self.assertEqual(status, 409, rejected)
        self.assertEqual(
            rejected["reason"],
            (
                "controlled evaluation retirement receipt "
                "is not canonical"
            ),
        )
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            self.assertEqual(tuple(connection.iterdump()), before)

    def test_controlled_retirement_middle_rank_is_generic(
        self,
    ) -> None:
        retirement, context = self.prepare_failed_controlled_retirement(
            cohort_id="controlled-retirement-rank-ten",
            dispatch_id=hashlib.sha256(
                b"retirement-rank-ten"
            ).hexdigest(),
            member_rank=10,
            cohort_size=20,
        )
        self.assertEqual(len(context["completed_members"]), 9)
        self.assertEqual(len(retirement["absent_dispatch_ids"]), 10)
        status, receipt = request_json(
            f"{self.base_url}/controlled-evaluations/retire",
            "POST",
            retirement,
        )
        self.assertEqual(status, 200, receipt)
        self.assertEqual(receipt["identity"]["member_rank"], 10)
        self.assertEqual(receipt["target_before"]["rank"], 10)
        self.assertEqual(receipt["target_after"]["rank"], 10)
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            job = connection.execute(
                "SELECT status FROM durable_jobs WHERE id = ?",
                (retirement["job_id"],),
            ).fetchone()
        self.assertEqual(job[0], "completed")

    def test_controlled_retirement_rejects_coercive_numeric_types(
        self,
    ) -> None:
        retirement, _ = self.prepare_failed_controlled_retirement()
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            before = tuple(connection.iterdump())
        for field in (
            "job_id",
            "member_rank",
            "cohort_size",
            "expected_attempt_count",
        ):
            for replacement in (str(retirement[field]), True):
                with self.subTest(
                    field=field,
                    replacement_type=type(replacement).__name__,
                ):
                    changed = dict(retirement)
                    changed[field] = replacement
                    status, rejected = request_json(
                        (
                            f"{self.base_url}"
                            "/controlled-evaluations/retire"
                        ),
                        "POST",
                        changed,
                    )
                    self.assertEqual(status, 409, rejected)
                    self.assertEqual(
                        rejected["reason"],
                        (
                            "controlled evaluation retirement identity "
                            "is invalid"
                        ),
                    )
                    with closing(
                        sqlite3.connect(self.db, timeout=5)
                    ) as connection:
                        self.assertEqual(
                            tuple(connection.iterdump()),
                            before,
                        )
        malformed_requests = []
        missing = dict(retirement)
        missing.pop("reason")
        malformed_requests.append(("missing-field", missing))
        extra = dict(retirement)
        extra["unexpected"] = "not allowed"
        malformed_requests.append(("extra-field", extra))
        for label, changed in malformed_requests:
            with self.subTest(malformed=label):
                status, rejected = request_json(
                    (
                        f"{self.base_url}"
                        "/controlled-evaluations/retire"
                    ),
                    "POST",
                    changed,
                )
                self.assertEqual(status, 409, rejected)
                with closing(
                    sqlite3.connect(self.db, timeout=5)
                ) as connection:
                    self.assertEqual(
                        tuple(connection.iterdump()),
                        before,
                    )

    def test_controlled_retirement_rejects_execution_telemetry_drift(
        self,
    ) -> None:
        retirement, context = (
            self.prepare_failed_controlled_retirement()
        )
        member = context["completed_members"][0]
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            connection.execute(
                """
                UPDATE incident_reanalysis_run_cases
                SET executed_model = 'contradictory-model',
                    executed_provider = 'contradictory-provider',
                    executed_model_path = 'contradictory-path'
                WHERE run_id = ?
                """,
                (member["run_id"],),
            )
            connection.execute(
                """
                UPDATE incident_reanalysis_attempts
                SET executed_model = 'contradictory-model',
                    executed_provider = 'contradictory-provider',
                    executed_model_path = 'contradictory-path'
                WHERE run_id = ?
                """,
                (member["run_id"],),
            )
            connection.commit()
            before = tuple(connection.iterdump())
        status, rejected = request_json(
            f"{self.base_url}/controlled-evaluations/retire",
            "POST",
            retirement,
        )
        self.assertEqual(status, 409, rejected)
        self.assertIn(
            "completed primary-and-reviewer lineage",
            rejected["reason"],
        )
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            self.assertEqual(tuple(connection.iterdump()), before)

    def test_controlled_retirement_rejects_reviewer_primary_drift(
        self,
    ) -> None:
        retirement, context = (
            self.prepare_failed_controlled_retirement()
        )
        member = context["completed_members"][0]
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            connection.execute(
                """
                UPDATE ai_second_opinion_runs
                SET primary_model = 'contradictory-model',
                    primary_model_path = 'contradictory-path',
                    primary_outcome = 'contradictory-outcome',
                    primary_confidence = 'contradictory-confidence'
                WHERE analysis_id = ?
                """,
                (member["analysis_id"],),
            )
            connection.commit()
            before = tuple(connection.iterdump())
        status, rejected = request_json(
            f"{self.base_url}/controlled-evaluations/retire",
            "POST",
            retirement,
        )
        self.assertEqual(status, 409, rejected)
        self.assertIn(
            "completed primary-and-reviewer lineage",
            rejected["reason"],
        )
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            self.assertEqual(tuple(connection.iterdump()), before)

    def test_controlled_retirement_rejects_contradictory_failure_records(
        self,
    ) -> None:
        retirement, _ = self.prepare_failed_controlled_retirement()
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            connection.execute(
                """
                UPDATE durable_jobs SET last_error = 'job failure'
                WHERE id = ?
                """,
                (retirement["job_id"],),
            )
            connection.execute(
                """
                UPDATE incident_reanalysis_run_cases
                SET latest_error = 'run case failure'
                WHERE run_id = ? AND case_id = ?
                """,
                (
                    retirement["reanalysis_run_id"],
                    retirement["case_id"],
                ),
            )
            connection.execute(
                """
                UPDATE incident_reanalysis_attempts
                SET latest_error = 'attempt failure'
                WHERE attempt_id = ?
                """,
                (retirement["expected_attempt_id"],),
            )
            connection.commit()
            before = tuple(connection.iterdump())
        status, rejected = request_json(
            f"{self.base_url}/controlled-evaluations/retire",
            "POST",
            retirement,
        )
        self.assertEqual(status, 409, rejected)
        self.assertEqual(
            rejected["reason"],
            (
                "controlled evaluation target failure lineage "
                "is contradictory"
            ),
        )
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            self.assertEqual(tuple(connection.iterdump()), before)

    def test_controlled_retirement_uses_worker_error_normalization(
        self,
    ) -> None:
        retirement, _ = self.prepare_failed_controlled_retirement()
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute(
                """
                UPDATE durable_jobs
                SET last_error = '  Synthetic   controlled worker failure.  '
                WHERE id = ?
                """,
                (retirement["job_id"],),
            )
            connection.commit()
            job_error = connection.execute(
                "SELECT last_error FROM durable_jobs WHERE id = ?",
                (retirement["job_id"],),
            ).fetchone()["last_error"]
            run_case_error = connection.execute(
                """
                SELECT latest_error FROM incident_reanalysis_run_cases
                WHERE run_id = ? AND case_id = ?
                """,
                (
                    retirement["reanalysis_run_id"],
                    retirement["case_id"],
                ),
            ).fetchone()["latest_error"]
            attempt_error = connection.execute(
                """
                SELECT latest_error FROM incident_reanalysis_attempts
                WHERE attempt_id = ?
                """,
                (retirement["expected_attempt_id"],),
            ).fetchone()["latest_error"]
        self.assertNotEqual(job_error, run_case_error)
        self.assertEqual(run_case_error, attempt_error)
        normalized_errors = {
            " ".join(value.strip().split())[:1000]
            for value in (job_error, run_case_error, attempt_error)
        }
        self.assertEqual(
            normalized_errors,
            {"Synthetic controlled worker failure."},
        )
        status, receipt = request_json(
            f"{self.base_url}/controlled-evaluations/retire",
            "POST",
            retirement,
        )
        self.assertEqual(status, 200, receipt)
        failure = receipt["target_before"]["failure"]
        self.assertNotEqual(
            failure["job"]["raw_sha256"],
            failure["run_case"]["raw_sha256"],
        )
        self.assertEqual(
            failure["job"]["normalized_sha256"],
            failure["run_case"]["normalized_sha256"],
        )
        self.assertEqual(
            failure["job"]["normalized_sha256"],
            failure["attempt"]["normalized_sha256"],
        )
        self.assertNotEqual(
            receipt["lineage_before_sha256"],
            receipt["lineage_after_sha256"],
        )

    def test_controlled_retirement_rolls_back_after_late_failure(
        self,
    ) -> None:
        retirement, _ = self.prepare_failed_controlled_retirement()
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            connection.execute(
                """
                CREATE TRIGGER inject_controlled_retirement_failure
                BEFORE INSERT ON incident_response_events
                WHEN NEW.event_type = 'controlled_evaluation_retired'
                BEGIN
                  SELECT RAISE(ABORT, 'injected late retirement failure');
                END
                """
            )
            connection.commit()
            before = tuple(connection.iterdump())
        status, rejected = request_json(
            f"{self.base_url}/controlled-evaluations/retire",
            "POST",
            retirement,
        )
        self.assertEqual(status, 400, rejected)
        self.assertEqual(
            rejected["reason"],
            "SQLITE_CONSTRAINT: injected late retirement failure",
        )
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            self.assertEqual(tuple(connection.iterdump()), before)

    def test_controlled_retirement_rejects_incomplete_completed_lineage(
        self,
    ) -> None:
        retirement, context = (
            self.prepare_failed_controlled_retirement()
        )
        missing = context["completed_members"][2]
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            connection.execute(
                """
                DELETE FROM ai_second_opinion_runs
                WHERE analysis_id = ?
                """,
                (missing["analysis_id"],),
            )
            connection.commit()
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            before = tuple(connection.iterdump())
        status, rejected = request_json(
            f"{self.base_url}/controlled-evaluations/retire",
            "POST",
            retirement,
        )
        self.assertEqual(status, 409, rejected)
        self.assertIn(
            "completed primary-and-reviewer lineage",
            rejected["reason"],
        )
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            self.assertEqual(tuple(connection.iterdump()), before)

    def test_controlled_retirement_rejects_nonabsent_later_rank(
        self,
    ) -> None:
        retirement, _ = self.prepare_failed_controlled_retirement()
        timestamp = "2020-01-01T00:01:00Z"
        group_id = "abababababababababab"
        alert_id = "unexpected-controlled-rank-eight"
        job_payload = {
            "agent_role": "incident-responder",
            "case_id": "ir-unexpected-controlled-rank-eight",
            "alert_id": alert_id,
            "group_id": group_id,
            "dashboard_group_id": group_id[:12],
            "representative_alert_id": alert_id,
            "stable_group_id": group_id,
            "stable_group_key": "v2|controlled|unexpected-rank-eight",
            "cohort_id": retirement["cohort_id"],
            "dispatch_id": retirement["absent_dispatch_ids"][0],
            "release_id": RELEASE_ID,
            "reanalysis_run_id": "irr-unexpected-controlled-rank-eight",
            "reanalysis_release_id": RELEASE_ID,
            "manual_reanalysis": True,
        }
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            connection.execute(
                """
                INSERT INTO durable_jobs (
                    job_type, dedupe_key, payload_json, status, priority,
                    attempt_count, max_attempts, next_attempt_at,
                    created_at, updated_at, requested_at, rerun_requested
                ) VALUES (
                    'incident_response_analysis', ?, ?, 'pending',
                    1200, 0, 12, ?, ?, ?, ?, 0
                )
                """,
                (
                    group_id,
                    json.dumps(job_payload, separators=(",", ":")),
                    timestamp,
                    timestamp,
                    timestamp,
                    timestamp,
                ),
            )
            connection.commit()
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            before = tuple(connection.iterdump())
        status, rejected = request_json(
            f"{self.base_url}/controlled-evaluations/retire",
            "POST",
            retirement,
        )
        self.assertEqual(status, 409, rejected)
        self.assertEqual(
            rejected["reason"],
            "controlled evaluation cohort job/run census is not exact",
        )
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            self.assertEqual(tuple(connection.iterdump()), before)

    def test_controlled_retirement_route_is_denied_in_production_mode(
        self,
    ) -> None:
        self.start_production()
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            before = tuple(connection.iterdump())
        status, response = request_json(
            f"{self.base_url}/controlled-evaluations/retire",
            "POST",
            {},
        )
        self.assertEqual(status, 403, response)
        self.assertEqual(
            response["reason"],
            (
                "controlled evaluation retirement is unavailable "
                "in production mode"
            ),
        )
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            self.assertEqual(tuple(connection.iterdump()), before)

    def test_controlled_incident_dispatch_is_idempotent_after_lost_response(
        self,
    ) -> None:
        case_id = "ir-controlled-dispatch-replay"
        group_id = "71717171717171717171"
        alert_id = "controlled-incident-dispatch-alert"
        stable_group_key = "v2|controlled|incident-dispatch-replay"
        dispatch_id = "7" * 64
        self.seed_controlled_incident_case(
            case_id=case_id,
            group_id=group_id,
            alert_id=alert_id,
            stable_group_key=stable_group_key,
        )
        self.start_controlled()
        payload = {
            "case_id": case_id,
            "representative_alert_id": alert_id,
            "stable_group_id": group_id,
            "stable_group_key": stable_group_key,
            "cohort_id": "controlled-cohort-ir-replay",
            "dispatch_id": dispatch_id,
            "release_id": RELEASE_ID,
            "requested_by": "controlled-runtime-test",
            "reason": "Prove exact controlled dispatch replay.",
        }

        status, first_receipt = request_json(
            f"{self.base_url}/incidents/reanalyze",
            "POST",
            payload,
        )
        self.assertEqual(status, 202, first_receipt)
        self.assertTrue(first_receipt["ok"])
        self.assertEqual(first_receipt["case_id"], case_id)
        self.assertEqual(first_receipt["dispatch_id"], dispatch_id)

        def database_snapshot() -> tuple[dict[str, int], tuple[str, ...]]:
            with closing(sqlite3.connect(self.db, timeout=5)) as connection:
                tables = [
                    str(row[0])
                    for row in connection.execute(
                        """
                        SELECT name FROM sqlite_master
                        WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
                        ORDER BY name
                        """
                    )
                ]
                counts = {
                    table: int(
                        connection.execute(
                            f'SELECT COUNT(*) FROM "{table}"'
                        ).fetchone()[0]
                    )
                    for table in tables
                }
                logical_dump = tuple(connection.iterdump())
            return counts, logical_dump

        after_first = database_snapshot()
        status, replay_receipt = request_json(
            f"{self.base_url}/incidents/reanalyze",
            "POST",
            payload,
        )
        self.assertEqual(status, 202, replay_receipt)
        self.assertEqual(replay_receipt, first_receipt)
        self.assertEqual(database_snapshot(), after_first)

        conflicting_payload = dict(payload)
        conflicting_payload["reason"] = (
            "The same dispatch cannot be rebound to changed request fields."
        )
        status, conflict = request_json(
            f"{self.base_url}/incidents/reanalyze",
            "POST",
            conflicting_payload,
        )
        self.assertEqual(status, 409, conflict)
        self.assertEqual(conflict["status"], "rejected")
        self.assertEqual(database_snapshot(), after_first)

    def test_exact_claim_result_atomically_completes_job(self) -> None:
        group_id = "11111111111111111111"
        alert_id = "controlled-alert-happy"
        stable_key = "v2|controlled|happy"
        dispatch_id = "1" * 64
        job_id = self.seed_controlled_job(
            group_id=group_id,
            alert_id=alert_id,
            stable_group_key=stable_key,
            dispatch_id=dispatch_id,
        )
        self.start_controlled()
        status, claim = self.claim_controlled_job(
            job_id=job_id,
            group_id=group_id,
            alert_id=alert_id,
            stable_group_key=stable_key,
            dispatch_id=dispatch_id,
        )
        self.assertEqual(status, 200, claim)
        result_payload = self.controlled_result_payload(
            analysis_id="controlled-happy-result",
            claim=claim,
        )
        status, result = request_json(
            f"{self.base_url}/analysis/result",
            "POST",
            result_payload,
        )
        self.assertEqual(status, 200, result)
        status, rejected = request_json(
            f"{self.base_url}/jobs/status",
            "POST",
            {
                "job_type": "ai_analysis",
                "dedupe_key": group_id,
                "status": "failed",
                "error": "must not erase a committed result",
                "lease_token": claim["lease_token"],
                "retryable": True,
            },
        )
        self.assertEqual(status, 409, rejected)
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            self.assertEqual(
                connection.execute(
                    """
                    SELECT status, attempt_count, lease_token, lease_expires_at
                    FROM durable_jobs WHERE id = ?
                    """,
                    (job_id,),
                ).fetchone(),
                ("completed", 1, None, None),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM ai_analysis_runs "
                    "WHERE analysis_id = 'controlled-happy-result'"
                ).fetchone()[0],
                1,
            )

    def test_controlled_soc_dispatch_persists_role_and_renews_lease(
        self,
    ) -> None:
        dashboard_group_id = "242424242424"
        group_id = "24242424242424242424"
        alert_id = "controlled-soc-dispatch-heartbeat"
        stable_key = "v2|controlled|soc-dispatch-heartbeat"
        dispatch_id = "2" * 64
        timestamp = "2020-01-01 00:00:00+00:00"
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            connection.execute(
                """
                INSERT INTO alerts (
                    alert_id, first_seen, last_seen, alert_json,
                    stable_group_id, stable_group_key, triage_level,
                    filter_status
                ) VALUES (?, ?, ?, ?, ?, ?, 'medium', 'accepted')
                """,
                (
                    alert_id,
                    timestamp,
                    timestamp,
                    json.dumps({"alert_id": alert_id}),
                    group_id,
                    stable_key,
                ),
            )
            connection.execute(
                """
                INSERT INTO alert_group_summary (
                    group_id, group_key, representative_alert_id,
                    first_seen, last_seen, raw_alert_count,
                    total_seen_count, triage_level, filter_status, updated_at
                ) VALUES (?, ?, ?, ?, ?, 1, 1, 'medium', 'accepted', ?)
                """,
                (
                    dashboard_group_id,
                    stable_key,
                    alert_id,
                    timestamp,
                    timestamp,
                    timestamp,
                ),
            )
            connection.commit()

        self.start_controlled()
        request_payload = {
            "group_id": dashboard_group_id,
            "representative_alert_id": alert_id,
            "stable_group_id": group_id,
            "stable_group_key": stable_key,
            "cohort_id": "controlled-cohort-soc-dispatch",
            "dispatch_id": dispatch_id,
            "release_id": RELEASE_ID,
            "requested_by": "controlled-runtime-test",
            "reason": "Prove controlled SOC dispatch role survives heartbeat.",
        }
        status, receipt = request_json(
            f"{self.base_url}/ai/request",
            "POST",
            request_payload,
        )
        self.assertEqual(status, 202, receipt)

        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            job_id, payload_json = connection.execute(
                """
                SELECT id, payload_json
                FROM durable_jobs
                WHERE job_type = 'ai_analysis' AND dedupe_key = ?
                """,
                (group_id,),
            ).fetchone()
        stored_payload = json.loads(payload_json)
        self.assertEqual(stored_payload["agent_role"], "soc-analyst")

        claim_status, claim = self.claim_controlled_job(
            job_id=int(job_id),
            group_id=group_id,
            alert_id=alert_id,
            stable_group_key=stable_key,
            dispatch_id=dispatch_id,
        )
        self.assertEqual(claim_status, 200, claim)
        heartbeat_status, heartbeat = request_json(
            f"{self.base_url}/jobs/status",
            "POST",
            {
                "job_type": "ai_analysis",
                "dedupe_key": group_id,
                "status": "processing",
                "error": "",
                "lease_token": claim["lease_token"],
                "retryable": True,
            },
        )
        self.assertEqual(heartbeat_status, 200, heartbeat)
        self.assertEqual(
            heartbeat["lease_token"],
            claim["lease_token"],
        )
        release_status, release = request_json(
            f"{self.base_url}/jobs/status",
            "POST",
            {
                "job_type": "ai_analysis",
                "dedupe_key": group_id,
                "status": "failed",
                "error": "controlled test releases the lease",
                "lease_token": claim["lease_token"],
                "retryable": True,
            },
        )
        self.assertEqual(release_status, 200, release)
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            self.assertEqual(
                connection.execute(
                    """
                    SELECT status, attempt_count, lease_token, lease_expires_at
                    FROM durable_jobs WHERE id = ?
                    """,
                    (job_id,),
                ).fetchone(),
                ("pending", 1, None, None),
            )

    def test_exact_claim_rejects_missing_role_before_acquiring_lease(
        self,
    ) -> None:
        frozen = {
            "group_id": "25252525252525252525",
            "alert_id": "controlled-alert-missing-role",
            "stable_group_key": "v2|controlled|missing-role",
            "dispatch_id": "2" * 63 + "5",
        }
        job_id = self.seed_controlled_job(
            **frozen,
            agent_role=None,
        )
        self.start_controlled()
        status, response = self.claim_controlled_job(
            job_id=job_id,
            **frozen,
        )
        self.assertEqual(status, 409, response)
        self.assertEqual(response["status"], "rejected")
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            self.assertEqual(
                connection.execute(
                    """
                    SELECT status, attempt_count, lease_token, lease_expires_at
                    FROM durable_jobs WHERE id = ?
                    """,
                    (job_id,),
                ).fetchone(),
                ("pending", 0, None, None),
            )

    def test_claimed_job_rejects_role_drift_before_heartbeat_or_result(
        self,
    ) -> None:
        frozen = {
            "group_id": "26262626262626262626",
            "alert_id": "controlled-alert-role-drift",
            "stable_group_key": "v2|controlled|role-drift",
            "dispatch_id": "2" * 63 + "6",
        }
        job_id = self.seed_controlled_job(**frozen)
        self.start_controlled()
        status, claim = self.claim_controlled_job(
            job_id=job_id,
            **frozen,
        )
        self.assertEqual(status, 200, claim)

        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            stored_payload = json.loads(
                connection.execute(
                    "SELECT payload_json FROM durable_jobs WHERE id = ?",
                    (job_id,),
                ).fetchone()[0]
            )
            stored_payload["agent_role"] = "SOC-ANALYST"
            connection.execute(
                "UPDATE durable_jobs SET payload_json = ? WHERE id = ?",
                (
                    json.dumps(
                        stored_payload,
                        separators=(",", ":"),
                        sort_keys=True,
                    ),
                    job_id,
                ),
            )
            connection.commit()

        heartbeat_status, heartbeat = request_json(
            f"{self.base_url}/jobs/status",
            "POST",
            {
                "job_type": "ai_analysis",
                "dedupe_key": frozen["group_id"],
                "status": "processing",
                "error": "",
                "lease_token": claim["lease_token"],
                "retryable": True,
            },
        )
        self.assertEqual(heartbeat_status, 409, heartbeat)

        result_payload = self.controlled_result_payload(
            analysis_id="controlled-role-drift-result",
            claim=claim,
        )
        result_status, result = request_json(
            f"{self.base_url}/analysis/result",
            "POST",
            result_payload,
        )
        self.assertEqual(result_status, 409, result)
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            self.assertEqual(
                connection.execute(
                    """
                    SELECT status, attempt_count, lease_token
                    FROM durable_jobs WHERE id = ?
                    """,
                    (job_id,),
                ).fetchone(),
                ("processing", 1, claim["lease_token"]),
            )
            self.assertEqual(
                connection.execute(
                    """
                    SELECT COUNT(*) FROM ai_analysis_runs
                    WHERE analysis_id = 'controlled-role-drift-result'
                    """
                ).fetchone()[0],
                0,
            )

    def test_controlled_worker_clients_propagate_ephemeral_token(
        self,
    ) -> None:
        frozen = {
            "group_id": "10101010101010101010",
            "alert_id": "controlled-alert-client-token",
            "stable_group_key": "v2|controlled|client-token",
            "dispatch_id": "1" * 63 + "0",
        }
        job_id = self.seed_controlled_job(**frozen)
        self.start_controlled()
        controlled_environment = {
            "ONION_SENTINEL_EVALUATION_MODE": "1",
            "ONION_SENTINEL_EVALUATION_TOKEN": EVALUATION_TOKEN,
            "ONION_SENTINEL_RELEASE_ID": RELEASE_ID,
        }
        with mock.patch.dict(
            os.environ,
            controlled_environment,
            clear=False,
        ):
            claim = self.scheduler.report_ai_job_status(
                self.base_url,
                frozen["group_id"],
                "processing",
                expected_job_id=job_id,
                expected_representative_alert_id=frozen["alert_id"],
                expected_dispatch_id=frozen["dispatch_id"],
                expected_stable_group_key=frozen["stable_group_key"],
            )
            self.assertIsInstance(
                claim,
                self.scheduler.ClaimedAiLease,
            )
            payload = self.controlled_result_payload(
                analysis_id="controlled-client-token-result",
                claim={
                    "lease_token": str(claim),
                    "claim": {
                        "job_id": claim.job_id,
                        "payload": claim.job_payload,
                    },
                },
            )
            receipt = self.runner.post_analysis_index(
                payload,
                self.base_url,
            )
            self.assertEqual(
                receipt["analysis_id"],
                "controlled-client-token-result",
            )
            replay = self.scheduler.post_controlled_recovery_result(
                payload,
                self.base_url,
                attempts=1,
            )
        self.assertTrue(replay["ok"])
        self.assertEqual(
            replay["analysis_id"],
            "controlled-client-token-result",
        )

    def test_lost_claim_response_replays_same_raw_lease(self) -> None:
        frozen = {
            "group_id": "12121212121212121212",
            "alert_id": "controlled-alert-lost-claim",
            "stable_group_key": "v2|controlled|lost-claim",
            "dispatch_id": "1" * 63 + "2",
        }
        job_id = self.seed_controlled_job(**frozen)
        self.start_controlled()

        # Treat the first successful POST as committed with its response lost.
        first_status, first_claim = self.claim_controlled_job(
            job_id=job_id,
            **frozen,
        )
        second_status, second_claim = self.claim_controlled_job(
            job_id=job_id,
            **frozen,
        )
        self.assertEqual(first_status, 200, first_claim)
        self.assertEqual(second_status, 200, second_claim)
        self.assertEqual(second_claim, first_claim)
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            self.assertEqual(
                connection.execute(
                    """
                    SELECT status, attempt_count, lease_token
                    FROM durable_jobs WHERE id = ?
                    """,
                    (job_id,),
                ).fetchone(),
                ("processing", 1, first_claim["lease_token"]),
            )

    def test_exact_claim_replays_after_alert_store_restart(self) -> None:
        frozen = {
            "group_id": "13131313131313131313",
            "alert_id": "controlled-alert-restart-claim",
            "stable_group_key": "v2|controlled|restart-claim",
            "dispatch_id": "1" * 63 + "3",
        }
        job_id = self.seed_controlled_job(**frozen)
        self.start_controlled()
        first_status, first_claim = self.claim_controlled_job(
            job_id=job_id,
            **frozen,
        )
        self.assertEqual(first_status, 200, first_claim)
        stop_process(self.process)
        self.process = None
        self.start_controlled()

        replay_status, replay_claim = self.claim_controlled_job(
            job_id=job_id,
            **frozen,
        )
        self.assertEqual(replay_status, 200, replay_claim)
        self.assertEqual(replay_claim, first_claim)
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            attempt_count, lease_expires_at = connection.execute(
                """
                SELECT attempt_count, lease_expires_at
                FROM durable_jobs WHERE id = ?
                """,
                (job_id,),
            ).fetchone()
        self.assertEqual(attempt_count, 1)
        self.assertGreater(
            dt.datetime.fromisoformat(
                lease_expires_at.replace("Z", "+00:00")
            ).timestamp(),
            time.time(),
        )

    def test_inflight_heartbeat_and_failure_survive_restart_and_expiry(
        self,
    ) -> None:
        frozen = {
            "group_id": "15151515151515151515",
            "alert_id": "controlled-alert-heartbeat-restart",
            "stable_group_key": "v2|controlled|heartbeat-restart",
            "dispatch_id": "1" * 63 + "5",
        }
        job_id = self.seed_controlled_job(**frozen)
        self.start_controlled()
        status, claim = self.claim_controlled_job(job_id=job_id, **frozen)
        self.assertEqual(status, 200, claim)
        stop_process(self.process)
        self.process = None
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            connection.execute(
                "UPDATE durable_jobs SET lease_expires_at = ? WHERE id = ?",
                ("2000-01-01T00:00:00.000Z", job_id),
            )
            connection.commit()
        self.start_controlled()

        heartbeat_status, heartbeat = request_json(
            f"{self.base_url}/jobs/status",
            "POST",
            {
                "job_type": "ai_analysis",
                "dedupe_key": frozen["group_id"],
                "status": "processing",
                "error": "",
                "lease_token": claim["lease_token"],
                "retryable": True,
            },
        )
        self.assertEqual(heartbeat_status, 200, heartbeat)
        self.assertEqual(heartbeat["lease_token"], claim["lease_token"])
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            attempt_count, lease_expires_at = connection.execute(
                """
                SELECT attempt_count, lease_expires_at
                FROM durable_jobs WHERE id = ?
                """,
                (job_id,),
            ).fetchone()
        self.assertEqual(attempt_count, 1)
        self.assertGreater(
            dt.datetime.fromisoformat(
                lease_expires_at.replace("Z", "+00:00")
            ).timestamp(),
            time.time(),
        )

        failure_status, failure = request_json(
            f"{self.base_url}/jobs/status",
            "POST",
            {
                "job_type": "ai_analysis",
                "dedupe_key": frozen["group_id"],
                "status": "failed",
                "error": "controlled worker interrupted",
                "lease_token": claim["lease_token"],
                "retryable": True,
            },
        )
        self.assertEqual(failure_status, 200, failure)
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            self.assertEqual(
                connection.execute(
                    """
                    SELECT status, attempt_count, lease_token, lease_expires_at
                    FROM durable_jobs WHERE id = ?
                    """,
                    (job_id,),
                ).fetchone(),
                ("pending", 1, None, None),
            )

    def test_production_exact_identity_cannot_replay_processing_lease(
        self,
    ) -> None:
        frozen = {
            "group_id": "16161616161616161616",
            "alert_id": "production-alert-exact-fields",
            "stable_group_key": "v2|production|exact-fields",
            "dispatch_id": "1" * 63 + "6",
        }
        job_id = self.seed_controlled_job(**frozen)
        self.start_production()
        request_payload = {
            "job_type": "ai_analysis",
            "dedupe_key": frozen["group_id"],
            "status": "processing",
            "error": "",
            "lease_token": "",
            "retryable": True,
            "expected_job_id": job_id,
            "expected_representative_alert_id": frozen["alert_id"],
            "expected_dispatch_id": frozen["dispatch_id"],
            "expected_stable_group_key": frozen["stable_group_key"],
        }
        first_status, first = request_json(
            f"{self.base_url}/jobs/status",
            "POST",
            request_payload,
        )
        self.assertEqual(first_status, 200, first)
        self.assertTrue(first["lease_token"])
        self.assertNotIn("job_id", first["claim"])

        replay_status, replay = request_json(
            f"{self.base_url}/jobs/status",
            "POST",
            request_payload,
        )
        self.assertEqual(replay_status, 404, replay)
        self.assertIsNone(replay["lease_token"])
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            self.assertEqual(
                connection.execute(
                    """
                    SELECT status, attempt_count, lease_token
                    FROM durable_jobs WHERE id = ?
                    """,
                    (job_id,),
                ).fetchone(),
                ("processing", 1, first["lease_token"]),
            )

    def test_expired_exact_claim_replays_without_new_attempt(self) -> None:
        frozen = {
            "group_id": "14141414141414141414",
            "alert_id": "controlled-alert-expired-claim",
            "stable_group_key": "v2|controlled|expired-claim",
            "dispatch_id": "1" * 63 + "4",
        }
        job_id = self.seed_controlled_job(**frozen)
        self.start_controlled()
        status, first_claim = self.claim_controlled_job(
            job_id=job_id,
            **frozen,
        )
        self.assertEqual(status, 200, first_claim)
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            connection.execute(
                "UPDATE durable_jobs SET lease_expires_at = ? WHERE id = ?",
                ("2000-01-01T00:00:00.000Z", job_id),
            )
            connection.commit()

        replay_status, replay_claim = self.claim_controlled_job(
            job_id=job_id,
            **frozen,
        )
        self.assertEqual(replay_status, 200, replay_claim)
        self.assertEqual(replay_claim, first_claim)
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            attempt_count, lease_expires_at = connection.execute(
                """
                SELECT attempt_count, lease_expires_at
                FROM durable_jobs WHERE id = ?
                """,
                (job_id,),
            ).fetchone()
        self.assertEqual(attempt_count, 1)
        self.assertGreater(
            dt.datetime.fromisoformat(
                lease_expires_at.replace("Z", "+00:00")
            ).timestamp(),
            time.time(),
        )

    def test_second_global_claim_is_rejected_without_changing_candidate(
        self,
    ) -> None:
        first = {
            "group_id": "22222222222222222222",
            "alert_id": "controlled-alert-first",
            "stable_group_key": "v2|controlled|first",
            "dispatch_id": "2" * 64,
        }
        second = {
            "group_id": "33333333333333333333",
            "alert_id": "controlled-alert-second",
            "stable_group_key": "v2|controlled|second",
            "dispatch_id": "3" * 64,
        }
        first_id = self.seed_controlled_job(**first)
        second_id = self.seed_controlled_job(**second)
        self.start_controlled()
        status, claim = self.claim_controlled_job(
            job_id=first_id,
            **first,
        )
        self.assertEqual(status, 200, claim)
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            before = connection.execute(
                """
                SELECT status, attempt_count, lease_token, lease_expires_at,
                       payload_json, updated_at
                FROM durable_jobs WHERE id = ?
                """,
                (second_id,),
            ).fetchone()
        status, rejected = self.claim_controlled_job(
            job_id=second_id,
            **second,
        )
        self.assertEqual(status, 409, rejected)
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            after = connection.execute(
                """
                SELECT status, attempt_count, lease_token, lease_expires_at,
                       payload_json, updated_at
                FROM durable_jobs WHERE id = ?
                """,
                (second_id,),
            ).fetchone()
        self.assertEqual(after, before)

    def test_restart_blocks_a_second_global_processing_claim(self) -> None:
        first = {
            "group_id": "23232323232323232323",
            "alert_id": "controlled-alert-restart-first",
            "stable_group_key": "v2|controlled|restart-first",
            "dispatch_id": "2" * 63 + "3",
        }
        second = {
            "group_id": "34343434343434343434",
            "alert_id": "controlled-alert-restart-second",
            "stable_group_key": "v2|controlled|restart-second",
            "dispatch_id": "3" * 63 + "4",
        }
        first_id = self.seed_controlled_job(**first)
        second_id = self.seed_controlled_job(**second)
        self.start_controlled()
        self.assertEqual(
            self.claim_controlled_job(job_id=first_id, **first)[0],
            200,
        )
        stop_process(self.process)
        self.process = None
        self.start_controlled()
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            before = connection.execute(
                """
                SELECT status, attempt_count, lease_token, lease_expires_at,
                       payload_json, updated_at
                FROM durable_jobs WHERE id = ?
                """,
                (second_id,),
            ).fetchone()
        status, rejected = self.claim_controlled_job(
            job_id=second_id,
            **second,
        )
        self.assertEqual(status, 409, rejected)
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            after = connection.execute(
                """
                SELECT status, attempt_count, lease_token, lease_expires_at,
                       payload_json, updated_at
                FROM durable_jobs WHERE id = ?
                """,
                (second_id,),
            ).fetchone()
        self.assertEqual(after, before)

    def test_tampered_bound_result_is_rejected_without_committing(
        self,
    ) -> None:
        group_id = "66666666666666666666"
        alert_id = "controlled-alert-tampered"
        stable_key = "v2|controlled|tampered"
        dispatch_id = "6" * 64
        job_id = self.seed_controlled_job(
            group_id=group_id,
            alert_id=alert_id,
            stable_group_key=stable_key,
            dispatch_id=dispatch_id,
        )
        self.start_controlled()
        status, claim = self.claim_controlled_job(
            job_id=job_id,
            group_id=group_id,
            alert_id=alert_id,
            stable_group_key=stable_key,
            dispatch_id=dispatch_id,
        )
        self.assertEqual(status, 200, claim)
        result_payload = self.controlled_result_payload(
            analysis_id="controlled-tampered-result",
            claim=claim,
        )
        result_payload["response"][
            "_analysis_controlled_claim_sha256"
        ] = "0" * 64
        status, rejected = request_json(
            f"{self.base_url}/analysis/result",
            "POST",
            result_payload,
        )
        self.assertEqual(status, 409, rejected)
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM ai_analysis_runs "
                    "WHERE analysis_id = 'controlled-tampered-result'"
                ).fetchone()[0],
                0,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT status FROM durable_jobs WHERE id = ?",
                    (job_id,),
                ).fetchone()[0],
                "processing",
            )

    def test_committed_result_replay_rejects_response_content_change(
        self,
    ) -> None:
        frozen = {
            "group_id": "67676767676767676767",
            "alert_id": "controlled-alert-content-replay",
            "stable_group_key": "v2|controlled|content-replay",
            "dispatch_id": "6" * 63 + "7",
        }
        job_id = self.seed_controlled_job(**frozen)
        self.start_controlled()
        status, claim = self.claim_controlled_job(
            job_id=job_id,
            **frozen,
        )
        self.assertEqual(status, 200, claim)
        payload = self.controlled_result_payload(
            analysis_id="controlled-content-replay",
            claim=claim,
        )
        self.assertEqual(
            request_json(
                f"{self.base_url}/analysis/result",
                "POST",
                payload,
            )[0],
            200,
        )
        changed = json.loads(json.dumps(payload))
        changed["response"]["summary"] = (
            "Different content with the same controlled claim digest."
        )
        replay_status, rejected = request_json(
            f"{self.base_url}/analysis/result",
            "POST",
            changed,
        )
        self.assertEqual(replay_status, 409, rejected)
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            stored, job = (
                connection.execute(
                    """
                    SELECT response_json FROM ai_analysis_runs
                    WHERE analysis_id = 'controlled-content-replay'
                    """
                ).fetchone()[0],
                connection.execute(
                    """
                    SELECT status, lease_token, lease_expires_at
                    FROM durable_jobs WHERE id = ?
                    """,
                    (job_id,),
                ).fetchone(),
            )
        self.assertEqual(
            json.loads(stored)["summary"],
            payload["response"]["summary"],
        )
        self.assertEqual(job, ("completed", None, None))

    def test_exact_result_replays_after_restart_and_expired_claim(
        self,
    ) -> None:
        frozen = {
            "group_id": "68686868686868686868",
            "alert_id": "controlled-alert-expired-result",
            "stable_group_key": "v2|controlled|expired-result",
            "dispatch_id": "6" * 63 + "8",
        }
        job_id = self.seed_controlled_job(**frozen)
        self.start_controlled()
        status, claim = self.claim_controlled_job(
            job_id=job_id,
            **frozen,
        )
        self.assertEqual(status, 200, claim)
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            connection.execute(
                "UPDATE durable_jobs SET lease_expires_at = ? WHERE id = ?",
                ("2000-01-01T00:00:00.000Z", job_id),
            )
            connection.commit()
        payload = self.controlled_result_payload(
            analysis_id="controlled-expired-result",
            claim=claim,
        )
        first_status, first_result = request_json(
            f"{self.base_url}/analysis/result",
            "POST",
            payload,
        )
        self.assertEqual(first_status, 200, first_result)
        stop_process(self.process)
        self.process = None
        self.start_controlled()
        replay_status, replay = request_json(
            f"{self.base_url}/analysis/result",
            "POST",
            payload,
        )
        self.assertEqual(replay_status, 200, replay)
        self.assertTrue(replay["idempotent"])
        self.assertEqual(
            replay["stored_response_sha256"],
            first_result["stored_response_sha256"],
        )
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            self.assertEqual(
                connection.execute(
                    """
                    SELECT status, attempt_count, lease_token, lease_expires_at
                    FROM durable_jobs WHERE id = ?
                    """,
                    (job_id,),
                ).fetchone(),
                ("completed", 1, None, None),
            )

    def test_committed_result_survives_restart_and_spool_recovery(
        self,
    ) -> None:
        group_id = "44444444444444444444"
        alert_id = "controlled-alert-recovery"
        stable_key = "v2|controlled|recovery"
        dispatch_id = "4" * 64
        job_id = self.seed_controlled_job(
            group_id=group_id,
            alert_id=alert_id,
            stable_group_key=stable_key,
            dispatch_id=dispatch_id,
        )
        self.start_controlled()
        status, claim = self.claim_controlled_job(
            job_id=job_id,
            group_id=group_id,
            alert_id=alert_id,
            stable_group_key=stable_key,
            dispatch_id=dispatch_id,
        )
        self.assertEqual(status, 200, claim)
        result_payload = self.controlled_result_payload(
            analysis_id="controlled-recovery-result",
            claim=claim,
        )
        evaluation_root = self.runtime / "harness-evaluations" / "rerun11"
        queue_dir = evaluation_root / "analysis-index-pending"
        queue_dir.mkdir(parents=True, mode=0o700)
        evaluation_root.chmod(0o700)
        queue_dir.chmod(0o700)
        spool_path = self.runner.queue_analysis_index(
            result_payload,
            queue_dir=queue_dir,
        )

        # The server atomically commits the result and terminal job state, but
        # the worker never observes that response before the service restarts.
        status, committed = request_json(
            f"{self.base_url}/analysis/result",
            "POST",
            result_payload,
        )
        self.assertEqual(status, 200, committed)
        stop_process(self.process)
        self.process = None
        self.start_controlled()

        args = SimpleNamespace(
            db=self.db,
            alert_store_url=self.base_url,
            only_group_id=group_id,
            only_alert_id=alert_id,
            only_stable_group_key=stable_key,
            only_dispatch_id=dispatch_id,
        )
        with (
            mock.patch.dict(
                os.environ,
                {
                    "ONION_SENTINEL_EVALUATION_MODE": "1",
                    "ONION_SENTINEL_EVALUATION_TOKEN": EVALUATION_TOKEN,
                    "ONION_SENTINEL_RELEASE_ID": RELEASE_ID,
                },
                clear=False,
            ),
            mock.patch.object(
                self.scheduler,
                "run_analysis",
                side_effect=AssertionError(
                    "recovery invoked a second inference"
                ),
            ),
            mock.patch.object(
                self.scheduler,
                "report_ai_job_status",
                side_effect=AssertionError(
                    "controlled result recovery posted a second completion"
                ),
            ),
        ):
            self.assertTrue(
                self.scheduler.recover_controlled_evaluation_spool(
                    args,
                    evaluation_root,
                )
            )

        self.assertFalse(spool_path.exists())
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            stored_response_json = connection.execute(
                "SELECT response_json FROM ai_analysis_runs "
                "WHERE analysis_id = 'controlled-recovery-result'"
            ).fetchone()[0]
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM ai_analysis_runs "
                    "WHERE analysis_id = 'controlled-recovery-result'"
                ).fetchone()[0],
                1,
            )
            job = connection.execute(
                """
                SELECT status, lease_token, lease_expires_at
                FROM durable_jobs WHERE id = ?
                """,
                (job_id,),
            ).fetchone()
        self.assertEqual(job, ("completed", None, None))
        lease_token = claim["lease_token"]
        self.assertNotIn(lease_token, stored_response_json)
        for artifact in evaluation_root.rglob("*"):
            if artifact.is_file():
                self.assertNotIn(
                    lease_token,
                    artifact.read_text(
                        encoding="utf-8",
                        errors="replace",
                    ),
                )

    def test_lost_completion_response_uses_exact_terminal_db_proof(
        self,
    ) -> None:
        group_id = "55555555555555555555"
        alert_id = "controlled-alert-terminal-proof"
        stable_key = "v2|controlled|terminal-proof"
        dispatch_id = "5" * 64
        job_id = self.seed_controlled_job(
            group_id=group_id,
            alert_id=alert_id,
            stable_group_key=stable_key,
            dispatch_id=dispatch_id,
        )
        self.start_controlled()
        status, claim = self.claim_controlled_job(
            job_id=job_id,
            group_id=group_id,
            alert_id=alert_id,
            stable_group_key=stable_key,
            dispatch_id=dispatch_id,
        )
        self.assertEqual(status, 200, claim)
        result_payload = self.controlled_result_payload(
            analysis_id="controlled-terminal-proof",
            claim=claim,
        )
        evaluation_root = (
            self.runtime / "harness-evaluations" / "terminal-proof"
        )
        queue_dir = evaluation_root / "analysis-index-pending"
        queue_dir.mkdir(parents=True, mode=0o700)
        evaluation_root.chmod(0o700)
        queue_dir.chmod(0o700)
        spool_path = self.runner.queue_analysis_index(
            result_payload,
            queue_dir=queue_dir,
        )
        self.assertEqual(
            request_json(
                f"{self.base_url}/analysis/result",
                "POST",
                result_payload,
            )[0],
            200,
        )
        # Model the single atomic result/completion response being lost.
        stop_process(self.process)
        self.process = None
        self.start_controlled()
        args = SimpleNamespace(
            db=self.db,
            alert_store_url=self.base_url,
            only_group_id=group_id,
            only_alert_id=alert_id,
            only_stable_group_key=stable_key,
            only_dispatch_id=dispatch_id,
        )
        with (
            mock.patch.dict(
                os.environ,
                {
                    "ONION_SENTINEL_EVALUATION_MODE": "1",
                    "ONION_SENTINEL_EVALUATION_TOKEN": EVALUATION_TOKEN,
                    "ONION_SENTINEL_RELEASE_ID": RELEASE_ID,
                },
                clear=False,
            ),
            mock.patch.object(
                self.scheduler,
                "report_ai_job_status",
                side_effect=AssertionError(
                    "controlled result recovery posted a second completion"
                ),
            ),
        ):
            self.assertTrue(
                self.scheduler.recover_controlled_evaluation_spool(
                    args,
                    evaluation_root,
                )
            )
        self.assertFalse(spool_path.exists())
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM ai_analysis_runs "
                    "WHERE analysis_id = 'controlled-terminal-proof'"
                ).fetchone()[0],
                1,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT status, lease_token FROM durable_jobs WHERE id = ?",
                    (job_id,),
                ).fetchone(),
                ("completed", None),
            )

    def test_http_unavailable_recovery_uses_terminal_db_proof(
        self,
    ) -> None:
        frozen = {
            "group_id": "57575757575757575757",
            "alert_id": "controlled-alert-offline-terminal-proof",
            "stable_group_key": "v2|controlled|offline-terminal-proof",
            "dispatch_id": "5" * 63 + "7",
        }
        job_id = self.seed_controlled_job(**frozen)
        self.start_controlled()
        status, claim = self.claim_controlled_job(
            job_id=job_id,
            **frozen,
        )
        self.assertEqual(status, 200, claim)
        payload = self.controlled_result_payload(
            analysis_id="controlled-offline-terminal-proof",
            claim=claim,
        )
        evaluation_root = (
            self.runtime
            / "harness-evaluations"
            / "offline-terminal-proof"
        )
        queue_dir = evaluation_root / "analysis-index-pending"
        queue_dir.mkdir(parents=True, mode=0o700)
        evaluation_root.chmod(0o700)
        queue_dir.chmod(0o700)
        spool_path = self.runner.queue_analysis_index(
            payload,
            queue_dir=queue_dir,
        )
        self.assertEqual(
            request_json(
                f"{self.base_url}/analysis/result",
                "POST",
                payload,
            )[0],
            200,
        )
        unavailable_url = self.base_url
        stop_process(self.process)
        self.process = None

        args = SimpleNamespace(
            db=self.db,
            alert_store_url=unavailable_url,
            only_group_id=frozen["group_id"],
            only_alert_id=frozen["alert_id"],
            only_stable_group_key=frozen["stable_group_key"],
            only_dispatch_id=frozen["dispatch_id"],
        )
        with mock.patch.dict(
            os.environ,
            {
                "ONION_SENTINEL_EVALUATION_MODE": "1",
                "ONION_SENTINEL_EVALUATION_TOKEN": EVALUATION_TOKEN,
                "ONION_SENTINEL_RELEASE_ID": RELEASE_ID,
            },
            clear=False,
        ):
            self.assertTrue(
                self.scheduler.recover_controlled_evaluation_spool(
                    args,
                    evaluation_root,
                )
            )

        self.assertFalse(spool_path.exists())
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            self.assertEqual(
                connection.execute(
                    """
                    SELECT status, lease_token, lease_expires_at
                    FROM durable_jobs WHERE id = ?
                    """,
                    (job_id,),
                ).fetchone(),
                ("completed", None, None),
            )

    def test_deterministic_replay_conflict_never_uses_subset_db_proof(
        self,
    ) -> None:
        frozen = {
            "group_id": "67676767676767676767",
            "alert_id": "controlled-alert-deterministic-conflict",
            "stable_group_key": "v2|controlled|deterministic-conflict",
            "dispatch_id": "6" * 63 + "7",
        }
        job_id = self.seed_controlled_job(**frozen)
        self.start_controlled()
        status, claim = self.claim_controlled_job(
            job_id=job_id,
            **frozen,
        )
        self.assertEqual(status, 200, claim)
        accepted_payload = self.controlled_result_payload(
            analysis_id="controlled-deterministic-conflict",
            claim=claim,
        )
        self.assertEqual(
            request_json(
                f"{self.base_url}/analysis/result",
                "POST",
                accepted_payload,
            )[0],
            200,
        )
        conflicting_payload = json.loads(json.dumps(accepted_payload))
        conflicting_payload["generated_at"] = (
            "2026-07-27 12:02:00+00:00"
        )
        evaluation_root = (
            self.runtime
            / "harness-evaluations"
            / "deterministic-conflict"
        )
        queue_dir = evaluation_root / "analysis-index-pending"
        queue_dir.mkdir(parents=True, mode=0o700)
        evaluation_root.chmod(0o700)
        queue_dir.chmod(0o700)
        spool_path = self.runner.queue_analysis_index(
            conflicting_payload,
            queue_dir=queue_dir,
        )
        args = SimpleNamespace(
            db=self.db,
            alert_store_url=self.base_url,
            only_group_id=frozen["group_id"],
            only_alert_id=frozen["alert_id"],
            only_stable_group_key=frozen["stable_group_key"],
            only_dispatch_id=frozen["dispatch_id"],
        )
        with mock.patch.dict(
            os.environ,
            {
                "ONION_SENTINEL_EVALUATION_MODE": "1",
                "ONION_SENTINEL_EVALUATION_TOKEN": EVALUATION_TOKEN,
                "ONION_SENTINEL_RELEASE_ID": RELEASE_ID,
            },
            clear=False,
        ):
            for field, changed_value in (
                ("generated_at", "2026-07-27 12:02:00+00:00"),
                ("model", "different-controlled-model"),
                ("model_path", "different-model-path"),
                ("artifact_path", "/different/evaluation/result.json"),
                ("evidence_hash", "f" * 64),
            ):
                with self.subTest(immutable_field=field):
                    changed_payload = json.loads(
                        json.dumps(accepted_payload)
                    )
                    changed_payload[field] = changed_value
                    changed_recovery = (
                        self.scheduler.validate_controlled_recovery_payload(
                            changed_payload,
                            args,
                        )
                    )
                    self.assertFalse(
                        self.scheduler.controlled_recovery_terminal_success(
                            args,
                            changed_recovery,
                        )
                    )
            recovery = self.scheduler.validate_controlled_recovery_payload(
                conflicting_payload,
                args,
            )
            self.assertFalse(
                self.scheduler.controlled_recovery_terminal_success(
                    args,
                    recovery,
                )
            )
            with self.assertRaisesRegex(RuntimeError, "HTTP 409"):
                self.scheduler.recover_controlled_evaluation_spool(
                    args,
                    evaluation_root,
                )
        self.assertTrue(spool_path.exists())

    def test_utf16_truncation_conflict_uses_full_terminal_db_proof(
        self,
    ) -> None:
        frozen = {
            "group_id": "68686868686868686868",
            "alert_id": "controlled-alert-utf16-proof",
            "stable_group_key": "v2|controlled|utf16-proof",
            "dispatch_id": "6" * 63 + "8",
        }
        job_id = self.seed_controlled_job(**frozen)
        self.start_controlled()
        status, claim = self.claim_controlled_job(
            job_id=job_id,
            **frozen,
        )
        self.assertEqual(status, 200, claim)
        payload = self.controlled_result_payload(
            analysis_id="controlled-utf16-proof",
            claim=claim,
        )
        payload["response"]["summary"] = "s" * 7999 + "😀tail"
        payload["response"]["bluf"] = "b" * 3999 + "😀tail"
        evaluation_root = (
            self.runtime / "harness-evaluations" / "utf16-proof"
        )
        queue_dir = evaluation_root / "analysis-index-pending"
        queue_dir.mkdir(parents=True, mode=0o700)
        evaluation_root.chmod(0o700)
        queue_dir.chmod(0o700)
        spool_path = self.runner.queue_analysis_index(
            payload,
            queue_dir=queue_dir,
        )
        self.assertEqual(
            request_json(
                f"{self.base_url}/analysis/result",
                "POST",
                payload,
            )[0],
            200,
        )
        # safeString() split the emoji at both UTF-16 limits. node-sqlite3
        # stores U+FFFD, so an HTTP replay conflicts even though the original
        # transaction committed the exact response and terminal job.
        self.assertEqual(
            request_json(
                f"{self.base_url}/analysis/result",
                "POST",
                payload,
            )[0],
            409,
        )
        args = SimpleNamespace(
            db=self.db,
            alert_store_url=self.base_url,
            only_group_id=frozen["group_id"],
            only_alert_id=frozen["alert_id"],
            only_stable_group_key=frozen["stable_group_key"],
            only_dispatch_id=frozen["dispatch_id"],
        )
        with mock.patch.dict(
            os.environ,
            {
                "ONION_SENTINEL_EVALUATION_MODE": "1",
                "ONION_SENTINEL_EVALUATION_TOKEN": EVALUATION_TOKEN,
                "ONION_SENTINEL_RELEASE_ID": RELEASE_ID,
            },
            clear=False,
        ):
            self.assertTrue(
                self.scheduler.recover_controlled_evaluation_spool(
                    args,
                    evaluation_root,
                )
            )
        self.assertFalse(spool_path.exists())
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            summary, bluf = connection.execute(
                """
                SELECT summary, bluf FROM ai_analysis_runs
                WHERE analysis_id = 'controlled-utf16-proof'
                """
            ).fetchone()
        self.assertTrue(summary.endswith("\ufffd"))
        self.assertTrue(bluf.endswith("\ufffd"))

    def test_unicode_response_digest_matches_node_storage_canonicalization(
        self,
    ) -> None:
        frozen = {
            "group_id": "58585858585858585858",
            "alert_id": "controlled-alert-unicode-digest",
            "stable_group_key": "v2|controlled|café|🧅|東京",
            "dispatch_id": "5" * 63 + "8",
        }
        job_id = self.seed_controlled_job(**frozen)
        self.start_controlled()
        status, claim = self.claim_controlled_job(
            job_id=job_id,
            **frozen,
        )
        self.assertEqual(status, 200, claim)
        payload = self.controlled_result_payload(
            analysis_id="controlled-unicode-digest",
            claim=claim,
        )
        payload["response"]["summary"] = (
            "Café telemetry from 東京 contains 🧅 and é."
        )
        payload["response"]["unicode_nested"] = {
            "emoji": ["🧅", "😀"],
            "non_ascii": "naïve résumé",
            # This is not an ECMAScript array-index key: the second digit is
            # Arabic-Indic. It must retain UTF-16 lexical object-key ordering.
            "1٢": "unicode numeric-looking key",
            "10": "actual array-index key",
        }
        post_status, receipt = request_json(
            f"{self.base_url}/analysis/result",
            "POST",
            payload,
        )
        self.assertEqual(post_status, 200, receipt)
        args = SimpleNamespace(
            db=self.db,
            alert_store_url=self.base_url,
            only_group_id=frozen["group_id"],
            only_alert_id=frozen["alert_id"],
            only_stable_group_key=frozen["stable_group_key"],
            only_dispatch_id=frozen["dispatch_id"],
        )
        with mock.patch.dict(
            os.environ,
            {"ONION_SENTINEL_RELEASE_ID": RELEASE_ID},
            clear=False,
        ):
            recovery = self.scheduler.validate_controlled_recovery_payload(
                payload,
                args,
            )
        self.assertEqual(
            recovery["stored_response_fallback_digest"],
            receipt["stored_response_sha256"],
        )
        self.assertEqual(
            recovery["response_digest"],
            self.runner.canonical_payload_digest(payload["response"]),
        )
        self.assertNotEqual(
            recovery["response_digest"],
            recovery["stored_response_fallback_digest"],
        )
        self.assertTrue(
            self.scheduler.controlled_recovery_terminal_success(
                args,
                recovery,
            )
        )

    def test_timestamp_response_digest_matches_node_normalization(
        self,
    ) -> None:
        frozen = {
            "group_id": "59595959595959595959",
            "alert_id": "controlled-alert-timestamp-digest",
            "stable_group_key": "v2|controlled|timestamp-digest",
            "dispatch_id": "5" * 63 + "9",
        }
        job_id = self.seed_controlled_job(**frozen)
        self.start_controlled()
        status, claim = self.claim_controlled_job(
            job_id=job_id,
            **frozen,
        )
        self.assertEqual(status, 200, claim)
        payload = self.controlled_result_payload(
            analysis_id="controlled-timestamp-digest",
            claim=claim,
        )
        original_timestamp = "2026-07-24T18:30:45.987654Z"
        unicode_space_timestamp = (
            "2026-07-24\u00a0\u00a018:30:45.987654Z"
        )
        historical_timestamp = "0510-01-03 13:34:37.8399035-06:00"
        normalized_overflow_timestamp = "2024-02-30T00:00:00Z"
        year_zero_timestamp = "0000-01-01T00:00:00Z"
        lower_boundary_timestamp = "0001-01-01T00:00:00Z"
        upper_boundary_timestamp = "9999-12-31T23:59:59-1200"
        js_trim_timestamp = "\ufeff2026-07-24T18:30:45Z\ufeff"
        non_js_trim_timestamp = (
            "\u001c2026-07-24T18:30:45Z\u0085"
        )
        payload["response"]["observed_at"] = original_timestamp
        payload["response"]["timestamp_context"] = (
            f"  observed at {original_timestamp}  "
        )
        payload["response"]["unicode_space_timestamp"] = (
            unicode_space_timestamp
        )
        payload["response"]["historical_timestamp"] = historical_timestamp
        payload["response"]["normalized_overflow_timestamp"] = (
            normalized_overflow_timestamp
        )
        payload["response"]["year_zero_timestamp"] = year_zero_timestamp
        payload["response"]["lower_boundary_timestamp"] = (
            lower_boundary_timestamp
        )
        payload["response"]["upper_boundary_timestamp"] = (
            upper_boundary_timestamp
        )
        payload["response"]["js_trim_timestamp"] = js_trim_timestamp
        payload["response"]["non_js_trim_timestamp"] = (
            non_js_trim_timestamp
        )
        post_status, receipt = request_json(
            f"{self.base_url}/analysis/result",
            "POST",
            payload,
        )
        self.assertEqual(post_status, 200, receipt)
        args = SimpleNamespace(
            db=self.db,
            alert_store_url=self.base_url,
            only_group_id=frozen["group_id"],
            only_alert_id=frozen["alert_id"],
            only_stable_group_key=frozen["stable_group_key"],
            only_dispatch_id=frozen["dispatch_id"],
        )
        with mock.patch.dict(
            os.environ,
            {"ONION_SENTINEL_RELEASE_ID": RELEASE_ID},
            clear=False,
        ):
            recovery = self.scheduler.validate_controlled_recovery_payload(
                payload,
                args,
            )
        self.assertEqual(
            recovery["stored_response_fallback_digest"],
            receipt["stored_response_sha256"],
        )
        self.assertEqual(
            recovery["response_digest"],
            self.runner.canonical_payload_digest(payload["response"]),
        )
        self.assertNotEqual(
            recovery["response_digest"],
            recovery["stored_response_fallback_digest"],
        )
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            stored_response = json.loads(
                connection.execute(
                    """
                    SELECT response_json FROM ai_analysis_runs
                    WHERE analysis_id = 'controlled-timestamp-digest'
                    """
                ).fetchone()[0]
            )
        self.assertEqual(
            stored_response["observed_at"],
            self.scheduler.controlled_normalize_timestamp(
                original_timestamp
            ),
        )
        self.assertEqual(
            stored_response["unicode_space_timestamp"],
            self.scheduler.controlled_normalize_timestamp(
                unicode_space_timestamp
            ),
        )
        self.assertEqual(
            stored_response["historical_timestamp"],
            self.scheduler.controlled_normalize_timestamp(
                historical_timestamp
            ),
        )
        self.assertEqual(
            stored_response["normalized_overflow_timestamp"],
            self.scheduler.controlled_normalize_timestamp(
                normalized_overflow_timestamp
            ),
        )
        self.assertEqual(
            stored_response["year_zero_timestamp"],
            self.scheduler.controlled_normalize_timestamp(
                year_zero_timestamp
            ),
        )
        for field, timestamp in (
            ("lower_boundary_timestamp", lower_boundary_timestamp),
            ("upper_boundary_timestamp", upper_boundary_timestamp),
            ("js_trim_timestamp", js_trim_timestamp),
            ("non_js_trim_timestamp", non_js_trim_timestamp),
        ):
            with self.subTest(field=field):
                self.assertEqual(
                    stored_response[field],
                    self.scheduler.controlled_normalize_timestamp(timestamp),
                )
        self.assertTrue(
            self.scheduler.controlled_recovery_terminal_success(
                args,
                recovery,
            )
        )

    def test_terminal_db_proof_rejects_full_response_content_mismatch(
        self,
    ) -> None:
        frozen = {
            "group_id": "56565656565656565656",
            "alert_id": "controlled-alert-terminal-digest",
            "stable_group_key": "v2|controlled|terminal-digest",
            "dispatch_id": "5" * 63 + "6",
        }
        job_id = self.seed_controlled_job(**frozen)
        self.start_controlled()
        status, claim = self.claim_controlled_job(
            job_id=job_id,
            **frozen,
        )
        self.assertEqual(status, 200, claim)
        payload = self.controlled_result_payload(
            analysis_id="controlled-terminal-digest",
            claim=claim,
        )
        self.assertEqual(
            request_json(
                f"{self.base_url}/analysis/result",
                "POST",
                payload,
            )[0],
            200,
        )
        args = SimpleNamespace(
            db=self.db,
            alert_store_url=self.base_url,
            only_group_id=frozen["group_id"],
            only_alert_id=frozen["alert_id"],
            only_stable_group_key=frozen["stable_group_key"],
            only_dispatch_id=frozen["dispatch_id"],
        )
        with mock.patch.dict(
            os.environ,
            {"ONION_SENTINEL_RELEASE_ID": RELEASE_ID},
            clear=False,
        ):
            recovery = self.scheduler.validate_controlled_recovery_payload(
                payload,
                args,
            )
            self.assertTrue(
                self.scheduler.controlled_recovery_terminal_success(
                    args,
                    recovery,
                )
            )
            with closing(sqlite3.connect(self.db, timeout=5)) as connection:
                stored = json.loads(
                    connection.execute(
                        """
                        SELECT response_json FROM ai_analysis_runs
                        WHERE analysis_id = 'controlled-terminal-digest'
                        """
                    ).fetchone()[0]
                )
                stored["summary"] = "Tampered after terminal commit."
                connection.execute(
                    """
                    UPDATE ai_analysis_runs SET response_json = ?
                    WHERE analysis_id = 'controlled-terminal-digest'
                    """,
                    (
                        json.dumps(
                            stored,
                            separators=(",", ":"),
                        ),
                    ),
                )
                connection.commit()
            self.assertFalse(
                self.scheduler.controlled_recovery_terminal_success(
                    args,
                    recovery,
                )
            )


class ControlledDashboardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="onion-sentinel-controlled-dashboard-"
        )
        self.root = Path(self.temporary.name).resolve()
        self.home = self.root / "home"
        self.dashboard_root = self.root / "runtime-dashboard"
        self.dashboard_root.mkdir(mode=0o700)
        self.alert_db = self.dashboard_root / "data" / "alerts.sqlite3"
        self.alert_db.parent.mkdir(mode=0o700)
        self.alert_db.write_bytes(b"controlled-dashboard-health-sentinel")
        self.alert_db.chmod(0o600)
        (self.dashboard_root / "index.html").write_text(
            "<!doctype html><title>controlled evaluation</title>",
            encoding="utf-8",
        )
        (self.dashboard_root / "index.html").chmod(0o600)
        self.port = available_port()
        self.alert_store_health_available = True
        self.alert_store_post_count = 0
        self.alert_store_health = {
            "ok": True,
            "status": "healthy",
            "service": "onion-sentinel-alert-store",
            "controlled_evaluation": True,
            "runtime_mode": "controlled-evaluation",
            "release_id": RELEASE_ID,
            "listen_host": "127.0.0.1",
            "listen_port": 0,
            "accepting_requests": True,
        }
        fixture = self

        class FakeControlledAlertStoreHandler(BaseHTTPRequestHandler):
            def log_message(self, _format: str, *args: object) -> None:
                """Keep readiness polling out of the test output."""

            def _send_json(self, status: int, payload: dict) -> None:
                body = json.dumps(payload).encode("utf-8")
                self.send_response(status)
                self.send_header(
                    "Content-Type",
                    "application/json; charset=utf-8",
                )
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:
                if (
                    self.path != "/health"
                    or not fixture.alert_store_health_available
                ):
                    self._send_json(503, {"ok": False})
                    return
                self._send_json(200, fixture.alert_store_health)

            def do_POST(self) -> None:
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                except ValueError:
                    length = 0
                if length > 0:
                    self.rfile.read(length)
                fixture.alert_store_post_count += 1
                self._send_json(
                    503,
                    {
                        "ok": False,
                        "status": "synthetic_downstream_unavailable",
                    },
                )

        self.alert_store_server = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            FakeControlledAlertStoreHandler,
        )
        self.alert_store_server.daemon_threads = True
        self.alert_store_port = int(
            self.alert_store_server.server_address[1]
        )
        self.alert_store_health["listen_port"] = self.alert_store_port
        self.alert_store_thread = threading.Thread(
            target=self.alert_store_server.serve_forever,
            name="controlled-dashboard-fake-alert-store",
            daemon=True,
        )
        self.alert_store_thread.start()
        self.base_url = f"http://127.0.0.1:{self.port}"
        self.log_file = tempfile.TemporaryFile(
            mode="w+t",
            encoding="utf-8",
        )
        environment = {
            **sanitized_environment(),
            "HOME": str(self.home),
            "ONION_SENTINEL_EVALUATION_MODE": "1",
            "ONION_SENTINEL_RELEASE_ID": RELEASE_ID,
            "ONION_SENTINEL_EVALUATION_TOKEN": EVALUATION_TOKEN,
            "SOC_ALERT_STORE_API_URL": (
                f"http://127.0.0.1:{self.alert_store_port}"
            ),
            "SOC_ALERT_STORE_DB": str(self.alert_db),
        }
        self.process = subprocess.Popen(
            [
                sys.executable,
                str(DASHBOARD_SERVER),
                "--host",
                "127.0.0.1",
                "--port",
                str(self.port),
                "--dashboard-root",
                str(self.dashboard_root),
            ],
            cwd=DASHBOARD_SERVER.parent,
            env=environment,
            stdout=self.log_file,
            stderr=subprocess.STDOUT,
            text=True,
        )
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                break
            try:
                if request_json(f"{self.base_url}/healthz")[0] == 200:
                    return
            except (OSError, urllib.error.URLError):
                time.sleep(0.05)
        self.fail(
            "controlled dashboard did not become healthy: "
            + process_output(self.log_file)
        )

    def tearDown(self) -> None:
        stop_process(self.process, graceful=False)
        self.alert_store_server.shutdown()
        self.alert_store_server.server_close()
        self.alert_store_thread.join(timeout=5)
        self.log_file.close()
        self.temporary.cleanup()

    def test_health_identifies_exact_runtime_and_all_other_reads_are_blocked(
        self,
    ) -> None:
        status, health = request_json(f"{self.base_url}/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(health["service"], "onion-sentinel")
        self.assertTrue(health["controlled_evaluation"])
        self.assertEqual(health["release_id"], RELEASE_ID)
        self.assertEqual(health["listen_host"], "127.0.0.1")
        self.assertEqual(health["listen_port"], self.port)
        self.assertEqual(
            health["alert_store_origin"],
            f"http://127.0.0.1:{self.alert_store_port}",
        )
        self.assertEqual(
            health["dispatch_route_patterns"],
            [
                "POST /api/soc-alerts/{12hex}/analyze",
                "POST /api/soc-incidents/{case_id}/reanalyze",
            ],
        )
        self.assertTrue(health["dashboard_ready"])
        self.assertTrue(health["alert_store_ready"])
        self.assertEqual(
            health["alert_store_health"],
            {
                "status": "ready",
                "service": "onion-sentinel-alert-store",
                "controlled_evaluation": True,
                "runtime_mode": "controlled-evaluation",
                "release_id": RELEASE_ID,
                "listen_host": "127.0.0.1",
                "listen_port": self.alert_store_port,
                "accepting_requests": True,
            },
        )
        self.assertEqual(
            request_json(
                f"{self.base_url}/healthz?unexpected=1"
            )[0],
            403,
        )
        self.assertEqual(
            request_status(
                f"{self.base_url}/healthz?unexpected=1",
                "HEAD",
            ),
            403,
        )
        for target in (
            "/healthz?",
            "/healthz;",
            "/healthz#fragment",
            "//healthz",
        ):
            with self.subTest(raw_target=target):
                self.assertEqual(
                    raw_request_status(
                        "127.0.0.1",
                        self.port,
                        target,
                    ),
                    403,
                )
                self.assertEqual(
                    raw_request_status(
                        "127.0.0.1",
                        self.port,
                        target,
                        "HEAD",
                    ),
                    403,
                )

        for route in (
            "/",
            "/index.html",
            "/api/soc-alerts",
            "/api/llm-analysis/current",
            "/admin",
        ):
            with self.subTest(route=route):
                self.assertEqual(
                    request_json(f"{self.base_url}{route}")[0],
                    403,
                )
                self.assertEqual(
                    request_status(
                        f"{self.base_url}{route}",
                        "HEAD",
                    ),
                    403,
                )

    def test_health_fails_closed_for_downstream_identity_and_availability(
        self,
    ) -> None:
        original_release = self.alert_store_health["release_id"]
        try:
            self.alert_store_health["release_id"] = "d" * 40
            status, health = request_json(f"{self.base_url}/healthz")
            self.assertEqual(status, 503, health)
            self.assertFalse(health["ok"])
            self.assertFalse(health["alert_store_ready"])
            self.assertEqual(
                health["alert_store_health"]["status"],
                "identity_mismatch",
            )
            self.assertEqual(
                health["alert_store_health"]["release_id"],
                "d" * 40,
            )
        finally:
            self.alert_store_health["release_id"] = original_release

        try:
            self.alert_store_health_available = False
            status, health = request_json(f"{self.base_url}/healthz")
            self.assertEqual(status, 503, health)
            self.assertFalse(health["ok"])
            self.assertFalse(health["alert_store_ready"])
            self.assertEqual(
                health["alert_store_health"],
                {"status": "unavailable"},
            )
        finally:
            self.alert_store_health_available = True

        status, health = request_json(f"{self.base_url}/healthz")
        self.assertEqual(status, 200, health)
        self.assertTrue(health["alert_store_ready"])

    def test_controlled_dispatch_requires_ephemeral_token_before_downstream(
        self,
    ) -> None:
        route = "/api/soc-alerts/0123456789ab/analyze"
        before = self.alert_store_post_count
        for label, token in (
            ("missing", ""),
            ("wrong", "8" * 64),
        ):
            with self.subTest(label=label):
                status, response = request_json(
                    f"{self.base_url}{route}",
                    "POST",
                    {},
                    evaluation_token=token,
                )
                self.assertEqual(status, 403, response)
                self.assertEqual(
                    response["error"],
                    "controlled evaluation authorization failed",
                )
                self.assertEqual(self.alert_store_post_count, before)

    def test_only_exact_dispatch_post_shapes_pass_the_route_guard(self) -> None:
        blocked = (
            "/api/soc-settings/ai-model",
            "/api/soc-alerts/0123456789ab/ack",
            "/api/soc-alerts/0123456789ab/escalate",
            "/api/soc-alerts/not-12hex/analyze",
            "/api/soc-incidents/reanalyze-all",
            "/api/soc-incidents/not-a-case/reanalyze",
            "/api/soc-alerts/0123456789ab/analyze?unexpected=1",
            "/api/soc-incidents/ir-synthetic/reanalyze?unexpected=1",
        )
        for route in blocked:
            with self.subTest(route=route):
                status, response = request_json(
                    f"{self.base_url}{route}",
                    "POST",
                    {},
                    request_headers={
                        "X-Onion-Sentinel-Request": "dashboard",
                        "Sec-Fetch-Site": "same-origin",
                        "Origin": self.base_url,
                    },
                )
                self.assertEqual(status, 403, response)

        for target in (
            "/api/soc-alerts/0123456789ab/analyze?",
            "/api/soc-alerts/0123456789ab/analyze;",
            "/api/soc-incidents/ir-synthetic/reanalyze?",
            "/api/soc-incidents/ir-synthetic/reanalyze;",
            "//api/soc-alerts/0123456789ab/analyze",
            "//api/soc-incidents/ir-synthetic/reanalyze",
        ):
            with self.subTest(raw_target=target):
                self.assertEqual(
                    raw_request_status(
                        "127.0.0.1",
                        self.port,
                        target,
                        "POST",
                    ),
                    403,
                )

        # The fake downstream returns 503 for every mutation. Exact dispatch
        # shapes therefore prove they crossed the evaluation route guard.
        allowed = (
            "/api/soc-alerts/0123456789ab/analyze",
            "/api/soc-incidents/ir-synthetic/reanalyze",
        )
        for route in allowed:
            with self.subTest(allowed_route=route):
                before = self.alert_store_post_count
                status, response = request_json(
                    f"{self.base_url}{route}",
                    "POST",
                    {},
                    request_headers={
                        "X-Onion-Sentinel-Request": "dashboard",
                        "Sec-Fetch-Site": "same-origin",
                        "Origin": self.base_url,
                    },
                )
                self.assertNotEqual(status, 403, response)
                if route.startswith("/api/soc-alerts/"):
                    self.assertEqual(
                        self.alert_store_post_count,
                        before + 1,
                    )
                else:
                    # The synthetic dashboard database contains no incident
                    # case, so this exact route is accepted and terminates
                    # locally before a downstream request is needed.
                    self.assertEqual(self.alert_store_post_count, before)


class ControlledWorkerIsolationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.runner = load_python_module(
            "controlled_evaluation_runner_tests",
            RUNNER_PATH,
        )
        cls.scheduler = load_python_module(
            "controlled_evaluation_scheduler_tests",
            SCHEDULER_PATH,
        )

    def test_run_local_requires_memory_freeze_before_any_result_identity(
        self,
    ) -> None:
        with (
            mock.patch.object(
                self.runner,
                "parse_args",
                return_value=SimpleNamespace(
                    alert_store_url="http://127.0.0.1:18787",
                ),
            ),
            mock.patch.object(
                self.runner,
                "controlled_evaluation_runtime",
                return_value=(True, Path("/tmp/controlled-evaluation-test")),
            ),
            mock.patch.dict(
                os.environ,
                {
                    "ONION_SENTINEL_EVALUATION_FREEZE_MEMORY": "0",
                },
                clear=False,
            ),
            mock.patch.object(
                self.runner,
                "controlled_evaluation_result_identity",
            ) as result_identity,
        ):
            with self.assertRaisesRegex(
                SystemExit,
                "controlled evaluation requires "
                "ONION_SENTINEL_EVALUATION_FREEZE_MEMORY=1",
            ):
                self.runner.main()
        result_identity.assert_not_called()

    def test_ephemeral_token_is_removed_before_unrelated_children(
        self,
    ) -> None:
        controlled_environment = {
            "ONION_SENTINEL_EVALUATION_MODE": "1",
            "ONION_SENTINEL_EVALUATION_TOKEN": EVALUATION_TOKEN,
        }
        with mock.patch.dict(
            os.environ,
            controlled_environment,
            clear=False,
        ):
            self.assertEqual(
                self.scheduler.consume_controlled_evaluation_token(True),
                EVALUATION_TOKEN,
            )
            self.assertNotIn(
                "ONION_SENTINEL_EVALUATION_TOKEN",
                os.environ,
            )
            self.assertEqual(
                self.scheduler.alert_store_mutation_headers()[
                    "X-Onion-Sentinel-Evaluation-Token"
                ],
                EVALUATION_TOKEN,
            )

        with mock.patch.dict(
            os.environ,
            controlled_environment,
            clear=False,
        ):
            self.assertEqual(
                self.runner.consume_controlled_evaluation_token(True),
                EVALUATION_TOKEN,
            )
            self.assertNotIn(
                "ONION_SENTINEL_EVALUATION_TOKEN",
                os.environ,
            )

    def test_controlled_enrichment_never_reads_production_credential(
        self,
    ) -> None:
        package = {
            "investigation_query_capability": {
                "enabled": True,
                "backends": {"enrichment": {"enabled": True}},
            }
        }
        with mock.patch.object(
            self.runner,
            "_runtime_env_value",
            side_effect=AssertionError("production credential was read"),
        ):
            config = self.runner.prepare_investigation_enrichment_context(
                package,
                "incident-responder",
                "http://127.0.0.1:18787",
                controlled_evaluation=True,
            )
        self.assertFalse(config["enabled"])
        self.assertEqual(config["token"], "")
        self.assertFalse(
            package["investigation_query_capability"]["backends"][
                "enrichment"
            ]["enabled"]
        )

    def test_controlled_lease_is_removed_from_process_environment_before_models(
        self,
    ) -> None:
        controlled_environment = {
            "ONION_SENTINEL_EVALUATION_JOB_ID": "7",
            "ONION_SENTINEL_EVALUATION_JOB_TYPE": "ai_analysis",
            "ONION_SENTINEL_EVALUATION_LEASE_TOKEN": (
                "77777777-7777-4777-8777-777777777777"
            ),
            "ONION_SENTINEL_EVALUATION_COHORT_ID": "controlled-cohort-11",
            "ONION_SENTINEL_EVALUATION_DISPATCH_ID": "7" * 64,
            "ONION_SENTINEL_EVALUATION_REPRESENTATIVE_ALERT_ID": (
                "controlled-alert-env"
            ),
            "ONION_SENTINEL_EVALUATION_STABLE_GROUP_ID": "7" * 20,
            "ONION_SENTINEL_EVALUATION_STABLE_GROUP_KEY": (
                "v2|controlled|environment"
            ),
            "ONION_SENTINEL_EVALUATION_AGENT_ROLE": "soc-analyst",
            "ONION_SENTINEL_EVALUATION_REANALYSIS_ATTEMPT_ID": "",
            "ONION_SENTINEL_RELEASE_ID": RELEASE_ID,
        }
        result_keys = tuple(
            self.runner.CONTROLLED_RESULT_ENVIRONMENT.values()
        )
        with mock.patch.dict(
            os.environ,
            controlled_environment,
            clear=False,
        ):
            identity = self.runner.controlled_evaluation_result_identity(
                True,
                reanalysis_attempt_id="",
            )
            self.assertEqual(
                identity["lease_token"],
                controlled_environment[
                    "ONION_SENTINEL_EVALUATION_LEASE_TOKEN"
                ],
            )
            for environment_key in result_keys:
                self.assertNotIn(environment_key, os.environ)

    def test_run_local_runtime_must_be_owner_only_and_under_evaluation_root(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary).resolve()
            home = temporary_root / "home"
            parent = home / "n8n-local" / "harness-evaluations"
            runtime = parent / "test-run"
            runtime.mkdir(parents=True, mode=0o700)
            parent.chmod(0o700)
            runtime.chmod(0o700)
            environment = {
                "ONION_SENTINEL_EVALUATION_MODE": "1",
                "ONION_SENTINEL_EVALUATION_RUNTIME_DIR": str(runtime),
                "ONION_SENTINEL_EVALUATION_TOKEN": EVALUATION_TOKEN,
            }
            with (
                mock.patch.object(self.runner, "HOME", home),
                mock.patch.dict(os.environ, environment, clear=False),
            ):
                self.assertEqual(
                    self.runner.controlled_evaluation_runtime(
                        "http://127.0.0.1:18787"
                    ),
                    (True, runtime),
                )
                for unsafe_origin in (
                    "http://127.0.0.1:0",
                    "http://127.0.0.1:8787",
                    "http://example.invalid:18787",
                    "http://127.0.0.1:18787/analysis/result",
                ):
                    with self.subTest(unsafe_origin=unsafe_origin):
                        with self.assertRaisesRegex(
                            SystemExit,
                            "alternate loopback",
                        ):
                            self.runner.controlled_evaluation_runtime(
                                unsafe_origin
                            )
                runtime.chmod(0o750)
                with self.assertRaisesRegex(
                    SystemExit,
                    "must be owner-only",
                ):
                    self.runner.controlled_evaluation_runtime(
                        "http://127.0.0.1:18787"
                    )

            outside = temporary_root / "outside"
            outside.mkdir(mode=0o700)
            environment[
                "ONION_SENTINEL_EVALUATION_RUNTIME_DIR"
            ] = str(outside)
            with (
                mock.patch.object(self.runner, "HOME", home),
                mock.patch.dict(os.environ, environment, clear=False),
            ):
                with self.assertRaisesRegex(SystemExit, "is unsafe"):
                    self.runner.controlled_evaluation_runtime(
                        "http://127.0.0.1:18787"
                    )

    def test_direct_controlled_run_local_requires_isolated_out_dir(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            evaluation_root = root / "evaluation"
            evaluation_root.mkdir(mode=0o700)
            inside = evaluation_root / "analysis"
            outside = root / "global-analysis"
            self.assertEqual(
                self.runner.controlled_evaluation_output_dir(
                    inside,
                    evaluation_root,
                ),
                inside,
            )
            with self.assertRaisesRegex(
                SystemExit,
                "out_dir must stay inside",
            ):
                self.runner.controlled_evaluation_output_dir(
                    outside,
                    evaluation_root,
                )

            args = SimpleNamespace(
                out_dir=outside,
                reanalysis_attempt_id="",
                alert_store_url="http://127.0.0.1:18787",
            )
            with (
                mock.patch.object(
                    self.runner,
                    "parse_args",
                    return_value=args,
                ),
                mock.patch.object(
                    self.runner,
                    "controlled_evaluation_runtime",
                    return_value=(True, evaluation_root),
                ),
                mock.patch.dict(
                    os.environ,
                    {"ONION_SENTINEL_EVALUATION_FREEZE_MEMORY": "1"},
                    clear=False,
                ),
                mock.patch.object(
                    self.runner,
                    "controlled_evaluation_result_identity",
                ) as result_identity,
            ):
                with self.assertRaisesRegex(
                    SystemExit,
                    "out_dir must stay inside",
                ):
                    self.runner.main()
            result_identity.assert_not_called()

    def test_mode_off_exact_target_runs_real_runner_without_controlled_identity(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            home = root / "home"
            home.mkdir(mode=0o700)
            database = root / "alerts.sqlite3"
            with closing(sqlite3.connect(database)) as connection:
                connection.execute("CREATE TABLE marker (id INTEGER)")
                connection.commit()
            settings = root / "ai-settings.json"
            settings.write_text("{}", encoding="utf-8")
            prompt = root / "mode-off-prompt.json"
            prompt.write_text(
                json.dumps(
                    {
                        "package_type": "deliberately-invalid-offline-package",
                    }
                ),
                encoding="utf-8",
            )
            group_id = "abababababababababab"
            alert_id = "mode-off-exact-target"
            stable_group_key = "v2|mode-off|exact-target"
            dispatch_id = "a" * 64
            job_payload = {
                "alert_id": alert_id,
                "representative_alert_id": alert_id,
                "group_id": group_id,
                "stable_group_id": group_id,
                "stable_group_key": stable_group_key,
                "dispatch_id": dispatch_id,
                "release_id": RELEASE_ID,
                "manual_reanalysis": True,
            }
            selected = {
                "alert_id": alert_id,
                "stable_group_id": group_id,
                "queue_group_key": stable_group_key,
                "durable_job_type": "ai_analysis",
                "has_durable_intent": 1,
                "durable_job_id": 17,
                "durable_payload_json": json.dumps(job_payload),
                "rule_name": "Mode-off exact target",
                "triage_level": "critical",
                "triage_score": 100,
                "last_seen": "2026-07-27  12:00:00+00:00",
                "queue_time": "2026-07-27  12:00:00+00:00",
            }
            args = SimpleNamespace(
                db=database,
                prompt_dir=root / "prompts",
                analysis_dir=root / "analysis",
                pcap_analysis_dir=root / "pcap-analysis",
                incident_evidence_dir=root / "incident-evidence",
                incident_evidence_config=root / "incident-evidence.json",
                ai_settings_file=settings,
                provider_lane="any",
                lock_file=root / "scheduler.lock",
                wake_file=root / "scheduler.wake",
                levels="critical,high,medium,low,informational",
                hours=87600,
                max_per_run=1,
                only_group_id=group_id,
                only_alert_id=alert_id,
                only_stable_group_key=stable_group_key,
                only_dispatch_id=dispatch_id,
                related_limit=8,
                correlation_limit=8,
                correlation_min_score=15,
                model=None,
                timeout=1,
                max_prompt_bytes=1024 * 1024,
                portal_wake_file=root / "dashboard.wake",
                no_portal_refresh=True,
                alert_store_url="http://127.0.0.1:9",
                include_tests=True,
                dry_run=False,
            )

            def status_transition(
                _base_url: str,
                _group_id: str,
                status: str,
                error: str = "",
                lease_token: str = "",
                **kwargs,
            ):
                del error, lease_token, kwargs
                if status == "processing":
                    return self.scheduler.ClaimedAiLease(
                        "17171717-1717-4171-8171-171717171717",
                        job_payload=job_payload,
                        job_type="ai_analysis",
                        resolved_key=group_id,
                        job_id=17,
                    )
                return True

            environment = sanitized_environment()
            environment.update(
                {
                    "HOME": str(home),
                    "ONION_SENTINEL_EVALUATION_MODE": "0",
                    "ONION_SENTINEL_RELEASE_ID": RELEASE_ID,
                }
            )
            for environment_key in (
                self.runner.CONTROLLED_RESULT_ENVIRONMENT.values()
            ):
                environment.pop(environment_key, None)

            original_flush = (
                self.scheduler.flush_deferred_analysis_results
            )
            with (
                mock.patch.object(
                    self.scheduler,
                    "parse_args",
                    return_value=args,
                ),
                mock.patch.object(
                    self.scheduler,
                    "require_runtime_capacity",
                ),
                mock.patch.object(
                    self.scheduler,
                    "indexed_scheduler_available",
                    return_value=True,
                ),
                mock.patch.object(
                    self.scheduler,
                    "flush_deferred_analysis_results",
                    wraps=original_flush,
                ) as flush_deferred,
                mock.patch.object(
                    self.scheduler,
                    "reconcile_worker_state",
                    return_value=0,
                ) as reconcile,
                mock.patch.object(
                    self.scheduler,
                    "select_next_alert_indexed",
                    return_value=selected,
                ),
                mock.patch.object(
                    self.scheduler,
                    "report_ai_job_status",
                    side_effect=status_transition,
                ) as report_status,
                mock.patch.object(
                    self.scheduler,
                    "claimed_durable_ai_job",
                    return_value=(
                        job_payload,
                        alert_id,
                        group_id,
                        "critical",
                    ),
                ),
                mock.patch.object(
                    self.scheduler,
                    "build_prompt",
                    return_value=prompt,
                ),
                mock.patch.dict(os.environ, environment, clear=True),
            ):
                self.assertEqual(self.scheduler.main(), 0)

            flush_deferred.assert_called_once_with(args)
            self.assertEqual(reconcile.call_count, 2)
            for call in reconcile.call_args_list:
                self.assertIs(
                    call.kwargs["controlled_evaluation"],
                    False,
                )
            failure = report_status.call_args_list[-1]
            self.assertEqual(failure.args[2], "failed")
            self.assertIn(
                "unexpected prompt package type",
                failure.args[3],
            )
            self.assertNotIn(
                "controlled result identity requires",
                failure.args[3],
            )

    def test_scheduler_retries_an_indeterminate_exact_claim_boundedly(
        self,
    ) -> None:
        response = io.BytesIO(
            json.dumps(
                {
                    "ok": True,
                    "lease_token": (
                        "77777777-7777-4777-8777-777777777777"
                    ),
                    "dedupe_key": "7" * 20,
                    "claim": {
                        "job_id": 7,
                        "job_type": "ai_analysis",
                        "dedupe_key": "7" * 20,
                        "payload": {
                            "group_id": "7" * 20,
                            "representative_alert_id": (
                                "controlled-alert-claim-retry"
                            ),
                        },
                    },
                }
            ).encode("utf-8")
        )
        response.status = 200
        with (
            mock.patch.object(
                self.scheduler.urllib.request,
                "urlopen",
                side_effect=[
                    urllib.error.URLError("lost response"),
                    response,
                ],
            ) as urlopen,
            mock.patch.object(self.scheduler.time, "sleep"),
        ):
            claim = self.scheduler.report_ai_job_status(
                "http://127.0.0.1:18787",
                "7" * 20,
                "processing",
                expected_job_id=7,
                expected_representative_alert_id=(
                    "controlled-alert-claim-retry"
                ),
                expected_dispatch_id="7" * 64,
                expected_stable_group_key="v2|controlled|claim-retry",
            )
        self.assertEqual(
            claim,
            "77777777-7777-4777-8777-777777777777",
        )
        self.assertEqual(urlopen.call_count, 2)
        self.assertEqual(
            urlopen.call_args_list[0].args[0].data,
            urlopen.call_args_list[1].args[0].data,
        )

    def test_scheduler_requires_exact_frozen_owner_only_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary).resolve()
            home = temporary_root / "home"
            parent = home / "n8n-local" / "harness-evaluations"
            runtime = parent / "test-run"
            runtime.mkdir(parents=True, mode=0o700)
            parent.chmod(0o700)
            runtime.chmod(0o700)
            settings = runtime / "ai-model-settings.json"
            harness_policy = runtime / "investigation-harness-policy.json"
            detection_playbooks = runtime / "detection-playbooks.json"
            incident_evidence_config = runtime / "incident-evidence.json"
            live_osquery_config = runtime / "live-osquery.json"
            adjudicator_prompt = runtime / "disagreement-adjudicator.md"
            shared_memory = runtime / "shared-agent-memory.md"
            asset_inventory = runtime / "asset-inventory.json"
            database = runtime / "alerts.sqlite3"
            for path in (
                settings,
                harness_policy,
                detection_playbooks,
                incident_evidence_config,
                live_osquery_config,
                adjudicator_prompt,
                shared_memory,
                asset_inventory,
                database,
            ):
                path.write_text("{}\n", encoding="utf-8")
                path.chmod(0o600)
            rollups = runtime / "rollups"
            pcap_analysis = runtime / "pcap-analysis"
            agent_memory = runtime / "agent-memory"
            for path in (rollups, pcap_analysis, agent_memory):
                path.mkdir(mode=0o700)
            args = SimpleNamespace(
                db=database,
                prompt_dir=runtime / "prompts",
                analysis_dir=runtime / "analysis",
                pcap_analysis_dir=pcap_analysis,
                incident_evidence_dir=runtime / "incident-evidence",
                investigation_pivot_dir=runtime / "investigation-pivots",
                incident_evidence_config=incident_evidence_config,
                live_osquery_config=live_osquery_config,
                disagreement_adjudicator_prompt_file=adjudicator_prompt,
                rollup_dir=rollups,
                agent_memory_dir=agent_memory,
                shared_memory_file=shared_memory,
                asset_inventory_file=asset_inventory,
                lock_file=runtime / "worker.lock",
                wake_file=runtime / "worker.wake",
                portal_wake_file=runtime / "dashboard.wake",
                alert_store_url="http://127.0.0.1:18787",
                only_group_id="0123456789abcdefabcd",
                only_alert_id="synthetic-controlled-alert",
                only_stable_group_key="v2|synthetic|controlled",
                only_dispatch_id="a" * 64,
                max_per_run=1,
                ai_settings_file=settings,
                investigation_harness_policy=harness_policy,
                detection_playbooks=detection_playbooks,
            )
            environment = {
                "ONION_SENTINEL_EVALUATION_MODE": "1",
                "ONION_SENTINEL_EVALUATION_RUNTIME_DIR": str(runtime),
                "ONION_SENTINEL_EVALUATION_FREEZE_MEMORY": "1",
                "ONION_SENTINEL_RELEASE_ID": RELEASE_ID,
                "ONION_SENTINEL_EVALUATION_TOKEN": EVALUATION_TOKEN,
            }
            with (
                mock.patch.object(self.scheduler, "HOME", home),
                mock.patch.dict(os.environ, environment, clear=False),
            ):
                self.assertEqual(
                    self.scheduler.controlled_evaluation_runtime(args),
                    runtime,
                )
                args.analysis_dir = temporary_root / "global-analysis"
                with self.assertRaisesRegex(
                    SystemExit,
                    "must stay inside",
                ):
                    self.scheduler.controlled_evaluation_runtime(args)

            args.analysis_dir = runtime / "analysis"
            args.investigation_harness_policy = (
                temporary_root / "global-harness-policy.json"
            )
            args.investigation_harness_policy.write_text(
                "{}\n",
                encoding="utf-8",
            )
            args.investigation_harness_policy.chmod(0o600)
            with (
                mock.patch.object(self.scheduler, "HOME", home),
                mock.patch.dict(os.environ, environment, clear=False),
            ):
                with self.assertRaisesRegex(
                    SystemExit,
                    "runtime configuration must stay inside",
                ):
                    self.scheduler.controlled_evaluation_runtime(args)

            args.investigation_harness_policy = harness_policy
            environment["ONION_SENTINEL_EVALUATION_FREEZE_MEMORY"] = "0"
            with (
                mock.patch.object(self.scheduler, "HOME", home),
                mock.patch.dict(os.environ, environment, clear=False),
            ):
                with self.assertRaisesRegex(
                    SystemExit,
                    "requires one exact frozen job",
                ):
                    self.scheduler.controlled_evaluation_runtime(args)

    def test_controlled_scheduler_does_not_reconcile_global_jobs(self) -> None:
        args = SimpleNamespace(
            only_group_id="0123456789abcdefabcd",
            db=Path("/must/not/be/opened.sqlite3"),
        )
        with (
            mock.patch.object(
                self.scheduler.sqlite3,
                "connect",
                side_effect=AssertionError(
                    "controlled worker opened the global database"
                ),
            ),
            mock.patch.object(
                self.scheduler,
                "reconcile_completed_ai_jobs",
                side_effect=AssertionError(
                    "controlled worker reconciled global durable jobs"
                ),
            ),
        ):
            self.assertEqual(
                self.scheduler.reconcile_worker_state(
                    args,
                    True,
                    controlled_evaluation=True,
                ),
                0,
            )

    def test_mode_off_exact_target_still_reconciles_global_jobs(self) -> None:
        args = SimpleNamespace(
            only_group_id="0123456789abcdefabcd",
            db=Path("/synthetic/production.sqlite3"),
            alert_store_url="http://127.0.0.1:8787",
        )
        connection = mock.MagicMock()
        with (
            mock.patch.object(
                self.scheduler.sqlite3,
                "connect",
                return_value=connection,
            ) as connect,
            mock.patch.object(
                self.scheduler,
                "indexed_reconcilable_ai_job_ids",
                return_value={"completed-group"},
            ),
            mock.patch.object(
                self.scheduler,
                "reconcile_completed_ai_jobs",
                return_value=1,
            ) as reconcile,
        ):
            self.assertEqual(
                self.scheduler.reconcile_worker_state(
                    args,
                    True,
                    controlled_evaluation=False,
                ),
                1,
            )
        connect.assert_called_once()
        connection.close.assert_called_once()
        reconcile.assert_called_once_with(
            args.alert_store_url,
            {"completed-group"},
        )

    def test_evaluation_spools_are_explicitly_wired_and_do_not_touch_global_dirs(
        self,
    ) -> None:
        source = RUNNER_PATH.read_text(encoding="utf-8")
        for wiring in (
            "queue_dir=evaluation_index_queue_dir",
            "quarantine_dir=evaluation_index_quarantine_dir",
            "pending_dir=evaluation_memory_pending_dir",
            "committed_dir=evaluation_memory_committed_dir",
            "receipt_dir=evaluation_memory_receipt_dir",
        ):
            self.assertIn(wiring, source)

        scheduler_source = SCHEDULER_PATH.read_text(encoding="utf-8")
        self.assertIn(
            "if indexed_mode and controlled_evaluation_dir is None:",
            scheduler_source,
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            evaluation_queue = root / "evaluation" / "analysis-index-pending"
            evaluation_memory = root / "evaluation" / "memory-pending"
            global_queue = root / "global" / "analysis-index-pending"
            global_memory = root / "global" / "memory-pending"
            global_queue.mkdir(parents=True)
            global_memory.mkdir(parents=True)
            global_queue_sentinel = global_queue / "production.json"
            global_memory_sentinel = global_memory / "production.json"
            global_queue_sentinel.write_text("production", encoding="utf-8")
            global_memory_sentinel.write_text("production", encoding="utf-8")

            queued = self.runner.queue_analysis_index(
                {
                    "analysis_id": "controlled-spool-test",
                    "response": {"summary": "synthetic"},
                },
                queue_dir=evaluation_queue,
            )
            memory_task = self.runner.stage_memory_writeback_task(
                analysis_id="controlled-spool-test",
                response_digest="a" * 64,
                agent_role="soc-analyst",
                role_memory_file=root / "role.md",
                shared_memory_file=root / "shared.md",
                source_artifact="synthetic",
                primary_candidates=[
                    {
                        "scope": "agent",
                        "category": "investigation_pivot",
                        "finding": (
                            "Validate synthetic evidence using an independent "
                            "network pivot before drawing a conclusion."
                        ),
                        "use_when": "A later synthetic alert is investigated.",
                        "evidence_basis": [
                            "Two independent synthetic sources agreed."
                        ],
                        "confidence": "medium",
                        "tags": ["synthetic"],
                        "ttl_days": 30,
                    }
                ],
                primary_allowed=True,
                primary_reason="synthetic controlled evaluation",
                reviewer_candidates=[],
                reviewer_allowed=False,
                reviewer_reason="not applicable",
                pending_dir=evaluation_memory,
            )

            self.assertTrue(queued.is_file())
            self.assertIsNotNone(memory_task)
            self.assertTrue(memory_task.is_file())
            self.assertEqual(
                global_queue_sentinel.read_text(encoding="utf-8"),
                "production",
            )
            self.assertEqual(
                global_memory_sentinel.read_text(encoding="utf-8"),
                "production",
            )
            self.assertEqual(
                sorted(path.name for path in global_queue.iterdir()),
                ["production.json"],
            )
            self.assertEqual(
                sorted(path.name for path in global_memory.iterdir()),
                ["production.json"],
            )


if __name__ == "__main__":
    unittest.main()
