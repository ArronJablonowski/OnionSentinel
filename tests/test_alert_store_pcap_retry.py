#!/usr/bin/env python3
"""End-to-end checks for durable, resumable PCAP transfer retries."""

from __future__ import annotations

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
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
ALERT_STORE_DIR = REPO_ROOT / "n8n" / "alert_store"
ALERT_STORE = ALERT_STORE_DIR / "alert_store.js"
SCORING_RULES = ALERT_STORE_DIR / "config" / "scoring_rules.json"


def available_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def request_json(url: str, method: str = "GET", payload: dict | None = None) -> tuple[int, dict]:
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
        return error.code, json.loads(error.read())


class AlertStorePcapRetryTest(unittest.TestCase):
    def setUp(self) -> None:
        if not (ALERT_STORE_DIR / "node_modules" / "sqlite3").exists():
            self.skipTest("run npm ci in n8n/alert_store to install the locked sqlite3 dependency")
        self.tempdir = tempfile.TemporaryDirectory(prefix="onion-sentinel-pcap-retry-")
        self.runtime = Path(self.tempdir.name)
        self.db_path = self.runtime / "alerts.sqlite3"
        self.ai_wake_path = self.runtime / "run" / "ai-analysis.wake"
        self.pcap_wake_path = self.runtime / "run" / "pcap-analysis.wake"
        self.port = available_port()
        env = {
            **os.environ,
            "ALERT_STORE_DB": str(self.db_path),
            "SCORING_RULES_PATH": str(SCORING_RULES),
            "ALERT_STORE_HOST": "127.0.0.1",
            "ALERT_STORE_PORT": str(self.port),
            "ALERT_STORE_BEACON_PATHS": str(self.runtime / "beacon.json"),
            "ALERT_STORE_BEACON_HISTORY_PATHS": str(self.runtime / "beacon-history.json"),
            "ALERT_STORE_DISK_MIN_FREE_BYTES": "0",
            "ALERT_STORE_DISK_START_MAX_USED_PERCENT": "79",
            "ALERT_STORE_DISK_HARD_MAX_USED_PERCENT": "80",
            "TELEGRAM_OUTBOX_AUTOSTART": "0",
            "ENRICHMENT_WORKER_INTERVAL_MS": "600000",
            "PIPELINE_DISK_SAMPLE_INTERVAL_SECONDS": "3600",
            "PCAP_CAPTURE_RETENTION_SECONDS": "0",
            "PCAP_TRANSFER_MAX_ATTEMPTS": "2",
            "PCAP_TRANSFER_MAX_RETRY_SECONDS": "300",
            "AI_ANALYSIS_WAKE_PATH": str(self.ai_wake_path),
            "PCAP_ANALYSIS_WAKE_PATH": str(self.pcap_wake_path),
        }
        self.process = subprocess.Popen(
            ["node", str(ALERT_STORE)],
            cwd=ALERT_STORE_DIR,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        self.base_url = f"http://127.0.0.1:{self.port}"
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            try:
                if request_json(f"{self.base_url}/health")[0] == 200:
                    break
            except (OSError, urllib.error.URLError):
                time.sleep(0.1)
        else:
            output = self.process.stdout.read() if self.process.poll() is not None and self.process.stdout else ""
            self.fail(f"alert-store did not become healthy: {output}")

    def tearDown(self) -> None:
        if hasattr(self, "process"):
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        if hasattr(self, "tempdir"):
            self.tempdir.cleanup()

    def post(self, path: str, payload: dict) -> dict:
        status, result = request_json(f"{self.base_url}{path}", "POST", payload)
        self.assertEqual(status, 200, result)
        return result

    def test_retry_preserves_progress_honors_backoff_and_exhausts(self) -> None:
        created = self.post(
            "/pcap/request",
            {
                "alert_id": "synthetic-pcap-retry",
                "group_id": "synthetic-group",
                "first_seen": "2026-07-16  08:00:00-06:00",
                "last_seen": "2026-07-16  08:01:00-06:00",
                "source_ip": "192.0.2.10",
                "destination_ip": "198.51.100.20",
                "destination_port": 443,
                "transport_protocol": "tcp",
                "reason": "synthetic retry validation",
            },
        )
        request_id = created["request"]["request_id"]
        first_claim = self.post("/pcap/claim", {"request_id": request_id, "relay_host": "relay-a"})
        self.assertEqual(first_claim["request"]["transfer_attempt_count"], 1)
        duplicate_claim = self.post("/pcap/claim", {"request_id": request_id, "relay_host": "relay-b"})
        self.assertFalse(duplicate_claim["claimed"])
        self.assertEqual(duplicate_claim["request"]["transfer_attempt_count"], 1)
        self.post(
            "/pcap/progress",
            {"request_id": request_id, "stage": "relay_to_mac", "transferred_bytes": 1024, "total_bytes": 4096},
        )
        retried = self.post(
            "/pcap/retry",
            {
                "request_id": request_id,
                "stage": "relay_to_mac",
                "error": "synthetic rsync connection failure",
                "retry_after_seconds": 120,
            },
        )
        request_row = retried["request"]
        self.assertTrue(retried["retry_scheduled"])
        self.assertEqual(request_row["status"], "pending")
        self.assertEqual(request_row["transfer_stage"], "relay_to_mac")
        self.assertEqual(request_row["transfer_bytes"], 1024)
        self.assertEqual(request_row["transfer_retry_count"], 1)
        self.assertEqual(request_row["transfer_last_failed_stage"], "relay_to_mac")

        _, delayed = request_json(f"{self.base_url}/pcap/requests?status=pending&limit=10")
        self.assertEqual(delayed["requests"], [])
        with sqlite3.connect(self.db_path, timeout=3) as connection:
            connection.execute(
                "UPDATE pcap_requests SET next_attempt_at = '2000-01-01T00:00:00Z' WHERE request_id = ?",
                (request_id,),
            )
            connection.commit()
        _, ready = request_json(f"{self.base_url}/pcap/requests?status=pending&limit=10")
        self.assertEqual([item["request_id"] for item in ready["requests"]], [request_id])

        second_claim = self.post("/pcap/claim", {"request_id": request_id, "relay_host": "relay-a"})
        self.assertEqual(second_claim["request"]["transfer_attempt_count"], 2)
        exhausted = self.post(
            "/pcap/retry",
            {"request_id": request_id, "stage": "verifying", "error": "synthetic checksum mismatch"},
        )
        self.assertTrue(exhausted["exhausted"])
        self.assertFalse(exhausted["retry_scheduled"])
        self.assertEqual(exhausted["request"]["status"], "failed")
        self.assertEqual(exhausted["request"]["outcome"], "checksum_failed")

    def test_pending_requests_are_scheduled_by_severity(self) -> None:
        requests: dict[str, str] = {}
        with sqlite3.connect(self.db_path, timeout=3) as connection:
            for level in ("low", "critical", "high"):
                group_id = f"synthetic-{level}-group"
                connection.execute(
                    """
                    INSERT INTO alert_group_summary (
                      group_id, group_key, triage_level, updated_at
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (group_id, f"synthetic-{level}-key", level, "2026-07-16  08:00:00-06:00"),
                )
            connection.commit()

        for level in ("low", "critical", "high"):
            created = self.post(
                "/pcap/request",
                {
                    "alert_id": f"synthetic-{level}-alert",
                    "group_id": f"synthetic-{level}-group",
                    "first_seen": "2026-07-16  08:00:00-06:00",
                    "last_seen": "2026-07-16  08:01:00-06:00",
                    "source_ip": "192.0.2.10",
                    "destination_ip": "198.51.100.20",
                    "destination_port": 443,
                    "transport_protocol": "tcp",
                    "reason": f"synthetic {level} scheduling validation",
                },
            )
            requests[level] = created["request"]["request_id"]

        _, pending = request_json(f"{self.base_url}/pcap/requests?status=pending&limit=10")
        self.assertEqual(
            [item["request_id"] for item in pending["requests"]],
            [requests["critical"], requests["high"], requests["low"]],
        )

    def test_fulfilled_transfer_wakes_parser_and_completed_parse_requeues_ai(self) -> None:
        with sqlite3.connect(self.db_path, timeout=3) as connection:
            connection.execute(
                """
                INSERT INTO alert_group_summary (
                  group_id, group_key, triage_level, updated_at
                ) VALUES (?, ?, ?, ?)
                """,
                ("synthetic-wake-group", "synthetic-wake-key", "high", "2026-07-16  08:00:00-06:00"),
            )
            connection.commit()
        created = self.post(
            "/pcap/request",
            {
                "alert_id": "synthetic-wake-alert",
                "group_id": "synthetic-wake-group",
                "group_key": "synthetic-wake-key",
                "first_seen": "2026-07-16  08:00:00-06:00",
                "last_seen": "2026-07-16  08:01:00-06:00",
                "source_ip": "192.0.2.10",
                "destination_ip": "198.51.100.20",
                "destination_port": 443,
                "transport_protocol": "tcp",
                "reason": "synthetic worker wake validation",
            },
        )
        request_id = created["request"]["request_id"]
        self.post("/pcap/claim", {"request_id": request_id, "relay_host": "relay-a"})
        self.post(
            "/pcap/complete",
            {
                "request_id": request_id,
                "status": "fulfilled",
                "artifact_path": "/tmp/synthetic-worker-wake.pcap",
                "artifact_sha256": "a" * 64,
                "artifact_size_bytes": 4096,
                "relay_host": "relay-a",
            },
        )
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline and not self.pcap_wake_path.exists():
            time.sleep(0.02)
        self.assertTrue(self.pcap_wake_path.exists())
        self.assertIn("pcap-transfer-completed", self.pcap_wake_path.read_text(encoding="utf-8"))

        self.post("/pcap/analysis-status", {"request_id": request_id, "status": "processing"})
        self.post("/pcap/analysis-status", {"request_id": request_id, "status": "completed"})
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline and not self.ai_wake_path.exists():
            time.sleep(0.02)
        self.assertTrue(self.ai_wake_path.exists())
        self.assertIn("pcap-analysis-completed", self.ai_wake_path.read_text(encoding="utf-8"))
        with sqlite3.connect(self.db_path, timeout=3) as connection:
            queued = connection.execute(
                "SELECT status, priority FROM durable_jobs WHERE job_type = 'ai_analysis' AND dedupe_key = ?",
                ("synthetic-wake-group",),
            ).fetchone()
        self.assertEqual(queued, ("pending", 3))

        # A second evidence completion while inference is active must survive
        # the first run's completion callback as exactly one coalesced rerun.
        self.post(
            "/jobs/status",
            {"job_type": "ai_analysis", "dedupe_key": "synthetic-wake-group", "status": "processing"},
        )
        self.post("/pcap/analysis-status", {"request_id": request_id, "status": "completed"})
        self.post(
            "/jobs/status",
            {"job_type": "ai_analysis", "dedupe_key": "synthetic-wake-group", "status": "completed"},
        )
        with sqlite3.connect(self.db_path, timeout=3) as connection:
            rerun = connection.execute(
                """
                SELECT status, rerun_requested, processing_started_at
                FROM durable_jobs WHERE job_type = 'ai_analysis' AND dedupe_key = ?
                """,
                ("synthetic-wake-group",),
            ).fetchone()
        self.assertEqual(rerun, ("pending", 0, None))

        self.post(
            "/jobs/status",
            {"job_type": "ai_analysis", "dedupe_key": "synthetic-wake-group", "status": "processing"},
        )
        self.post(
            "/jobs/status",
            {"job_type": "ai_analysis", "dedupe_key": "synthetic-wake-group", "status": "completed"},
        )
        with sqlite3.connect(self.db_path, timeout=3) as connection:
            completed = connection.execute(
                "SELECT status FROM durable_jobs WHERE job_type = 'ai_analysis' AND dedupe_key = ?",
                ("synthetic-wake-group",),
            ).fetchone()
        self.assertEqual(completed, ("completed",))


if __name__ == "__main__":
    unittest.main()
