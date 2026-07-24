#!/usr/bin/env python3
"""End-to-end durability checks for alert-store's post-commit n8n handoff."""
from __future__ import annotations

import json
import os
import socket
import sqlite3
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from contextlib import closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
ALERT_STORE_DIR = REPO_ROOT / "n8n" / "alert_store"
ALERT_STORE = ALERT_STORE_DIR / "alert_store.js"
SCORING_RULES = ALERT_STORE_DIR / "config" / "scoring_rules.json"


class N8nStubHandler(BaseHTTPRequestHandler):
    accepting = False
    requests: list[dict] = []
    lock = threading.Lock()

    def do_POST(self):  # noqa: N802 - stdlib callback name
        size = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(size))
        with self.lock:
            self.requests.append(
                {
                    "payload": payload,
                    "token": self.headers.get("X-Relay-Token"),
                    "accepted": self.accepting,
                }
            )
        if self.accepting:
            body = {"ok": True, "report_written": True, "report_job_id": payload["report_job_id"]}
            status = 200
        else:
            body = {"ok": False, "status": "error", "reason": "synthetic n8n outage"}
            status = 503
        encoded = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, _format, *_args):
        return


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
        with urllib.request.urlopen(request, timeout=3) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())


class AlertStorePostCommitTest(unittest.TestCase):
    def setUp(self) -> None:
        if not (ALERT_STORE_DIR / "node_modules" / "sqlite3").exists():
            self.skipTest("run npm ci in n8n/alert_store to install the locked sqlite3 dependency")
        N8nStubHandler.accepting = False
        N8nStubHandler.requests = []
        self.n8n = ThreadingHTTPServer(("127.0.0.1", 0), N8nStubHandler)
        self.n8n_thread = threading.Thread(target=self.n8n.serve_forever, daemon=True)
        self.n8n_thread.start()
        self.tempdir = tempfile.TemporaryDirectory(prefix="onion-sentinel-post-commit-")
        self.runtime = Path(self.tempdir.name)
        self.db_path = self.runtime / "alerts.sqlite3"
        self.alert_store_port = available_port()
        env = {
            **os.environ,
            "ALERT_STORE_DB": str(self.db_path),
            "SCORING_RULES_PATH": str(SCORING_RULES),
            "ALERT_STORE_HOST": "127.0.0.1",
            "ALERT_STORE_PORT": str(self.alert_store_port),
            "ALERT_STORE_BEACON_PATHS": str(self.runtime / "n8n-beacon.json"),
            "ALERT_STORE_BEACON_HISTORY_PATHS": str(self.runtime / "n8n-beacon-history.json"),
            "ALERT_STORE_DISK_MIN_FREE_BYTES": "0",
            # Keep the production 80% hard stop while allowing this isolated
            # temp-database test to run on a development volume near the cap.
            "ALERT_STORE_DISK_START_MAX_USED_PERCENT": "79.99",
            "ALERT_STORE_DISK_HARD_MAX_USED_PERCENT": "80",
            "TELEGRAM_OUTBOX_AUTOSTART": "0",
            "ENRICHMENT_WORKER_INTERVAL_MS": "600000",
            "PIPELINE_DISK_SAMPLE_INTERVAL_SECONDS": "3600",
            "N8N_POST_COMMIT_URL": (
                f"http://127.0.0.1:{self.n8n.server_port}/webhook/onion-sentinel-committed-alert"
            ),
            "N8N_POST_COMMIT_TOKEN": "synthetic-post-commit-token",
            "N8N_POST_COMMIT_INTERVAL_MS": "1000",
            "N8N_POST_COMMIT_TIMEOUT_MS": "5000",
            "N8N_POST_COMMIT_MAX_ATTEMPTS": "3",
            "N8N_POST_COMMIT_BASE_RETRY_SECONDS": "5",
        }
        self.process = subprocess.Popen(
            ["node", str(ALERT_STORE)],
            cwd=ALERT_STORE_DIR,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        self.base_url = f"http://127.0.0.1:{self.alert_store_port}"
        self.wait_for(lambda: request_json(f"{self.base_url}/health")[0] == 200, timeout=15)

    def tearDown(self) -> None:
        if hasattr(self, "process"):
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
            if self.process.stdout:
                self.process.stdout.close()
        if hasattr(self, "n8n"):
            self.n8n.shutdown()
            self.n8n.server_close()
        if hasattr(self, "n8n_thread"):
            self.n8n_thread.join(timeout=5)
        if hasattr(self, "tempdir"):
            self.tempdir.cleanup()

    def wait_for(self, predicate, timeout: float = 10) -> None:
        deadline = time.monotonic() + timeout
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            try:
                if predicate():
                    return
            except (OSError, sqlite3.Error, urllib.error.URLError) as error:
                last_error = error
            time.sleep(0.1)
        output = ""
        if hasattr(self, "process") and self.process.poll() is not None and self.process.stdout:
            output = self.process.stdout.read()
        self.fail(f"condition not met before timeout; last_error={last_error}; alert-store={output}")

    def durable_job(self) -> sqlite3.Row | None:
        with closing(sqlite3.connect(self.db_path, timeout=3)) as connection:
            connection.row_factory = sqlite3.Row
            return connection.execute(
                "SELECT * FROM durable_jobs WHERE job_type = 'n8n_post_commit'"
            ).fetchone()

    @staticmethod
    def synthetic_alert() -> dict:
        return {
            "alert_id": "synthetic-post-commit-alert",
            "timestamp": "2026-07-16T12:00:00Z",
            "rule_name": "Synthetic durable boundary validation",
            "event_dataset": "synthetic.alert",
            "severity": 1,
            "severity_label": "low",
            "source": {"ip": "10.0.0.10", "port": 49152},
            "destination": {"ip": "10.0.0.20", "port": 443},
            "network": {"protocol": "tls", "transport": "tcp"},
        }

    def test_n8n_outage_cannot_roll_back_alert_and_recovery_is_exactly_once(self) -> None:
        status, result = request_json(
            f"{self.base_url}/alert", method="POST", payload=self.synthetic_alert()
        )
        self.assertEqual(status, 200)
        self.assertEqual(result["status"], "accepted")
        self.assertTrue(result["stored"])

        self.wait_for(
            lambda: (
                (job := self.durable_job()) is not None
                and job["status"] == "pending"
                and job["attempt_count"] >= 1
            )
        )
        with closing(sqlite3.connect(self.db_path)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM alerts WHERE alert_id = ?",
                    (self.synthetic_alert()["alert_id"],),
                ).fetchone()[0],
                1,
            )

        N8nStubHandler.accepting = True
        self.wait_for(
            lambda: (job := self.durable_job()) is not None and job["status"] == "completed",
            timeout=10,
        )
        with N8nStubHandler.lock:
            successful = [request for request in N8nStubHandler.requests if request["accepted"]]
            self.assertEqual(len(successful), 1)
            self.assertEqual(successful[0]["token"], "synthetic-post-commit-token")
            self.assertTrue(successful[0]["payload"]["should_write_report"])

        replay_status, replay = request_json(
            f"{self.base_url}/alert", method="POST", payload=self.synthetic_alert()
        )
        self.assertEqual(replay_status, 200)
        self.assertEqual(replay["status"], "already_seen")
        self.assertFalse(replay["stored"])
        time.sleep(1.5)
        with N8nStubHandler.lock:
            successful = [request for request in N8nStubHandler.requests if request["accepted"]]
            self.assertEqual(len(successful), 1)


if __name__ == "__main__":
    unittest.main()
