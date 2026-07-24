#!/usr/bin/env python3
"""Concurrent ingestion regression test for alert-store's SQLite boundary."""
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
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
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
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())


class AlertStoreConcurrencyTests(unittest.TestCase):
    unique_alerts = 32
    repeats_per_alert = 4

    def setUp(self) -> None:
        if not (ALERT_STORE_DIR / "node_modules" / "sqlite3").exists():
            self.skipTest("run npm ci in n8n/alert_store to install the locked sqlite3 dependency")
        self.tempdir = tempfile.TemporaryDirectory(prefix="onion-sentinel-ingest-load-")
        self.runtime = Path(self.tempdir.name)
        self.db_path = self.runtime / "alerts.sqlite3"
        self.port = available_port()
        self.process_log = tempfile.TemporaryFile(mode="w+t", encoding="utf-8")
        env = {
            **os.environ,
            "ALERT_STORE_DB": str(self.db_path),
            "SCORING_RULES_PATH": str(SCORING_RULES),
            "ALERT_STORE_HOST": "127.0.0.1",
            "ALERT_STORE_PORT": str(self.port),
            "ALERT_STORE_MAX_CONNECTIONS": "128",
            "ALERT_STORE_BEACON_PATHS": str(self.runtime / "beacon.json"),
            "ALERT_STORE_BEACON_HISTORY_PATHS": str(self.runtime / "beacon-history.json"),
            "ALERT_STORE_DISK_MIN_FREE_BYTES": "0",
            # Keep the production 80% hard stop while allowing this isolated
            # temp-database test to run on a development volume near the cap.
            "ALERT_STORE_DISK_START_MAX_USED_PERCENT": "79.99",
            "ALERT_STORE_DISK_HARD_MAX_USED_PERCENT": "80",
            "TELEGRAM_OUTBOX_AUTOSTART": "0",
            "N8N_POST_COMMIT_TOKEN": "",
            "ENRICHMENT_WORKER_INTERVAL_MS": "600000",
            "PIPELINE_DISK_SAMPLE_INTERVAL_SECONDS": "3600",
            "PCAP_CAPTURE_RETENTION_SECONDS": "0",
            "AI_ANALYSIS_WAKE_PATH": str(self.runtime / "run" / "ai-analysis.wake"),
            "PCAP_ANALYSIS_WAKE_PATH": str(self.runtime / "run" / "pcap-analysis.wake"),
        }
        self.process = subprocess.Popen(
            ["node", str(ALERT_STORE)],
            cwd=ALERT_STORE_DIR,
            env=env,
            stdout=self.process_log,
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
                time.sleep(0.05)
        else:
            self.fail(f"alert-store did not become healthy: {self._process_output()}")

    def tearDown(self) -> None:
        if hasattr(self, "process"):
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        if hasattr(self, "process_log"):
            self.process_log.close()
        if hasattr(self, "tempdir"):
            self.tempdir.cleanup()

    def _process_output(self) -> str:
        self.process_log.flush()
        self.process_log.seek(0)
        return self.process_log.read()

    @staticmethod
    def alert(alert_number: int) -> dict:
        return {
            "alert_id": f"synthetic-concurrent-{alert_number:04d}",
            "timestamp": "2026-07-19T12:00:00Z",
            "rule_name": "Synthetic concurrent ingestion validation",
            "event_dataset": "synthetic.alert",
            "severity": 1,
            "severity_label": "low",
            "source": {"ip": "192.0.2.10", "port": 49152},
            "destination": {"ip": "198.51.100.20", "port": 443},
            "network": {"protocol": "tls", "transport": "tcp"},
            # A bounded synthetic record prevents the asynchronous enrichment
            # worker from making public network calls during this load test.
            "enrichment": {
                "external_intel": {
                    "records": [
                        {
                            "source": "synthetic",
                            "indicator": "198.51.100.20",
                            "indicator_type": "ip",
                            "verdict": "unknown",
                        }
                    ]
                }
            },
        }

    def test_concurrent_duplicates_are_serialized_without_loss_or_lock_errors(self) -> None:
        workload = [
            self.alert(alert_number)
            for _ in range(self.repeats_per_alert)
            for alert_number in range(self.unique_alerts)
        ]

        def submit(alert: dict) -> tuple[int, dict]:
            return request_json(f"{self.base_url}/alert", "POST", alert)

        with ThreadPoolExecutor(max_workers=24) as executor:
            results = list(executor.map(submit, workload))

        failures = [(status, payload) for status, payload in results if status != 200 or not payload.get("ok")]
        self.assertEqual(failures, [], self._process_output())
        statuses = [payload["status"] for _, payload in results]
        self.assertEqual(statuses.count("accepted"), self.unique_alerts)
        self.assertEqual(statuses.count("already_seen"), len(workload) - self.unique_alerts)

        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            row_count, total_seen, minimum_seen, maximum_seen = connection.execute(
                "SELECT COUNT(*), SUM(seen_count), MIN(seen_count), MAX(seen_count) FROM alerts"
            ).fetchone()
            integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
            group_total = connection.execute(
                "SELECT MAX(total_seen_count) FROM alert_group_summary"
            ).fetchone()[0]
            group_key = connection.execute(
                "SELECT group_key FROM alert_group_summary LIMIT 1"
            ).fetchone()[0]
            group_expression = """
                COALESCE(
                  NULLIF(suppression_key, ''),
                  (
                    CASE lower(COALESCE(triage_level, ''))
                      WHEN 'critical' THEN 'critical'
                      WHEN 'high' THEN 'high'
                      WHEN 'medium' THEN 'medium'
                      WHEN 'low' THEN 'low'
                      WHEN 'informational' THEN 'informational'
                      WHEN 'info' THEN 'informational'
                      ELSE CASE lower(COALESCE(severity_label, ''))
                        WHEN 'critical' THEN 'critical'
                        WHEN 'high' THEN 'high'
                        WHEN 'medium' THEN 'medium'
                        WHEN 'low' THEN 'low'
                        WHEN 'informational' THEN 'informational'
                        WHEN 'info' THEN 'informational'
                        ELSE 'unknown'
                      END
                    END
                  ) || '|' ||
                  COALESCE(rule_name, 'unknown-rule') || '|' ||
                  COALESCE(source_ip, 'unknown-source') || '|' ||
                  COALESCE(destination_ip, 'unknown-destination') || '|' ||
                  COALESCE(filter_status, 'accepted')
                )
            """
            query_plan = " ".join(
                str(row[-1])
                for row in connection.execute(
                    f"EXPLAIN QUERY PLAN SELECT COUNT(*) FROM alerts WHERE {group_expression} = ?",
                    (group_key,),
                )
            )

        self.assertEqual(row_count, self.unique_alerts)
        self.assertEqual(total_seen, len(workload))
        self.assertEqual((minimum_seen, maximum_seen), (self.repeats_per_alert, self.repeats_per_alert))
        self.assertEqual(group_total, len(workload))
        self.assertEqual(integrity, "ok")
        self.assertIn("idx_alerts_group_key_expr_v2", query_plan)

        metrics_status, metrics_payload = request_json(f"{self.base_url}/metrics")
        self.assertEqual(metrics_status, 200)
        process_metrics = metrics_payload["metrics"]["process"]
        self.assertEqual(process_metrics["ingest_requests"], len(workload))
        self.assertEqual(process_metrics["ingest_errors"], 0)


if __name__ == "__main__":
    unittest.main()
