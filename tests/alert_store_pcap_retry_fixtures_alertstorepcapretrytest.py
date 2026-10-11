from __future__ import annotations

from alert_store_pcap_retry_fixtures import (
    ALERT_STORE,
    ALERT_STORE_DIR,
    CONTROLLED_ROUTE_FIELDS,
    DEPLOYED_RELEASE,
    Path,
    REPO_ROOT,
    SCORING_RULES,
    available_port,
    closing,
    io,
    json,
    mock,
    os,
    request_json,
    socket,
    sqlite3,
    subprocess,
    tempfile,
    time,
    unittest,
    urllib,
)

class AlertStorePcapRetryTestFixtures(unittest.TestCase):
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
            "PCAP_PRIORITY_MAX_WAIT_SECONDS": "1200",
            "PCAP_TRANSFER_MAX_ATTEMPTS": "2",
            "PCAP_TRANSFER_MAX_RETRY_SECONDS": "300",
            "AI_ANALYSIS_WAKE_PATH": str(self.ai_wake_path),
            "PCAP_ANALYSIS_WAKE_PATH": str(self.pcap_wake_path),
            "ONION_SENTINEL_RELEASE_ID": DEPLOYED_RELEASE,
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
            if self.process.stdout:
                self.process.stdout.close()
        if hasattr(self, "tempdir"):
            self.tempdir.cleanup()


    def post(self, path: str, payload: dict) -> dict:
        status, result = request_json(f"{self.base_url}{path}", "POST", payload)
        self.assertEqual(status, 200, result)
        return result


    def seed_manual_dispatch_group(self) -> dict[str, str]:
        identity = {
            "dashboard_group_id": "1234567890ab",
            "stable_group_id": "abcdef1234567890abcd",
            "stable_group_key": "v2|manual-dispatch-group",
            "current_alert_id": "manual-dispatch-current-alert",
            "pinned_alert_id": "manual-dispatch-frozen-alert",
            "foreign_alert_id": "manual-dispatch-foreign-alert",
            "key_collision_alert_id": "manual-dispatch-key-collision-alert",
        }
        timestamp = "2026-07-26  01:00:00-06:00"
        rows = (
            (
                identity["current_alert_id"],
                identity["stable_group_key"],
                identity["stable_group_id"],
                "192.0.2.10",
                "198.51.100.10",
            ),
            (
                identity["pinned_alert_id"],
                identity["stable_group_key"],
                identity["stable_group_id"],
                "192.0.2.11",
                "198.51.100.11",
            ),
            (
                identity["foreign_alert_id"],
                "v2|manual-dispatch-foreign",
                "fedcba0987654321fedc",
                "192.0.2.12",
                "198.51.100.12",
            ),
            (
                identity["key_collision_alert_id"],
                "v2|manual-dispatch-conflicting-key",
                identity["stable_group_id"],
                "192.0.2.13",
                "198.51.100.13",
            ),
        )
        with closing(sqlite3.connect(self.db_path, timeout=3)) as connection:
            for alert_id, stable_key, stable_id, source_ip, destination_ip in rows:
                alert = {
                    "alert_id": alert_id,
                    "timestamp": timestamp,
                    "rule_name": "Synthetic frozen dispatch identity",
                    "severity": 3,
                    "severity_label": "high",
                    "source": {"ip": source_ip},
                    "destination": {"ip": destination_ip},
                }
                connection.execute(
                    """
                    INSERT INTO alerts (
                      alert_id, first_seen, last_seen, timestamp, rule_name,
                      severity, severity_label, source_ip, destination_ip,
                      triage_level, filter_status, stable_group_key,
                      stable_group_id, alert_json
                    ) VALUES (?, ?, ?, ?, ?, 3, 'high', ?, ?, 'high',
                              'accepted', ?, ?, ?)
                    """,
                    (
                        alert_id,
                        timestamp,
                        timestamp,
                        timestamp,
                        alert["rule_name"],
                        source_ip,
                        destination_ip,
                        stable_key,
                        stable_id,
                        json.dumps(alert),
                    ),
                )
            connection.execute(
                """
                INSERT INTO alert_group_summary (
                  group_id, group_key, representative_alert_id,
                  triage_level, updated_at
                ) VALUES (?, 'manual-dispatch-dashboard-group', ?, 'high', ?)
                """,
                (
                    identity["dashboard_group_id"],
                    identity["current_alert_id"],
                    timestamp,
                ),
            )
            connection.commit()
        return identity


    def manual_dispatch_request(
        self,
        path: str,
        payload: dict,
    ) -> tuple[int, dict]:
        return request_json(
            f"{self.base_url}{path}",
            "POST",
            payload,
        )


