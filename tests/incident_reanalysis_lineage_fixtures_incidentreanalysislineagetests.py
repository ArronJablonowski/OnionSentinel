from __future__ import annotations

from incident_reanalysis_lineage_fixtures import (
    ALERT_STORE,
    ALERT_STORE_DIR,
    COHORT_MODULE_PATH,
    COHORT_SPEC,
    CONTROLLED_ROUTE_FIELDS,
    DEPLOYED_RELEASE,
    PRIMARY_ROUTE,
    Path,
    REPO_ROOT,
    REVIEWER_ROUTE,
    SCORING_RULES,
    available_port,
    closing,
    cohort,
    dt,
    hashlib,
    importlib,
    json,
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

class IncidentReanalysisLineageTestsFixtures(unittest.TestCase):
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
