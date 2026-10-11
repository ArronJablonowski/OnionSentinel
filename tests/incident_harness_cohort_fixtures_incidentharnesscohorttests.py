from __future__ import annotations

from incident_harness_cohort_fixtures import (
    EVALUATOR_PATH,
    EVALUATOR_SPEC,
    MODULE_PATH,
    Path,
    ROOT,
    SPEC,
    cohort,
    cohort_analysis_metadata,
    cohort_artifact_adapters,
    cohort_artifact_io,
    cohort_dispatch_adapters,
    cohort_dispatch_identity,
    cohort_evaluation_query_audit,
    cohort_evaluator,
    cohort_execution_proof_service,
    cohort_freeze_state_composition,
    cohort_manifest_adapters,
    cohort_manifest_contract,
    cohort_monitor_adapters,
    cohort_preflight,
    cohort_private_input,
    cohort_query_audit_projection,
    cohort_representative_state,
    cohort_runner_contracts,
    cohort_runtime_composition,
    cohort_second_opinion_state,
    cohort_source_rows,
    cohort_storage_core,
    cohort_storage_state,
    hashlib,
    importlib,
    json,
    mock,
    os,
    sqlite3,
    stat,
    tempfile,
    unittest,
)

class IncidentHarnessCohortTestsFixtures(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="onion-sentinel-cohort-"
        )
        self.root = Path(self.temporary.name)
        self.db_path = self.root / "alerts.sqlite3"
        self.manifest_path = self.root / "private" / "cohort.json"
        self.output_path = self.root / "private" / "export.json"
        self.dashboard_a = "a" * 12
        self.dashboard_b = "b" * 12
        self.dashboard_c = "c" * 12
        self.stable_one = "1" * 20
        self.stable_two = "2" * 20
        self.release_id = "a" * 40
        self._create_database()


    def tearDown(self) -> None:
        self.temporary.cleanup()


    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)


    def _create_database(self) -> None:
        connection = self._connect()
        connection.executescript(
            """
            CREATE TABLE alert_group_summary (
              group_id TEXT PRIMARY KEY,
              representative_alert_id TEXT NOT NULL,
              first_seen TEXT,
              last_seen TEXT,
              timestamp TEXT,
              rule_name TEXT,
              event_dataset TEXT,
              severity INTEGER,
              severity_label TEXT,
              source_ip TEXT,
              source_port INTEGER,
              destination_ip TEXT,
              destination_port INTEGER,
              network_protocol TEXT,
              transport_protocol TEXT,
              traffic_direction TEXT,
              triage_score INTEGER,
              triage_level TEXT,
              raw_alert_count INTEGER,
              total_seen_count INTEGER,
              updated_at TEXT
            );
            CREATE TABLE alert_group_alias (
              legacy_group_id TEXT PRIMARY KEY,
              stable_group_id TEXT NOT NULL,
              stable_group_key TEXT,
              updated_at TEXT
            );
            CREATE TABLE alerts (
              alert_id TEXT PRIMARY KEY,
              stable_group_id TEXT NOT NULL,
              stable_group_key TEXT,
              timestamp TEXT,
              rule_name TEXT,
              event_dataset TEXT,
              severity INTEGER,
              severity_label TEXT,
              source_ip TEXT,
              source_port INTEGER,
              destination_ip TEXT,
              destination_port INTEGER,
              network_protocol TEXT,
              transport_protocol TEXT,
              traffic_direction TEXT
            );
            CREATE TABLE incident_response_cases (
              case_id TEXT PRIMARY KEY,
              group_id TEXT NOT NULL UNIQUE,
              dashboard_group_id TEXT NOT NULL,
              representative_alert_id TEXT NOT NULL,
              status TEXT NOT NULL,
              agent_status TEXT NOT NULL,
              escalated_at TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              escalated_by TEXT,
              reason TEXT,
              latest_analysis_id TEXT,
              latest_model TEXT,
              latest_generated_at TEXT,
              latest_error TEXT
            );
            CREATE TABLE durable_jobs (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              job_type TEXT NOT NULL,
              dedupe_key TEXT NOT NULL,
              payload_json TEXT NOT NULL DEFAULT '{}',
              status TEXT NOT NULL,
              priority INTEGER NOT NULL DEFAULT 0,
              attempt_count INTEGER NOT NULL DEFAULT 0,
              max_attempts INTEGER NOT NULL DEFAULT 12,
              next_attempt_at TEXT,
              lease_expires_at TEXT,
              lease_token TEXT,
              last_error TEXT,
              created_at TEXT,
              updated_at TEXT,
              completed_at TEXT,
              last_completed_at TEXT,
              requested_at TEXT,
              processing_started_at TEXT,
              rerun_requested INTEGER NOT NULL DEFAULT 0,
              UNIQUE(job_type, dedupe_key)
            );
            CREATE TABLE incident_reanalysis_runs (
              run_id TEXT PRIMARY KEY,
              release_id TEXT NOT NULL,
              scope TEXT NOT NULL,
              status TEXT NOT NULL,
              requested_by TEXT,
              reason TEXT,
              total_count INTEGER NOT NULL,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              completed_at TEXT
            );
            CREATE TABLE incident_reanalysis_run_cases (
              run_id TEXT NOT NULL,
              case_id TEXT NOT NULL,
              group_id TEXT NOT NULL,
              dashboard_group_id TEXT NOT NULL,
              representative_alert_id TEXT NOT NULL,
              status TEXT NOT NULL,
              skip_reason TEXT,
              latest_error TEXT,
              queued_at TEXT,
              started_at TEXT,
              completed_at TEXT,
              latest_attempt_id TEXT,
              analysis_id TEXT,
              executed_model TEXT,
              executed_provider TEXT,
              executed_model_path TEXT,
              result_generated_at TEXT,
              updated_at TEXT NOT NULL,
              PRIMARY KEY (run_id, case_id)
            );
            CREATE TABLE ai_analysis_runs (
              analysis_id TEXT PRIMARY KEY,
              group_id TEXT NOT NULL,
              alert_id TEXT NOT NULL,
              agent_role TEXT NOT NULL,
              generated_at TEXT NOT NULL,
              model TEXT,
              model_path TEXT,
              detection_outcome TEXT,
              bluf TEXT,
              summary TEXT,
              confidence TEXT,
              artifact_path TEXT,
              evidence_hash TEXT,
              response_json TEXT NOT NULL,
              created_at TEXT NOT NULL
            );
            CREATE TABLE ai_second_opinion_runs (
              analysis_id TEXT PRIMARY KEY,
              group_id TEXT NOT NULL,
              alert_id TEXT NOT NULL,
              agent_role TEXT NOT NULL,
              trigger TEXT,
              status TEXT NOT NULL,
              primary_model TEXT,
              primary_model_path TEXT,
              primary_outcome TEXT,
              primary_confidence TEXT,
              reviewer_model TEXT,
              reviewer_model_path TEXT,
              reviewer_outcome TEXT,
              reviewer_confidence TEXT,
              agreement TEXT,
              material_disagreement INTEGER,
              reviewer_runtime_seconds REAL,
              generated_at TEXT,
              created_at TEXT,
              updated_at TEXT
            );
            """
        )
        summaries = [
            (
                self.dashboard_a,
                "alert-a-newest",
                "2026-07-25T12:00:00Z",
                "Newest distinct detection",
                "192.0.2.1",
                "198.51.100.1",
            ),
            (
                self.dashboard_b,
                "alert-b-alias",
                "2026-07-25T11:59:00Z",
                "Older alias of newest detection",
                "192.0.2.1",
                "198.51.100.1",
            ),
            (
                self.dashboard_c,
                "alert-c-existing",
                "2026-07-25T11:58:00Z",
                "Second distinct detection",
                "192.0.2.2",
                "198.51.100.2",
            ),
        ]
        for dashboard, alert_id, seen_at, rule_name, source_ip, destination_ip in summaries:
            connection.execute(
                """
                INSERT INTO alert_group_summary (
                  group_id, representative_alert_id, first_seen, last_seen,
                  timestamp, rule_name, event_dataset, severity, severity_label,
                  source_ip, source_port, destination_ip, destination_port,
                  network_protocol, transport_protocol, traffic_direction,
                  triage_score, triage_level, raw_alert_count, total_seen_count,
                  updated_at
                ) VALUES (
                  ?, ?, ?, ?, ?, ?, 'suricata.alert', 3, 'high',
                  ?, 12345, ?, 443, 'tcp', 'tcp', 'outbound',
                  80, 'high', 1, 1, ?
                )
                """,
                (
                    dashboard,
                    alert_id,
                    seen_at,
                    seen_at,
                    seen_at,
                    rule_name,
                    source_ip,
                    destination_ip,
                    seen_at,
                ),
            )
            stable_group_id = (
                self.stable_one
                if dashboard in {self.dashboard_a, self.dashboard_b}
                else self.stable_two
            )
            connection.execute(
                """
                INSERT INTO alerts (
                  alert_id, stable_group_id, stable_group_key, timestamp,
                  rule_name, event_dataset, severity, severity_label,
                  source_ip, source_port, destination_ip, destination_port,
                  network_protocol, transport_protocol, traffic_direction
                ) VALUES (
                  ?, ?, ?, ?, ?, 'suricata.alert', 3, 'high',
                  ?, 12345, ?, 443, 'tcp', 'tcp', 'outbound'
                )
                """,
                (
                    alert_id,
                    stable_group_id,
                    (
                        "v2|one"
                        if stable_group_id == self.stable_one
                        else "v2|two"
                    ),
                    seen_at,
                    rule_name,
                    source_ip,
                    destination_ip,
                ),
            )
        connection.executemany(
            """
            INSERT INTO alert_group_alias (
              legacy_group_id, stable_group_id, stable_group_key, updated_at
            ) VALUES (?, ?, ?, '2026-07-25T12:00:01Z')
            """,
            [
                (self.dashboard_a, self.stable_one, "v2|one"),
                (self.dashboard_b, self.stable_one, "v2|one"),
                (self.dashboard_c, self.stable_two, "v2|two"),
            ],
        )
        connection.execute(
            """
            INSERT INTO incident_response_cases (
              case_id, group_id, dashboard_group_id, representative_alert_id,
              status, agent_status, escalated_at, updated_at, escalated_by,
              reason, latest_analysis_id, latest_model, latest_generated_at,
              latest_error
            ) VALUES (
              'ir-existing', ?, ?, 'alert-c-existing', 'open', 'analyzed',
              '2026-07-25T11:58:10Z', '2026-07-25T11:58:20Z', 'fixture',
              'Existing fixture case', NULL, NULL, NULL, NULL
            )
            """,
            (self.stable_two, self.dashboard_c),
        )
        connection.commit()
        connection.close()


    def _freeze(self, count: int = 2) -> dict:
        return cohort.freeze_cohort(
            self.db_path,
            self.manifest_path,
            cohort_id="newest-20-evaluation",
            reason="Evaluate the new Incident Responder harness reproducibly.",
            count=count,
            expected_release_id=self.release_id,
        )


    def _rotate_dashboard_a_representative(
        self,
        alert_id: str = "alert-a-rotated",
    ) -> None:
        connection = self._connect()
        connection.execute(
            """
            INSERT INTO alerts (
              alert_id, stable_group_id, stable_group_key, timestamp,
              rule_name, event_dataset, severity, severity_label,
              source_ip, source_port, destination_ip, destination_port,
              network_protocol, transport_protocol, traffic_direction
            ) VALUES (
              ?, ?, 'v2|one', '2026-07-25T12:02:00Z',
              'Newest distinct detection', 'suricata.alert', 3, 'high',
              '192.0.2.1', 12345, '198.51.100.1', 443,
              'tcp', 'tcp', 'outbound'
            )
            """,
            (alert_id, self.stable_one),
        )
        connection.execute(
            """
            UPDATE alert_group_summary
            SET representative_alert_id = ?,
                last_seen = '2026-07-25T12:02:00Z',
                timestamp = '2026-07-25T12:02:00Z',
                updated_at = '2026-07-25T12:02:00Z'
            WHERE group_id = ?
            """,
            (alert_id, self.dashboard_a),
        )
        connection.commit()
        connection.close()


    def _api_poster(self):
        calls: list[tuple[str, dict]] = []

        def post(url: str, payload):
            calls.append((url, dict(payload)))
            connection = self._connect()
            if url.endswith(f"/{self.dashboard_a}/escalate"):
                connection.execute(
                    """
                    INSERT INTO incident_response_cases (
                      case_id, group_id, dashboard_group_id,
                      representative_alert_id, status, agent_status,
                      escalated_at, updated_at, escalated_by, reason,
                      latest_analysis_id, latest_model, latest_generated_at,
                      latest_error
                    ) VALUES (
                      'ir-new', ?, ?, 'alert-a-newest', 'open', 'queued',
                      '2026-07-25T12:01:00Z', '2026-07-25T12:01:00Z',
                      'harness-cohort', ?, NULL, NULL, NULL, NULL
                    )
                    """,
                    (self.stable_one, self.dashboard_a, payload["reason"]),
                )
                connection.execute(
                    """
                    INSERT INTO durable_jobs (
                      job_type, dedupe_key, payload_json, status, attempt_count,
                      requested_at, updated_at
                    ) VALUES (
                      'incident_response_analysis', ?, ?, 'pending', 0,
                      '2026-07-25T12:01:00Z', '2026-07-25T12:01:00Z'
                    )
                    """,
                    (
                        self.stable_one,
                        json.dumps(
                            {
                                "alert_id": payload[
                                    "representative_alert_id"
                                ],
                                "representative_alert_id": payload[
                                    "representative_alert_id"
                                ],
                                "group_id": payload["stable_group_id"],
                                "stable_group_id": payload[
                                    "stable_group_id"
                                ],
                                "stable_group_key": payload[
                                    "stable_group_key"
                                ],
                                "dashboard_group_id": self.dashboard_a,
                                "case_id": "ir-new",
                                "cohort_id": payload["cohort_id"],
                                "dispatch_id": payload["dispatch_id"],
                                "release_id": payload["release_id"],
                                "expected_assigned_route": payload[
                                    "expected_assigned_route"
                                ],
                                "expected_reviewer_route": payload[
                                    "expected_reviewer_route"
                                ],
                                "reviewer_required": payload[
                                    "reviewer_required"
                                ],
                                "agent_role": "incident-responder",
                                "manual_reanalysis": False,
                            }
                        ),
                    ),
                )
                response = {
                    "ok": True,
                    "status": "queued",
                    "case_id": "ir-new",
                    "group_id": self.dashboard_a,
                    "queue_group_id": self.stable_one,
                    "stable_group_id": self.stable_one,
                    "stable_group_key": payload["stable_group_key"],
                    "representative_alert_id": "alert-a-newest",
                    "cohort_id": payload["cohort_id"],
                    "dispatch_id": payload["dispatch_id"],
                    "release_id": payload["release_id"],
                    "expected_assigned_route": payload[
                        "expected_assigned_route"
                    ],
                    "expected_reviewer_route": payload[
                        "expected_reviewer_route"
                    ],
                    "reviewer_required": payload["reviewer_required"],
                    "requested_at": "2026-07-25T12:01:00Z",
                }
            elif url.endswith("/ir-existing/reanalyze"):
                run_id = "irr-11111111-1111-1111-1111-111111111111"
                connection.execute(
                    """
                    INSERT INTO incident_reanalysis_runs VALUES (
                      ?, ?, 'single_case', 'queued',
                      'harness-cohort', ?, 1, '2026-07-25T12:01:01Z',
                      '2026-07-25T12:01:01Z', NULL
                    )
                    """,
                    (run_id, payload["release_id"], payload["reason"]),
                )
                connection.execute(
                    """
                    INSERT INTO incident_reanalysis_run_cases (
                      run_id, case_id, group_id, dashboard_group_id,
                      representative_alert_id, status, queued_at, updated_at
                    ) VALUES (
                      ?, 'ir-existing', ?, ?, 'alert-c-existing', 'queued',
                      '2026-07-25T12:01:01Z', '2026-07-25T12:01:01Z'
                    )
                    """,
                    (run_id, self.stable_two, self.dashboard_c),
                )
                connection.execute(
                    """
                    INSERT INTO durable_jobs (
                      job_type, dedupe_key, payload_json, status, attempt_count,
                      requested_at, updated_at
                    ) VALUES (
                      'incident_response_analysis', ?, ?, 'pending', 0,
                      '2026-07-25T12:01:01Z', '2026-07-25T12:01:01Z'
                    )
                    """,
                    (
                        self.stable_two,
                        json.dumps(
                            {
                                "alert_id": payload[
                                    "representative_alert_id"
                                ],
                                "representative_alert_id": payload[
                                    "representative_alert_id"
                                ],
                                "group_id": payload["stable_group_id"],
                                "stable_group_id": payload[
                                    "stable_group_id"
                                ],
                                "stable_group_key": payload[
                                    "stable_group_key"
                                ],
                                "dashboard_group_id": self.dashboard_c,
                                "case_id": "ir-existing",
                                "reanalysis_run_id": run_id,
                                "cohort_id": payload["cohort_id"],
                                "dispatch_id": payload["dispatch_id"],
                                "release_id": payload["release_id"],
                                "expected_assigned_route": payload[
                                    "expected_assigned_route"
                                ],
                                "expected_reviewer_route": payload[
                                    "expected_reviewer_route"
                                ],
                                "reviewer_required": payload[
                                    "reviewer_required"
                                ],
                                "agent_role": "incident-responder",
                                "manual_reanalysis": True,
                            }
                        ),
                    ),
                )
                connection.execute(
                    """
                    UPDATE incident_response_cases
                    SET agent_status = 'queued',
                        updated_at = '2026-07-25T12:01:01Z'
                    WHERE case_id = 'ir-existing'
                    """
                )
                response = {
                    "ok": True,
                    "run_id": run_id,
                    "release_id": payload["release_id"],
                    "scope": "single_case",
                    "status": "queued",
                    "total_count": 1,
                    "created_at": "2026-07-25T12:01:01Z",
                    "stable_group_id": self.stable_two,
                    "stable_group_key": payload["stable_group_key"],
                    "representative_alert_id": "alert-c-existing",
                    "cohort_id": payload["cohort_id"],
                    "dispatch_id": payload["dispatch_id"],
                    "expected_assigned_route": payload[
                        "expected_assigned_route"
                    ],
                    "expected_reviewer_route": payload[
                        "expected_reviewer_route"
                    ],
                    "reviewer_required": payload["reviewer_required"],
                }
            else:
                connection.close()
                raise AssertionError(f"unexpected URL: {url}")
            connection.commit()
            connection.close()
            return cohort.HttpResult(
                202,
                response,
                cohort.sha256_value(response),
            )

        return calls, post


    def _soc_api_poster(self, *, create_fresh_analysis: bool = False):
        calls: list[tuple[str, dict]] = []

        def post(url: str, payload):
            calls.append((url, dict(payload)))
            self.assertTrue(
                url.endswith(f"/{self.dashboard_a}/analyze")
            )
            connection = self._connect()
            connection.execute(
                """
                INSERT INTO durable_jobs (
                  job_type, dedupe_key, payload_json, status, attempt_count,
                  requested_at, updated_at
                ) VALUES (
                  'ai_analysis', ?, ?, 'pending', 0,
                  '2026-07-25T12:10:00Z', '2026-07-25T12:10:00Z'
                )
                """,
                (
                    self.stable_one,
                    json.dumps(
                        {
                            "alert_id": payload[
                                "representative_alert_id"
                            ],
                            "representative_alert_id": payload[
                                "representative_alert_id"
                            ],
                            "group_id": payload["stable_group_id"],
                            "stable_group_id": payload[
                                "stable_group_id"
                            ],
                            "stable_group_key": payload[
                                "stable_group_key"
                            ],
                            "dashboard_group_id": self.dashboard_a,
                            "cohort_id": payload["cohort_id"],
                            "dispatch_id": payload["dispatch_id"],
                            "release_id": payload["release_id"],
                            "expected_assigned_route": payload[
                                "expected_assigned_route"
                            ],
                            "expected_reviewer_route": payload[
                                "expected_reviewer_route"
                            ],
                            "reviewer_required": payload[
                                "reviewer_required"
                            ],
                            "agent_role": "soc-analyst",
                            "manual_reanalysis": True,
                        }
                    ),
                ),
            )
            if create_fresh_analysis:
                connection.execute(
                    """
                    INSERT INTO ai_analysis_runs (
                      analysis_id, group_id, alert_id, agent_role,
                      generated_at, response_json, created_at
                    ) VALUES (
                      'analysis-raced-soc', ?, 'alert-a-newest',
                      'soc-analyst', '2026-07-25T12:10:01Z', '{}',
                      '2026-07-25T12:10:01Z'
                    )
                    """,
                    (self.stable_one,),
                )
            connection.commit()
            connection.close()
            response = {
                "ok": True,
                "status": "queued",
                "group_id": self.dashboard_a,
                "queue_group_id": self.stable_one,
                "stable_group_id": self.stable_one,
                "stable_group_key": payload["stable_group_key"],
                "representative_alert_id": "alert-a-newest",
                "cohort_id": payload["cohort_id"],
                "dispatch_id": payload["dispatch_id"],
                "release_id": payload["release_id"],
                "expected_assigned_route": payload[
                    "expected_assigned_route"
                ],
                "expected_reviewer_route": payload[
                    "expected_reviewer_route"
                ],
                "reviewer_required": payload["reviewer_required"],
                "requested_at": "2026-07-25T12:10:00Z",
            }
            return cohort.HttpResult(
                202,
                response,
                cohort.sha256_value(response),
            )

        return calls, post


    def _queue(self):
        calls, poster = self._api_poster()
        result = cohort.queue_cohort(
            self.db_path,
            self.manifest_path,
            base_url="http://127.0.0.1:8766",
            poster=poster,
        )
        for member in result["members"]:
            member["dispatch"]["started_at"] = "2026-07-25T12:00:00Z"
        result = cohort.write_private_json(
            self.manifest_path,
            result,
            digest_field="manifest_sha256",
        )
        return calls, result
