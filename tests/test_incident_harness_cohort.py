#!/usr/bin/env python3
"""Tests for the safe Incident Responder harness cohort orchestrator."""

from __future__ import annotations

import importlib.util
import hashlib
import json
import os
import sqlite3
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "operations" / "cohort_runner_service.py"
SPEC = importlib.util.spec_from_file_location(
    "run_incident_harness_cohort",
    MODULE_PATH,
)
assert SPEC and SPEC.loader
cohort = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cohort)
EVALUATOR_PATH = ROOT / "operations" / "evaluate-investigation-cohort.py"
EVALUATOR_SPEC = importlib.util.spec_from_file_location(
    "evaluate_investigation_cohort_for_export_test",
    EVALUATOR_PATH,
)
assert EVALUATOR_SPEC and EVALUATOR_SPEC.loader
cohort_evaluator = importlib.util.module_from_spec(EVALUATOR_SPEC)
EVALUATOR_SPEC.loader.exec_module(cohort_evaluator)
import cohort_evaluation_query_audit  # noqa: E402
import cohort_query_audit_projection  # noqa: E402
import cohort_execution_proof_service  # noqa: E402
import cohort_analysis_metadata  # noqa: E402
import cohort_preflight  # noqa: E402
import cohort_dispatch_identity  # noqa: E402
import cohort_manifest_contract  # noqa: E402
import cohort_private_input  # noqa: E402
import cohort_artifact_io  # noqa: E402
import cohort_storage_core  # noqa: E402
import cohort_storage_state  # noqa: E402
import cohort_source_rows  # noqa: E402
import cohort_representative_state  # noqa: E402
import cohort_second_opinion_state  # noqa: E402
import cohort_runner_contracts  # noqa: E402
import cohort_dispatch_adapters  # noqa: E402
import cohort_monitor_adapters  # noqa: E402
import cohort_artifact_adapters  # noqa: E402
import cohort_manifest_adapters  # noqa: E402
import cohort_freeze_state_composition  # noqa: E402
import cohort_runtime_composition  # noqa: E402


class IncidentHarnessCohortTests(unittest.TestCase):
    def test_runner_uses_canonical_query_audit_services(self) -> None:
        self.assertIs(
            cohort.project_query_audit,
            cohort_query_audit_projection.project_query_audit,
        )
        self.assertIs(
            cohort.normalize_query_audit_binding,
            cohort_evaluation_query_audit.query_audit_execution_binding,
        )

    def test_runner_uses_extracted_execution_proof_service(self) -> None:
        self.assertIs(
            cohort.build_execution_proof,
            cohort_execution_proof_service.build_execution_proof,
        )

    def test_runner_uses_extracted_analysis_metadata_loader(self) -> None:
        self.assertIs(
            cohort.load_analysis_metadata,
            cohort_analysis_metadata.load_analysis_metadata,
        )

    def test_runner_uses_extracted_preflight_services(self) -> None:
        self.assertIs(
            cohort.prove_representative_binding,
            cohort_preflight.validate_representative_binding,
        )
        self.assertIs(
            cohort.run_member_preflight,
            cohort_preflight.validate_member_preflight,
        )

    def test_runner_uses_extracted_dispatch_identity_service(self) -> None:
        self.assertIs(
            cohort.derive_dispatch_id,
            cohort_dispatch_identity.deterministic_dispatch_id,
        )

    def test_runner_uses_extracted_manifest_and_private_input_services(self) -> None:
        self.assertIs(
            cohort.calculate_frozen_plan_digest,
            cohort_manifest_contract.frozen_plan_digest,
        )
        self.assertIs(
            cohort.validate_manifest_document,
            cohort_manifest_contract.validate_manifest_document,
        )
        self.assertIs(
            cohort.read_private_manifest,
            cohort_private_input.load_private_manifest,
        )
        self.assertIs(
            cohort.read_private_source_rows,
            cohort_private_input.load_private_source_rows,
        )

    def test_runner_uses_extracted_artifact_services(self) -> None:
        self.assertIs(
            cohort.verify_alert_store_response_sha256,
            cohort_artifact_io.alert_store_response_sha256,
        )
        self.assertIs(
            cohort.persist_private_json,
            cohort_artifact_io.write_private_json,
        )

    def test_runner_uses_extracted_storage_core(self) -> None:
        self.assertIs(
            cohort.open_cohort_database_read_only,
            cohort_storage_core.connect_read_only,
        )
        self.assertIs(
            cohort.calculate_schema_fingerprint,
            cohort_storage_core.schema_fingerprint,
        )
        self.assertIs(cohort.read_group_aliases, cohort_storage_core.load_aliases)
        self.assertIs(cohort.resolve_group_alias, cohort_storage_core.resolve_alias)

    def test_runner_uses_extracted_storage_state(self) -> None:
        self.assertIs(cohort.query_summary_rows, cohort_storage_state.summary_rows)
        self.assertIs(cohort.query_active_jobs, cohort_storage_state.active_jobs)
        self.assertIs(
            cohort.query_analysis_ids_for_group,
            cohort_storage_state.analysis_ids_for_group,
        )
        self.assertIs(
            cohort.build_incident_pre_state,
            cohort_storage_state.incident_pre_state,
        )

    def test_runner_uses_extracted_source_row_contracts(self) -> None:
        self.assertIs(
            cohort.read_source_identity,
            cohort_source_rows.source_identity,
        )
        self.assertIs(
            cohort.project_source_detection,
            cohort_source_rows.source_detection_projection,
        )
        self.assertIs(
            cohort.prove_source_detection,
            cohort_source_rows.validate_source_detection,
        )

    def test_runner_uses_extracted_representative_state(self) -> None:
        self.assertIs(
            cohort.read_current_summary_identity,
            cohort_representative_state.current_summary_identity,
        )
        self.assertIs(
            cohort.read_alert_representative_identity,
            cohort_representative_state.alert_representative_identity,
        )
        self.assertIs(
            cohort.bind_stable_group_key,
            cohort_representative_state.bind_representative_stable_group_key,
        )

    def test_runner_uses_extracted_second_opinion_state(self) -> None:
        self.assertIs(
            cohort.read_second_opinion_metadata,
            cohort_second_opinion_state.second_opinion_metadata,
        )

    def test_runner_uses_extracted_runner_contracts(self) -> None:
        self.assertIs(cohort.CohortError, cohort_runner_contracts.CohortError)
        self.assertIs(cohort.sha256_value, cohort_runner_contracts.sha256_value)
        self.assertEqual(cohort.SCHEMA, cohort_runner_contracts.SCHEMA)

    def test_runner_uses_extracted_dispatch_adapters(self) -> None:
        self.assertIs(
            cohort.validate_loopback_base_url,
            cohort_dispatch_adapters.validate_loopback_base_url,
        )
        self.assertIs(
            cohort.dashboard_post_json,
            cohort_dispatch_adapters.dashboard_post_json,
        )
        self.assertIs(
            cohort.build_adapter_dispatch_request,
            cohort_dispatch_adapters.request_for_member,
        )

    def test_runner_uses_extracted_monitor_adapters(self) -> None:
        self.assertIs(
            cohort.resolve_adapter_job_monitor_state,
            cohort_monitor_adapters.durable_job_monitor_state,
        )
        self.assertIs(
            cohort._reanalysis_monitor_case,
            cohort_monitor_adapters.reanalysis_monitor_case,
        )

    def test_runner_uses_extracted_artifact_adapters(self) -> None:
        self.assertIs(
            cohort.alert_store_response_sha256,
            cohort_artifact_adapters.alert_store_response_sha256,
        )
        self.assertIs(
            cohort.write_private_json,
            cohort_artifact_adapters.write_private_json,
        )
        self.assertIs(
            cohort._digest_bound,
            cohort_artifact_adapters.digest_bound,
        )

    def test_runner_uses_extracted_manifest_adapters(self) -> None:
        self.assertIs(
            cohort.load_private_manifest,
            cohort_manifest_adapters.load_private_manifest,
        )
        self.assertIs(
            cohort.validate_release_id,
            cohort_manifest_adapters.validate_release_id,
        )
        self.assertIs(
            cohort.deterministic_dispatch_id,
            cohort_manifest_adapters.deterministic_dispatch_id,
        )

    def test_runner_uses_extracted_freeze_state_composition(self) -> None:
        self.assertIs(
            cohort.connect_read_only,
            cohort_freeze_state_composition.connect_read_only,
        )
        self.assertIs(
            cohort._summary_rows,
            cohort_freeze_state_composition.summary_rows,
        )
        self.assertIs(
            cohort.validate_member_preflight,
            cohort_freeze_state_composition.validate_member_preflight,
        )

    def test_runner_uses_extracted_runtime_composition(self) -> None:
        self.assertIs(
            cohort.runtime_queue_cohort,
            cohort_runtime_composition.queue_cohort,
        )
        self.assertIs(
            cohort.monitor_cohort_once,
            cohort_runtime_composition.monitor_cohort_once,
        )
        self.assertIs(
            cohort.runtime_harness_execution_proof,
            cohort_runtime_composition.harness_execution_proof,
        )
        self.assertIs(
            cohort.runtime_export_cohort,
            cohort_runtime_composition.export_cohort,
        )

    def test_query_audit_projection_excludes_query_and_result_content(self) -> None:
        projected = cohort._bounded_query_audit_metadata(
            {
                "_incident_query_audit": {
                    "read_only": True,
                    "queries": [
                        {
                            "query_id": "alert-context",
                            "status": "completed",
                            "query": "secret query text",
                            "rows": [{"secret": "result"}],
                            "request_digest": "a" * 64,
                            "result_digest": "b" * 64,
                        }
                    ],
                }
            }
        )
        query = projected["_incident_query_audit"]["queries"][0]
        self.assertEqual(query["query_id"], "alert-context")
        self.assertNotIn("query", query)
        self.assertNotIn("rows", query)

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

    def test_freeze_selects_newest_distinct_stable_groups_owner_only(self) -> None:
        manifest = self._freeze()

        self.assertEqual(
            [item["dashboard_group_id"] for item in manifest["members"]],
            [self.dashboard_a, self.dashboard_c],
        )
        self.assertEqual(
            [item["stable_group_id"] for item in manifest["members"]],
            [self.stable_one, self.stable_two],
        )
        self.assertEqual(
            [item["stable_group_key"] for item in manifest["members"]],
            ["v2|one", "v2|two"],
        )
        self.assertTrue(
            all(
                item["stable_group_key"]
                == item["detection"]["stable_group_key"]
                for item in manifest["members"]
            )
        )
        self.assertEqual(
            [item["dispatch"]["kind"] for item in manifest["members"]],
            ["escalate", "reanalyze"],
        )
        self.assertEqual(
            stat.S_IMODE(self.manifest_path.stat().st_mode),
            0o600,
        )
        self.assertEqual(
            stat.S_IMODE(self.manifest_path.parent.stat().st_mode),
            0o700,
        )
        loaded = cohort.load_private_manifest(self.manifest_path)
        self.assertEqual(loaded["manifest_sha256"], manifest["manifest_sha256"])

    def test_controlled_profile_cli_pins_exact_independent_routes(self) -> None:
        profile = "onion-sentinel-gpt55-high-gpt56-sol-xhigh-v1"
        parsed = cohort.build_parser().parse_args(
            [
                "freeze",
                "--db",
                str(self.db_path),
                "--manifest",
                str(self.manifest_path),
                "--cohort-id",
                "profile-cli-test",
                "--reason",
                "Validate the exact controlled evaluation profile.",
                "--count",
                "1",
                "--expected-release-id",
                self.release_id,
                "--expected-assigned-route",
                "codex-cli:gpt-5.5:high",
                "--expected-reviewer-route",
                "codex-cli:gpt-5.6-sol:xhigh",
                "--evaluation-profile",
                profile,
            ]
        )
        self.assertEqual(parsed.evaluation_profile, profile)
        frozen = cohort.freeze_cohort(
            self.db_path,
            self.manifest_path,
            cohort_id="profile-freeze-test",
            reason="Freeze the exact controlled evaluation profile.",
            count=1,
            expected_release_id=self.release_id,
            expected_assigned_route="codex-cli:gpt-5.5:high",
            expected_reviewer_route="codex-cli:gpt-5.6-sol:xhigh",
            evaluation_profile=profile,
        )
        self.assertEqual(
            frozen["execution_contract"]["evaluation_profile"], profile
        )

        wrong_manifest = self.root / "wrong-profile-manifest.json"
        with self.assertRaisesRegex(cohort.CohortError, "profile"):
            cohort.freeze_cohort(
                self.db_path,
                wrong_manifest,
                cohort_id="profile-wrong-route-test",
                reason="Reject a profile whose primary route drifted.",
                count=1,
                expected_release_id=self.release_id,
                expected_assigned_route="codex-cli:gpt-5.6-terra:high",
                expected_reviewer_route="codex-cli:gpt-5.6-sol:xhigh",
                evaluation_profile=profile,
            )
        self.assertFalse(wrong_manifest.exists())

    def test_generic_contract_rejects_same_model_different_effort(self) -> None:
        generic = cohort.execution_contract(
            expected_release_id=self.release_id,
            expected_assigned_route="codex-cli:gpt-5.6-terra:high",
            expected_reviewer_route="codex-cli:gpt-5.6-luna:xhigh",
        )
        self.assertEqual(generic["evaluation_profile"], "")
        with self.assertRaisesRegex(cohort.CohortError, "distinct"):
            cohort.execution_contract(
                expected_release_id=self.release_id,
                expected_assigned_route="codex-cli:gpt-5.5:high",
                expected_reviewer_route="codex-cli:gpt-5.5:xhigh",
            )
        with self.assertRaisesRegex(
            cohort_evaluator.CohortEvaluationError,
            "reviewer route contract",
        ):
            cohort_evaluator._execution_contract(
                {
                    **generic,
                    "expected_assigned_route": "codex-cli:gpt-5.5:high",
                    "expected_reviewer_route": "codex-cli:gpt-5.5:xhigh",
                },
                "same-model contract",
            )

    def test_frozen_plan_digest_binds_detection_evidence(self) -> None:
        self._freeze(count=1)
        document = json.loads(
            self.manifest_path.read_text(encoding="utf-8")
        )
        document["members"][0]["detection"]["source_ip"] = "203.0.113.99"
        document.pop("manifest_sha256")
        document["manifest_sha256"] = cohort.sha256_value(document)
        self.manifest_path.write_text(
            json.dumps(document),
            encoding="utf-8",
        )

        with self.assertRaisesRegex(
            cohort.CohortError,
            "frozen plan digest does not match",
        ):
            cohort.load_private_manifest(self.manifest_path)

    def test_frozen_plan_digest_binds_expected_release(self) -> None:
        self._freeze(count=1)
        document = json.loads(
            self.manifest_path.read_text(encoding="utf-8")
        )
        document["execution_contract"]["expected_release_id"] = "b" * 40
        document.pop("manifest_sha256")
        document["manifest_sha256"] = cohort.sha256_value(document)
        self.manifest_path.write_text(
            json.dumps(document),
            encoding="utf-8",
        )

        with self.assertRaisesRegex(
            cohort.CohortError,
            "frozen plan digest does not match",
        ):
            cohort.load_private_manifest(self.manifest_path)

    def test_freeze_rejects_missing_stable_group_key(self) -> None:
        connection = self._connect()
        connection.execute(
            """
            UPDATE alerts
            SET stable_group_key = ''
            WHERE alert_id = 'alert-a-newest'
            """
        )
        connection.commit()
        connection.close()

        with self.assertRaisesRegex(
            cohort.CohortError,
            "stable_group_key.*missing or malformed",
        ):
            self._freeze(count=1)

    def test_freeze_rejects_oversized_stable_group_key(self) -> None:
        connection = self._connect()
        connection.execute(
            """
            UPDATE alerts
            SET stable_group_key = ?
            WHERE alert_id = 'alert-a-newest'
            """,
            ("x" * (cohort.MAX_STABLE_GROUP_KEY_BYTES + 1),),
        )
        connection.commit()
        connection.close()

        with self.assertRaisesRegex(
            cohort.CohortError,
            "bounded stable-group-key contract",
        ):
            self._freeze(count=1)

    def test_freeze_rejects_pending_or_processing_incident_job(self) -> None:
        connection = self._connect()
        connection.execute(
            """
            INSERT INTO durable_jobs (
              job_type, dedupe_key, status, attempt_count,
              requested_at, updated_at
            ) VALUES (
              'incident_response_analysis', ?, 'processing', 1,
              '2026-07-25T12:02:00Z', '2026-07-25T12:02:00Z'
            )
            """,
            (self.stable_one,),
        )
        connection.commit()
        connection.close()

        with self.assertRaisesRegex(cohort.CohortError, "pending/processing"):
            self._freeze(count=1)
        self.assertFalse(self.manifest_path.exists())

    def test_freeze_from_rows_preserves_supplied_order_without_reselection(self) -> None:
        source_path = self.root / "frozen-rows.json"
        source_rows = [
            {
                "dashboard_group_id": self.dashboard_c,
                "stable_group_id": self.stable_two,
                "representative_alert_id": "alert-c-existing",
                "case_id": "ir-existing",
                "case_agent_status": "analyzed",
            },
            {
                "dashboard_group_id": self.dashboard_a,
                "stable_group_id": self.stable_one,
                "representative_alert_id": "alert-a-newest",
            },
        ]
        source_path.write_text(json.dumps(source_rows), encoding="utf-8")
        os.chmod(source_path, 0o600)

        manifest = cohort.freeze_cohort_from_rows(
            self.db_path,
            source_path,
            self.manifest_path,
            cohort_id="preselected-live-cohort",
            reason="Preserve the exact request-time cohort selection order.",
            expected_count=2,
            expected_release_id=self.release_id,
        )

        self.assertEqual(
            [item["dashboard_group_id"] for item in manifest["members"]],
            [self.dashboard_c, self.dashboard_a],
        )
        self.assertEqual(manifest["selection"]["mode"], "imported_rows")
        self.assertEqual(
            manifest["selection"]["source_sha256"],
            hashlib.sha256(source_path.read_bytes()).hexdigest(),
        )
        self.assertTrue(manifest["selection"]["order_preserved"])

    def test_freeze_from_rows_allows_proven_representative_rotation(
        self,
    ) -> None:
        connection = cohort.connect_read_only(self.db_path)
        try:
            frozen_summary = next(
                row
                for row in cohort._summary_rows(connection)
                if row["group_id"] == self.dashboard_a
            )
        finally:
            connection.close()
        source_path = self.root / "frozen-rows.json"
        source_path.write_text(
            json.dumps(
                [
                    {
                        "dashboard_group_id": self.dashboard_a,
                        "stable_group_id": self.stable_one,
                        "representative_alert_id": "alert-a-newest",
                        "detection": {
                            key: value
                            for key, value in frozen_summary.items()
                            if key != "group_id"
                        },
                    }
                ]
            ),
            encoding="utf-8",
        )
        os.chmod(source_path, 0o600)
        self._rotate_dashboard_a_representative()

        manifest = cohort.freeze_cohort_from_rows(
            self.db_path,
            source_path,
            self.manifest_path,
            cohort_id="preselected-live-cohort",
            reason="Preserve a proven frozen alert after summary rotation.",
            expected_count=1,
            expected_release_id=self.release_id,
            agent_role="soc-analyst",
        )

        member = manifest["members"][0]
        self.assertEqual(
            member["representative_alert_id"],
            "alert-a-newest",
        )
        self.assertEqual(
            member["detection"]["timestamp"],
            "2026-07-25T12:00:00Z",
        )
        validated = cohort.queue_cohort(
            self.db_path,
            self.manifest_path,
            base_url="http://127.0.0.1:8766",
            dry_run=True,
        )
        self.assertEqual(validated["state"], "frozen")

    def test_freeze_from_rows_rejects_rotation_without_frozen_evidence(
        self,
    ) -> None:
        source_path = self.root / "frozen-rows.json"
        source_path.write_text(
            json.dumps(
                [
                    {
                        "dashboard_group_id": self.dashboard_a,
                        "stable_group_id": self.stable_one,
                        "representative_alert_id": "alert-a-newest",
                    }
                ]
            ),
            encoding="utf-8",
        )
        os.chmod(source_path, 0o600)
        self._rotate_dashboard_a_representative()

        with self.assertRaisesRegex(
            cohort.CohortError,
            "missing immutable fields",
        ):
            cohort.freeze_cohort_from_rows(
                self.db_path,
                source_path,
                self.manifest_path,
                cohort_id="preselected-live-cohort",
                reason="Reject unproven representative rotation safely.",
                expected_count=1,
                expected_release_id=self.release_id,
                agent_role="soc-analyst",
            )

    def test_freeze_from_rows_rejects_supplied_stable_group_key_drift(
        self,
    ) -> None:
        source_path = self.root / "frozen-rows.json"
        source_path.write_text(
            json.dumps(
                [
                    {
                        "dashboard_group_id": self.dashboard_a,
                        "stable_group_id": self.stable_one,
                        "representative_alert_id": "alert-a-newest",
                        "detection": {
                            "stable_group_key": "v2|mutated",
                        },
                    }
                ]
            ),
            encoding="utf-8",
        )
        os.chmod(source_path, 0o600)

        with self.assertRaisesRegex(
            cohort.CohortError,
            "immutable evidence drift.*stable_group_key",
        ):
            cohort.freeze_cohort_from_rows(
                self.db_path,
                source_path,
                self.manifest_path,
                cohort_id="preselected-live-cohort",
                reason="Reject frozen source stable group key drift.",
                expected_count=1,
                expected_release_id=self.release_id,
                agent_role="soc-analyst",
            )

    def test_freeze_from_rows_rejects_identity_or_prestate_drift(self) -> None:
        source_path = self.root / "frozen-rows.json"
        source_path.write_text(
            json.dumps(
                [
                    {
                        "dashboard_group_id": self.dashboard_c,
                        "stable_group_id": self.stable_two,
                        "representative_alert_id": "alert-c-existing",
                        "case_id": "ir-wrong",
                    }
                ]
            ),
            encoding="utf-8",
        )
        os.chmod(source_path, 0o600)

        with self.assertRaisesRegex(cohort.CohortError, "case_id"):
            cohort.freeze_cohort_from_rows(
                self.db_path,
                source_path,
                self.manifest_path,
                cohort_id="preselected-live-cohort",
                reason="Reject request-time identity drift before dispatch.",
                expected_count=1,
                expected_release_id=self.release_id,
            )
        self.assertFalse(self.manifest_path.exists())

    def test_freeze_rejects_noncanonical_representative_alert_id(self) -> None:
        connection = self._connect()
        connection.execute(
            """
            UPDATE alert_group_summary
            SET representative_alert_id = 'alert/with/path'
            WHERE group_id = ?
            """,
            (self.dashboard_a,),
        )
        connection.commit()
        connection.close()

        with self.assertRaisesRegex(
            cohort.CohortError,
            "invalid representative alert ID",
        ):
            self._freeze(count=1)

    def test_freeze_from_rows_rejects_noncanonical_representative_alert_id(
        self,
    ) -> None:
        source_path = self.root / "frozen-rows.json"
        source_path.write_text(
            json.dumps(
                [
                    {
                        "dashboard_group_id": self.dashboard_a,
                        "stable_group_id": self.stable_one,
                        "representative_alert_id": "alert/with/path",
                    }
                ]
            ),
            encoding="utf-8",
        )
        os.chmod(source_path, 0o600)

        with self.assertRaisesRegex(
            cohort.CohortError,
            "invalid representative alert ID",
        ):
            cohort.freeze_cohort_from_rows(
                self.db_path,
                source_path,
                self.manifest_path,
                cohort_id="preselected-live-cohort",
                reason="Reject invalid representative identity grammar.",
                expected_count=1,
                expected_release_id=self.release_id,
            )

    def test_case_and_run_identity_grammars_match_runtime_bounds(self) -> None:
        self.assertIsNotNone(cohort.CASE_ID_RE.fullmatch("ir-case_1"))
        self.assertIsNotNone(
            cohort.CASE_ID_RE.fullmatch("ir-" + ("a" * 64))
        )
        self.assertIsNone(
            cohort.CASE_ID_RE.fullmatch("ir-" + ("a" * 65))
        )
        self.assertIsNotNone(
            cohort.RUN_ID_RE.fullmatch("irr-" + ("a" * 64))
        )
        self.assertIsNone(
            cohort.RUN_ID_RE.fullmatch("irr-" + ("a" * 65))
        )

    def test_freeze_requires_exact_lowercase_git_release_id(self) -> None:
        for release_id in ("a" * 39, "A" * 40, "g" * 40, "a" * 41):
            with self.subTest(release_id=release_id), self.assertRaisesRegex(
                cohort.CohortError,
                "40 lowercase hexadecimal",
            ):
                cohort.freeze_cohort(
                    self.db_path,
                    self.manifest_path,
                    cohort_id="release-bound-cohort",
                    reason="Reject a malformed expected production release.",
                    count=1,
                    expected_release_id=release_id,
                )

    def test_completed_analysis_must_be_inside_exact_job_window(self) -> None:
        dispatch = {"started_at": "2026-07-25T12:00:00Z"}
        job = {
            "status": "completed",
            "requested_at": "2026-07-25T12:00:01Z",
            "completed_at": "2026-07-25T12:00:03Z",
            "last_completed_at": "2026-07-25T12:00:03Z",
            "updated_at": "2026-07-25T12:00:04Z",
        }
        cohort._validate_completed_analysis_job_window(
            dispatch=dispatch,
            job=job,
            analysis={"generated_at": "2026-07-25T12:00:02Z"},
        )
        for field, value in (
            ("requested_at", "2026-07-25T11:59:59Z"),
            ("completed_at", "2026-07-25T12:00:01Z"),
            ("last_completed_at", "2026-07-25T12:00:01Z"),
            ("updated_at", "2026-07-25T12:00:02Z"),
        ):
            mutated = dict(job)
            mutated[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(
                cohort.CohortError,
                "job window",
            ):
                cohort._validate_completed_analysis_job_window(
                    dispatch=dispatch,
                    job=mutated,
                    analysis={"generated_at": "2026-07-25T12:00:02Z"},
                )

    def test_queue_dry_run_never_calls_dashboard_or_mutates_manifest(self) -> None:
        manifest = self._freeze()
        original_digest = manifest["manifest_sha256"]

        def forbidden(_url, _payload):
            raise AssertionError("dry run must not send HTTP")

        result = cohort.queue_cohort(
            self.db_path,
            self.manifest_path,
            base_url="http://localhost:8766",
            dry_run=True,
            poster=forbidden,
        )

        self.assertEqual(result["manifest_sha256"], original_digest)
        self.assertEqual(
            cohort.load_private_manifest(self.manifest_path)["state"],
            "frozen",
        )

    def test_evaluation_token_is_sent_as_post_header_only(self) -> None:
        token = "a" * 64
        captured_requests = []

        class Response:
            status = 202

            def __enter__(self):
                return self

            def __exit__(self, _exc_type, _exc, _traceback):
                return False

            def read(self, _limit):
                return b'{"ok":true}'

        def urlopen(request, *, timeout):
            self.assertEqual(timeout, 3.0)
            captured_requests.append(request)
            return Response()

        with mock.patch.object(
            cohort.urllib.request,
            "urlopen",
            side_effect=urlopen,
        ):
            cohort.dashboard_post_json(
                "http://127.0.0.1:8766/api/test",
                {"safe": "payload"},
                timeout=3.0,
                evaluation_token=token,
            )
            cohort.dashboard_post_json(
                "http://127.0.0.1:8766/api/test",
                {"safe": "payload"},
                timeout=3.0,
            )

        self.assertEqual(len(captured_requests), 2)
        protected_headers = {
            key.lower(): value
            for key, value in captured_requests[0].header_items()
        }
        normal_headers = {
            key.lower(): value
            for key, value in captured_requests[1].header_items()
        }
        self.assertEqual(
            protected_headers["x-onion-sentinel-evaluation-token"],
            token,
        )
        self.assertNotIn(
            "x-onion-sentinel-evaluation-token",
            normal_headers,
        )
        self.assertEqual(captured_requests[0].get_method(), "POST")
        self.assertNotIn(token.encode("ascii"), captured_requests[0].data)

    def test_queue_uses_private_token_file_without_persisting_token(self) -> None:
        self._freeze(count=1)
        token = "b" * 64
        token_path = self.root / "evaluation-token"
        token_path.write_text(token, encoding="ascii")
        os.chmod(token_path, 0o600)
        _calls, poster = self._api_poster()
        observed_tokens = []

        def transport(url, payload, *, timeout, evaluation_token=None):
            self.assertEqual(timeout, 15.0)
            observed_tokens.append(evaluation_token)
            return poster(url, payload)

        with mock.patch.object(
            cohort,
            "dashboard_post_json",
            side_effect=transport,
        ):
            queued = cohort.queue_cohort(
                self.db_path,
                self.manifest_path,
                base_url="http://127.0.0.1:8766",
                evaluation_token_file=token_path,
            )

        self.assertEqual(observed_tokens, [token])
        self.assertNotIn(token, self.manifest_path.read_text(encoding="utf-8"))
        self.assertNotIn(token, json.dumps(queued, sort_keys=True))

    def test_evaluation_token_file_must_exist(self) -> None:
        with self.assertRaisesRegex(
            cohort.CohortError,
            "missing or inaccessible",
        ):
            cohort.load_evaluation_token(self.root / "missing-token")

    def test_evaluation_token_file_rejects_malformed_secret_without_leak(self) -> None:
        malformed = "SECRET-MARKER-" + ("a" * 50)
        token_path = self.root / "malformed-token"
        token_path.write_text(malformed, encoding="ascii")
        os.chmod(token_path, 0o600)

        with self.assertRaises(cohort.CohortError) as raised:
            cohort.load_evaluation_token(token_path)

        self.assertIn("exactly 64 lowercase hexadecimal", str(raised.exception))
        self.assertNotIn(malformed, str(raised.exception))

    def test_evaluation_token_file_rejects_insecure_permissions(self) -> None:
        token_path = self.root / "insecure-token"
        token_path.write_text("c" * 64, encoding="ascii")
        os.chmod(token_path, 0o644)

        with self.assertRaisesRegex(cohort.CohortError, "owner-only"):
            cohort.load_evaluation_token(token_path)

    def test_evaluation_token_file_rejects_symlink(self) -> None:
        token_path = self.root / "real-token"
        token_path.write_text("d" * 64, encoding="ascii")
        os.chmod(token_path, 0o600)
        symlink_path = self.root / "linked-token"
        symlink_path.symlink_to(token_path)

        with self.assertRaisesRegex(
            cohort.CohortError,
            "regular non-symlink",
        ):
            cohort.load_evaluation_token(symlink_path)

    def test_dispatch_rejects_noncanonical_representative_alert_id(self) -> None:
        manifest = self._freeze()
        manifest["members"][0]["representative_alert_id"] = "alert/with/path"
        manifest["frozen_plan_sha256"] = cohort._frozen_plan_digest(manifest)

        with self.assertRaisesRegex(
            cohort.CohortError,
            "invalid frozen representative alert ID",
        ):
            cohort.deterministic_dispatch_id(
                manifest,
                manifest["members"][0],
            )

    def test_queue_allows_proven_representative_rotation_and_pins_frozen_alert(
        self,
    ) -> None:
        frozen = self._freeze(count=1)
        self._rotate_dashboard_a_representative()

        calls, queued = self._queue()

        self.assertEqual(len(calls), 1)
        request = calls[0][1]
        member = queued["members"][0]
        dispatch = member["dispatch"]
        self.assertEqual(
            request["representative_alert_id"],
            "alert-a-newest",
        )
        self.assertEqual(request["stable_group_id"], self.stable_one)
        self.assertEqual(request["stable_group_key"], "v2|one")
        self.assertEqual(request["cohort_id"], frozen["cohort_id"])
        self.assertEqual(request["release_id"], self.release_id)
        self.assertRegex(request["dispatch_id"], r"^[a-f0-9]{64}$")
        self.assertEqual(
            request["dispatch_id"],
            cohort.deterministic_dispatch_id(queued, member),
        )
        self.assertEqual(dispatch["dispatch_id"], request["dispatch_id"])
        self.assertTrue(
            dispatch["representative_binding"]["representative_drifted"]
        )
        self.assertEqual(
            dispatch["representative_binding"][
                "current_representative_alert_id"
            ],
            "alert-a-rotated",
        )
        self.assertEqual(
            dispatch["accepted"]["dispatch_id"],
            request["dispatch_id"],
        )
        self.assertEqual(
            dispatch["accepted"]["stable_group_key"],
            request["stable_group_key"],
        )
        self.assertEqual(
            dispatch["readback"]["dispatch_id"],
            request["dispatch_id"],
        )
        self.assertEqual(
            dispatch["readback"]["stable_group_key"],
            request["stable_group_key"],
        )
        self.assertEqual(
            dispatch["readback"]["representative_alert_id"],
            "alert-a-newest",
        )
        self.assertEqual(dispatch["accepted"]["release_id"], self.release_id)
        self.assertEqual(dispatch["readback"]["release_id"], self.release_id)
        self.assertRegex(
            dispatch["readback"]["job_payload_sha256"],
            r"^[a-f0-9]{64}$",
        )

    def test_queue_rejects_stable_group_drift_after_freeze(self) -> None:
        self._freeze(count=1)
        connection = self._connect()
        connection.execute(
            """
            UPDATE alert_group_alias
            SET stable_group_id = ?
            WHERE legacy_group_id = ?
            """,
            (self.stable_two, self.dashboard_a),
        )
        connection.commit()
        connection.close()

        with self.assertRaisesRegex(
            cohort.CohortError,
            "frozen stable identity drift",
        ):
            cohort.queue_cohort(
                self.db_path,
                self.manifest_path,
                base_url="http://127.0.0.1:8766",
                dry_run=True,
            )

    def test_queue_rejects_missing_frozen_alert_after_rotation(self) -> None:
        self._freeze(count=1)
        self._rotate_dashboard_a_representative()
        connection = self._connect()
        connection.execute(
            "DELETE FROM alerts WHERE alert_id = 'alert-a-newest'"
        )
        connection.commit()
        connection.close()

        with self.assertRaisesRegex(
            cohort.CohortError,
            "frozen representative alert is missing",
        ):
            cohort.queue_cohort(
                self.db_path,
                self.manifest_path,
                base_url="http://127.0.0.1:8766",
                dry_run=True,
            )

    def test_queue_rejects_missing_frozen_alert_without_rotation(self) -> None:
        self._freeze(count=1)
        connection = self._connect()
        connection.execute(
            "DELETE FROM alerts WHERE alert_id = 'alert-a-newest'"
        )
        connection.commit()
        connection.close()

        with self.assertRaisesRegex(
            cohort.CohortError,
            "frozen representative alert is missing",
        ):
            cohort.queue_cohort(
                self.db_path,
                self.manifest_path,
                base_url="http://127.0.0.1:8766",
                dry_run=True,
            )

    def test_queue_rejects_missing_current_alert_after_rotation(self) -> None:
        self._freeze(count=1)
        self._rotate_dashboard_a_representative()
        connection = self._connect()
        connection.execute(
            "DELETE FROM alerts WHERE alert_id = 'alert-a-rotated'"
        )
        connection.commit()
        connection.close()

        with self.assertRaisesRegex(
            cohort.CohortError,
            "current representative alert is missing",
        ):
            cohort.queue_cohort(
                self.db_path,
                self.manifest_path,
                base_url="http://127.0.0.1:8766",
                dry_run=True,
            )

    def test_queue_rejects_frozen_stable_id_drift_without_rotation(
        self,
    ) -> None:
        self._freeze(count=1)
        connection = self._connect()
        connection.execute(
            """
            UPDATE alerts
            SET stable_group_id = ?
            WHERE alert_id = 'alert-a-newest'
            """,
            (self.stable_two,),
        )
        connection.commit()
        connection.close()

        with self.assertRaisesRegex(
            cohort.CohortError,
            "frozen representative alert stable identity drift",
        ):
            cohort.queue_cohort(
                self.db_path,
                self.manifest_path,
                base_url="http://127.0.0.1:8766",
                dry_run=True,
            )

    def test_queue_rejects_current_stable_id_drift_after_rotation(
        self,
    ) -> None:
        self._freeze(count=1)
        self._rotate_dashboard_a_representative()
        connection = self._connect()
        connection.execute(
            """
            UPDATE alerts
            SET stable_group_id = ?
            WHERE alert_id = 'alert-a-rotated'
            """,
            (self.stable_two,),
        )
        connection.commit()
        connection.close()

        with self.assertRaisesRegex(
            cohort.CohortError,
            "current representative alert stable identity drift",
        ):
            cohort.queue_cohort(
                self.db_path,
                self.manifest_path,
                base_url="http://127.0.0.1:8766",
                dry_run=True,
            )

    def test_queue_rejects_stable_group_key_drift_without_rotation(
        self,
    ) -> None:
        self._freeze(count=1)
        connection = self._connect()
        connection.execute(
            """
            UPDATE alerts
            SET stable_group_key = 'v2|mutated'
            WHERE alert_id = 'alert-a-newest'
            """
        )
        connection.commit()
        connection.close()

        with self.assertRaisesRegex(
            cohort.CohortError,
            "immutable evidence drift.*stable_group_key",
        ):
            cohort.queue_cohort(
                self.db_path,
                self.manifest_path,
                base_url="http://127.0.0.1:8766",
                dry_run=True,
            )

    def test_queue_rejects_incompatible_stable_group_key_after_rotation(
        self,
    ) -> None:
        self._freeze(count=1)
        self._rotate_dashboard_a_representative()
        connection = self._connect()
        connection.execute(
            """
            UPDATE alerts
            SET stable_group_key = 'v2|mutated'
            WHERE alert_id = 'alert-a-rotated'
            """
        )
        connection.commit()
        connection.close()

        with self.assertRaisesRegex(
            cohort.CohortError,
            "representative alert stable group key drift",
        ):
            cohort.queue_cohort(
                self.db_path,
                self.manifest_path,
                base_url="http://127.0.0.1:8766",
                dry_run=True,
            )

    def test_queue_rejects_frozen_alert_immutable_evidence_drift(self) -> None:
        self._freeze(count=1)
        self._rotate_dashboard_a_representative()
        connection = self._connect()
        connection.execute(
            """
            UPDATE alerts
            SET source_port = 54321
            WHERE alert_id = 'alert-a-newest'
            """
        )
        connection.commit()
        connection.close()

        with self.assertRaisesRegex(
            cohort.CohortError,
            "immutable evidence drift.*source_port",
        ):
            cohort.queue_cohort(
                self.db_path,
                self.manifest_path,
                base_url="http://127.0.0.1:8766",
                dry_run=True,
            )

    def test_queue_uses_only_single_member_endpoints_and_is_exactly_once(self) -> None:
        self._freeze()
        calls, manifest = self._queue()

        self.assertEqual(len(calls), 2)
        self.assertTrue(calls[0][0].endswith(f"/{self.dashboard_a}/escalate"))
        self.assertTrue(calls[1][0].endswith("/ir-existing/reanalyze"))
        self.assertEqual(
            calls[1][1]["stable_group_id"],
            self.stable_two,
        )
        self.assertEqual(calls[0][1]["stable_group_key"], "v2|one")
        self.assertEqual(calls[1][1]["stable_group_key"], "v2|two")
        self.assertTrue(
            all(payload["release_id"] == self.release_id for _, payload in calls)
        )
        self.assertEqual(
            calls[1][1]["representative_alert_id"],
            "alert-c-existing",
        )
        self.assertRegex(calls[1][1]["dispatch_id"], r"^[a-f0-9]{64}$")
        self.assertNotIn("reanalyze-all", "\n".join(url for url, _ in calls))
        self.assertTrue(
            all(
                member["dispatch"]["state"] == "accepted"
                for member in manifest["members"]
            )
        )
        self.assertEqual(
            manifest["members"][1]["dispatch"]["accepted"]["run_id"],
            "irr-11111111-1111-1111-1111-111111111111",
        )
        self.assertEqual(
            manifest["members"][1]["dispatch"]["readback"]["dispatch_id"],
            calls[1][1]["dispatch_id"],
        )

        def forbidden(_url, _payload):
            raise AssertionError("accepted cohort must never be sent twice")

        replay = cohort.queue_cohort(
            self.db_path,
            self.manifest_path,
            base_url="http://127.0.0.1:8766",
            poster=forbidden,
        )
        self.assertEqual(replay["state"], "queued")

    def test_queue_rejects_mismatched_response_dispatch_identity(self) -> None:
        self._freeze(count=1)
        _calls, accepted_poster = self._api_poster()

        def mismatched(url, payload):
            result = accepted_poster(url, payload)
            response = dict(result.payload)
            response["dispatch_id"] = "0" * 64
            return cohort.HttpResult(
                result.status,
                response,
                cohort.sha256_value(response),
            )

        with self.assertRaisesRegex(
            cohort.AmbiguousDispatchError,
            "response identity",
        ):
            cohort.queue_cohort(
                self.db_path,
                self.manifest_path,
                base_url="http://127.0.0.1:8766",
                poster=mismatched,
            )

    def test_queue_rejects_mismatched_response_stable_group_key(self) -> None:
        self._freeze(count=1)
        _calls, accepted_poster = self._api_poster()

        def mismatched(url, payload):
            result = accepted_poster(url, payload)
            response = dict(result.payload)
            response["stable_group_key"] = "v2|different"
            return cohort.HttpResult(
                result.status,
                response,
                cohort.sha256_value(response),
            )

        with self.assertRaisesRegex(
            cohort.AmbiguousDispatchError,
            "response identity",
        ):
            cohort.queue_cohort(
                self.db_path,
                self.manifest_path,
                base_url="http://127.0.0.1:8766",
                poster=mismatched,
            )

    def test_queue_rejects_durable_payload_with_unpaired_dispatch_id(
        self,
    ) -> None:
        self._freeze(count=1)
        _calls, accepted_poster = self._api_poster()

        def unpaired(url, payload):
            result = accepted_poster(url, payload)
            connection = self._connect()
            row = connection.execute(
                """
                SELECT payload_json
                FROM durable_jobs
                WHERE job_type = 'incident_response_analysis'
                  AND dedupe_key = ?
                """,
                (self.stable_one,),
            ).fetchone()
            job_payload = json.loads(row[0])
            job_payload.pop("dispatch_id")
            connection.execute(
                """
                UPDATE durable_jobs
                SET payload_json = ?
                WHERE job_type = 'incident_response_analysis'
                  AND dedupe_key = ?
                """,
                (json.dumps(job_payload), self.stable_one),
            )
            connection.commit()
            connection.close()
            return result

        with self.assertRaisesRegex(
            cohort.AmbiguousDispatchError,
            "must be present together",
        ):
            cohort.queue_cohort(
                self.db_path,
                self.manifest_path,
                base_url="http://127.0.0.1:8766",
                poster=unpaired,
            )

    def test_queue_rejects_durable_payload_without_stable_group_key(
        self,
    ) -> None:
        self._freeze(count=1)
        _calls, accepted_poster = self._api_poster()

        def missing_key(url, payload):
            result = accepted_poster(url, payload)
            connection = self._connect()
            row = connection.execute(
                """
                SELECT payload_json
                FROM durable_jobs
                WHERE job_type = 'incident_response_analysis'
                  AND dedupe_key = ?
                """,
                (self.stable_one,),
            ).fetchone()
            job_payload = json.loads(row[0])
            job_payload.pop("stable_group_key")
            connection.execute(
                """
                UPDATE durable_jobs
                SET payload_json = ?
                WHERE job_type = 'incident_response_analysis'
                  AND dedupe_key = ?
                """,
                (json.dumps(job_payload), self.stable_one),
            )
            connection.commit()
            connection.close()
            return result

        with self.assertRaisesRegex(
            cohort.AmbiguousDispatchError,
            "payload identity",
        ):
            cohort.queue_cohort(
                self.db_path,
                self.manifest_path,
                base_url="http://127.0.0.1:8766",
                poster=missing_key,
            )

    def test_dispatch_readback_requires_exact_agent_role(self) -> None:
        base_manifest = self._freeze(count=1)
        member = base_manifest["members"][0]
        for expected_role in ("soc-analyst", "incident-responder"):
            manifest = json.loads(json.dumps(base_manifest))
            manifest["agent_role"] = expected_role
            payload = {
                "alert_id": member["representative_alert_id"],
                "representative_alert_id": member[
                    "representative_alert_id"
                ],
                "group_id": member["stable_group_id"],
                "stable_group_id": member["stable_group_id"],
                "stable_group_key": cohort._member_stable_group_key(member),
                "dashboard_group_id": member["dashboard_group_id"],
                "cohort_id": manifest["cohort_id"],
                "dispatch_id": cohort.deterministic_dispatch_id(
                    manifest,
                    member,
                ),
                "release_id": manifest["execution_contract"][
                    "expected_release_id"
                ],
                "expected_assigned_route": manifest["execution_contract"][
                    "expected_assigned_route"
                ],
                "expected_reviewer_route": manifest["execution_contract"][
                    "expected_reviewer_route"
                ],
                "reviewer_required": manifest["execution_contract"][
                    "reviewer_required"
                ],
                "agent_role": expected_role,
                "manual_reanalysis": expected_role == "soc-analyst",
            }
            accepted = cohort._validate_dispatch_job_payload(
                manifest,
                member,
                {"payload_json": json.dumps(payload)},
                manual_reanalysis=payload["manual_reanalysis"],
            )
            self.assertEqual(accepted["agent_role"], expected_role)

            for mutation in ("missing", "wrong"):
                with self.subTest(
                    expected_role=expected_role,
                    mutation=mutation,
                ):
                    changed = dict(payload)
                    if mutation == "missing":
                        changed.pop("agent_role")
                    else:
                        changed["agent_role"] = (
                            "incident-responder"
                            if expected_role == "soc-analyst"
                            else "soc-analyst"
                        )
                    with self.assertRaisesRegex(
                        cohort.AmbiguousDispatchError,
                        "payload identity",
                    ):
                        cohort._validate_dispatch_job_payload(
                            manifest,
                            member,
                            {"payload_json": json.dumps(changed)},
                            manual_reanalysis=payload["manual_reanalysis"],
                        )

    def test_queue_rejects_escalation_job_for_a_different_case(self) -> None:
        self._freeze(count=1)
        _calls, accepted_poster = self._api_poster()

        def mismatched_case(url, payload):
            result = accepted_poster(url, payload)
            connection = self._connect()
            row = connection.execute(
                """
                SELECT payload_json
                FROM durable_jobs
                WHERE job_type = 'incident_response_analysis'
                  AND dedupe_key = ?
                """,
                (self.stable_one,),
            ).fetchone()
            job_payload = json.loads(row[0])
            job_payload["case_id"] = "ir-different"
            connection.execute(
                """
                UPDATE durable_jobs
                SET payload_json = ?
                WHERE job_type = 'incident_response_analysis'
                  AND dedupe_key = ?
                """,
                (json.dumps(job_payload), self.stable_one),
            )
            connection.commit()
            connection.close()
            return result

        with self.assertRaisesRegex(
            cohort.AmbiguousDispatchError,
            "payload identity",
        ):
            cohort.queue_cohort(
                self.db_path,
                self.manifest_path,
                base_url="http://127.0.0.1:8766",
                poster=mismatched_case,
            )

    def test_queue_rejects_reanalysis_job_for_a_different_run(self) -> None:
        self._freeze()
        _calls, accepted_poster = self._api_poster()

        def mismatched_run(url, payload):
            result = accepted_poster(url, payload)
            if url.endswith("/ir-existing/reanalyze"):
                connection = self._connect()
                row = connection.execute(
                    """
                    SELECT payload_json
                    FROM durable_jobs
                    WHERE job_type = 'incident_response_analysis'
                      AND dedupe_key = ?
                    """,
                    (self.stable_two,),
                ).fetchone()
                job_payload = json.loads(row[0])
                job_payload["reanalysis_run_id"] = (
                    "irr-22222222-2222-2222-2222-222222222222"
                )
                connection.execute(
                    """
                    UPDATE durable_jobs
                    SET payload_json = ?
                    WHERE job_type = 'incident_response_analysis'
                      AND dedupe_key = ?
                    """,
                    (json.dumps(job_payload), self.stable_two),
                )
                connection.commit()
                connection.close()
            return result

        with self.assertRaisesRegex(
            cohort.AmbiguousDispatchError,
            "payload identity",
        ):
            cohort.queue_cohort(
                self.db_path,
                self.manifest_path,
                base_url="http://127.0.0.1:8766",
                poster=mismatched_run,
            )

    def test_monitor_rejects_accepted_job_payload_replacement(self) -> None:
        self._freeze(count=1)
        self._queue()
        connection = self._connect()
        row = connection.execute(
            """
            SELECT payload_json
            FROM durable_jobs
            WHERE job_type = 'incident_response_analysis'
              AND dedupe_key = ?
            """,
            (self.stable_one,),
        ).fetchone()
        job_payload = json.loads(row[0])
        job_payload["reason"] = "replacement after accepted readback"
        connection.execute(
            """
            UPDATE durable_jobs
            SET payload_json = ?
            WHERE job_type = 'incident_response_analysis'
              AND dedupe_key = ?
            """,
            (json.dumps(job_payload), self.stable_one),
        )
        connection.commit()
        connection.close()

        with self.assertRaisesRegex(
            cohort.CohortError,
            "payload changed during monitoring",
        ):
            cohort.monitor_cohort_once(
                self.db_path,
                self.manifest_path,
            )

    def test_monitor_rejects_accepted_job_identity_replacement(self) -> None:
        self._freeze(count=1)
        self._queue()
        connection = self._connect()
        connection.execute(
            """
            UPDATE durable_jobs
            SET id = id + 100
            WHERE job_type = 'incident_response_analysis'
              AND dedupe_key = ?
            """,
            (self.stable_one,),
        )
        connection.commit()
        connection.close()

        with self.assertRaisesRegex(
            cohort.CohortError,
            "job identity changed during monitoring",
        ):
            cohort.monitor_cohort_once(
                self.db_path,
                self.manifest_path,
            )

    def test_monitor_rejects_release_provenance_mutation(self) -> None:
        self._freeze(count=1)
        self._queue()
        manifest = cohort.load_private_manifest(self.manifest_path)
        manifest["members"][0]["dispatch"]["readback"]["release_id"] = "b" * 40
        cohort.write_private_json(
            self.manifest_path,
            manifest,
            digest_field="manifest_sha256",
        )

        with self.assertRaisesRegex(
            cohort.CohortError,
            "dispatch identity changed during monitoring",
        ):
            cohort.monitor_cohort_once(
                self.db_path,
                self.manifest_path,
            )

    def test_monitor_rejects_accepted_dispatch_identity_mutation(self) -> None:
        self._freeze(count=1)
        self._queue()
        manifest = cohort.load_private_manifest(self.manifest_path)
        manifest["members"][0]["dispatch"]["accepted"]["dispatch_id"] = (
            "0" * 64
        )
        cohort.write_private_json(
            self.manifest_path,
            manifest,
            digest_field="manifest_sha256",
        )

        with self.assertRaisesRegex(
            cohort.CohortError,
            "accepted response dispatch identity changed",
        ):
            cohort.monitor_cohort_once(
                self.db_path,
                self.manifest_path,
            )

    def test_monitor_rejects_stable_group_key_provenance_mutation(self) -> None:
        self._freeze(count=1)
        self._queue()
        manifest = cohort.load_private_manifest(self.manifest_path)
        manifest["members"][0]["dispatch"]["readback"][
            "stable_group_key"
        ] = "v2|different"
        cohort.write_private_json(
            self.manifest_path,
            manifest,
            digest_field="manifest_sha256",
        )

        with self.assertRaisesRegex(
            cohort.CohortError,
            "dispatch identity changed during monitoring",
        ):
            cohort.monitor_cohort_once(
                self.db_path,
                self.manifest_path,
            )

    def test_monitor_reproves_raw_stable_group_key_binding(self) -> None:
        self._freeze(count=1)
        self._queue()
        connection = self._connect()
        connection.execute(
            """
            UPDATE alerts
            SET stable_group_key = 'v2|changed-after-acceptance'
            WHERE alert_id = 'alert-a-newest'
            """
        )
        connection.commit()
        connection.close()

        with self.assertRaisesRegex(
            cohort.CohortError,
            "immutable evidence drift.*stable_group_key",
        ):
            cohort.monitor_cohort_once(
                self.db_path,
                self.manifest_path,
            )

    def test_monitor_keeps_fresh_result_nonterminal_while_job_is_active(
        self,
    ) -> None:
        self._freeze(count=1)
        self._queue()
        connection = self._connect()
        connection.execute(
            """
            INSERT INTO ai_analysis_runs (
              analysis_id, group_id, alert_id, agent_role, generated_at,
              model, model_path, detection_outcome, confidence,
              evidence_hash, response_json, created_at
            ) VALUES (
              'analysis-fresh-active', ?, 'alert-a-newest',
              'incident-responder', '2026-07-25T12:02:00Z',
              'gpt-5.6-sol', 'codex_cli',
              'true_positive_suspicious', 'high', 'evidence-fresh-active',
              '{}', '2026-07-25T12:02:00Z'
            )
            """,
            (self.stable_one,),
        )
        connection.execute(
            """
            UPDATE incident_response_cases
            SET agent_status = 'analyzed',
                latest_analysis_id = 'analysis-fresh-active',
                updated_at = '2026-07-25T12:02:00Z'
            WHERE case_id = 'ir-new'
            """
        )
        connection.commit()
        connection.close()

        monitored, terminal = cohort.monitor_cohort_once(
            self.db_path,
            self.manifest_path,
        )

        self.assertFalse(terminal)
        self.assertEqual(
            monitored["members"][0]["monitor"]["state"],
            "queued",
        )
        self.assertEqual(
            monitored["members"][0]["monitor"]["analysis_id"],
            "",
        )

    def test_monitor_rejects_prefreeze_nonlatest_incident_analysis_id(
        self,
    ) -> None:
        connection = self._connect()
        for analysis_id, generated_at in (
            ("analysis-ir-old-nonlatest", "2026-07-25T11:56:00Z"),
            ("analysis-ir-latest-before-freeze", "2026-07-25T11:57:00Z"),
        ):
            connection.execute(
                """
                INSERT INTO ai_analysis_runs (
                  analysis_id, group_id, alert_id, agent_role, generated_at,
                  model, model_path, detection_outcome, confidence,
                  evidence_hash, response_json, created_at
                ) VALUES (
                  ?, ?, 'alert-c-existing', 'incident-responder', ?,
                  'gpt-5.6-sol', 'codex_cli',
                  'true_positive_suspicious', 'high', ?, '{}', ?
                )
                """,
                (
                    analysis_id,
                    self.stable_two,
                    generated_at,
                    f"evidence-{analysis_id}",
                    generated_at,
                ),
            )
        connection.execute(
            """
            UPDATE incident_response_cases
            SET latest_analysis_id = 'analysis-ir-latest-before-freeze',
                latest_model = 'gpt-5.6-sol',
                latest_generated_at = '2026-07-25T11:57:00Z',
                updated_at = '2026-07-25T11:57:00Z'
            WHERE case_id = 'ir-existing'
            """
        )
        connection.commit()
        connection.close()

        source_path = self.root / "prefreeze-ir-source.json"
        source_path.write_text(
            json.dumps(
                [
                    {
                        "dashboard_group_id": self.dashboard_c,
                        "stable_group_id": self.stable_two,
                        "representative_alert_id": "alert-c-existing",
                    }
                ]
            ),
            encoding="utf-8",
        )
        os.chmod(source_path, 0o600)
        cohort.freeze_cohort_from_rows(
            self.db_path,
            source_path,
            self.manifest_path,
            cohort_id="prefreeze-nonlatest-ir-id",
            reason=(
                "Reject a pre-freeze nonlatest Incident Responder analysis."
            ),
            expected_count=1,
            expected_release_id=self.release_id,
        )
        self._queue()

        connection = self._connect()
        connection.execute(
            """
            UPDATE incident_reanalysis_run_cases
            SET status = 'completed',
                analysis_id = 'analysis-ir-old-nonlatest',
                completed_at = '2026-07-25T12:05:00Z',
                updated_at = '2026-07-25T12:05:00Z'
            WHERE case_id = 'ir-existing'
            """
        )
        connection.execute(
            """
            UPDATE incident_response_cases
            SET agent_status = 'analyzed',
                latest_analysis_id = 'analysis-ir-old-nonlatest',
                updated_at = '2026-07-25T12:05:00Z'
            WHERE case_id = 'ir-existing'
            """
        )
        connection.execute(
            """
            UPDATE durable_jobs
            SET status = 'completed',
                completed_at = '2026-07-25T12:05:00Z',
                last_completed_at = '2026-07-25T12:05:00Z',
                updated_at = '2026-07-25T12:05:00Z'
            WHERE job_type = 'incident_response_analysis'
              AND dedupe_key = ?
            """,
            (self.stable_two,),
        )
        connection.commit()
        connection.close()

        with self.assertRaisesRegex(
            cohort.CohortError,
            "not the exact fresh analysis",
        ):
            cohort.monitor_cohort_once(
                self.db_path,
                self.manifest_path,
            )

    def test_monitor_rejects_unrelated_group_analysis_alert(self) -> None:
        self._freeze(count=1)
        self._queue()
        connection = self._connect()
        connection.execute(
            """
            INSERT INTO ai_analysis_runs (
              analysis_id, group_id, alert_id, agent_role, generated_at,
              model, model_path, detection_outcome, confidence,
              evidence_hash, response_json, created_at
            ) VALUES (
              'analysis-wrong-alert', ?, 'alert-c-existing',
              'incident-responder', '2026-07-25T12:05:00Z',
              'gpt-5.6-sol', 'codex_cli',
              'true_positive_suspicious', 'high', 'evidence-wrong-alert',
              '{}', '2026-07-25T12:05:00Z'
            )
            """,
            (self.stable_one,),
        )
        connection.execute(
            """
            UPDATE incident_response_cases
            SET agent_status = 'analyzed',
                latest_analysis_id = 'analysis-wrong-alert',
                updated_at = '2026-07-25T12:05:00Z'
            WHERE case_id = 'ir-new'
            """
        )
        connection.execute(
            """
            UPDATE durable_jobs
            SET status = 'completed',
                completed_at = '2026-07-25T12:05:00Z',
                last_completed_at = '2026-07-25T12:05:00Z',
                updated_at = '2026-07-25T12:05:00Z'
            WHERE job_type = 'incident_response_analysis'
              AND dedupe_key = ?
            """,
            (self.stable_one,),
        )
        connection.commit()
        connection.close()

        with self.assertRaisesRegex(
            cohort.CohortError,
            "not bound to the frozen incident-responder identity",
        ):
            cohort.monitor_cohort_once(
                self.db_path,
                self.manifest_path,
            )

    def test_soc_dispatch_rejects_analysis_race_during_readback(self) -> None:
        source_path = self.root / "soc-race-source.json"
        source_path.write_text(
            json.dumps(
                [
                    {
                        "dashboard_group_id": self.dashboard_a,
                        "stable_group_id": self.stable_one,
                        "representative_alert_id": "alert-a-newest",
                    }
                ]
            ),
            encoding="utf-8",
        )
        os.chmod(source_path, 0o600)
        cohort.freeze_cohort_from_rows(
            self.db_path,
            source_path,
            self.manifest_path,
            cohort_id="soc-readback-race",
            reason="Reject a SOC worker result racing controlled readback.",
            expected_count=1,
            expected_release_id=self.release_id,
            agent_role="soc-analyst",
        )
        _calls, poster = self._soc_api_poster(
            create_fresh_analysis=True
        )

        with self.assertRaisesRegex(
            cohort.AmbiguousDispatchError,
            "fresh soc-analyst analysis appeared",
        ):
            cohort.queue_cohort(
                self.db_path,
                self.manifest_path,
                base_url="http://127.0.0.1:8766",
                poster=poster,
            )

    def test_escalation_rejects_analysis_race_during_readback(self) -> None:
        self._freeze(count=1)
        _calls, accepted_poster = self._api_poster()

        def raced(url, payload):
            result = accepted_poster(url, payload)
            connection = self._connect()
            connection.execute(
                """
                INSERT INTO ai_analysis_runs (
                  analysis_id, group_id, alert_id, agent_role,
                  generated_at, response_json, created_at
                ) VALUES (
                  'analysis-raced-escalation', ?, 'alert-a-newest',
                  'incident-responder', '2026-07-25T12:01:01Z', '{}',
                  '2026-07-25T12:01:01Z'
                )
                """,
                (self.stable_one,),
            )
            connection.commit()
            connection.close()
            return result

        with self.assertRaisesRegex(
            cohort.AmbiguousDispatchError,
            "fresh incident-responder analysis appeared",
        ):
            cohort.queue_cohort(
                self.db_path,
                self.manifest_path,
                base_url="http://127.0.0.1:8766",
                poster=raced,
            )

    def test_reanalysis_rejects_analysis_race_during_readback(self) -> None:
        self._freeze()
        _calls, accepted_poster = self._api_poster()

        def raced(url, payload):
            result = accepted_poster(url, payload)
            if url.endswith("/ir-existing/reanalyze"):
                connection = self._connect()
                connection.execute(
                    """
                    INSERT INTO ai_analysis_runs (
                      analysis_id, group_id, alert_id, agent_role,
                      generated_at, response_json, created_at
                    ) VALUES (
                      'analysis-raced-reanalysis', ?, 'alert-c-existing',
                      'incident-responder', '2026-07-25T12:01:02Z', '{}',
                      '2026-07-25T12:01:02Z'
                    )
                    """,
                    (self.stable_two,),
                )
                connection.commit()
                connection.close()
            return result

        with self.assertRaisesRegex(
            cohort.AmbiguousDispatchError,
            "fresh incident-responder analysis appeared",
        ):
            cohort.queue_cohort(
                self.db_path,
                self.manifest_path,
                base_url="http://127.0.0.1:8766",
                poster=raced,
            )

    def test_soc_role_uses_analyze_and_monitors_exact_new_analysis_id(self) -> None:
        source_path = self.root / "shared-frozen-rows.json"
        source_path.write_text(
            json.dumps(
                [
                    {
                        "dashboard_group_id": self.dashboard_a,
                        "stable_group_id": self.stable_one,
                        "representative_alert_id": "alert-a-newest",
                    }
                ]
            ),
            encoding="utf-8",
        )
        os.chmod(source_path, 0o600)
        manifest = cohort.freeze_cohort_from_rows(
            self.db_path,
            source_path,
            self.manifest_path,
            cohort_id="preselected-soc-cohort",
            reason="Exercise the SOC Analyst harness on the frozen cohort.",
            expected_count=1,
            expected_release_id=self.release_id,
            agent_role="soc-analyst",
        )
        self.assertEqual(manifest["agent_role"], "soc-analyst")
        self.assertEqual(manifest["members"][0]["dispatch"]["kind"], "analyze")
        self.assertEqual(
            manifest["members"][0]["pre_state"]["soc_analysis_ids"],
            [],
        )
        calls = []

        def analyze(url: str, payload):
            calls.append((url, dict(payload)))
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
                hashlib.sha256(json.dumps(response).encode()).hexdigest(),
            )

        queued = cohort.queue_cohort(
            self.db_path,
            self.manifest_path,
            base_url="http://127.0.0.1:8766",
            poster=analyze,
        )
        self.assertEqual(len(calls), 1)
        self.assertTrue(
            calls[0][0].endswith(f"/{self.dashboard_a}/analyze")
        )
        self.assertEqual(queued["members"][0]["dispatch"]["state"], "accepted")
        queued["members"][0]["dispatch"]["started_at"] = (
            "2026-07-25T12:10:00Z"
        )
        cohort.write_private_json(
            self.manifest_path,
            queued,
            digest_field="manifest_sha256",
        )

        soc_tool_call_bindings = [
            {
                "call_id": "round-1-soc-pivot",
                "round_number": 1,
                "query_id": "soc-pivot",
                "backend": "elastic",
                "status": "ok",
                "request_digest": "d" * 64,
                "result_digest": "e" * 64,
                "read_only": True,
            }
        ]
        response = {
            "event_status": "observed",
            "detection_validity": "matched_intent",
            "activity_disposition": "suspicious",
            "handling": "investigate",
            "summary": "Observed café traffic — reviewed.",
            "confidence_score": 0.0000001,
            "serialization_probe": {
                "observed_at": "2026-07-25T18:00:00Z",
                "\ue000": "private-use",
                "😀": "astral",
            },
            "_analysis_model": "gpt-5.5",
            "_analysis_model_path": "codex_cli",
            "_analysis_model_route": "codex-cli:gpt-5.5:high",
            "_analysis_provider": "codex-cli",
            "_analysis_harness": "onion-sentinel",
            "_analysis_evaluation_memory_frozen": True,
            "_second_opinion": {
                "status": "completed",
                "model_route": "codex-cli:gpt-5.6-sol:xhigh",
                "response": {
                    "_analysis_model_route": (
                        "codex-cli:gpt-5.6-sol:xhigh"
                    )
                },
            },
            "_investigation_query_audit": {
                "read_only": True,
                "complete": True,
                "all_tool_call_bindings_read_only": True,
                "evaluation_requirement_satisfied": True,
                "query_contract": (
                    "onion-sentinel-investigation-pivots-v2"
                ),
                "provider_neutral": True,
                "rounds_completed": 1,
                "queries_admitted": 1,
                "successful_read_only_queries": 1,
                "tool_call_bindings": soc_tool_call_bindings,
                "rounds": [
                    {
                        "round": 1,
                        "trusted_queries": [
                            {
                                "query_id": "soc-pivot",
                                "backend": "elastic",
                                "status": "ok",
                                "query_digest": "f" * 64,
                                "result_digest": "e" * 64,
                                "returned_hits": 1,
                            }
                        ],
                        "results": [
                            {
                                "query_id": "soc-pivot",
                                "backend": "elastic",
                                "status": "ok",
                                "query_digest": "f" * 64,
                            }
                        ],
                    }
                ],
            },
        }
        connection = self._connect()
        connection.execute(
            """
            INSERT INTO ai_analysis_runs (
              analysis_id, group_id, alert_id, agent_role, generated_at,
              model, model_path, detection_outcome, confidence,
              evidence_hash, response_json, created_at
            ) VALUES (
              'analysis-soc-new', ?, 'alert-a-newest', 'soc-analyst',
              '2026-07-25T12:11:00Z', 'gpt-5.5', 'codex_cli',
              'true_positive_suspicious', 'high', 'evidence-soc',
              ?, '2026-07-25T12:11:00Z'
            )
            """,
            (self.stable_one, json.dumps(response)),
        )
        connection.execute(
            """
            UPDATE durable_jobs
            SET status = 'completed', completed_at = '2026-07-25T12:11:00Z',
                last_completed_at = '2026-07-25T12:11:00Z',
                updated_at = '2026-07-25T12:11:00Z'
            WHERE job_type = 'ai_analysis' AND dedupe_key = ?
            """,
            (self.stable_one,),
        )
        connection.commit()
        connection.close()

        monitored, terminal = cohort.monitor_cohort_once(
            self.db_path,
            self.manifest_path,
        )
        self.assertTrue(terminal)
        result = monitored["members"][0]["monitor"]
        self.assertEqual(result["analysis_id"], "analysis-soc-new")
        self.assertEqual(result["analysis"]["agent_role"], "soc-analyst")
        self.assertEqual(
            result["analysis"]["result"]["_analysis_harness"],
            "onion-sentinel",
        )
        self.assertEqual(
            result["analysis"]["response_canonical_sha256"],
            cohort.alert_store_response_sha256(json.dumps(response)),
        )
        manifest = cohort.load_private_manifest(self.manifest_path)
        analysis = manifest["members"][0]["monitor"]["analysis"]
        exported_tool_bindings = analysis["query_audit"][
            "_investigation_query_audit"
        ]["tool_call_bindings"]
        exported_model_call_facts = [
            {
                "call_id": "primary-initial",
                "purpose": "initial primary analysis",
                "requested_route": "codex-cli:gpt-5.5:high",
                "independent_review": False,
                "status": "completed",
            },
            {
                "call_id": "independent-review-1",
                "purpose": "independent second-opinion review",
                "requested_route": "codex-cli:gpt-5.6-sol:xhigh",
                "independent_review": True,
                "status": "completed",
            },
        ]
        proof = {
            "status": "passed",
            "fresh_analysis": True,
            "dispatch_accepted_once": True,
            "analysis_id": "analysis-soc-new",
            "analysis_generated_at": "2026-07-25T12:11:00Z",
            "release_id": self.release_id,
            "harness": {
                "run_id": "analysis-soc-new",
                "trace_id": "trace-soc-export",
                "stable_group_id": self.stable_one,
                "representative_alert_id": "alert-a-newest",
                "status": "succeeded",
                "stage": "complete",
                "role": "soc-analyst",
                "task_kind": "reanalysis",
                "policy_mode": "shadow",
                "assigned_route": "codex-cli:gpt-5.5:high",
                "assigned_reviewer_route": "codex-cli:gpt-5.6-sol:xhigh",
                "started_at": "2026-07-25T12:10:30Z",
                "completed_at": "2026-07-25T12:12:00Z",
                "chain_valid": True,
                "chain_head_sha256": "a" * 64,
                "ledger_manifest_bound": True,
                "ledger_manifest_schema": (
                    "onion-sentinel-harness-ledger-manifest-v2"
                ),
                "skill_selection_attestation_validated": True,
                "skill_selection_attestation": {
                    "registry_version": 1,
                    "registry_sha256": "9" * 64,
                    "selected": [],
                    "selected_count": 0,
                    "truncated": False,
                    "advisory_mode": "advisory_only",
                },
                "model_call_count": 2,
                "successful_model_call_count": 2,
                "successful_primary_model_call_count": 1,
                "model_purpose_count": 2,
                "terminally_successful_model_purpose_count": 2,
                "incomplete_model_purpose_count": 0,
                "exact_reviewer_repair_count": 0,
                "superseded_validation_failure_count": 0,
                "unexpected_unsuccessful_model_call_count": 0,
                "malformed_model_purpose_sequence_count": 0,
                "model_call_contract": {
                    "schema": "onion-sentinel-model-call-contract-v1",
                    "valid": True,
                    "model_call_count": 2,
                    "canonical_model_call_count": 2,
                    "noncanonical_model_call_count": 0,
                    "primary_initial_call_count": 1,
                    "query_planning_call_count": 0,
                    "primary_followup_call_count": 0,
                    "reviewer_model_call_count": 1,
                    "facts": exported_model_call_facts,
                    "facts_sha256": cohort.sha256_value(
                        exported_model_call_facts
                    ),
                    "violation_count": 0,
                    "violations": [],
                    "global_reasons": [],
                },
                "reviewer_completion": {
                    "model_call_count": 1,
                    "completed_model_call_count": 1,
                    "primary_decision_count": 1,
                    "reviewer_decision_count": 1,
                    "has_primary_decision": True,
                    "has_reviewer_decision": True,
                    "decision_comparable": True,
                    "missing_reviewer_decision": False,
                    "completion_contract_required": True,
                    "completion_contract_satisfied": True,
                    "completion_contract_failure_reasons": [],
                },
                "route_authorization_failure_count": 0,
                "route_identity_mismatch_count": 0,
                "tool_call_count": 1,
                "successful_tool_call_count": 1,
                "read_only_tool_call_count": 1,
                "read_only_violation_count": 0,
                "successful_read_only_tool_call_bindings": (
                    exported_tool_bindings
                ),
                "successful_read_only_tool_call_bindings_sha256": (
                    cohort.sha256_value(exported_tool_bindings)
                ),
                "query_audit": cohort._query_audit_execution_binding(
                    analysis
                ),
                "memory_frozen": True,
                "submitted_response_sha256": "b" * 64,
                "response_canonical_sha256": analysis[
                    "response_canonical_sha256"
                ],
            },
        }
        proof["proof_sha256"] = cohort.sha256_value(proof)
        with mock.patch.object(
            cohort,
            "_harness_execution_proof",
            return_value=proof,
        ):
            exported = cohort.export_cohort(
                self.db_path,
                self.manifest_path,
                self.output_path,
                harness_database_path=self.root / "harness.sqlite3",
            )
        self.assertEqual(exported["agent_role"], "soc-analyst")
        self.assertEqual(
            exported["members"][0]["result"]["analysis"]["model"],
            "gpt-5.5",
        )
        loaded, _source_file_sha256 = (
            cohort_evaluator.load_result_export(
                self.output_path,
                role="soc-analyst",
                expected_count=1,
            )
        )
        self.assertEqual(
            loaded["ordered_identities"][0]["stable_group_id"],
            self.stable_one,
        )

    def test_ambiguous_dispatch_is_recorded_and_never_retried(self) -> None:
        self._freeze(count=1)
        calls = 0

        def ambiguous(_url, _payload):
            nonlocal calls
            calls += 1
            raise cohort.AmbiguousDispatchError("synthetic timeout")

        with self.assertRaises(cohort.AmbiguousDispatchError):
            cohort.queue_cohort(
                self.db_path,
                self.manifest_path,
                base_url="http://127.0.0.1:8766",
                poster=ambiguous,
            )
        recorded = cohort.load_private_manifest(self.manifest_path)
        self.assertEqual(recorded["state"], "dispatch_ambiguous")
        self.assertEqual(recorded["members"][0]["dispatch"]["attempt_count"], 1)

        with self.assertRaisesRegex(cohort.CohortError, "refusing"):
            cohort.queue_cohort(
                self.db_path,
                self.manifest_path,
                base_url="http://127.0.0.1:8766",
                poster=ambiguous,
            )
        self.assertEqual(calls, 1)

    def test_monitor_and_export_bind_exact_results_without_raw_content(self) -> None:
        self._freeze()
        self._queue()
        queued_manifest = cohort.load_private_manifest(self.manifest_path)
        for member in queued_manifest["members"]:
            member["dispatch"]["started_at"] = "2026-07-25T12:00:00Z"
        cohort.write_private_json(
            self.manifest_path,
            queued_manifest,
            digest_field="manifest_sha256",
        )
        secret_marker = "never-export-this-api-key"
        response = {
            "event_status": "observed",
            "detection_validity": "matched_intent",
            "activity_disposition": "suspicious",
            "handling": "investigate",
            "_analysis_model": "gpt-5.6-sol",
            "_analysis_model_path": "codex_cli",
            "_analysis_provider": "codex-cli",
            "api_key": secret_marker,
            "_incident_query_audit": {
                "trusted_source": "restricted-security-onion-wrapper",
                "read_only": True,
                "complete": True,
                "queries": [
                    {
                        "pack": "network_flow",
                        "status": "ok",
                        "query_digest": "query-digest-unit",
                        "returned_hits": 2,
                        "query_dsl": {
                            "query": {"term": {"source.ip": "192.0.2.1"}}
                        },
                        "rows": [{"secret": secret_marker}],
                    }
                ],
            },
        }
        connection = self._connect()
        for analysis_id, stable, alert_id in (
            ("analysis-new", self.stable_one, "alert-a-newest"),
            ("analysis-reanalysis", self.stable_two, "alert-c-existing"),
        ):
            connection.execute(
                """
                INSERT INTO ai_analysis_runs (
                  analysis_id, group_id, alert_id, agent_role, generated_at,
                  model, model_path, detection_outcome, confidence,
                  evidence_hash, response_json, created_at
                ) VALUES (
                  ?, ?, ?, 'incident-responder', '2026-07-25T12:05:00Z',
                  'gpt-5.6-sol', 'codex_cli',
                  'true_positive_suspicious', 'high', ?, ?,
                  '2026-07-25T12:05:00Z'
                )
                """,
                (
                    analysis_id,
                    stable,
                    alert_id,
                    f"evidence-{analysis_id}",
                    json.dumps(response),
                ),
            )
        connection.execute(
            """
            UPDATE incident_response_cases
            SET agent_status = 'analyzed', latest_analysis_id = 'analysis-new',
                latest_model = 'gpt-5.6-sol',
                latest_generated_at = '2026-07-25T12:05:00Z',
                updated_at = '2026-07-25T12:05:00Z'
            WHERE case_id = 'ir-new'
            """
        )
        connection.execute(
            """
            UPDATE incident_response_cases
            SET agent_status = 'analyzed',
                latest_analysis_id = 'analysis-reanalysis',
                latest_model = 'gpt-5.6-sol',
                latest_generated_at = '2026-07-25T12:05:00Z',
                updated_at = '2026-07-25T12:05:00Z'
            WHERE case_id = 'ir-existing'
            """
        )
        connection.execute(
            """
            UPDATE incident_reanalysis_run_cases
            SET status = 'completed', analysis_id = 'analysis-reanalysis',
                executed_model = 'gpt-5.6-sol',
                executed_provider = 'codex-cli',
                executed_model_path = 'codex_cli',
                result_generated_at = '2026-07-25T12:05:00Z',
                completed_at = '2026-07-25T12:05:00Z',
                updated_at = '2026-07-25T12:05:00Z'
            """
        )
        connection.execute(
            """
            UPDATE durable_jobs
            SET status = 'completed',
                completed_at = '2026-07-25T12:05:00Z',
                last_completed_at = '2026-07-25T12:05:00Z',
                updated_at = '2026-07-25T12:05:00Z'
            """
        )
        connection.commit()
        connection.close()

        monitored, terminal = cohort.monitor_cohort_once(
            self.db_path,
            self.manifest_path,
        )
        self.assertTrue(terminal)
        self.assertEqual(monitored["state"], "terminal")
        self.assertEqual(
            [item["monitor"]["analysis_id"] for item in monitored["members"]],
            ["analysis-new", "analysis-reanalysis"],
        )

        exported = cohort.export_cohort(
            self.db_path,
            self.manifest_path,
            self.output_path,
        )
        text = self.output_path.read_text(encoding="utf-8")
        self.assertNotIn(secret_marker, text)
        self.assertNotIn("source.ip", text)
        self.assertNotIn("query_dsl", text)
        self.assertIn("query-digest-unit", text)
        self.assertTrue(exported["content_policy"]["contains_credentials"] is False)
        self.assertEqual(
            stat.S_IMODE(self.output_path.stat().st_mode),
            0o600,
        )

    def test_tampered_manifest_is_rejected(self) -> None:
        self._freeze(count=1)
        document = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        document["reason"] = "Tampered reason that is deliberately long enough."
        self.manifest_path.write_text(json.dumps(document), encoding="utf-8")
        os.chmod(self.manifest_path, 0o600)

        with self.assertRaisesRegex(cohort.CohortError, "does not match"):
            cohort.load_private_manifest(self.manifest_path)

    def test_dashboard_transport_is_loopback_only_and_has_no_bulk_route(self) -> None:
        with self.assertRaisesRegex(cohort.CohortError, "loopback"):
            cohort.validate_loopback_base_url("http://192.0.2.10:8766")
        self.assertEqual(
            cohort.validate_loopback_base_url("http://127.0.0.1:8766"),
            "http://127.0.0.1:8766",
        )
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertNotIn('"/api/soc-incidents/reanalyze-all"', source)

    def test_execution_proof_accepts_timestamp_normalization_and_distinct_submission_digest(
        self,
    ) -> None:
        analysis_id = "analysis-normalized-timestamp"
        response_digest = "a" * 64
        submitted_digest = "b" * 64
        member = {
            "rank": 1,
            "dashboard_group_id": self.dashboard_a,
            "stable_group_id": self.stable_one,
            "representative_alert_id": "alert-a-newest",
            "pre_state": {"soc_analysis_ids": []},
            "dispatch": {
                "kind": "analyze",
                "state": "accepted",
                "attempt_count": 1,
                "started_at": "2026-07-25  23:00:00.000-06:00",
            },
        }
        manifest = {
            "agent_role": "soc-analyst",
            "execution_contract": cohort.execution_contract(
                expected_release_id=self.release_id,
                expected_assigned_route=(
                    "codex-cli:gpt-5.5:high"
                ),
                expected_reviewer_route=(
                    "codex-cli:gpt-5.6-sol:xhigh"
                ),
            ),
        }
        tool_call_bindings = [
            {
                "call_id": "round-1-soc-proof-pivot",
                "round_number": 1,
                "query_id": "soc-proof-pivot",
                "backend": "elastic",
                "status": "ok",
                "request_digest": "d" * 64,
                "result_digest": "e" * 64,
                "read_only": True,
            }
        ]
        monitor = {
            "state": "completed",
            "analysis_id": analysis_id,
            "analysis": {
                "analysis_id": analysis_id,
                "agent_role": "soc-analyst",
                "generated_at": "2026-07-25  23:02:35.980-06:00",
                "response_canonical_sha256": response_digest,
                "result": {
                    "_analysis_model_route": (
                        "codex-cli:gpt-5.5:high"
                    ),
                    "_analysis_evaluation_memory_frozen": True,
                    "_second_opinion": {
                        "status": "completed",
                        "model_route": "codex-cli:gpt-5.6-sol:xhigh",
                        "response": {
                            "_analysis_model_route": (
                                "codex-cli:gpt-5.6-sol:xhigh"
                            )
                        },
                    },
                },
                "query_audit": {
                    "_investigation_query_audit": {
                        "read_only": True,
                        "complete": True,
                        "all_tool_call_bindings_read_only": True,
                        "evaluation_requirement_satisfied": True,
                        "query_contract": (
                            "onion-sentinel-investigation-pivots-v2"
                        ),
                        "provider_neutral": True,
                        "rounds_completed": 1,
                        "queries_admitted": 1,
                        "successful_read_only_queries": 1,
                        "queries": [
                            {
                                "query_id": "soc-proof-pivot",
                                "backend": "elastic",
                                "status": "ok",
                                "query_digest": "f" * 64,
                                "result_digest": "e" * 64,
                                "returned_hits": 1,
                            }
                        ],
                        "round_results": [
                            {
                                "query_id": "soc-proof-pivot",
                                "backend": "elastic",
                                "status": "ok",
                                "query_digest": "f" * 64,
                            }
                        ],
                        "tool_call_bindings": tool_call_bindings,
                    }
                },
            },
        }
        zero_routes = {
            "contract_available": True,
            "authorization_failure_count": 0,
            "authorization_denied_event_count": 0,
            "authorization_malformed_event_count": 0,
            "authorization_orphan_event_count": 0,
            "authorization_unverified_call_count": 0,
            "observation_denied_event_count": 0,
            "observation_malformed_event_count": 0,
            "observation_orphan_event_count": 0,
            "identity_mismatch_count": 0,
            "identity_unverified_call_count": 0,
        }
        model_call_facts = [
            {
                "call_id": "primary-initial",
                "purpose": "initial primary analysis",
                "requested_route": "codex-cli:gpt-5.5:high",
                "independent_review": False,
                "status": "completed",
            },
            {
                "call_id": "independent-review-1",
                "purpose": "independent second-opinion review",
                "requested_route": "codex-cli:gpt-5.6-sol:xhigh",
                "independent_review": True,
                "status": "completed",
            },
        ]
        trace_report = {
            "runs": [
                {
                    "run_id": analysis_id,
                    "trace_id": "trace-normalized",
                    "correlation_id": self.stable_one,
                    "alert_id": "alert-a-newest",
                    "role": "soc-analyst",
                    "task_kind": "reanalysis",
                    "status": "succeeded",
                    "stage": "complete",
                    "assigned_route": "codex-cli:gpt-5.5:high",
                    "assigned_reviewer_route": (
                        "codex-cli:gpt-5.6-sol:xhigh"
                    ),
                    "policy_mode": "shadow",
                    "started_at": "2026-07-25  23:00:01.000-06:00",
                    "completed_at": "2026-07-25  23:03:00.000-06:00",
                    "terminal_execution_summary": {
                        "analysis_id": analysis_id,
                        "submitted_response_sha256": submitted_digest,
                        "stored_response_sha256": response_digest,
                        "evaluation_memory_frozen": True,
                    },
                    "skill_selection_attestation": {
                        "present": True,
                        "legacy": False,
                        "valid": True,
                        "available": True,
                        "job_digest_bound": True,
                        "mandatory_ready": True,
                        "registry_version": 1,
                        "registry_sha256": "9" * 64,
                        "selected": [
                            {
                                "id": "suricata-detection-validation",
                                "version": 3,
                                "skill_sha256": "8" * 64,
                            }
                        ],
                        "selected_count": 1,
                        "truncated": False,
                        "advisory_mode": "advisory_only",
                        "error_count": 0,
                        "errors": [],
                    },
                    "integrity": {
                        "valid": True,
                        "head_sha256": "c" * 64,
                        "ledger_manifest_bound": True,
                        "ledger_manifest_schema": (
                            "onion-sentinel-harness-ledger-manifest-v2"
                        ),
                    },
                    "counts": {"model_calls": 2, "tool_calls": 1},
                    "models": {
                        "successful_call_count": 2,
                        "successful_primary_call_count": 1,
                        "purpose_count": 2,
                        "terminally_successful_purpose_count": 2,
                        "incomplete_purpose_count": 0,
                        "exact_reviewer_repair_count": 0,
                        "superseded_validation_failure_count": 0,
                        "unexpected_unsuccessful_call_count": 0,
                        "malformed_purpose_sequence_count": 0,
                        "model_call_contract": {
                            "schema": (
                                "onion-sentinel-model-call-contract-v1"
                            ),
                            "valid": True,
                            "model_call_count": 2,
                            "canonical_model_call_count": 2,
                            "noncanonical_model_call_count": 0,
                            "primary_initial_call_count": 1,
                            "query_planning_call_count": 0,
                            "primary_followup_call_count": 0,
                            "reviewer_model_call_count": 1,
                            "facts": model_call_facts,
                            "facts_sha256": cohort.sha256_value(
                                model_call_facts
                            ),
                            "violation_count": 0,
                            "violations": [],
                            "global_reasons": [],
                        },
                        "route_consistency": zero_routes,
                    },
                    "reviewer": {
                        "model_call_count": 1,
                        "completed_model_call_count": 1,
                        "primary_decision_count": 1,
                        "reviewer_decision_count": 1,
                        "has_primary_decision": True,
                        "has_reviewer_decision": True,
                        "decision_comparable": True,
                        "missing_reviewer_decision": False,
                        "completion_contract_required": True,
                        "completion_contract_satisfied": True,
                        "completion_contract_failure_reasons": [],
                    },
                    "tools": {
                        "successful_call_count": 1,
                        "read_only_call_count": 1,
                        "read_only_violation_count": 0,
                        "successful_read_only_call_bindings": (
                            tool_call_bindings
                        ),
                        "successful_read_only_call_bindings_sha256": (
                            cohort.sha256_value(tool_call_bindings)
                        ),
                    },
                }
            ],
            "data_quality": {"malformed_json_counts": {}},
        }
        fake_evaluator = type(
            "FakeTraceEvaluator",
            (),
            {"evaluate_database": staticmethod(lambda _path, _run: trace_report)},
        )

        with mock.patch.object(
            cohort,
            "_load_trace_evaluator",
            return_value=fake_evaluator,
        ):
            proof = cohort._harness_execution_proof(
                harness_database_path=self.root / "synthetic-harness.sqlite3",
                manifest=manifest,
                member=member,
                monitor=monitor,
            )

        self.assertEqual(proof["status"], "passed")
        self.assertEqual(
            proof["harness"]["submitted_response_sha256"],
            submitted_digest,
        )
        self.assertNotEqual(submitted_digest, response_digest)
        self.assertEqual(proof["harness"]["tool_call_count"], 1)
        self.assertEqual(
            proof["harness"]["successful_tool_call_count"],
            1,
        )
        self.assertTrue(
            proof["harness"][
                "skill_selection_attestation_validated"
            ]
        )
        self.assertEqual(
            proof["harness"]["skill_selection_attestation"],
            {
                "registry_version": 1,
                "registry_sha256": "9" * 64,
                "selected": [
                    {
                        "id": "suricata-detection-validation",
                        "version": 3,
                        "skill_sha256": "8" * 64,
                    }
                ],
                "selected_count": 1,
                "truncated": False,
                "advisory_mode": "advisory_only",
            },
        )

        trace = trace_report["runs"][0]
        trace["skill_selection_attestation"]["mandatory_ready"] = False
        with mock.patch.object(
            cohort,
            "_load_trace_evaluator",
            return_value=fake_evaluator,
        ):
            with self.assertRaisesRegex(
                cohort.CohortError,
                "harness-skill-selection-attestation-invalid",
            ):
                cohort._harness_execution_proof(
                    harness_database_path=(
                        self.root / "synthetic-harness.sqlite3"
                    ),
                    manifest=manifest,
                    member=member,
                    monitor=monitor,
                )
        trace["skill_selection_attestation"]["mandatory_ready"] = True
        trace["skill_selection_attestation"]["registry_version"] = 0
        with mock.patch.object(
            cohort,
            "_load_trace_evaluator",
            return_value=fake_evaluator,
        ):
            with self.assertRaisesRegex(
                cohort.CohortError,
                "harness-skill-selection-attestation-invalid",
            ):
                cohort._harness_execution_proof(
                    harness_database_path=(
                        self.root / "synthetic-harness.sqlite3"
                    ),
                    manifest=manifest,
                    member=member,
                    monitor=monitor,
                )
        trace["skill_selection_attestation"]["registry_version"] = 1
        trace["counts"]["model_calls"] = 1
        trace["models"].update(
            {
                "successful_call_count": 1,
                "purpose_count": 1,
                "terminally_successful_purpose_count": 1,
            }
        )
        trace["models"]["model_call_contract"].update(
            {
                "model_call_count": 1,
                "canonical_model_call_count": 1,
                "reviewer_model_call_count": 0,
                "facts": model_call_facts[:1],
                "facts_sha256": cohort.sha256_value(
                    model_call_facts[:1]
                ),
            }
        )
        trace["reviewer"].update(
            {
                "model_call_count": 0,
                "completed_model_call_count": 0,
                "reviewer_decision_count": 0,
                "has_reviewer_decision": False,
                "decision_comparable": False,
                "missing_reviewer_decision": False,
                "completion_contract_required": False,
                "completion_contract_satisfied": True,
            }
        )
        with mock.patch.object(
            cohort,
            "_load_trace_evaluator",
            return_value=fake_evaluator,
        ):
            with self.assertRaisesRegex(
                cohort.CohortError,
                "harness-required-reviewer-call-missing",
            ):
                cohort._harness_execution_proof(
                    harness_database_path=(
                        self.root / "synthetic-harness.sqlite3"
                    ),
                    manifest=manifest,
                    member=member,
                    monitor=monitor,
                )

        trace["counts"]["model_calls"] = 3
        trace["models"].update(
            {
                "successful_call_count": 2,
                "purpose_count": 2,
                "terminally_successful_purpose_count": 2,
                "exact_reviewer_repair_count": 1,
                "superseded_validation_failure_count": 1,
            }
        )
        trace["reviewer"]["model_call_count"] = 2
        trace["reviewer"].update(
            {
                "completed_model_call_count": 1,
                "reviewer_decision_count": 1,
                "has_reviewer_decision": True,
                "decision_comparable": True,
                "completion_contract_required": True,
                "completion_contract_satisfied": True,
            }
        )
        trace["models"]["model_call_contract"].update(
            {
                "model_call_count": 3,
                "canonical_model_call_count": 3,
                "reviewer_model_call_count": 2,
            }
        )
        repaired_facts = [
            model_call_facts[0],
            {
                **model_call_facts[1],
                "status": "validation-failed",
            },
            {
                **model_call_facts[1],
                "call_id": "independent-review-2",
            },
        ]
        trace["models"]["model_call_contract"]["facts"] = repaired_facts
        trace["models"]["model_call_contract"]["facts_sha256"] = (
            cohort.sha256_value(repaired_facts)
        )
        with mock.patch.object(
            cohort,
            "_load_trace_evaluator",
            return_value=fake_evaluator,
        ):
            repaired_proof = cohort._harness_execution_proof(
                harness_database_path=self.root / "synthetic-harness.sqlite3",
                manifest=manifest,
                member=member,
                monitor=monitor,
            )
        self.assertEqual(
            repaired_proof["harness"][
                "superseded_validation_failure_count"
            ],
            1,
        )

        trace["reviewer"]["decision_comparable"] = False
        trace["reviewer"]["completion_contract_satisfied"] = False
        trace["reviewer"]["completion_contract_failure_reasons"] = [
            "reviewer-decision-not-comparable"
        ]
        with mock.patch.object(
            cohort,
            "_load_trace_evaluator",
            return_value=fake_evaluator,
        ):
            with self.assertRaisesRegex(
                cohort.CohortError,
                "harness-reviewer-completion-incomplete",
            ):
                cohort._harness_execution_proof(
                    harness_database_path=(
                        self.root / "synthetic-harness.sqlite3"
                    ),
                    manifest=manifest,
                    member=member,
                    monitor=monitor,
                )
        trace["reviewer"]["decision_comparable"] = True
        trace["reviewer"]["completion_contract_satisfied"] = True
        trace["reviewer"]["completion_contract_failure_reasons"] = []

        trace["models"]["model_call_contract"]["valid"] = False
        with mock.patch.object(
            cohort,
            "_load_trace_evaluator",
            return_value=fake_evaluator,
        ):
            with self.assertRaisesRegex(
                cohort.CohortError,
                "harness-model-call-contract-noncanonical",
            ):
                cohort._harness_execution_proof(
                    harness_database_path=(
                        self.root / "synthetic-harness.sqlite3"
                    ),
                    manifest=manifest,
                    member=member,
                    monitor=monitor,
                )
        trace["models"]["model_call_contract"]["valid"] = True

        trace["models"]["unexpected_unsuccessful_call_count"] = 1
        with mock.patch.object(
            cohort,
            "_load_trace_evaluator",
            return_value=fake_evaluator,
        ):
            with self.assertRaisesRegex(
                cohort.CohortError,
                "harness-model-purpose-incomplete",
            ):
                cohort._harness_execution_proof(
                    harness_database_path=(
                        self.root / "synthetic-harness.sqlite3"
                    ),
                    manifest=manifest,
                    member=member,
                    monitor=monitor,
                )
        trace["models"]["unexpected_unsuccessful_call_count"] = 0

        trace_report["runs"][0]["counts"]["tool_calls"] = 0
        trace_report["runs"][0]["tools"]["successful_call_count"] = 0
        trace_report["runs"][0]["tools"]["read_only_call_count"] = 0
        with mock.patch.object(
            cohort,
            "_load_trace_evaluator",
            return_value=fake_evaluator,
        ):
            with self.assertRaisesRegex(
                cohort.CohortError,
                "harness-tool-call-ledger-missing",
            ):
                cohort._harness_execution_proof(
                    harness_database_path=(
                        self.root / "synthetic-harness.sqlite3"
                    ),
                    manifest=manifest,
                    member=member,
                    monitor=monitor,
                )


if __name__ == "__main__":
    unittest.main()
