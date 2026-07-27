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


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "operations" / "run-incident-harness-cohort.py"
SPEC = importlib.util.spec_from_file_location(
    "run_incident_harness_cohort",
    MODULE_PATH,
)
assert SPEC and SPEC.loader
cohort = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cohort)


class IncidentHarnessCohortTests(unittest.TestCase):
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
        )

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
                      job_type, dedupe_key, status, attempt_count,
                      requested_at, updated_at
                    ) VALUES (
                      'incident_response_analysis', ?, 'pending', 0,
                      '2026-07-25T12:01:00Z', '2026-07-25T12:01:00Z'
                    )
                    """,
                    (self.stable_one,),
                )
                response = {
                    "ok": True,
                    "status": "queued",
                    "case_id": "ir-new",
                    "group_id": self.dashboard_a,
                    "queue_group_id": self.stable_one,
                    "representative_alert_id": "alert-a-newest",
                    "requested_at": "2026-07-25T12:01:00Z",
                }
            elif url.endswith("/ir-existing/reanalyze"):
                run_id = "irr-11111111-1111-1111-1111-111111111111"
                connection.execute(
                    """
                    INSERT INTO incident_reanalysis_runs VALUES (
                      ?, 'fixture-release', 'single_case', 'queued',
                      'harness-cohort', ?, 1, '2026-07-25T12:01:01Z',
                      '2026-07-25T12:01:01Z', NULL
                    )
                    """,
                    (run_id, payload["reason"]),
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
                      job_type, dedupe_key, status, attempt_count,
                      requested_at, updated_at
                    ) VALUES (
                      'incident_response_analysis', ?, 'pending', 0,
                      '2026-07-25T12:01:01Z', '2026-07-25T12:01:01Z'
                    )
                    """,
                    (self.stable_two,),
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
                    "release_id": "fixture-release",
                    "scope": "single_case",
                    "status": "queued",
                    "total_count": 1,
                    "created_at": "2026-07-25T12:01:01Z",
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

    def _queue(self):
        calls, poster = self._api_poster()
        result = cohort.queue_cohort(
            self.db_path,
            self.manifest_path,
            base_url="http://127.0.0.1:8766",
            poster=poster,
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
            )
        self.assertFalse(self.manifest_path.exists())

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

    def test_queue_uses_only_single_member_endpoints_and_is_exactly_once(self) -> None:
        self._freeze()
        calls, manifest = self._queue()

        self.assertEqual(len(calls), 2)
        self.assertTrue(calls[0][0].endswith(f"/{self.dashboard_a}/escalate"))
        self.assertTrue(calls[1][0].endswith("/ir-existing/reanalyze"))
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

        def forbidden(_url, _payload):
            raise AssertionError("accepted cohort must never be sent twice")

        replay = cohort.queue_cohort(
            self.db_path,
            self.manifest_path,
            base_url="http://127.0.0.1:8766",
            poster=forbidden,
        )
        self.assertEqual(replay["state"], "queued")

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
                  job_type, dedupe_key, status, attempt_count,
                  requested_at, updated_at
                ) VALUES (
                  'ai_analysis', ?, 'pending', 0,
                  '2026-07-25T12:10:00Z', '2026-07-25T12:10:00Z'
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
                "representative_alert_id": "alert-a-newest",
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

        response = {
            "event_status": "observed",
            "detection_validity": "matched_intent",
            "activity_disposition": "suspicious",
            "handling": "investigate",
            "_analysis_model": "gpt-5.6-sol",
            "_analysis_model_path": "codex_cli",
            "_analysis_model_route": "codex-cli:gpt-5.6-sol:high",
            "_analysis_provider": "codex-cli",
            "_analysis_harness": "onion-sentinel",
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
              '2026-07-25T12:11:00Z', 'gpt-5.6-sol', 'codex_cli',
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
        exported = cohort.export_cohort(
            self.db_path,
            self.manifest_path,
            self.output_path,
        )
        self.assertEqual(exported["agent_role"], "soc-analyst")
        self.assertEqual(
            exported["members"][0]["result"]["analysis"]["model"],
            "gpt-5.6-sol",
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
            SET status = 'completed', updated_at = '2026-07-25T12:05:00Z'
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
            cohort.validate_loopback_base_url("http://10.77.7.225:8766")
        self.assertEqual(
            cohort.validate_loopback_base_url("http://127.0.0.1:8766"),
            "http://127.0.0.1:8766",
        )
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertNotIn('"/api/soc-incidents/reanalyze-all"', source)


if __name__ == "__main__":
    unittest.main()
