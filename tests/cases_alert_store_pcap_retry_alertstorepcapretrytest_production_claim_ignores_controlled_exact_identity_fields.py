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

class AlertStorePcapRetryTestProductionClaimIgnoresControlledExactIdentityFieldsCases:
    def test_production_claim_ignores_controlled_exact_identity_fields(
        self,
    ) -> None:
        identity = self.seed_manual_dispatch_group()
        dispatch_id = "4" * 64
        request = {
            "group_id": identity["dashboard_group_id"],
            "representative_alert_id": identity["pinned_alert_id"],
            "stable_group_id": identity["stable_group_id"],
            "stable_group_key": identity["stable_group_key"],
            "cohort_id": "newest-20-soc.exact-claim",
            "dispatch_id": dispatch_id,
            "release_id": DEPLOYED_RELEASE,
            **CONTROLLED_ROUTE_FIELDS,
        }
        status, queued = self.manual_dispatch_request("/ai/request", request)
        self.assertEqual(status, 202, queued)
        with closing(sqlite3.connect(self.db_path, timeout=3)) as connection:
            before = connection.execute(
                """
                SELECT id, payload_json, status, attempt_count, lease_token
                FROM durable_jobs
                WHERE job_type = 'ai_analysis' AND dedupe_key = ?
                """,
                (identity["stable_group_id"],),
            ).fetchone()

        status, claimed = self.manual_dispatch_request(
            "/jobs/status",
            {
                "job_type": "ai_analysis",
                "dedupe_key": identity["stable_group_id"],
                "status": "processing",
                "expected_job_id": before[0],
                "expected_representative_alert_id": identity["pinned_alert_id"],
                "expected_dispatch_id": "5" * 64,
                "expected_stable_group_key": identity["stable_group_key"],
            },
        )
        self.assertEqual(status, 200, claimed)
        self.assertTrue(claimed["lease_token"])
        self.assertNotIn("job_id", claimed["claim"])
        with closing(sqlite3.connect(self.db_path, timeout=3)) as connection:
            after_claim = connection.execute(
                """
                SELECT id, payload_json, status, attempt_count, lease_token
                FROM durable_jobs
                WHERE job_type = 'ai_analysis' AND dedupe_key = ?
                """,
                (identity["stable_group_id"],),
            ).fetchone()
        self.assertEqual(after_claim[0:2], before[0:2])
        self.assertEqual(after_claim[2:4], ("processing", 1))
        self.assertEqual(after_claim[4], claimed["lease_token"])

        status, replay = self.manual_dispatch_request(
            "/jobs/status",
            {
                "job_type": "ai_analysis",
                "dedupe_key": identity["stable_group_id"],
                "status": "processing",
                "expected_job_id": before[0],
                "expected_representative_alert_id": identity["pinned_alert_id"],
                "expected_dispatch_id": dispatch_id,
                "expected_stable_group_key": identity["stable_group_key"],
            },
        )
        self.assertEqual(status, 404, replay)
        self.assertIsNone(replay["lease_token"])


    def test_controlled_ai_request_rejects_processing_job_without_mutation(
        self,
    ) -> None:
        identity = self.seed_manual_dispatch_group()
        status, _legacy = self.manual_dispatch_request(
            "/ai/request",
            {"group_id": identity["dashboard_group_id"]},
        )
        self.assertEqual(status, 202)
        status, _claim = self.manual_dispatch_request(
            "/jobs/status",
            {
                "job_type": "ai_analysis",
                "dedupe_key": identity["stable_group_id"],
                "status": "processing",
            },
        )
        self.assertEqual(status, 200)
        with closing(sqlite3.connect(self.db_path, timeout=3)) as connection:
            before = connection.execute(
                """
                SELECT payload_json, status, attempt_count, lease_token,
                       rerun_requested
                FROM durable_jobs
                WHERE job_type = 'ai_analysis' AND dedupe_key = ?
                """,
                (identity["stable_group_id"],),
            ).fetchone()

        status, rejected = self.manual_dispatch_request(
            "/ai/request",
            {
                "group_id": identity["dashboard_group_id"],
                "representative_alert_id": identity["pinned_alert_id"],
                "stable_group_id": identity["stable_group_id"],
                "stable_group_key": identity["stable_group_key"],
                "cohort_id": "newest-20-soc.processing-conflict",
                "dispatch_id": "6" * 64,
                "release_id": DEPLOYED_RELEASE,
                **CONTROLLED_ROUTE_FIELDS,
            },
        )
        self.assertEqual(status, 409, rejected)
        with closing(sqlite3.connect(self.db_path, timeout=3)) as connection:
            after = connection.execute(
                """
                SELECT payload_json, status, attempt_count, lease_token,
                       rerun_requested
                FROM durable_jobs
                WHERE job_type = 'ai_analysis' AND dedupe_key = ?
                """,
                (identity["stable_group_id"],),
            ).fetchone()
        self.assertEqual(after, before)


    def test_manual_incident_escalation_uses_pinned_alert_for_case_and_job(
        self,
    ) -> None:
        identity = self.seed_manual_dispatch_group()
        status, legacy = self.manual_dispatch_request(
            "/incidents/escalate",
            {"group_id": identity["dashboard_group_id"]},
        )
        self.assertEqual(status, 202, legacy)
        self.assertEqual(
            legacy["representative_alert_id"],
            identity["current_alert_id"],
        )
        self.assertNotIn("stable_group_id", legacy)
        self.assertNotIn("cohort_id", legacy)
        self.assertNotIn("dispatch_id", legacy)
        self.assertNotIn("release_id", legacy)

        cohort_id = "newest-20-ir.2026_07_26"
        dispatch_id = "e" * 64
        status, pinned = self.manual_dispatch_request(
            "/incidents/escalate",
            {
                "group_id": identity["dashboard_group_id"],
                "representative_alert_id": identity["pinned_alert_id"],
                "stable_group_id": identity["stable_group_id"],
                "stable_group_key": identity["stable_group_key"],
                "cohort_id": cohort_id,
                "dispatch_id": dispatch_id,
                "release_id": DEPLOYED_RELEASE,
                **CONTROLLED_ROUTE_FIELDS,
            },
        )
        self.assertEqual(status, 202, pinned)
        self.assertEqual(
            pinned["representative_alert_id"],
            identity["pinned_alert_id"],
        )
        self.assertEqual(pinned["stable_group_id"], identity["stable_group_id"])
        self.assertEqual(pinned["stable_group_key"], identity["stable_group_key"])
        self.assertEqual(pinned["cohort_id"], cohort_id)
        self.assertEqual(pinned["dispatch_id"], dispatch_id)
        self.assertEqual(pinned["release_id"], DEPLOYED_RELEASE)

        with closing(sqlite3.connect(self.db_path, timeout=3)) as connection:
            case_alert_id = connection.execute(
                """
                SELECT representative_alert_id FROM incident_response_cases
                WHERE group_id = ?
                """,
                (identity["stable_group_id"],),
            ).fetchone()[0]
            payload_json = connection.execute(
                """
                SELECT payload_json FROM durable_jobs
                WHERE job_type = 'incident_response_analysis'
                  AND dedupe_key = ?
                """,
                (identity["stable_group_id"],),
            ).fetchone()[0]
        self.assertEqual(case_alert_id, identity["pinned_alert_id"])
        durable_payload = json.loads(payload_json)
        self.assertEqual(
            durable_payload["alert_id"],
            identity["pinned_alert_id"],
        )
        self.assertEqual(
            durable_payload["representative_alert_id"],
            identity["pinned_alert_id"],
        )
        self.assertEqual(durable_payload["cohort_id"], cohort_id)
        self.assertEqual(durable_payload["dispatch_id"], dispatch_id)
        self.assertEqual(durable_payload["release_id"], DEPLOYED_RELEASE)
        self.assertEqual(
            durable_payload["stable_group_key"],
            identity["stable_group_key"],
        )

        status, rejected = self.manual_dispatch_request(
            "/incidents/escalate",
            {
                "group_id": identity["dashboard_group_id"],
                "representative_alert_id": identity["foreign_alert_id"],
                "stable_group_id": identity["stable_group_id"],
                "stable_group_key": identity["stable_group_key"],
                "cohort_id": cohort_id,
                "dispatch_id": "f" * 64,
                "release_id": DEPLOYED_RELEASE,
            },
        )
        self.assertEqual(status, 409, rejected)
        with closing(sqlite3.connect(self.db_path, timeout=3)) as connection:
            retained_case_alert_id = connection.execute(
                """
                SELECT representative_alert_id FROM incident_response_cases
                WHERE group_id = ?
                """,
                (identity["stable_group_id"],),
            ).fetchone()[0]
            retained_payload_json = connection.execute(
                """
                SELECT payload_json FROM durable_jobs
                WHERE job_type = 'incident_response_analysis'
                  AND dedupe_key = ?
                """,
                (identity["stable_group_id"],),
            ).fetchone()[0]
        self.assertEqual(retained_case_alert_id, identity["pinned_alert_id"])
        self.assertEqual(json.loads(retained_payload_json), durable_payload)


    def test_controlled_escalation_rejects_processing_job_before_case_mutation(
        self,
    ) -> None:
        identity = self.seed_manual_dispatch_group()
        status, legacy = self.manual_dispatch_request(
            "/incidents/escalate",
            {"group_id": identity["dashboard_group_id"]},
        )
        self.assertEqual(status, 202, legacy)
        status, _claim = self.manual_dispatch_request(
            "/jobs/status",
            {
                "job_type": "incident_response_analysis",
                "dedupe_key": identity["stable_group_id"],
                "status": "processing",
            },
        )
        self.assertEqual(status, 200)
        with closing(sqlite3.connect(self.db_path, timeout=3)) as connection:
            before_case = connection.execute(
                """
                SELECT representative_alert_id, agent_status, updated_at
                FROM incident_response_cases WHERE group_id = ?
                """,
                (identity["stable_group_id"],),
            ).fetchone()
            before_events = connection.execute(
                "SELECT COUNT(*) FROM incident_response_events"
            ).fetchone()[0]
            before_job = connection.execute(
                """
                SELECT payload_json, status, attempt_count, lease_token,
                       rerun_requested
                FROM durable_jobs
                WHERE job_type = 'incident_response_analysis'
                  AND dedupe_key = ?
                """,
                (identity["stable_group_id"],),
            ).fetchone()

        status, rejected = self.manual_dispatch_request(
            "/incidents/escalate",
            {
                "group_id": identity["dashboard_group_id"],
                "representative_alert_id": identity["pinned_alert_id"],
                "stable_group_id": identity["stable_group_id"],
                "stable_group_key": identity["stable_group_key"],
                "cohort_id": "newest-20-ir.processing-conflict",
                "dispatch_id": "7" * 64,
                "release_id": DEPLOYED_RELEASE,
                **CONTROLLED_ROUTE_FIELDS,
            },
        )
        self.assertEqual(status, 409, rejected)
        with closing(sqlite3.connect(self.db_path, timeout=3)) as connection:
            after_case = connection.execute(
                """
                SELECT representative_alert_id, agent_status, updated_at
                FROM incident_response_cases WHERE group_id = ?
                """,
                (identity["stable_group_id"],),
            ).fetchone()
            after_events = connection.execute(
                "SELECT COUNT(*) FROM incident_response_events"
            ).fetchone()[0]
            after_job = connection.execute(
                """
                SELECT payload_json, status, attempt_count, lease_token,
                       rerun_requested
                FROM durable_jobs
                WHERE job_type = 'incident_response_analysis'
                  AND dedupe_key = ?
                """,
                (identity["stable_group_id"],),
            ).fetchone()
        self.assertEqual(after_case, before_case)
        self.assertEqual(after_events, before_events)
        self.assertEqual(after_job, before_job)


