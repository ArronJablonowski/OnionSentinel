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

class IncidentReanalysisLineageTestsInitialEscalationIsNotClaimedAsCaseBoundReanalysisCases:
    def test_initial_escalation_is_not_claimed_as_case_bound_reanalysis(
        self,
    ) -> None:
        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            connection.execute(
                """
                INSERT INTO alert_group_summary (
                  group_id, group_key, representative_alert_id,
                  raw_alert_count, total_seen_count, updated_at
                ) VALUES (?, 'lineage-dashboard-group', ?, 1, 1, ?)
                """,
                (
                    self.dashboard_group_id,
                    self.alert_id,
                    self.generated_at(),
                ),
            )
            connection.commit()

        self.post(
            "/incidents/escalate",
            {
                "group_id": self.dashboard_group_id,
                "requested_by": "initial-escalation-test",
            },
            expected_status=202,
        )

        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            payload_json = connection.execute(
                """
                SELECT payload_json FROM durable_jobs
                WHERE job_type = 'incident_response_analysis'
                  AND dedupe_key = ?
                """,
                (self.group_id,),
            ).fetchone()[0]
        payload = json.loads(payload_json)
        self.assertIs(payload["manual_reanalysis"], False)
        self.assertNotIn("reanalysis_run_id", payload)

        claim = self.post(
            "/jobs/status",
            {
                "job_type": "incident_response_analysis",
                "dedupe_key": self.group_id,
                "status": "processing",
            },
        )
        self.assertIs(claim["claim"]["payload"]["manual_reanalysis"], False)
        self.assertIsNone(claim["claim"]["reanalysis_attempt_id"])


    def test_case_reanalysis_pins_and_persists_frozen_dispatch_identity(
        self,
    ) -> None:
        cohort_id = "newest-20-ir.2026_07_26"
        dispatch_id = "c" * 64
        frozen = self.post(
            "/incidents/reanalyze",
            {
                "case_id": self.case_id,
                "representative_alert_id": self.alert_id,
                "stable_group_id": self.group_id,
                "stable_group_key": "synthetic-lineage-group",
                "cohort_id": cohort_id,
                "dispatch_id": dispatch_id,
                "release_id": DEPLOYED_RELEASE,
                "requested_by": "frozen-lineage-test",
                **CONTROLLED_ROUTE_FIELDS,
            },
            expected_status=202,
        )
        self.assertEqual(frozen["representative_alert_id"], self.alert_id)
        self.assertEqual(frozen["stable_group_id"], self.group_id)
        self.assertEqual(
            frozen["stable_group_key"],
            "synthetic-lineage-group",
        )
        self.assertEqual(frozen["cohort_id"], cohort_id)
        self.assertEqual(frozen["dispatch_id"], dispatch_id)
        self.assertEqual(frozen["release_id"], DEPLOYED_RELEASE)

        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            payload_json = connection.execute(
                """
                SELECT payload_json FROM durable_jobs
                WHERE job_type = 'incident_response_analysis'
                  AND dedupe_key = ?
                """,
                (self.group_id,),
            ).fetchone()[0]
        durable_payload = json.loads(payload_json)
        self.assertEqual(durable_payload["alert_id"], self.alert_id)
        self.assertEqual(
            durable_payload["representative_alert_id"],
            self.alert_id,
        )
        self.assertEqual(durable_payload["group_id"], self.group_id)
        self.assertEqual(durable_payload["stable_group_id"], self.group_id)
        self.assertEqual(
            durable_payload["stable_group_key"],
            "synthetic-lineage-group",
        )
        self.assertEqual(durable_payload["cohort_id"], cohort_id)
        self.assertEqual(durable_payload["dispatch_id"], dispatch_id)
        self.assertEqual(durable_payload["release_id"], DEPLOYED_RELEASE)

        conflicts = (
            {
                "representative_alert_id": "different-alert",
                "stable_group_id": self.group_id,
                "stable_group_key": "synthetic-lineage-group",
                "cohort_id": cohort_id,
                "dispatch_id": "d" * 64,
                "release_id": DEPLOYED_RELEASE,
            },
            {
                "representative_alert_id": self.alert_id,
                "stable_group_id": "abcdef1234567890abcd",
                "stable_group_key": "synthetic-lineage-group",
                "cohort_id": cohort_id,
                "dispatch_id": "e" * 64,
                "release_id": DEPLOYED_RELEASE,
            },
            {
                "representative_alert_id": self.alert_id,
                "stable_group_id": self.group_id,
                "stable_group_key": "synthetic-lineage-group",
                "cohort_id": cohort_id,
                "release_id": DEPLOYED_RELEASE,
            },
            {
                "representative_alert_id": self.alert_id,
                "stable_group_id": self.group_id,
                "stable_group_key": "synthetic-lineage-group",
                "cohort_id": cohort_id,
                "dispatch_id": "f" * 64,
            },
            {
                "representative_alert_id": self.alert_id,
                "stable_group_id": self.group_id,
                "stable_group_key": "synthetic-lineage-group",
                "cohort_id": cohort_id,
                "dispatch_id": "0" * 64,
                "release_id": "e" * 40,
            },
        )
        for conflict in conflicts:
            with self.subTest(conflict=conflict):
                rejected = self.post(
                    "/incidents/reanalyze",
                    {"case_id": self.case_id, **conflict},
                    expected_status=409,
                )
                self.assertFalse(rejected["ok"])

        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            retained_json = connection.execute(
                """
                SELECT payload_json FROM durable_jobs
                WHERE job_type = 'incident_response_analysis'
                  AND dedupe_key = ?
                """,
                (self.group_id,),
            ).fetchone()[0]
        self.assertEqual(json.loads(retained_json), durable_payload)


    def test_controlled_reanalysis_rebinds_same_stable_representative(
        self,
    ) -> None:
        pinned_alert_id = "synthetic-incident-lineage-newest"
        self.seed_representative(pinned_alert_id)
        cohort_id = "newest-20-ir.representative-rotation"
        dispatch_id = "6" * 64

        accepted = self.post(
            "/incidents/reanalyze",
            {
                "case_id": self.case_id,
                "representative_alert_id": pinned_alert_id,
                "stable_group_id": self.group_id,
                "stable_group_key": "synthetic-lineage-group",
                "cohort_id": cohort_id,
                "dispatch_id": dispatch_id,
                "release_id": DEPLOYED_RELEASE,
                "requested_by": "frozen-rebind-test",
                **CONTROLLED_ROUTE_FIELDS,
            },
            expected_status=202,
        )

        case = self.incident_case()
        run_case = self.run_case(accepted["run_id"])
        self.assertEqual(case["group_id"], self.group_id)
        self.assertEqual(case["representative_alert_id"], pinned_alert_id)
        self.assertEqual(run_case["group_id"], self.group_id)
        self.assertEqual(run_case["representative_alert_id"], pinned_alert_id)
        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            durable_payload = json.loads(
                connection.execute(
                    """
                    SELECT payload_json FROM durable_jobs
                    WHERE job_type = 'incident_response_analysis'
                      AND dedupe_key = ?
                    """,
                    (self.group_id,),
                ).fetchone()[0]
            )
            event = connection.execute(
                """
                SELECT detail_json FROM incident_response_events
                WHERE case_id = ? AND event_type = 'reanalysis_basis_rebound'
                """,
                (self.case_id,),
            ).fetchone()
        self.assertEqual(durable_payload["case_id"], self.case_id)
        self.assertEqual(
            durable_payload["reanalysis_run_id"],
            accepted["run_id"],
        )
        self.assertEqual(durable_payload["alert_id"], pinned_alert_id)
        self.assertEqual(
            durable_payload["representative_alert_id"],
            pinned_alert_id,
        )
        self.assertEqual(durable_payload["release_id"], DEPLOYED_RELEASE)
        self.assertIsNotNone(event)
        event_detail = json.loads(event[0])
        self.assertEqual(
            event_detail["previous_representative_alert_id"],
            self.alert_id,
        )
        self.assertEqual(
            event_detail["representative_alert_id"],
            pinned_alert_id,
        )
        self.assertEqual(event_detail["cohort_id"], cohort_id)
        self.assertEqual(event_detail["dispatch_id"], dispatch_id)
        self.assertEqual(event_detail["release_id"], DEPLOYED_RELEASE)


    def test_controlled_reanalysis_canonicalizes_legacy_case_group(
        self,
    ) -> None:
        legacy_group_id = "3f83e4cd0123456789ab"
        pinned_alert_id = "synthetic-incident-lineage-canonical"
        self.seed_representative(pinned_alert_id)
        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            connection.execute(
                """
                INSERT INTO alert_group_alias (
                  legacy_group_id, stable_group_id, stable_group_key, updated_at
                ) VALUES (?, ?, 'synthetic-lineage-group', ?)
                """,
                (legacy_group_id, self.group_id, self.generated_at()),
            )
            connection.execute(
                """
                UPDATE incident_response_cases SET group_id = ?
                WHERE case_id = ?
                """,
                (legacy_group_id, self.case_id),
            )
            connection.execute(
                """
                INSERT INTO durable_jobs (
                  job_type, dedupe_key, payload_json, status, priority,
                  attempt_count, max_attempts, next_attempt_at, created_at,
                  updated_at, requested_at
                ) VALUES (
                  'incident_response_analysis', ?, ?, 'pending', 10,
                  0, 8, ?, ?, ?, ?
                )
                """,
                (
                    legacy_group_id,
                    json.dumps(
                        {
                            "case_id": self.case_id,
                            "alert_id": self.alert_id,
                            "group_id": legacy_group_id,
                            "manual_reanalysis": False,
                        }
                    ),
                    self.generated_at(),
                    self.generated_at(),
                    self.generated_at(),
                    self.generated_at(),
                ),
            )
            connection.commit()

        accepted = self.post(
            "/incidents/reanalyze",
            {
                "case_id": self.case_id,
                "representative_alert_id": pinned_alert_id,
                "stable_group_id": self.group_id,
                "stable_group_key": "synthetic-lineage-group",
                "cohort_id": "newest-20-ir.legacy-case",
                "dispatch_id": "7" * 64,
                "release_id": DEPLOYED_RELEASE,
                "requested_by": "legacy-case-rebind-test",
                **CONTROLLED_ROUTE_FIELDS,
            },
            expected_status=202,
        )

        case = self.incident_case()
        run_case = self.run_case(accepted["run_id"])
        self.assertEqual(case["group_id"], self.group_id)
        self.assertEqual(case["representative_alert_id"], pinned_alert_id)
        self.assertEqual(run_case["group_id"], self.group_id)
        self.assertEqual(run_case["representative_alert_id"], pinned_alert_id)
        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            old_job = connection.execute(
                """
                SELECT status FROM durable_jobs
                WHERE job_type = 'incident_response_analysis'
                  AND dedupe_key = ?
                """,
                (legacy_group_id,),
            ).fetchone()
            current_payload = json.loads(
                connection.execute(
                    """
                    SELECT payload_json FROM durable_jobs
                    WHERE job_type = 'incident_response_analysis'
                      AND dedupe_key = ?
                    """,
                    (self.group_id,),
                ).fetchone()[0]
            )
        self.assertEqual(old_job[0], "completed")
        self.assertEqual(current_payload["case_id"], self.case_id)
        self.assertEqual(current_payload["alert_id"], pinned_alert_id)
        self.assertEqual(
            current_payload["reanalysis_run_id"],
            accepted["run_id"],
        )


    def test_controlled_reanalysis_identity_rejections_are_read_only(
        self,
    ) -> None:
        wrong_group_id = "abcdef1234567890abcd"
        wrong_group_alert_id = "synthetic-incident-lineage-wrong-group"
        wrong_key_alert_id = "synthetic-incident-lineage-wrong-key"
        self.seed_representative(
            wrong_group_alert_id,
            group_id=wrong_group_id,
            group_key="wrong-stable-group",
        )
        self.seed_representative(
            wrong_key_alert_id,
            group_key="colliding-but-different-key",
        )
        conflicts = (
            ("missing-frozen-representative", "8"),
            (wrong_group_alert_id, "9"),
            (wrong_key_alert_id, "a"),
        )
        for representative_alert_id, dispatch_character in conflicts:
            with self.subTest(representative_alert_id=representative_alert_id):
                before = self.mutation_snapshot()
                rejected = self.post(
                    "/incidents/reanalyze",
                    {
                        "case_id": self.case_id,
                        "representative_alert_id": representative_alert_id,
                        "stable_group_id": self.group_id,
                        "stable_group_key": "synthetic-lineage-group",
                        "cohort_id": "newest-20-ir.invalid-rebind",
                        "dispatch_id": dispatch_character * 64,
                        "release_id": DEPLOYED_RELEASE,
                    },
                    expected_status=409,
                )
                self.assertFalse(rejected["ok"])
                self.assertEqual(self.mutation_snapshot(), before)


    def test_controlled_reanalysis_rejects_canonical_case_collision(
        self,
    ) -> None:
        legacy_group_id = "2f83e4cd0123456789ab"
        conflicting_case_id = "ir-canonical-conflict"
        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            connection.execute(
                """
                INSERT INTO alert_group_alias (
                  legacy_group_id, stable_group_id, stable_group_key, updated_at
                ) VALUES (?, ?, 'synthetic-lineage-group', ?)
                """,
                (legacy_group_id, self.group_id, self.generated_at()),
            )
            connection.execute(
                """
                INSERT INTO incident_response_cases (
                  case_id, group_id, dashboard_group_id,
                  representative_alert_id, status, agent_status,
                  escalated_at, updated_at, escalated_by, reason
                ) VALUES (?, ?, ?, ?, 'open', 'analyzed', ?, ?,
                          'unit-test', 'Canonical collision fixture')
                """,
                (
                    conflicting_case_id,
                    legacy_group_id,
                    self.dashboard_group_id,
                    self.alert_id,
                    self.generated_at(),
                    self.generated_at(),
                ),
            )
            connection.commit()
        before = self.mutation_snapshot()

        rejected = self.post(
            "/incidents/reanalyze",
            {
                "case_id": self.case_id,
                "representative_alert_id": self.alert_id,
                "stable_group_id": self.group_id,
                "stable_group_key": "synthetic-lineage-group",
                "cohort_id": "newest-20-ir.case-collision",
                "dispatch_id": "b" * 64,
                "release_id": DEPLOYED_RELEASE,
            },
            expected_status=409,
        )

        self.assertFalse(rejected["ok"])
        self.assertEqual(self.mutation_snapshot(), before)


    def test_controlled_reanalysis_rejects_processing_canonical_job_read_only(
        self,
    ) -> None:
        queued = self.post(
            "/incidents/reanalyze",
            {"case_id": self.case_id, "requested_by": "processing-fixture"},
            expected_status=202,
        )
        self.post(
            "/jobs/status",
            {
                "job_type": "incident_response_analysis",
                "dedupe_key": self.group_id,
                "status": "processing",
            },
        )
        before = self.mutation_snapshot()

        rejected = self.post(
            "/incidents/reanalyze",
            {
                "case_id": self.case_id,
                "representative_alert_id": self.alert_id,
                "stable_group_id": self.group_id,
                "stable_group_key": "synthetic-lineage-group",
                "cohort_id": "newest-20-ir.processing-canonical",
                "dispatch_id": "c" * 64,
                "release_id": DEPLOYED_RELEASE,
            },
            expected_status=409,
        )

        self.assertFalse(rejected["ok"])
        self.assertEqual(self.mutation_snapshot(), before)
        self.assertEqual(self.run_case(queued["run_id"])["status"], "running")


    def test_controlled_reanalysis_rejects_processing_legacy_job_read_only(
        self,
    ) -> None:
        legacy_group_id = "1f83e4cd0123456789ab"
        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            timestamp = self.generated_at()
            connection.execute(
                """
                INSERT INTO alert_group_alias (
                  legacy_group_id, stable_group_id, stable_group_key, updated_at
                ) VALUES (?, ?, 'synthetic-lineage-group', ?)
                """,
                (legacy_group_id, self.group_id, timestamp),
            )
            connection.execute(
                """
                UPDATE incident_response_cases SET group_id = ?
                WHERE case_id = ?
                """,
                (legacy_group_id, self.case_id),
            )
            connection.execute(
                """
                INSERT INTO durable_jobs (
                  job_type, dedupe_key, payload_json, status, priority,
                  attempt_count, max_attempts, next_attempt_at,
                  lease_expires_at, lease_token, processing_started_at,
                  created_at, updated_at, requested_at
                ) VALUES (
                  'incident_response_analysis', ?, ?, 'processing', 10,
                  1, 8, ?, '2099-01-01  00:00:00+00:00',
                  'legacy-processing-lease', ?, ?, ?, ?
                )
                """,
                (
                    legacy_group_id,
                    json.dumps(
                        {
                            "case_id": self.case_id,
                            "alert_id": self.alert_id,
                            "group_id": legacy_group_id,
                            "manual_reanalysis": False,
                        }
                    ),
                    timestamp,
                    timestamp,
                    timestamp,
                    timestamp,
                    timestamp,
                ),
            )
            connection.commit()
        before = self.mutation_snapshot()

        rejected = self.post(
            "/incidents/reanalyze",
            {
                "case_id": self.case_id,
                "representative_alert_id": self.alert_id,
                "stable_group_id": self.group_id,
                "stable_group_key": "synthetic-lineage-group",
                "cohort_id": "newest-20-ir.processing-legacy",
                "dispatch_id": "d" * 64,
                "release_id": DEPLOYED_RELEASE,
            },
            expected_status=409,
        )

        self.assertFalse(rejected["ok"])
        self.assertEqual(self.mutation_snapshot(), before)
        self.assertEqual(self.incident_case()["group_id"], legacy_group_id)


    def test_overlap_preserves_attempt_owner_and_result_lineage(self) -> None:
        first = self.post(
            "/incidents/reanalyze",
            {
                "case_id": self.case_id,
                "release_id": "spoofed-client-release",
                "requested_by": "lineage-test",
            },
            expected_status=202,
        )
        first_run = first["run_id"]
        self.assertEqual(first["release_id"], DEPLOYED_RELEASE)

        first_claim = self.post(
            "/jobs/status",
            {
                "job_type": "incident_response_analysis",
                "dedupe_key": self.group_id,
                "status": "processing",
            },
        )
        first_lease = first_claim["lease_token"]
        first_running = self.run_case(first_run)
        self.assertEqual(first_running["status"], "running")
        self.assertTrue(first_running["latest_attempt_id"])
        first_attempt_id = first_running["latest_attempt_id"]
        first_analysis_started_at = first_running["started_at"]

        second = self.post(
            "/incidents/reanalyze",
            {
                "case_id": self.case_id,
                "release_id": "another-spoofed-release",
                "requested_by": "lineage-test",
            },
            expected_status=202,
        )
        second_run = second["run_id"]
        self.assertEqual(second["release_id"], DEPLOYED_RELEASE)
        self.assertEqual(self.run_case(first_run)["status"], "running")
        self.assertEqual(self.run_case(second_run)["status"], "queued")

        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            payload_json, rerun_requested = connection.execute(
                """
                SELECT payload_json, rerun_requested FROM durable_jobs
                WHERE job_type = 'incident_response_analysis' AND dedupe_key = ?
                """,
                (self.group_id,),
            ).fetchone()
        self.assertEqual(json.loads(payload_json)["reanalysis_run_id"], second_run)
        self.assertEqual(rerun_requested, 1)

        rejected = self.post(
            "/analysis/result",
            self.analysis_payload(
                "lineage-spoofed-attempt",
                model="gpt-5.6-luna",
                model_path="frontier-codex-cli",
                reanalysis_attempt_id="ira-" + ("f" * 40),
                analysis_started_at=first_analysis_started_at,
                generated_at=self.generated_at(3),
            ),
            expected_status=409,
        )
        self.assertIn("does not match", rejected["reason"])
        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            spoofed = connection.execute(
                "SELECT 1 FROM ai_analysis_runs WHERE analysis_id = ?",
                ("lineage-spoofed-attempt",),
            ).fetchone()
        self.assertIsNone(spoofed)

        first_result = self.post(
            "/analysis/result",
            self.analysis_payload(
                "lineage-analysis-a",
                model="gpt-5.6-sol",
                model_path="frontier-codex-cli",
                reanalysis_attempt_id=first_attempt_id,
                analysis_started_at=first_analysis_started_at,
                generated_at=self.generated_at(5),
            ),
        )
        self.assertEqual(first_result["reanalysis_run_id"], first_run)
        self.assertFalse(first_result["reanalysis_authoritative"])
        first_completed = self.run_case(first_run)
        second_still_queued = self.run_case(second_run)
        self.assertEqual(first_completed["status"], "completed")
        self.assertEqual(first_completed["analysis_id"], "lineage-analysis-a")
        self.assertEqual(first_completed["executed_model"], "gpt-5.6-sol")
        self.assertEqual(first_completed["executed_provider"], "codex-cli")
        self.assertIsNone(second_still_queued["analysis_id"])
        self.assertEqual(second_still_queued["status"], "queued")
        queued_case = self.incident_case()
        self.assertEqual(queued_case["agent_status"], "queued")
        self.assertIsNone(queued_case["latest_analysis_id"])

        self.post(
            "/jobs/status",
            {
                "job_type": "incident_response_analysis",
                "dedupe_key": self.group_id,
                "status": "completed",
                "lease_token": first_lease,
            },
        )
        self.assertEqual(self.run_case(first_run)["status"], "completed")
        self.assertEqual(self.run_case(second_run)["status"], "queued")

        second_claim = self.post(
            "/jobs/status",
            {
                "job_type": "incident_response_analysis",
                "dedupe_key": self.group_id,
                "status": "processing",
            },
        )
        second_lease = second_claim["lease_token"]
        second_running = self.run_case(second_run)
        self.assertEqual(second_running["status"], "running")
        second_attempt_id = second_running["latest_attempt_id"]
        second_result = self.post(
            "/analysis/result",
            self.analysis_payload(
                "lineage-analysis-b",
                model="gemma4:31b",
                model_path="ollama",
                reanalysis_attempt_id=second_attempt_id,
                analysis_started_at=second_running["started_at"],
                generated_at=self.generated_at(10),
            ),
        )
        self.assertEqual(second_result["reanalysis_run_id"], second_run)
        self.post(
            "/jobs/status",
            {
                "job_type": "incident_response_analysis",
                "dedupe_key": self.group_id,
                "status": "completed",
                "lease_token": second_lease,
            },
        )

        first_final = self.run_case(first_run)
        second_final = self.run_case(second_run)
        self.assertEqual(first_final["analysis_id"], "lineage-analysis-a")
        self.assertEqual(first_final["executed_provider"], "codex-cli")
        self.assertEqual(second_final["analysis_id"], "lineage-analysis-b")
        self.assertEqual(second_final["executed_model"], "gemma4:31b")
        self.assertEqual(second_final["executed_provider"], "ollama")
        self.assertNotEqual(
            first_final["latest_attempt_id"],
            second_final["latest_attempt_id"],
        )

        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            attempts = connection.execute(
                """
                SELECT run_id, status, analysis_id, executed_model,
                       executed_provider
                FROM incident_reanalysis_attempts
                ORDER BY started_at ASC
                """
            ).fetchall()
            releases = connection.execute(
                """
                SELECT release_id FROM incident_reanalysis_runs
                WHERE run_id IN (?, ?) ORDER BY run_id
                """,
                (first_run, second_run),
            ).fetchall()
        self.assertEqual(
            {tuple(item) for item in attempts},
            {
                (
                    first_run,
                    "completed",
                    "lineage-analysis-a",
                    "gpt-5.6-sol",
                    "codex-cli",
                ),
                (
                    second_run,
                    "completed",
                    "lineage-analysis-b",
                    "gemma4:31b",
                    "ollama",
                ),
            },
        )
        self.assertEqual({item[0] for item in releases}, {DEPLOYED_RELEASE})
