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

class IncidentHarnessCohortTestsCaseAndRunIdentityGrammarsMatchRuntimeBoundsCases:
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


