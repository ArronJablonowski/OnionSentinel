from __future__ import annotations

from controlled_evaluation_runtime_fixtures import (
    ALERT_STORE,
    ALERT_STORE_DIR,
    BIN_DIR,
    BaseHTTPRequestHandler,
    CONTROLLED_CREDENTIAL_KEYS,
    CONTROLLED_ROUTE_FIELDS,
    DASHBOARD_SERVER,
    EVALUATION_TOKEN,
    INSTALLER_PATH,
    PIPELINE_ADAPTER_PATH,
    PRIMARY_ROUTE,
    Path,
    RELEASE_ID,
    REPLACEMENT_RELEASE_ID,
    REVIEWER_ROUTE,
    ROOT,
    RUNNER_PATH,
    SCHEDULER_PATH,
    SCORING_RULES,
    SimpleNamespace,
    ThreadingHTTPServer,
    available_port,
    closing,
    dt,
    hashlib,
    importlib,
    io,
    json,
    load_python_module,
    mock,
    os,
    process_output,
    raw_request_status,
    request_json,
    request_json_bytes,
    request_status,
    sanitized_environment,
    shutil,
    socket,
    sqlite3,
    startup_failure_diagnostic,
    stop_process,
    subprocess,
    sys,
    tempfile,
    threading,
    time,
    unittest,
    urllib,
    write_controlled_route_fixture,
)

class ControlledAlertStoreTestsUtf16TruncationConflictUsesFullTerminalDbProofCases:
    def test_utf16_truncation_conflict_uses_full_terminal_db_proof(
        self,
    ) -> None:
        frozen = {
            "group_id": "68686868686868686868",
            "alert_id": "controlled-alert-utf16-proof",
            "stable_group_key": "v2|controlled|utf16-proof",
            "dispatch_id": "6" * 63 + "8",
        }
        job_id = self.seed_controlled_job(**frozen)
        self.start_controlled()
        status, claim = self.claim_controlled_job(
            job_id=job_id,
            **frozen,
        )
        self.assertEqual(status, 200, claim)
        payload = self.controlled_result_payload(
            analysis_id="controlled-utf16-proof",
            claim=claim,
        )
        payload["response"]["summary"] = "s" * 7999 + "😀tail"
        payload["response"]["bluf"] = "b" * 3999 + "😀tail"
        evaluation_root = (
            self.runtime / "harness-evaluations" / "utf16-proof"
        )
        queue_dir = evaluation_root / "analysis-index-pending"
        queue_dir.mkdir(parents=True, mode=0o700)
        evaluation_root.chmod(0o700)
        queue_dir.chmod(0o700)
        spool_path = self.runner.queue_analysis_index(
            payload,
            queue_dir=queue_dir,
        )
        self.assertEqual(
            request_json(
                f"{self.base_url}/analysis/result",
                "POST",
                payload,
            )[0],
            200,
        )
        # safeString() split the emoji at both UTF-16 limits. node-sqlite3
        # stores U+FFFD, so an HTTP replay conflicts even though the original
        # transaction committed the exact response and terminal job.
        self.assertEqual(
            request_json(
                f"{self.base_url}/analysis/result",
                "POST",
                payload,
            )[0],
            409,
        )
        args = SimpleNamespace(
            db=self.db,
            alert_store_url=self.base_url,
            only_group_id=frozen["group_id"],
            only_alert_id=frozen["alert_id"],
            only_stable_group_key=frozen["stable_group_key"],
            only_dispatch_id=frozen["dispatch_id"],
        )
        with mock.patch.dict(
            os.environ,
            {
                "ONION_SENTINEL_EVALUATION_MODE": "1",
                "ONION_SENTINEL_EVALUATION_TOKEN": EVALUATION_TOKEN,
                "ONION_SENTINEL_RELEASE_ID": RELEASE_ID,
            },
            clear=False,
        ):
            self.assertTrue(
                self.scheduler.recover_controlled_evaluation_spool(
                    args,
                    evaluation_root,
                )
            )
        self.assertFalse(spool_path.exists())
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            summary, bluf = connection.execute(
                """
                SELECT summary, bluf FROM ai_analysis_runs
                WHERE analysis_id = 'controlled-utf16-proof'
                """
            ).fetchone()
        self.assertTrue(summary.endswith("\ufffd"))
        self.assertTrue(bluf.endswith("\ufffd"))


    def test_unicode_response_digest_matches_node_storage_canonicalization(
        self,
    ) -> None:
        frozen = {
            "group_id": "58585858585858585858",
            "alert_id": "controlled-alert-unicode-digest",
            "stable_group_key": "v2|controlled|café|🧅|東京",
            "dispatch_id": "5" * 63 + "8",
        }
        job_id = self.seed_controlled_job(**frozen)
        self.start_controlled()
        status, claim = self.claim_controlled_job(
            job_id=job_id,
            **frozen,
        )
        self.assertEqual(status, 200, claim)
        payload = self.controlled_result_payload(
            analysis_id="controlled-unicode-digest",
            claim=claim,
        )
        payload["response"]["summary"] = (
            "Café telemetry from 東京 contains 🧅 and é."
        )
        payload["response"]["unicode_nested"] = {
            "emoji": ["🧅", "😀"],
            "non_ascii": "naïve résumé",
            # This is not an ECMAScript array-index key: the second digit is
            # Arabic-Indic. It must retain UTF-16 lexical object-key ordering.
            "1٢": "unicode numeric-looking key",
            "10": "actual array-index key",
        }
        post_status, receipt = request_json(
            f"{self.base_url}/analysis/result",
            "POST",
            payload,
        )
        self.assertEqual(post_status, 200, receipt)
        args = SimpleNamespace(
            db=self.db,
            alert_store_url=self.base_url,
            only_group_id=frozen["group_id"],
            only_alert_id=frozen["alert_id"],
            only_stable_group_key=frozen["stable_group_key"],
            only_dispatch_id=frozen["dispatch_id"],
        )
        with mock.patch.dict(
            os.environ,
            {"ONION_SENTINEL_RELEASE_ID": RELEASE_ID},
            clear=False,
        ):
            recovery = self.scheduler.validate_controlled_recovery_payload(
                payload,
                args,
            )
        self.assertEqual(
            recovery["stored_response_fallback_digest"],
            receipt["stored_response_sha256"],
        )
        self.assertEqual(
            recovery["response_digest"],
            self.runner.canonical_payload_digest(payload["response"]),
        )
        self.assertNotEqual(
            recovery["response_digest"],
            recovery["stored_response_fallback_digest"],
        )
        self.assertTrue(
            self.scheduler.controlled_recovery_terminal_success(
                args,
                recovery,
            )
        )


    def test_timestamp_response_digest_matches_node_normalization(
        self,
    ) -> None:
        frozen = {
            "group_id": "59595959595959595959",
            "alert_id": "controlled-alert-timestamp-digest",
            "stable_group_key": "v2|controlled|timestamp-digest",
            "dispatch_id": "5" * 63 + "9",
        }
        job_id = self.seed_controlled_job(**frozen)
        self.start_controlled()
        status, claim = self.claim_controlled_job(
            job_id=job_id,
            **frozen,
        )
        self.assertEqual(status, 200, claim)
        payload = self.controlled_result_payload(
            analysis_id="controlled-timestamp-digest",
            claim=claim,
        )
        original_timestamp = "2026-07-24T18:30:45.987654Z"
        unicode_space_timestamp = (
            "2026-07-24\u00a0\u00a018:30:45.987654Z"
        )
        historical_timestamp = "0510-01-03 13:34:37.8399035-06:00"
        normalized_overflow_timestamp = "2024-02-30T00:00:00Z"
        year_zero_timestamp = "0000-01-01T00:00:00Z"
        lower_boundary_timestamp = "0001-01-01T00:00:00Z"
        upper_boundary_timestamp = "9999-12-31T23:59:59-1200"
        js_trim_timestamp = "\ufeff2026-07-24T18:30:45Z\ufeff"
        non_js_trim_timestamp = (
            "\u001c2026-07-24T18:30:45Z\u0085"
        )
        payload["response"]["observed_at"] = original_timestamp
        payload["response"]["timestamp_context"] = (
            f"  observed at {original_timestamp}  "
        )
        payload["response"]["unicode_space_timestamp"] = (
            unicode_space_timestamp
        )
        payload["response"]["historical_timestamp"] = historical_timestamp
        payload["response"]["normalized_overflow_timestamp"] = (
            normalized_overflow_timestamp
        )
        payload["response"]["year_zero_timestamp"] = year_zero_timestamp
        payload["response"]["lower_boundary_timestamp"] = (
            lower_boundary_timestamp
        )
        payload["response"]["upper_boundary_timestamp"] = (
            upper_boundary_timestamp
        )
        payload["response"]["js_trim_timestamp"] = js_trim_timestamp
        payload["response"]["non_js_trim_timestamp"] = (
            non_js_trim_timestamp
        )
        post_status, receipt = request_json(
            f"{self.base_url}/analysis/result",
            "POST",
            payload,
        )
        self.assertEqual(post_status, 200, receipt)
        args = SimpleNamespace(
            db=self.db,
            alert_store_url=self.base_url,
            only_group_id=frozen["group_id"],
            only_alert_id=frozen["alert_id"],
            only_stable_group_key=frozen["stable_group_key"],
            only_dispatch_id=frozen["dispatch_id"],
        )
        with mock.patch.dict(
            os.environ,
            {"ONION_SENTINEL_RELEASE_ID": RELEASE_ID},
            clear=False,
        ):
            recovery = self.scheduler.validate_controlled_recovery_payload(
                payload,
                args,
            )
        self.assertEqual(
            recovery["stored_response_fallback_digest"],
            receipt["stored_response_sha256"],
        )
        self.assertEqual(
            recovery["response_digest"],
            self.runner.canonical_payload_digest(payload["response"]),
        )
        self.assertNotEqual(
            recovery["response_digest"],
            recovery["stored_response_fallback_digest"],
        )
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            stored_response = json.loads(
                connection.execute(
                    """
                    SELECT response_json FROM ai_analysis_runs
                    WHERE analysis_id = 'controlled-timestamp-digest'
                    """
                ).fetchone()[0]
            )
        self.assertEqual(
            stored_response["observed_at"],
            self.scheduler.controlled_normalize_timestamp(
                original_timestamp
            ),
        )
        self.assertEqual(
            stored_response["unicode_space_timestamp"],
            self.scheduler.controlled_normalize_timestamp(
                unicode_space_timestamp
            ),
        )
        self.assertEqual(
            stored_response["historical_timestamp"],
            self.scheduler.controlled_normalize_timestamp(
                historical_timestamp
            ),
        )
        self.assertEqual(
            stored_response["normalized_overflow_timestamp"],
            self.scheduler.controlled_normalize_timestamp(
                normalized_overflow_timestamp
            ),
        )
        self.assertEqual(
            stored_response["year_zero_timestamp"],
            self.scheduler.controlled_normalize_timestamp(
                year_zero_timestamp
            ),
        )
        for field, timestamp in (
            ("lower_boundary_timestamp", lower_boundary_timestamp),
            ("upper_boundary_timestamp", upper_boundary_timestamp),
            ("js_trim_timestamp", js_trim_timestamp),
            ("non_js_trim_timestamp", non_js_trim_timestamp),
        ):
            with self.subTest(field=field):
                self.assertEqual(
                    stored_response[field],
                    self.scheduler.controlled_normalize_timestamp(timestamp),
                )
        self.assertTrue(
            self.scheduler.controlled_recovery_terminal_success(
                args,
                recovery,
            )
        )


    def test_terminal_db_proof_rejects_full_response_content_mismatch(
        self,
    ) -> None:
        frozen = {
            "group_id": "56565656565656565656",
            "alert_id": "controlled-alert-terminal-digest",
            "stable_group_key": "v2|controlled|terminal-digest",
            "dispatch_id": "5" * 63 + "6",
        }
        job_id = self.seed_controlled_job(**frozen)
        self.start_controlled()
        status, claim = self.claim_controlled_job(
            job_id=job_id,
            **frozen,
        )
        self.assertEqual(status, 200, claim)
        payload = self.controlled_result_payload(
            analysis_id="controlled-terminal-digest",
            claim=claim,
        )
        self.assertEqual(
            request_json(
                f"{self.base_url}/analysis/result",
                "POST",
                payload,
            )[0],
            200,
        )
        args = SimpleNamespace(
            db=self.db,
            alert_store_url=self.base_url,
            only_group_id=frozen["group_id"],
            only_alert_id=frozen["alert_id"],
            only_stable_group_key=frozen["stable_group_key"],
            only_dispatch_id=frozen["dispatch_id"],
        )
        with mock.patch.dict(
            os.environ,
            {"ONION_SENTINEL_RELEASE_ID": RELEASE_ID},
            clear=False,
        ):
            recovery = self.scheduler.validate_controlled_recovery_payload(
                payload,
                args,
            )
            self.assertTrue(
                self.scheduler.controlled_recovery_terminal_success(
                    args,
                    recovery,
                )
            )
            with closing(sqlite3.connect(self.db, timeout=5)) as connection:
                stored = json.loads(
                    connection.execute(
                        """
                        SELECT response_json FROM ai_analysis_runs
                        WHERE analysis_id = 'controlled-terminal-digest'
                        """
                    ).fetchone()[0]
                )
                stored["summary"] = "Tampered after terminal commit."
                connection.execute(
                    """
                    UPDATE ai_analysis_runs SET response_json = ?
                    WHERE analysis_id = 'controlled-terminal-digest'
                    """,
                    (
                        json.dumps(
                            stored,
                            separators=(",", ":"),
                        ),
                    ),
                )
                connection.commit()
            self.assertFalse(
                self.scheduler.controlled_recovery_terminal_success(
                    args,
                    recovery,
                )
            )
