from __future__ import annotations

from onion_sentinel_harness_fixtures import (
    HARNESS,
    MODULE_PATH,
    Path,
    ROOT,
    SPEC,
    contextlib,
    dataclasses,
    gc,
    importlib,
    inspect,
    json,
    mock,
    os,
    sqlite3,
    stat,
    subprocess,
    sys,
    tempfile,
    threading,
    unittest,
    warnings,
)

class OnionSentinelHarnessTestsSqliteStoreIsOwnerOnlyCases:
    def test_sqlite_store_is_owner_only(self) -> None:
        store = HARNESS.HarnessStore(self.db_path)
        self.assertEqual(
            stat.S_IMODE(os.stat(store.path).st_mode),
            stat.S_IRUSR | stat.S_IWUSR,
        )


    def test_sqlite_connections_close_without_resource_warnings(self) -> None:
        run = self.make_run("connection-close-run")
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", ResourceWarning)
            for _ in range(10):
                run.store.snapshot(run.run_id)
                run.store.verify_chain(run.run_id)
                run.store.export_trace(run.run_id)
            gc.collect()
        resource_warnings = [
            warning
            for warning in caught
            if issubclass(warning.category, ResourceWarning)
        ]
        self.assertEqual(resource_warnings, [])


    def test_sqlite_database_and_active_wal_sidecars_are_owner_only(self) -> None:
        store = HARNESS.HarnessStore(self.db_path)
        wal_path = Path(f"{self.db_path}-wal")
        shm_path = Path(f"{self.db_path}-shm")
        with HARNESS._connect(store.path) as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS sidecar_mode_probe(value INTEGER)"
            )
            connection.execute(
                "INSERT INTO sidecar_mode_probe(value) VALUES(1)"
            )
            present = [
                path
                for path in (store.path, wal_path, shm_path)
                if path.exists()
            ]
            self.assertIn(store.path, present)
            self.assertTrue(wal_path.exists() or shm_path.exists())
            for path in present:
                self.assertEqual(
                    stat.S_IMODE(os.stat(path).st_mode),
                    stat.S_IRUSR | stat.S_IWUSR,
                    path.name,
                )

        for path in (store.path, wal_path, shm_path):
            if path.exists():
                self.assertEqual(
                    stat.S_IMODE(os.stat(path).st_mode),
                    stat.S_IRUSR | stat.S_IWUSR,
                    path.name,
                )


    def test_sqlite_security_tolerates_sidecar_disappearing_before_chmod(self) -> None:
        self.db_path.parent.mkdir(parents=True)
        self.db_path.touch()
        wal_path = Path(f"{self.db_path}-wal")
        wal_path.touch()
        real_chmod = os.chmod

        def racing_chmod(path, mode):
            if Path(path) == wal_path:
                wal_path.unlink()
                raise FileNotFoundError(2, "sidecar closed concurrently", str(path))
            return real_chmod(path, mode)

        with mock.patch.object(HARNESS.os, "chmod", side_effect=racing_chmod):
            HARNESS._secure_sqlite_files(self.db_path)

        self.assertEqual(stat.S_IMODE(self.db_path.stat().st_mode), 0o600)
        self.assertFalse(wal_path.exists())


    def test_sqlite_security_does_not_hide_database_disappearance(self) -> None:
        self.db_path.parent.mkdir(parents=True)
        self.db_path.touch()
        with (
            mock.patch.object(
                HARNESS.os,
                "chmod",
                side_effect=FileNotFoundError(
                    2,
                    "database disappeared",
                    str(self.db_path),
                ),
            ),
            self.assertRaises(FileNotFoundError),
        ):
            HARNESS._secure_sqlite_files(self.db_path)


    def test_full_lifecycle_exports_a_complete_secret_safe_trace(self) -> None:
        self.write_policy(enabled=True)
        run = HARNESS.start_harness_run(
            run_id="lifecycle-run",
            source_revision="1" * 40,
            prompt_package=self.prompt_package(),
            role=HARNESS.AgentRole.SOC_ANALYST.value,
            assigned_route="codex-cli:gpt-5.6-sol:high",
            configuration={"query_mode": "read-only"},
            policy_path=self.policy_path,
            db_path=self.db_path,
        )
        self.assertIsNotNone(run)
        assert run is not None

        run.phase(
            "primary_analysis",
            route="codex-cli:gpt-5.6-sol:high",
            reason="primary investigation",
        )
        response = self.response()
        run.preflight_model_call(
            call_id="primary-1",
            input_value={
                "prompt": "sensitive prompt body",
                "api_token": "must-not-be-exported",
            },
            requested_route=run.envelope.assigned_route,
            purpose="primary investigation",
        )
        run.model_call(
            call_id="primary-1",
            purpose="primary investigation",
            requested_route="codex-cli:gpt-5.6-sol:high",
            response=response,
            input_value={
                "prompt": "sensitive prompt body",
                "api_token": "must-not-be-exported",
            },
            duration_seconds=1.234,
        )
        query_digest = "a" * 64
        result_digest = "b" * 64
        run.query_round(
            {
                "round": 1,
                "requests": [
                    {
                        "query_id": "q-1",
                        "backend": "elastic",
                        "purpose": "Corroborate the alert against network events.",
                        "query": {"query": {"term": {"network.community_id": "1:test"}}},
                    }
                ],
                "results": [
                    {
                        "query_id": "q-1",
                        "backend": "elastic",
                        "status": "ok",
                        "read_only": True,
                        "evidence": {
                            "coverage": "bounded-time-window",
                            "returned_rows": 2,
                            "truncated": False,
                        },
                        "trusted_query_audit": [
                            {
                                "query_id": "q-1",
                                "query_digest": query_digest,
                                "result_digest": result_digest,
                                "evidence_ref": "query:elastic:q-1",
                                "status": "ok",
                                "returned_rows": 2,
                                "truncated": False,
                            }
                        ],
                    }
                ],
            }
        )
        run.record_response(
            response,
            decision_id="primary-decision",
            decision_type="alert-triage",
            hypothesis_revision=1,
        )
        run.store.append_event(
            run.run_id,
            "security.redaction-check",
            HARNESS.Stage.POST_PROCESSING.value,
            {
                "api_token": "literal-secret-must-not-appear",
                "note": (
                    "Bearer abcdefghijklmnopqrstuvwxyz0123456789 "
                    "must be redacted"
                ),
            },
            idempotency_key="security.redaction-check",
        )
        run.complete(
            {
                "artifact_digest": "c" * 64,
                "password": "literal-summary-secret",
            }
        )

        snapshot = run.store.snapshot(run.run_id)
        self.assertEqual(snapshot["status"], HARNESS.RunStatus.SUCCEEDED.value)
        self.assertEqual(snapshot["stage"], HARNESS.Stage.COMPLETE.value)
        self.assertEqual(snapshot["counts"]["evidence"], 3)
        self.assertEqual(snapshot["counts"]["hypotheses"], 2)
        self.assertEqual(snapshot["counts"]["decisions"], 1)
        self.assertEqual(snapshot["counts"]["model_calls"], 1)
        self.assertEqual(snapshot["counts"]["tool_calls"], 1)

        trace = run.store.export_trace(run.run_id)
        self.assertEqual(trace["schema"], HARNESS.TRACE_SCHEMA)
        self.assertTrue(trace["integrity"]["valid"])
        self.assertEqual(trace["model_calls"][0]["observed_model"], "gpt-5.6-sol")
        self.assertEqual(trace["model_calls"][0]["duration_ms"], 1234)
        self.assertEqual(trace["tool_calls"][0]["capability"], "security-onion.events.query")
        self.assertEqual(trace["tool_calls"][0]["coverage"], "bounded-time-window")
        decision_payload = json.loads(trace["decisions"][0]["payload_json"])
        self.assertEqual(
            decision_payload["response_digest"],
            HARNESS.digest_json(response),
        )
        decision_event = next(
            event
            for event in trace["events"]
            if event["event_type"] == "decision.recorded"
        )
        self.assertEqual(
            json.loads(decision_event["payload_json"])["response_digest"],
            HARNESS.digest_json(response),
        )
        hypothesis_status = {
            item["hypothesis_id"]: item["status"]
            for item in trace["hypotheses"]
        }
        self.assertEqual(hypothesis_status["supported-hypothesis"], "supported")
        self.assertEqual(hypothesis_status["unsupported-hypothesis"], "unresolved")

        serialized_trace = json.dumps(trace, sort_keys=True)
        self.assertNotIn("never-persist-this-sensitive-value", serialized_trace)
        self.assertNotIn("sensitive prompt body", serialized_trace)
        self.assertNotIn("must-not-be-exported", serialized_trace)
        self.assertNotIn("literal-secret-must-not-appear", serialized_trace)
        self.assertNotIn("literal-summary-secret", serialized_trace)
        self.assertIn("[redacted-sensitive-field]", serialized_trace)
        self.assertIn("[redacted-sensitive-value]", serialized_trace)


    def test_hash_chain_detects_payload_tampering(self) -> None:
        run = self.make_run("tamper-run")
        run.phase("primary_analysis", reason="before tamper")
        self.assertTrue(run.store.verify_chain(run.run_id)["valid"])

        with HARNESS._connect(self.db_path) as connection:
            connection.execute(
                """
                UPDATE harness_events
                SET payload_json = '{"tampered":true}'
                WHERE run_id = ? AND sequence = 2
                """,
                (run.run_id,),
            )
        verification = run.store.verify_chain(run.run_id)
        self.assertFalse(verification["valid"])
        self.assertTrue(
            any("payload digest mismatch" in item for item in verification["errors"])
        )


    def test_terminal_ledger_manifest_detects_direct_ledger_tampering(self) -> None:
        run = self.make_run("terminal-ledger-tamper")
        run.catalogue_prompt_evidence(self.prompt_package())
        run.complete()

        verification = run.store.verify_chain(run.run_id)
        self.assertTrue(verification["valid"])
        self.assertTrue(verification["ledger_manifest_bound"])

        with HARNESS._connect(self.db_path) as connection:
            connection.execute(
                """
                UPDATE harness_evidence
                SET status = 'tampered-after-completion'
                WHERE run_id = ? AND evidence_ref = 'alert:42'
                """,
                (run.run_id,),
            )

        verification = run.store.verify_chain(run.run_id)
        self.assertFalse(verification["valid"])
        self.assertTrue(verification["ledger_manifest_bound"])
        self.assertIn(
            "terminal ledger manifest mismatch",
            verification["errors"],
        )


    def test_current_terminal_manifest_is_v3_and_required(self) -> None:
        run = self.make_run("terminal-manifest-v3")
        run.complete()

        verification = run.store.verify_chain(run.run_id)
        self.assertTrue(verification["valid"])
        self.assertEqual(
            verification["ledger_manifest_schema"],
            HARNESS.LEDGER_MANIFEST_SCHEMA,
        )
        self.assertEqual(
            HARNESS.LEDGER_MANIFEST_SCHEMA,
            "onion-sentinel-harness-ledger-manifest-v3",
        )

        self.replace_terminal_manifest(run, None)
        verification = run.store.verify_chain(run.run_id)
        self.assertFalse(verification["valid"])
        self.assertFalse(verification["ledger_manifest_bound"])
        self.assertIn(
            "terminal ledger manifest is missing or malformed",
            verification["errors"],
        )


    def test_legacy_v1_terminal_manifest_survives_v5_projection(self) -> None:
        run = self.make_run("terminal-manifest-v1")
        run.complete()
        with HARNESS._connect(run.store.path) as connection:
            legacy_manifest = HARNESS.ledger_manifest(
                connection,
                run.run_id,
                schema=HARNESS.LEDGER_MANIFEST_SCHEMA_V1,
            )
        self.replace_terminal_manifest(run, legacy_manifest)
        verification = run.store.verify_chain(run.run_id)
        self.assertFalse(verification["valid"])
        self.assertIn(
            "terminal ledger manifest schema downgrade",
            verification["errors"],
        )

        self.replace_terminal_manifest(
            run,
            legacy_manifest,
            legacy_identity=True,
        )

        verification = run.store.verify_chain(run.run_id)
        self.assertTrue(verification["valid"])
        self.assertTrue(verification["ledger_manifest_bound"])
        self.assertEqual(
            verification["ledger_manifest_schema"],
            HARNESS.LEDGER_MANIFEST_SCHEMA_V1,
        )


    def test_terminal_run_rejects_events_and_evidence_without_state_drift(
        self,
    ) -> None:
        run = self.make_run("terminal-immutable-run")
        run.complete()
        before = run.store.snapshot(run.run_id)

        with self.assertRaisesRegex(
            HARNESS.HarnessIntegrityError,
            "terminal harness run is immutable",
        ):
            run.store.append_event(
                run.run_id,
                "late.event",
                HARNESS.Stage.POST_PROCESSING.value,
                {"should": "not persist"},
                idempotency_key="late.event",
            )
        with self.assertRaisesRegex(
            HARNESS.HarnessIntegrityError,
            "terminal harness run is immutable",
        ):
            run.store.register_evidence(
                run.run_id,
                evidence_ref="late:evidence",
                source="test",
                source_class="test",
                trust_tier=HARNESS.TrustTier.READ_ONLY_BACKEND.value,
                corroborating=False,
                status="late",
            )

        after = run.store.snapshot(run.run_id)
        self.assertEqual(after["status"], HARNESS.RunStatus.SUCCEEDED.value)
        self.assertEqual(after["stage"], HARNESS.Stage.COMPLETE.value)
        self.assertEqual(after["counts"]["events"], before["counts"]["events"])
        self.assertEqual(after["counts"]["evidence"], before["counts"]["evidence"])
        verification = run.store.verify_chain(run.run_id)
        self.assertTrue(verification["valid"])
        self.assertTrue(verification["ledger_manifest_bound"])


    def test_event_idempotency_is_replay_safe_and_rejects_collision(self) -> None:
        run = self.make_run("idempotency-run")
        first = run.store.append_event(
            run.run_id,
            "test.event",
            HARNESS.Stage.POST_PROCESSING.value,
            {"value": 1},
            idempotency_key="stable-key",
        )
        replay = run.store.append_event(
            run.run_id,
            "test.event",
            HARNESS.Stage.POST_PROCESSING.value,
            {"value": 1},
            idempotency_key="stable-key",
        )
        self.assertEqual(first["event_id"], replay["event_id"])
        self.assertEqual(run.store.snapshot(run.run_id)["counts"]["events"], 2)

        with self.assertRaisesRegex(
            HARNESS.HarnessIntegrityError,
            "idempotency key was reused",
        ):
            run.store.append_event(
                run.run_id,
                "test.event",
                HARNESS.Stage.POST_PROCESSING.value,
                {"value": 2},
                idempotency_key="stable-key",
            )


    def test_evidence_references_are_immutable(self) -> None:
        run = self.make_run("evidence-run")
        kwargs = {
            "evidence_ref": "elastic:event-1",
            "source": "elastic",
            "source_class": "security_onion_event",
            "trust_tier": HARNESS.TrustTier.READ_ONLY_BACKEND.value,
            "corroborating": True,
            "status": "ok",
            "evidence_digest": "d" * 64,
            "metadata": {"returned_rows": 1},
        }
        run.store.register_evidence(run.run_id, **kwargs)
        run.store.register_evidence(run.run_id, **kwargs)
        self.assertEqual(run.store.snapshot(run.run_id)["counts"]["evidence"], 1)

        with self.assertRaisesRegex(
            HARNESS.HarnessIntegrityError,
            "immutable evidence reference collides",
        ):
            run.store.register_evidence(
                run.run_id,
                **{**kwargs, "evidence_digest": "e" * 64},
            )


    def test_model_and_tool_call_ids_are_immutable(self) -> None:
        run = self.make_run("call-collision-run")
        response = self.response()
        model_kwargs = {
            "call_id": "model-1",
            "purpose": "triage",
            "requested_route": "codex-cli:gpt-5.6-sol:high",
            "response": response,
            "independent_review": False,
            "input_digest": "f" * 64,
            "duration_ms": 100,
        }
        run.store.record_model_call(run.run_id, **model_kwargs)
        run.store.record_model_call(
            run.run_id,
            **{**model_kwargs, "duration_ms": 999},
        )
        with self.assertRaisesRegex(
            HARNESS.HarnessIntegrityError,
            "model call_id collides",
        ):
            run.store.record_model_call(
                run.run_id,
                **{
                    **model_kwargs,
                    "response": {**response, "confidence_score": 0.01},
                },
            )

        tool_kwargs = {
            "call_id": "tool-1",
            "round_number": 1,
            "backend": "elastic",
            "capability": "security-onion.events.query",
            "purpose": "corroborate",
            "request_digest": "1" * 64,
            "result_digest": "2" * 64,
            "status": "ok",
            "read_only": True,
            "coverage": "bounded",
            "truncated": False,
        }
        run.store.record_tool_call(run.run_id, **tool_kwargs)
        run.store.record_tool_call(run.run_id, **tool_kwargs)
        with self.assertRaisesRegex(
            HARNESS.HarnessIntegrityError,
            "tool call_id collides",
        ):
            run.store.record_tool_call(
                run.run_id,
                **{**tool_kwargs, "result_digest": "3" * 64},
            )


    def test_query_budgets_audit_in_shadow_and_block_in_enforce(self) -> None:
        constrained = {"max_queries_total": 1, "max_queries_per_round": 1}
        shadow_policy = HARNESS.HarnessPolicy.from_dict(
            self.policy_document(mode="shadow", budgets=constrained)
        )
        shadow = self.make_run(
            "shadow-budget-run",
            policy=shadow_policy,
            db_path=self.root / "shadow.sqlite3",
        )
        over_budget_round = {
            "round": 1,
            "requests": [
                {"query_id": "q-1", "backend": "elastic", "purpose": "first"},
                {"query_id": "q-2", "backend": "oql", "purpose": "second"},
            ],
            "results": [],
        }
        shadow.query_round(over_budget_round)
        trace = shadow.store.export_trace(shadow.run_id)
        query_event = next(
            event
            for event in trace["events"]
            if event["event_type"] == "queries.completed"
        )
        self.assertEqual(
            set(query_event["payload"]["budget_violations"]),
            {"max_queries_total", "max_queries_per_round"},
        )
        self.assertEqual(trace["integrity"]["valid"], True)

        enforce_policy = dataclasses.replace(shadow_policy, mode="enforce")
        enforce = self.make_run(
            "enforce-budget-run",
            policy=enforce_policy,
            db_path=self.root / "enforce.sqlite3",
        )
        with self.assertRaisesRegex(
            HARNESS.HarnessPolicyError,
            "exceeds harness budget",
        ):
            enforce.query_round(over_budget_round)
        enforced_trace = enforce.store.export_trace(enforce.run_id)
        self.assertTrue(
            any(
                event["event_type"] == "policy.budget"
                for event in enforced_trace["events"]
            )
        )
        self.assertFalse(
            any(
                event["event_type"] == "queries.completed"
                for event in enforced_trace["events"]
            )
        )
        self.assertTrue(enforced_trace["integrity"]["valid"])


    def test_concurrent_model_preflight_allows_exactly_one_reservation(self) -> None:
        policy = HARNESS.HarnessPolicy.from_dict(
            self.policy_document(
                mode="enforce",
                budgets={"max_model_calls": 1},
            )
        )
        first = self.make_run("concurrent-model-budget", policy=policy)
        second = HARNESS.HarnessRun(
            HARNESS.HarnessStore(self.db_path),
            first.envelope,
            policy,
        )
        barrier = threading.Barrier(3)
        outcome_lock = threading.Lock()
        outcomes: list[tuple[str, str, object]] = []

        def reserve(run, call_id: str) -> None:
            try:
                barrier.wait(timeout=10)
                run.preflight_model_call(
                    call_id=call_id,
                    input_value={"context": "small"},
                    requested_route=run.envelope.assigned_route,
                    purpose="concurrent budget test",
                )
            except Exception as exc:  # captured for deterministic main-thread assertions
                outcome = ("error", call_id, exc)
            else:
                outcome = ("reserved", call_id, None)
            with outcome_lock:
                outcomes.append(outcome)

        workers = [
            threading.Thread(target=reserve, args=(first, "parallel-a")),
            threading.Thread(target=reserve, args=(second, "parallel-b")),
        ]
        for worker in workers:
            worker.start()
        barrier.wait(timeout=10)
        for worker in workers:
            worker.join(timeout=20)
            self.assertFalse(worker.is_alive(), "model reservation worker hung")

        self.assertEqual(len(outcomes), 2)
        reserved = [item for item in outcomes if item[0] == "reserved"]
        rejected = [item for item in outcomes if item[0] == "error"]
        self.assertEqual(len(reserved), 1)
        self.assertEqual(len(rejected), 1)
        self.assertIsInstance(rejected[0][2], HARNESS.HarnessPolicyError)
        self.assertIn("max_model_calls", str(rejected[0][2]))

        with HARNESS._connect(self.db_path) as connection:
            reservations = connection.execute(
                """
                SELECT reservation_id
                FROM harness_budget_reservations
                WHERE run_id = ? AND reservation_type = 'model-call'
                """,
                (first.run_id,),
            ).fetchall()
        self.assertEqual([row["reservation_id"] for row in reservations], [reserved[0][1]])
        self.assertTrue(first.store.verify_chain(first.run_id)["valid"])
