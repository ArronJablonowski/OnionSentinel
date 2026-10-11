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

class OnionSentinelHarnessTestsModelPreflightBindsPrimaryAndReviewerRoutesCases:
    def test_model_preflight_binds_primary_and_reviewer_routes(self) -> None:
        enforce_policy = HARNESS.HarnessPolicy.from_dict(
            self.policy_document(mode="enforce")
        )
        primary = self.make_run(
            "primary-route-binding",
            policy=enforce_policy,
        )
        with self.assertRaisesRegex(
            HARNESS.HarnessPolicyError,
            "does not match",
        ):
            primary.preflight_model_call(
                call_id="primary-wrong-route",
                input_value={"context": "small"},
                requested_route="ollama:unexpected-model",
                purpose="initial primary analysis",
            )
        primary_trace = primary.store.export_trace(primary.run_id)
        route_events = [
            event
            for event in primary_trace["events"]
            if event["event_type"] == "policy.model-route"
        ]
        self.assertEqual(len(route_events), 1)
        self.assertFalse(
            json.loads(route_events[0]["payload_json"])["allowed"]
        )
        self.assertEqual(primary_trace["budget_reservations"], [])

        reviewer = self.make_run(
            "reviewer-route-binding",
            policy=enforce_policy,
            db_path=self.root / "reviewer-route-binding.sqlite3",
        )
        reviewer.preflight_model_call(
            call_id="reviewer-assigned-route",
            input_value={"context": "small"},
            requested_route=reviewer.envelope.assigned_reviewer_route,
            purpose="independent second-opinion review",
            independent_review=True,
        )
        reviewer_trace = reviewer.store.export_trace(reviewer.run_id)
        reviewer_route_event = next(
            event
            for event in reviewer_trace["events"]
            if event["event_type"] == "policy.model-route"
        )
        reviewer_payload = json.loads(
            reviewer_route_event["payload_json"]
        )
        self.assertTrue(reviewer_payload["allowed"])
        self.assertEqual(
            reviewer_payload["expected_route"],
            reviewer.envelope.assigned_reviewer_route,
        )
        self.assertTrue(reviewer_payload["independent_review"])

        observed_mismatch = self.make_run(
            "observed-route-mismatch",
            policy=enforce_policy,
            db_path=self.root / "observed-route-mismatch.sqlite3",
        )
        observed_mismatch.preflight_model_call(
            call_id="observed-wrong-route",
            input_value={"context": "small"},
            requested_route=observed_mismatch.envelope.assigned_route,
            purpose="observed route test",
        )
        mismatched_response = self.response()
        mismatched_response["_analysis_model_route"] = "ollama:gemma4:31b"
        with self.assertRaisesRegex(
            HARNESS.HarnessPolicyError,
            "observed route differs",
        ):
            observed_mismatch.model_call(
                call_id="observed-wrong-route",
                purpose="observed route test",
                requested_route=observed_mismatch.envelope.assigned_route,
                response=mismatched_response,
                input_value={"context": "small"},
                duration_seconds=0.01,
            )
        mismatch_trace = observed_mismatch.store.export_trace(
            observed_mismatch.run_id
        )
        self.assertEqual(mismatch_trace["model_calls"], [])
        self.assertFalse(
            json.loads(
                next(
                    event["payload_json"]
                    for event in mismatch_trace["events"]
                    if event["event_type"] == "policy.model-observation"
                )
            )["allowed"]
        )

        missing_preflight = self.make_run(
            "missing-model-preflight",
            policy=enforce_policy,
            db_path=self.root / "missing-model-preflight.sqlite3",
        )
        with self.assertRaisesRegex(
            HARNESS.HarnessPolicyError,
            "no matching allowed preflight",
        ):
            missing_preflight.model_call(
                call_id="not-preflighted",
                purpose="must be rejected",
                requested_route=missing_preflight.envelope.assigned_route,
                response=self.response(),
                input_value={"context": "small"},
                duration_seconds=0.01,
            )

        shadow_policy = HARNESS.HarnessPolicy.from_dict(
            self.policy_document(mode="shadow")
        )
        shadow = self.make_run(
            "shadow-route-mismatch",
            policy=shadow_policy,
            db_path=self.root / "shadow-route-mismatch.sqlite3",
        )
        shadow.preflight_model_call(
            call_id="shadow-mismatch",
            input_value={"context": "small"},
            requested_route="ollama:unexpected-model",
            purpose="shadow route audit",
        )
        shadow_trace = shadow.store.export_trace(shadow.run_id)
        self.assertEqual(len(shadow_trace["budget_reservations"]), 1)
        self.assertFalse(
            json.loads(
                next(
                    event["payload_json"]
                    for event in shadow_trace["events"]
                    if event["event_type"] == "policy.model-route"
                )
            )["allowed"]
        )


    def test_model_count_prompt_bytes_and_evidence_rows_shadow_and_enforce(
        self,
    ) -> None:
        cases = {
            "max_model_calls": {
                "budgets": {"max_model_calls": 1},
                "input": {"context": "small"},
                "prepare_existing_call": True,
            },
            "max_prompt_evidence_bytes": {
                "budgets": {"max_prompt_evidence_bytes": 4_096},
                "input": {"context": "x" * 8_192},
                "prepare_existing_call": False,
            },
            "max_prompt_evidence_rows": {
                "budgets": {"max_prompt_evidence_rows": 1},
                "input": {"rows": [{"event": 1}, {"event": 2}]},
                "prepare_existing_call": False,
            },
        }
        for violation, case in cases.items():
            for mode in ("shadow", "enforce"):
                with self.subTest(violation=violation, mode=mode):
                    policy = HARNESS.HarnessPolicy.from_dict(
                        self.policy_document(
                            mode=mode,
                            budgets=case["budgets"],
                        )
                    )
                    run = self.make_run(
                        f"{violation}-{mode}",
                        policy=policy,
                        db_path=self.root / f"{violation}-{mode}.sqlite3",
                    )
                    if case["prepare_existing_call"]:
                        run.preflight_model_call(
                            call_id="existing-model-call",
                            input_value={"context": "first"},
                            requested_route=run.envelope.assigned_route,
                            purpose="establish model-call usage",
                        )
                        run.model_call(
                            call_id="existing-model-call",
                            purpose="establish model-call usage",
                            requested_route="codex-cli:gpt-5.6-sol:high",
                            response=self.response(),
                            input_value={"context": "first"},
                            duration_seconds=0.01,
                        )

                    operation = lambda: run.preflight_model_call(
                        call_id=f"next-{violation}",
                        input_value=case["input"],
                        requested_route=run.envelope.assigned_route,
                        purpose=f"{violation} budget test",
                    )
                    if mode == "enforce":
                        with self.assertRaisesRegex(
                            HARNESS.HarnessPolicyError,
                            violation,
                        ):
                            operation()
                    else:
                        operation()

                    events = self.budget_events(run)
                    matching_events = [
                        event
                        for event in events
                        if violation in event["payload"]["violations"]
                    ]
                    self.assertEqual(len(matching_events), 1)
                    self.assertIn(
                        violation,
                        matching_events[0]["payload"]["violations"],
                    )
                    self.assertEqual(
                        matching_events[0]["payload"]["policy_mode"],
                        mode,
                    )
                    self.assertTrue(run.store.verify_chain(run.run_id)["valid"])


    def test_runtime_budget_is_audited_in_shadow_and_blocks_enforcement(
        self,
    ) -> None:
        for mode in ("shadow", "enforce"):
            with self.subTest(mode=mode):
                policy = HARNESS.HarnessPolicy.from_dict(
                    self.policy_document(
                        mode=mode,
                        budgets={"max_run_seconds": 1},
                    )
                )
                run = self.make_run(
                    f"runtime-{mode}",
                    policy=policy,
                    db_path=self.root / f"runtime-{mode}.sqlite3",
                )
                self.age_run(run)

                preflight = lambda: run.preflight_model_call(
                    call_id="runtime-preflight",
                    input_value={"context": "small"},
                    requested_route=run.envelope.assigned_route,
                    purpose="runtime budget test",
                )
                if mode == "enforce":
                    with self.assertRaisesRegex(
                        HARNESS.HarnessPolicyError,
                        "max_run_seconds",
                    ):
                        preflight()
                    with self.assertRaisesRegex(
                        HARNESS.HarnessPolicyError,
                        "max_run_seconds",
                    ):
                        run.complete({"test": "must remain running"})
                    self.assertEqual(
                        run.store.snapshot(run.run_id)["status"],
                        HARNESS.RunStatus.RUNNING.value,
                    )
                else:
                    preflight()
                    run.complete({"test": "shadow records but permits"})
                    self.assertEqual(
                        run.store.snapshot(run.run_id)["status"],
                        HARNESS.RunStatus.SUCCEEDED.value,
                    )

                events = self.budget_events(run)
                self.assertEqual(len(events), 2)
                self.assertTrue(
                    all(
                        "max_run_seconds" in event["payload"]["violations"]
                        for event in events
                    )
                )
                operations = {
                    event["payload"]["operation"]
                    for event in events
                }
                self.assertEqual(
                    operations,
                    {"model call", "run completion"},
                )
                self.assertTrue(run.store.verify_chain(run.run_id)["valid"])


    def test_tool_authorization_is_role_scoped_and_default_deny(self) -> None:
        policy = HARNESS.HarnessPolicy.from_dict(self.policy_document())
        soc = self.make_run(
            "soc-tool-policy",
            policy=policy,
            db_path=self.root / "soc-tool-policy.sqlite3",
        )
        elastic = soc.authorize_tool(
            round_number=1,
            query_id="elastic-allowed",
            backend="elastic",
        )
        self.assertTrue(elastic.allowed)
        self.assertFalse(elastic.requires_approval)

        live_osquery = soc.authorize_tool(
            round_number=1,
            query_id="osquery-unapproved",
            backend="osquery",
        )
        self.assertFalse(live_osquery.allowed)
        self.assertTrue(live_osquery.requires_approval)
        self.assertIn("human approval", live_osquery.reason)
        self.assertTrue(
            soc.authorize_tool(
                round_number=1,
                query_id="osquery-approved",
                backend="osquery",
                approved=True,
            ).allowed
        )

        unknown = soc.authorize_tool(
            round_number=1,
            query_id="unknown-default-deny",
            backend="shell",
            approved=True,
        )
        self.assertFalse(unknown.allowed)
        self.assertIn("not registered", unknown.reason)

        intel = self.make_run(
            "intel-tool-policy",
            policy=policy,
            db_path=self.root / "intel-tool-policy.sqlite3",
            role=HARNESS.AgentRole.CYBER_THREAT_INTEL.value,
        )
        role_denied = intel.authorize_tool(
            round_number=1,
            query_id="osquery-not-assigned",
            backend="osquery",
            approved=True,
        )
        self.assertFalse(role_denied.allowed)
        self.assertTrue(role_denied.requires_approval)
        self.assertIn("not assigned", role_denied.reason)

        authorization_events = [
            event
            for event in soc.store.export_trace(soc.run_id)["events"]
            if event["event_type"] == "policy.tool-authorization"
        ]
        self.assertEqual(len(authorization_events), 4)
        unapproved_payload = next(
            event["payload"]
            for event in authorization_events
            if event["payload"]["query_id"] == "osquery-unapproved"
        )
        self.assertFalse(unapproved_payload["allowed"])
        self.assertTrue(unapproved_payload["requires_approval"])
        self.assertFalse(unapproved_payload["effective_in_shadow"])


    def test_query_round_records_result_semantics_and_rejected_proposals(
        self,
    ) -> None:
        run = self.make_run("query-result-semantics")
        run.query_round(
            {
                "round": 1,
                "requests": [
                    {
                        "query_id": "zero",
                        "backend": "elastic",
                        "purpose": "Prove an exact empty result.",
                    },
                    {
                        "query_id": "unknown",
                        "backend": "oql",
                        "purpose": "Exercise an omitted returned count.",
                    },
                    {
                        "query_id": "positive",
                        "backend": "pcap_zeek",
                        "purpose": "Exercise a positive bounded result.",
                    },
                ],
                "results": [
                    {
                        "query_id": "zero",
                        "backend": "elastic",
                        "status": "ok",
                        "read_only": True,
                        "evidence": {"returned_rows": 0},
                    },
                    {
                        "query_id": "unknown",
                        "backend": "oql",
                        "status": "ok",
                        "evidence": {"window": "bounded"},
                    },
                    {
                        "query_id": "positive",
                        "backend": "pcap_zeek",
                        "status": "ok",
                        "read_only": True,
                        "evidence": {
                            "projection": {
                                "returned_hits": 3,
                                "source_truncated": True,
                            }
                        },
                    },
                    {
                        "query_id": "rejected",
                        "backend": "osquery",
                        "status": "rejected",
                        "read_only": True,
                        "error": "proposal rejected by policy",
                    },
                ],
            }
        )

        trace = run.store.export_trace(run.run_id)
        calls = {item["call_id"]: item for item in trace["tool_calls"]}
        self.assertEqual(len(calls), 4)
        self.assertEqual(calls["round-1-zero"]["coverage"], "exact-zero")
        self.assertEqual(calls["round-1-zero"]["read_only"], 1)
        self.assertEqual(calls["round-1-unknown"]["coverage"], "unknown")
        self.assertEqual(calls["round-1-unknown"]["read_only"], 0)
        self.assertEqual(calls["round-1-positive"]["coverage"], "bounded-result")
        self.assertEqual(calls["round-1-positive"]["truncated"], 1)

        rejected = calls["round-1-rejected"]
        self.assertEqual(rejected["status"], "rejected")
        self.assertEqual(rejected["coverage"], "evidence-gap")
        self.assertEqual(rejected["capability"], "endpoint.osquery.query")
        self.assertEqual(rejected["purpose"], "proposal rejected before execution")
        query_event = next(
            event
            for event in trace["events"]
            if event["event_type"] == "queries.completed"
        )
        self.assertEqual(query_event["payload"]["request_count"], 3)
        self.assertEqual(query_event["payload"]["result_count"], 4)
        self.assertEqual(query_event["payload"]["rejected_proposal_count"], 1)
        self.assertTrue(trace["integrity"]["valid"])


