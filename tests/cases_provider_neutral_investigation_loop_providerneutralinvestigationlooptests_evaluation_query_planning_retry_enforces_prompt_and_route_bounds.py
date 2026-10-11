from __future__ import annotations

from provider_neutral_investigation_loop_fixtures import (
    BIN_DIR,
    Path,
    REPO_ROOT,
    RecordingHarness,
    argparse,
    ast,
    copy,
    hashlib,
    importlib,
    json,
    load_module,
    mock,
    sys,
    tempfile,
    unittest,
)

class ProviderNeutralInvestigationLoopTestsEvaluationQueryPlanningRetryEnforcesPromptAndRouteBoundsCases:
    def test_evaluation_query_planning_retry_enforces_prompt_and_route_bounds(
        self,
    ) -> None:
        route = "codex-cli:gpt-5.5:high"
        settings = {"agent_models": {"soc-analyst": route}}
        model_executor = mock.Mock()
        with (
            mock.patch.dict(
                self.runner.os.environ,
                {self.runner.EVALUATION_FREEZE_MEMORY_ENV: "1"},
            ),
            self.assertRaisesRegex(
                self.runner.InvestigationQueryError,
                "prompt exceeds max_prompt_bytes",
            ),
        ):
            self.runner.apply_investigation_query_loop(
                {"case_id": "case-prompt-bound"},
                {"summary": "no request", "_analysis_model_route": route},
                self.runner.argparse.Namespace(max_prompt_bytes=64),
                settings,
                "soc-analyst",
                harness_runtime=RecordingHarness([], mode="shadow"),
                model_executor=model_executor,
            )
        model_executor.assert_not_called()

        route_events: list[tuple] = []
        with (
            mock.patch.dict(
                self.runner.os.environ,
                {self.runner.EVALUATION_FREEZE_MEMORY_ENV: "1"},
            ),
            self.assertRaisesRegex(
                self.runner.InvestigationQueryError,
                "preserve the assigned model route",
            ),
        ):
            self.runner.apply_investigation_query_loop(
                {},
                {"summary": "no request", "_analysis_model_route": route},
                self.runner.argparse.Namespace(
                    max_prompt_bytes=self.runner.DEFAULT_MAX_PROMPT_BYTES,
                ),
                settings,
                "soc-analyst",
                harness_runtime=RecordingHarness(
                    route_events,
                    mode="shadow",
                ),
                model_executor=mock.Mock(
                    return_value={
                        "investigation_query_requests": [
                            self.elastic_request()
                        ],
                        "_analysis_model_route": (
                            "codex-cli:gpt-5.6-terra:high"
                        ),
                    }
                ),
                query_executor=mock.Mock(),
            )
        self.assertIn(
            ("model_call", "primary-query-planning-retry-1", False),
            route_events,
        )


    def test_evaluation_shadow_trace_failures_are_fail_closed(self) -> None:
        route = "codex-cli:gpt-5.5:high"
        settings = {"agent_models": {"soc-analyst": route}}
        initial_model_executor = mock.Mock()
        initial_harness = RecordingHarness([], mode="shadow")
        initial_harness.preflight_model_call = mock.Mock(
            side_effect=RuntimeError("synthetic initial trace failure")
        )
        with (
            mock.patch.dict(
                self.runner.os.environ,
                {self.runner.EVALUATION_FREEZE_MEMORY_ENV: "1"},
            ),
            mock.patch.object(
                self.runner,
                "analyze_model_route",
                initial_model_executor,
            ),
            self.assertRaisesRegex(
                RuntimeError,
                "synthetic initial trace failure",
            ),
        ):
            self.runner.analyze_with_config(
                {"case_id": "case-initial-trace-failure"},
                object(),
                settings=settings,
                harness_runtime=initial_harness,
            )
        initial_model_executor.assert_not_called()

        query_executor = mock.Mock()
        query_harness = RecordingHarness(
            [],
            mode="shadow",
            fail_authorization=True,
        )
        with (
            mock.patch.dict(
                self.runner.os.environ,
                {self.runner.EVALUATION_FREEZE_MEMORY_ENV: "1"},
            ),
            self.assertRaisesRegex(
                RuntimeError,
                "synthetic shadow observation failure",
            ),
        ):
            self.runner.apply_investigation_query_loop(
                {
                    "investigation_query_capability": {
                        "enabled": True,
                        "backends": {"elastic": {"enabled": True}},
                    },
                    "_local_investigation_query_context": {
                        "anchor": {
                            "index": (
                                ".ds-logs-suricata.alerts-so-"
                                "2026.07.24-000001"
                            ),
                            "id": "alert-query-trace-failure",
                        },
                    },
                },
                {
                    "investigation_query_requests": [
                        self.elastic_request()
                    ],
                    "_analysis_model_route": route,
                },
                object(),
                settings,
                "soc-analyst",
                harness_runtime=query_harness,
                model_executor=mock.Mock(),
                query_executor=query_executor,
            )
        query_executor.assert_not_called()


    def test_evaluation_audit_bindings_match_durable_harness_tool_rows(
        self,
    ) -> None:
        route = "codex-cli:gpt-5.5:high"
        prompt_package = {
            "case_id": "case-durable-query-binding",
            "alert": {
                "alert_id": (
                    ".ds-logs-suricata.alerts-so-2026.07.24-000001:"
                    "alert-durable-query-binding"
                ),
            },
            "investigation_query_capability": {
                "enabled": True,
                "backends": {"elastic": {"enabled": True}},
            },
            "_local_investigation_query_context": {
                "anchor": {
                    "index": ".ds-logs-suricata.alerts-so-2026.07.24-000001",
                    "id": "alert-durable-query-binding",
                },
            },
        }
        self.runner.attach_evidence_reference_contract(prompt_package)
        policy_value = json.loads(
            (
                REPO_ROOT
                / "n8n"
                / "config"
                / "investigation_harness_policy.json"
            ).read_text(encoding="utf-8")
        )
        policy_value["enabled"] = True
        policy_value["mode"] = "enforce"
        policy = self.harness.HarnessPolicy.from_dict(policy_value)
        model_call_count = 0

        def model_executor(
            observed_route,
            _package,
            _args,
            _settings,
        ):
            nonlocal model_call_count
            model_call_count += 1
            self.assertEqual(observed_route, route)
            if model_call_count == 1:
                return {
                    "investigation_query_requests": [self.elastic_request()],
                    "_analysis_model_route": route,
                }
            return {
                "summary": "Durably bound final response.",
                "_analysis_model_route": route,
            }

        with tempfile.TemporaryDirectory() as temp_name:
            runtime = self.harness.start_harness_run(
                run_id="run-durable-query-binding",
                source_revision="1" * 40,
                prompt_package=prompt_package,
                role="soc-analyst",
                assigned_route=route,
                configuration={
                    "evaluation_memory_frozen": True,
                    "test": True,
                },
                policy=policy,
                db_path=Path(temp_name) / "harness.sqlite3",
            )
            self.assertIsNotNone(runtime)
            with mock.patch.dict(
                self.runner.os.environ,
                {self.runner.EVALUATION_FREEZE_MEMORY_ENV: "1"},
            ):
                response = self.runner.apply_investigation_query_loop(
                    prompt_package,
                    {
                        "summary": "Initial response omitted a pivot.",
                        "_analysis_model_route": route,
                    },
                    self.runner.argparse.Namespace(
                        max_prompt_bytes=self.runner.DEFAULT_MAX_PROMPT_BYTES,
                    ),
                    {"agent_models": {"soc-analyst": route}},
                    "soc-analyst",
                    harness_runtime=runtime,
                    model_executor=model_executor,
                    query_executor=lambda _package, requests, **kwargs: (
                        self.successful_security_onion_round(
                            requests,
                            round_number=kwargs["round_number"],
                        )
                    ),
                )
            trace = runtime.store.export_trace(runtime.run_id)

        binding = response["_investigation_query_audit"][
            "tool_call_bindings"
        ][0]
        tool_row = trace["tool_calls"][0]
        for key in (
            "call_id",
            "round_number",
            "backend",
            "status",
            "request_digest",
            "result_digest",
        ):
            self.assertEqual(binding[key], tool_row[key])
        self.assertIs(binding["read_only"], True)
        self.assertEqual(bool(tool_row["read_only"]), binding["read_only"])


    def test_query_authorization_and_batch_preflight_precede_executor(
        self,
    ) -> None:
        events: list[tuple] = []
        harness = RecordingHarness(events)
        prompt_package = {
            "investigation_query_capability": {
                "enabled": True,
                "backends": {"elastic": {"enabled": True}},
            },
            "_local_investigation_query_context": {
                "anchor": {
                    "index": ".ds-logs-suricata.alerts-so-2026.07.24-000001",
                    "id": "alert-order",
                },
            },
        }

        def query_executor(
            _package,
            requests,
            *,
            round_number,
            live_osquery_config,
        ):
            self.assertIsNone(live_osquery_config)
            events.append(("query_executor", round_number))
            return {
                "schema": self.runner.INVESTIGATION_QUERY_RESULT_SCHEMA,
                "round": round_number,
                "requests": requests,
                "results": [
                    {
                        "query_id": requests[0]["query_id"],
                        "backend": "elastic",
                        "status": "ok",
                        "read_only": True,
                        "query_digest": "a" * 64,
                        "result_digest": "b" * 64,
                        "returned_hits": 1,
                    }
                ],
                "audit": [],
            }

        response = self.runner.apply_investigation_query_loop(
            prompt_package,
            {"investigation_query_requests": [self.elastic_request()]},
            object(),
            {"agent_models": {"soc-analyst": "codex-cli:gpt-5.5:medium"}},
            "soc-analyst",
            harness_runtime=harness,
            model_executor=mock.Mock(return_value={"summary": "done"}),
            query_executor=query_executor,
        )

        self.assertEqual(response["summary"], "done")
        authorization_position = next(
            index
            for index, event in enumerate(events)
            if event[0] == "authorize_tool"
        )
        preflight_position = next(
            index
            for index, event in enumerate(events)
            if event[0] == "preflight_query_batch"
        )
        execution_position = events.index(("query_executor", 1))
        self.assertLess(authorization_position, preflight_position)
        self.assertLess(preflight_position, execution_position)


    def test_enforce_tool_denial_prevents_query_execution(self) -> None:
        events: list[tuple] = []
        harness = RecordingHarness(
            events,
            mode="enforce",
            tool_allowed=False,
        )
        prompt_package = {
            "investigation_query_capability": {
                "enabled": True,
                "backends": {"elastic": {"enabled": True}},
            },
            "_local_investigation_query_context": {
                "anchor": {
                    "index": ".ds-logs-suricata.alerts-so-2026.07.24-000001",
                    "id": "alert-denied",
                },
            },
        }
        query_executor = mock.Mock()

        response = self.runner.apply_investigation_query_loop(
            prompt_package,
            {"investigation_query_requests": [self.elastic_request()]},
            object(),
            {"agent_models": {"soc-analyst": "codex-cli:gpt-5.5:medium"}},
            "soc-analyst",
            harness_runtime=harness,
            model_executor=mock.Mock(return_value={"summary": "denied"}),
            query_executor=query_executor,
        )

        query_executor.assert_not_called()
        self.assertFalse(
            any(event[0] == "preflight_query_batch" for event in events)
        )
        result = response["_investigation_query_audit"]["rounds"][0]["results"][0]
        self.assertEqual(result["status"], "rejected")
        self.assertIn("harness denied capability", result["error"].lower())


    def test_shadow_approval_denial_prevents_operational_query_execution(
        self,
    ) -> None:
        events: list[tuple] = []
        harness = RecordingHarness(
            events,
            mode="shadow",
            tool_allowed=False,
            tool_requires_approval=True,
        )
        prompt_package = {
            "investigation_query_capability": {
                "enabled": True,
                "backends": {"osquery": {"enabled": True}},
            },
        }
        request = {
            "query_id": "live-endpoint-denied",
            "backend": "osquery",
            "purpose": "Inspect a bounded endpoint process fact.",
            "parameters": {
                "target_alias": "endpoint-a",
                "query": "SELECT pid FROM processes LIMIT 1",
            },
        }
        query_executor = mock.Mock()

        response = self.runner.apply_investigation_query_loop(
            prompt_package,
            {"investigation_query_requests": [request]},
            object(),
            {"agent_models": {"soc-analyst": "codex-cli:gpt-5.5:medium"}},
            "soc-analyst",
            live_osquery_config={
                "enabled": True,
                "allowed_target_aliases": ["endpoint-a"],
            },
            harness_runtime=harness,
            model_executor=mock.Mock(return_value={"summary": "denied"}),
            query_executor=query_executor,
        )

        query_executor.assert_not_called()
        self.assertFalse(
            any(event[0] == "preflight_query_batch" for event in events)
        )
        result = response["_investigation_query_audit"]["rounds"][0]["results"][0]
        self.assertEqual(result["status"], "rejected")
        self.assertIn("harness denied capability", result["error"].lower())


    def test_time_bounded_operator_approval_reaches_harness(self) -> None:
        events: list[tuple] = []
        harness = RecordingHarness(
            events,
            mode="enforce",
            tool_allowed=True,
            tool_requires_approval=True,
        )
        request = {
            "query_id": "live-endpoint-approved",
            "backend": "osquery",
            "purpose": "Inspect a bounded endpoint process fact.",
            "parameters": {
                "target_alias": "endpoint-a",
                "query": "SELECT pid FROM processes LIMIT 1",
            },
        }
        query_executor = mock.Mock(
            return_value={
                "schema": self.runner.INVESTIGATION_QUERY_RESULT_SCHEMA,
                "round": 1,
                "requests": [request],
                "results": [
                    {
                        "query_id": "live-endpoint-approved",
                        "backend": "osquery",
                        "status": "ok",
                        "read_only": True,
                        "query_digest": "a" * 64,
                        "result_digest": "b" * 64,
                    }
                ],
                "audit": [],
            }
        )

        self.runner.apply_investigation_query_loop(
            {
                "investigation_query_capability": {
                    "enabled": True,
                    "backends": {"osquery": {"enabled": True}},
                },
            },
            {"investigation_query_requests": [request]},
            object(),
            {"agent_models": {"incident-responder": "codex-cli:gpt-5.5:medium"}},
            "incident-responder",
            live_osquery_config={
                "enabled": True,
                "allowed_target_aliases": ["endpoint-a"],
                "harness_operator_approval": {
                    "approved": True,
                    "expires_at": "2099-01-01T00:00:00Z",
                    "target_aliases": ["endpoint-a"],
                },
            },
            harness_runtime=harness,
            model_executor=mock.Mock(return_value={"summary": "approved"}),
            query_executor=query_executor,
        )

        query_executor.assert_called_once()
        authorization = next(
            event for event in events if event[0] == "authorize_tool"
        )
        self.assertTrue(authorization[4])


    def test_live_osquery_results_bind_by_digest_not_array_position(self) -> None:
        prompt_package = {
            "_local_investigation_query_context": {
                "permitted_observables": {
                    "ips": ["192.0.2.10"],
                    "domains": [],
                    "hosts": [],
                    "users": [],
                }
            }
        }
        raw_requests = [
            {
                "query_id": "process-query",
                "backend": "osquery",
                "purpose": "Inspect processes.",
                "parameters": {
                    "target_alias": "endpoint-a",
                    "query": "SELECT pid, name FROM processes LIMIT 2",
                },
            },
            {
                "query_id": "system-query",
                "backend": "osquery",
                "purpose": "Inspect system identity.",
                "parameters": {
                    "target_alias": "endpoint-a",
                    "query": "SELECT hostname FROM system_info LIMIT 1",
                },
            },
        ]
        requests = [
            self.runner.normalize_investigation_query_request(
                raw,
                round_number=1,
                position=index,
            )
            for index, raw in enumerate(raw_requests, 1)
        ]

        def evidence_for(request: dict, row: dict[str, str]) -> dict:
            query = self.runner.normalize_live_osquery_query(
                request["parameters"]["query"]
            )
            return {
                "target_alias": request["parameters"]["target_alias"],
                "query": query,
                "purpose": request["purpose"],
                "query_digest": hashlib.sha256(query.encode("utf-8")).hexdigest(),
                "status": "ok",
                "rows": [row],
                "total_rows": 1,
                "truncated": False,
                "duration_ms": 1,
                "error": "",
            }

        process_evidence = evidence_for(
            requests[0],
            {"pid": "1", "name": "process"},
        )
        system_evidence = evidence_for(
            requests[1],
            {"hostname": "system"},
        )
        result = self.runner.execute_investigation_query_batch(
            prompt_package,
            requests,
            round_number=1,
            live_osquery_config={
                "enabled": True,
                "target_bindings": {
                    "endpoint-a": {
                        "ips": ["192.0.2.10"],
                        "hosts": [],
                    }
                },
            },
            osquery_executor=mock.Mock(
                return_value={
                    "schema": self.runner.LIVE_OSQUERY_SCHEMA,
                    "case_id": self.runner.live_osquery_case_id(prompt_package),
                    "generated_at": "2026-07-24T18:31:00Z",
                    "complete": True,
                    "read_only": True,
                    # Deliberately reverse the trusted response order.
                    "results": [system_evidence, process_evidence],
                }
            ),
        )

        by_id = {
            item["query_id"]: item["evidence"]["rows"][0]
            for item in result["results"]
        }
        self.assertEqual(
            by_id["process-query"],
            {"pid": "1", "name": "process"},
        )
        self.assertEqual(by_id["system-query"], {"hostname": "system"})


    def test_live_osquery_transport_failure_is_preserved_in_final_audit(self) -> None:
        raw = {
            "query_id": "endpoint-failure",
            "backend": "osquery",
            "purpose": "Inspect a bounded endpoint process fact.",
            "parameters": {
                "target_alias": "endpoint-a",
                "query": "SELECT pid, name FROM processes LIMIT 2",
            },
        }
        request = self.runner.normalize_investigation_query_request(
            raw,
            round_number=1,
            position=1,
        )
        prompt_package: dict = {
            "_local_investigation_query_context": {
                "permitted_observables": {
                    "ips": ["192.0.2.10"],
                    "domains": [],
                    "hosts": [],
                    "users": [],
                }
            }
        }
        result = self.runner.execute_investigation_query_batch(
            prompt_package,
            [request],
            round_number=1,
            live_osquery_config={
                "enabled": True,
                "target_bindings": {
                    "endpoint-a": {
                        "ips": ["192.0.2.10"],
                        "hosts": [],
                    }
                },
            },
            osquery_executor=mock.Mock(
                side_effect=self.runner.LiveOsqueryClientError("transport down")
            ),
        )

        self.assertEqual(result["results"][0]["status"], "error")
        accumulator = prompt_package["_live_osquery_evidence_accumulator"]
        self.assertFalse(accumulator["complete"])
        self.assertFalse(accumulator["batches"][0]["validated"])
        audit = self.runner.incident_live_osquery_audit(prompt_package)
        self.assertEqual(audit["batches"], 1)
        self.assertEqual(audit["validated_batches"], 0)
        self.assertEqual(audit["failed_batches"], 1)
        self.assertEqual(audit["control_plane_write_status"], "possible")
        self.assertEqual(audit["queries"][0]["status"], "error")
        self.assertIn("transport down", audit["error"])


    def test_real_shadow_harness_never_dispatches_unapproved_live_osquery(
        self,
    ) -> None:
        route = "codex-cli:gpt-5.5:medium"
        prompt_package = {
            "case_id": "case-shadow-live-osquery-denied",
            "alert": {"alert_id": "alert-shadow-live-osquery-denied"},
            "investigation_query_capability": {
                "enabled": True,
                "backends": {"osquery": {"enabled": True}},
            },
        }
        request = {
            "query_id": "live-endpoint-real-policy-denied",
            "backend": "osquery",
            "purpose": "Inspect a bounded endpoint process fact.",
            "parameters": {
                "target_alias": "endpoint-a",
                "query": "SELECT pid FROM processes LIMIT 1",
            },
        }
        policy_value = json.loads(
            (
                REPO_ROOT
                / "n8n"
                / "config"
                / "investigation_harness_policy.json"
            ).read_text(encoding="utf-8")
        )
        policy_value["enabled"] = True
        policy_value["mode"] = "shadow"
        policy = self.harness.HarnessPolicy.from_dict(policy_value)
        query_executor = mock.Mock(
            side_effect=AssertionError("live OSQuery collector was invoked")
        )

        with tempfile.TemporaryDirectory() as temp_name:
            runtime = self.harness.start_harness_run(
                run_id="run-shadow-live-osquery-denied",
                source_revision="1" * 40,
                prompt_package=prompt_package,
                role="soc-analyst",
                assigned_route=route,
                configuration={
                    "reviewer_route": "codex-cli:gpt-5.6-sol:high",
                },
                policy=policy,
                db_path=Path(temp_name) / "harness.sqlite3",
            )
            self.assertIsNotNone(runtime)
            response = self.runner.apply_investigation_query_loop(
                prompt_package,
                {"investigation_query_requests": [request]},
                object(),
                {"agent_models": {"soc-analyst": route}},
                "soc-analyst",
                live_osquery_config={
                    "enabled": True,
                    "allowed_target_aliases": ["endpoint-a"],
                },
                harness_runtime=runtime,
                model_executor=mock.Mock(
                    return_value={
                        "summary": "Unapproved endpoint query stayed blocked.",
                        "_analysis_model_route": route,
                    }
                ),
                query_executor=query_executor,
            )
            trace = runtime.store.export_trace(runtime.run_id)

        query_executor.assert_not_called()
        result = response["_investigation_query_audit"]["rounds"][0]["results"][0]
        self.assertEqual(result["status"], "rejected")
        authorization = next(
            event["payload"]
            for event in trace["events"]
            if event["event_type"] == "policy.tool-authorization"
        )
        self.assertFalse(authorization["allowed"])
        self.assertTrue(authorization["requires_approval"])
        self.assertFalse(authorization["effective_in_shadow"])
        tool_call = next(
            item
            for item in trace["tool_calls"]
            if item["backend"] == "osquery"
        )
        self.assertEqual(tool_call["status"], "rejected")
        self.assertEqual(tool_call["coverage"], "evidence-gap")
        self.assertFalse(
            any(
                item["source_class"] == "live_endpoint_osquery"
                for item in trace["evidence"]
            )
        )
