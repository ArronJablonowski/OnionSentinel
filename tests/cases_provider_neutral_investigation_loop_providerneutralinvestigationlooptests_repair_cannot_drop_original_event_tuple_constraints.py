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

class ProviderNeutralInvestigationLoopTestsRepairCannotDropOriginalEventTupleConstraintsCases:
    def test_repair_cannot_drop_original_event_tuple_constraints(
        self,
    ) -> None:
        route = "codex-cli:gpt-5.5:medium"
        prompt_package = {
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
                    "id": "alert-tuple-repair",
                },
                "permitted_event_tuples": [
                    {
                        "event_tuple": {
                            "source_ip": "192.0.2.10",
                            "destination_ip": "198.51.100.20",
                            "source_port": 49152,
                            "destination_port": 443,
                            "transport": "tcp",
                        },
                        "role_semantics": "packet_direction",
                        "source": "trusted_context",
                    }
                ],
            },
        }
        invalid = self.elastic_request("repair-dropped-tuple")
        invalid["parameters"]["event_tuple"] = {
            "source_ip": "192.0.2.10",
            "destination_ip": "198.51.100.20",
            "source_port": 49152,
            "destination_port": 443,
            "transport": "tcp",
        }
        invalid["parameters"]["query_dsl"] = {"match_all": {}}

        def model_executor(_route, package, *_args):
            if "investigation_query_planning_repair" in package:
                return {
                    "investigation_query_requests": [
                        self.elastic_request("repair-dropped-tuple")
                    ]
                }
            return {"summary": "Tuple widening was blocked."}

        query_executor = mock.Mock(
            side_effect=lambda _package, requests, **kwargs: (
                self.successful_security_onion_round(
                    requests,
                    round_number=kwargs["round_number"],
                )
            )
        )
        response = self.runner.apply_investigation_query_loop(
            prompt_package,
            {"investigation_query_requests": [invalid]},
            object(),
            {"agent_models": {"soc-analyst": route}},
            "soc-analyst",
            model_executor=model_executor,
            query_executor=query_executor,
        )

        query_executor.assert_called_once()
        repaired_request = query_executor.call_args.args[1][0]
        self.assertEqual(
            repaired_request["parameters"]["event_tuple"],
            invalid["parameters"]["event_tuple"],
        )
        audit = response["_investigation_query_audit"]
        self.assertEqual(
            audit["query_planning_repair"]["admitted_repair_requests"],
            1,
        )
        self.assertEqual(
            audit["query_planning_repair"]["rejected_repair_requests"],
            0,
        )
        self.assertTrue(
            audit["query_planning_repair"][
                "deterministic_scope_execution"
            ]
        )


    def test_invalid_broker_envelope_gets_one_bounded_repair(
        self,
    ) -> None:
        route = "codex-cli:gpt-5.5:medium"
        prompt_package = {
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
                    "id": "alert-invalid-broker-response",
                },
            },
        }
        broker_calls = 0

        def query_executor(_package, requests, **kwargs):
            nonlocal broker_calls
            broker_calls += 1
            if broker_calls == 1:
                return {"unexpected": "invalid envelope"}
            return self.successful_security_onion_round(
                requests,
                round_number=kwargs["round_number"],
            )

        def model_executor(_route, package, *_args):
            if "investigation_query_planning_repair" in package:
                return {
                    "investigation_query_requests": [
                        self.elastic_request("broker-invalid")
                    ]
                }
            return {"summary": "Broker retry synthesized."}

        response = self.runner.apply_investigation_query_loop(
            prompt_package,
            {
                "investigation_query_requests": [
                    self.elastic_request("broker-invalid")
                ]
            },
            object(),
            {"agent_models": {"soc-analyst": route}},
            "soc-analyst",
            model_executor=model_executor,
            query_executor=query_executor,
        )

        self.assertEqual(broker_calls, 2)
        audit = response["_investigation_query_audit"]
        self.assertEqual(
            audit["query_planning_repair"]["attempts"],
            1,
        )
        self.assertEqual(
            audit["query_planning_repair"]["candidates"][0]["trigger"],
            "broker_rejection_or_invalid_response",
        )
        self.assertEqual(
            audit["query_planning_repair"]["admitted_repair_requests"],
            1,
        )


    def test_query_repair_prompt_omits_raw_broker_error_values(
        self,
    ) -> None:
        route = "codex-cli:gpt-5.5:medium"
        rejected_domain = "attacker-controlled.example"
        rejected_ip = "203.0.113.77"
        raw_error = (
            "invalid response contained "
            f"{rejected_domain} and {rejected_ip}"
        )
        prompt_package = {
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
                    "id": "alert-value-free-query-repair",
                },
            },
        }
        broker_calls = 0

        def query_executor(_package, requests, **kwargs):
            nonlocal broker_calls
            broker_calls += 1
            result = self.successful_security_onion_round(
                requests,
                round_number=kwargs["round_number"],
            )
            if broker_calls == 1:
                evidence_result = result["results"][0]["evidence"][
                    "results"
                ][0]
                evidence_result["status"] = "invalid_response"
                evidence_result["error"] = raw_error
                trusted = result["results"][0]["trusted_query_audit"][0]
                trusted["status"] = "invalid_response"
                trusted["error"] = raw_error
            return result

        def model_executor(_route, package, *_args):
            if "investigation_query_planning_repair" in package:
                serialized = json.dumps(
                    package,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                self.assertNotIn(rejected_domain, serialized)
                self.assertNotIn(rejected_ip, serialized)
                repair = package["investigation_query_planning_repair"]
                rejected = repair["rejected_queries"][0]
                self.assertEqual(
                    rejected["error"],
                    "invalid_broker_response",
                )
                self.assertRegex(
                    rejected["error_sha256"],
                    r"^[a-f0-9]{64}$",
                )
                self.assertIn(
                    "invalid_broker_response",
                    serialized,
                )
                return {
                    "investigation_query_requests": [
                        self.elastic_request("value-free-repair")
                    ]
                }
            return {"summary": "Sanitized repair evidence synthesized."}

        response = self.runner.apply_investigation_query_loop(
            prompt_package,
            {
                "investigation_query_requests": [
                    self.elastic_request("value-free-repair")
                ]
            },
            object(),
            {"agent_models": {"soc-analyst": route}},
            "soc-analyst",
            model_executor=model_executor,
            query_executor=query_executor,
        )

        self.assertEqual(broker_calls, 2)
        self.assertEqual(
            response["_investigation_query_audit"][
                "query_planning_repair"
            ]["admitted_repair_requests"],
            1,
        )


    def test_evaluation_retry_collects_successful_read_only_pivot_and_binds_audit(
        self,
    ) -> None:
        events: list[tuple] = []
        harness = RecordingHarness(events, mode="shadow")
        route = "codex-cli:gpt-5.6-sol:high"
        prompt_package = {
            "case_id": "case-evaluation-retry",
            "investigation_query_capability": {
                "enabled": True,
                "backends": {"elastic": {"enabled": True}},
            },
            "_local_investigation_query_context": {
                "anchor": {
                    "index": ".ds-logs-suricata.alerts-so-2026.07.24-000001",
                    "id": "alert-evaluation-retry",
                },
            },
        }
        settings = {"agent_models": {"soc-analyst": route}}
        executed_round: dict[str, dict] = {}

        def model_executor(
            observed_route,
            package,
            _args,
            _settings,
        ):
            self.assertEqual(observed_route, route)
            if "investigation_follow_up" not in package:
                events.append(("model_executor", "query-planning", observed_route))
                retry = package["investigation_query_planning_retry"]
                self.assertEqual(retry["attempt"], 1)
                self.assertEqual(retry["maximum_attempts"], 1)
                return {
                    "investigation_query_requests": [self.elastic_request()],
                    "_analysis_model_route": route,
                }
            events.append(("model_executor", "evidence-synthesis", observed_route))
            return {
                "summary": "Final response after a dynamic pivot.",
                "_analysis_model_route": route,
            }

        def query_executor(
            _package,
            requests,
            *,
            round_number,
            live_osquery_config,
        ):
            self.assertIsNone(live_osquery_config)
            result = self.successful_security_onion_round(
                requests,
                round_number=round_number,
            )
            executed_round["value"] = result
            return result

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
                settings,
                "soc-analyst",
                harness_runtime=harness,
                model_executor=model_executor,
                query_executor=query_executor,
            )

        audit = response["_investigation_query_audit"]
        self.assertTrue(audit["planning_retry_attempted"])
        self.assertTrue(audit["planning_retry_produced_requests"])
        self.assertTrue(audit["query_planning_retry"]["attempted"])
        self.assertTrue(audit["read_only"])
        self.assertTrue(audit["all_tool_call_bindings_read_only"])
        self.assertTrue(audit["complete"])
        self.assertEqual(audit["successful_read_only_queries"], 1)
        self.assertTrue(audit["evaluation_requirement_satisfied"])
        self.assertTrue(
            audit["evaluation_query_guarantee"][
                "evaluation_requirement_satisfied"
            ]
        )
        self.assertEqual(len(audit["tool_call_bindings"]), 1)
        binding = audit["tool_call_bindings"][0]
        exact_round = executed_round["value"]
        self.assertEqual(
            binding["request_digest"],
            self.harness.digest_json(exact_round["requests"][0]),
        )
        self.assertEqual(
            binding["result_digest"],
            self.harness.digest_json(exact_round["results"][0]),
        )
        self.assertEqual(binding["call_id"], "round-1-pivot-1")
        self.assertEqual(binding["backend"], "elastic")
        self.assertEqual(binding["status"], "ok")
        self.assertIs(binding["read_only"], True)
        planning_preflight = next(
            index
            for index, event in enumerate(events)
            if event[:2]
            == ("preflight_model_call", "primary-query-planning-retry-1")
        )
        planning_execution = events.index(
            ("model_executor", "query-planning", route)
        )
        self.assertLess(planning_preflight, planning_execution)
        self.assertIn(
            ("model_call", "primary-query-planning-retry-1", False),
            events,
        )
        self.assertIn(("model_call", "primary-followup-1", False), events)


    def test_evaluation_retry_without_query_fails_before_pivot_or_persistence(
        self,
    ) -> None:
        events: list[tuple] = []
        harness = RecordingHarness(events, mode="shadow")
        route = "codex-cli:gpt-5.5:high"
        model_executor = mock.Mock(
            return_value={
                "summary": "Still no query request.",
                "_analysis_model_route": route,
            }
        )
        query_executor = mock.Mock()

        with (
            mock.patch.dict(
                self.runner.os.environ,
                {self.runner.EVALUATION_FREEZE_MEMORY_ENV: "1"},
            ),
            self.assertRaisesRegex(
                self.runner.InvestigationQueryError,
                "produced no investigation_query_requests",
            ),
        ):
            self.runner.apply_investigation_query_loop(
                {},
                {
                    "summary": "Initial response omitted a pivot.",
                    "_analysis_model_route": route,
                },
                self.runner.argparse.Namespace(
                    max_prompt_bytes=self.runner.DEFAULT_MAX_PROMPT_BYTES,
                ),
                {"agent_models": {"soc-analyst": route}},
                "soc-analyst",
                harness_runtime=harness,
                model_executor=model_executor,
                query_executor=query_executor,
            )

        model_executor.assert_called_once()
        query_executor.assert_not_called()
        self.assertIn(
            ("model_call", "primary-query-planning-retry-1", False),
            events,
        )


    def test_evaluation_fails_when_dynamic_pivot_is_not_successful_read_only(
        self,
    ) -> None:
        events: list[tuple] = []
        harness = RecordingHarness(events, mode="shadow")
        route = "codex-cli:gpt-5.5:high"

        def failed_query_round(
            _package,
            requests,
            *,
            round_number,
            live_osquery_config,
        ):
            self.assertIsNone(live_osquery_config)
            return {
                "schema": self.runner.INVESTIGATION_QUERY_RESULT_SCHEMA,
                "round": round_number,
                "requests": copy.deepcopy(requests),
                "results": [
                    {
                        "query_id": requests[0]["query_id"],
                        "backend": "elastic",
                        "status": "error",
                        "read_only": True,
                        "error": "synthetic broker failure",
                    }
                ],
                "audit": [],
            }

        with (
            mock.patch.dict(
                self.runner.os.environ,
                {self.runner.EVALUATION_FREEZE_MEMORY_ENV: "1"},
            ),
            self.assertRaisesRegex(
                self.runner.InvestigationQueryError,
                "at least one successful read-only dynamic pivot",
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
                            "id": "alert-failed-evaluation-pivot",
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
                {"agent_models": {"soc-analyst": route}},
                "soc-analyst",
                harness_runtime=harness,
                model_executor=mock.Mock(
                    return_value={
                        "summary": "No evidence was collected.",
                        "_analysis_model_route": route,
                    }
                ),
                query_executor=failed_query_round,
            )

        self.assertIn(("query_round", 1), events)


    def test_evaluation_counts_digest_bound_success_inside_partial_broker_batch(
        self,
    ) -> None:
        events: list[tuple] = []
        harness = RecordingHarness(events, mode="shadow")
        route = "codex-cli:gpt-5.5:high"
        successful = self.elastic_request("successful-pivot")
        failed = self.elastic_request("failed-pivot")
        failed["parameters"]["size"] = 26
        query_digest_ok = "a" * 64
        result_digest_ok = "b" * 64
        query_digest_failed = "c" * 64
        result_digest_failed = "d" * 64
        executed_round: dict[str, dict] = {}

        def mixed_query_round(
            _package,
            requests,
            *,
            round_number,
            live_osquery_config,
        ):
            self.assertIsNone(live_osquery_config)
            result = {
                "schema": self.runner.INVESTIGATION_QUERY_RESULT_SCHEMA,
                "round": round_number,
                "requests": copy.deepcopy(requests),
                "results": [
                    {
                        "backend": "security_onion",
                        "query_ids": [
                            "successful-pivot",
                            "failed-pivot",
                        ],
                        "status": "partial",
                        "read_only": True,
                        "security_onion_response_digest": "e" * 64,
                        "evidence": {
                            "complete": False,
                            "partial": True,
                            "read_only": True,
                            "controls_valid": True,
                            "results": [
                                {
                                    "query_id": "successful-pivot",
                                    "status": "ok",
                                    "semantic_valid": True,
                                    "query_digest": query_digest_ok,
                                    "result_digest": result_digest_ok,
                                    "returned_hits": 1,
                                },
                                {
                                    "query_id": "failed-pivot",
                                    "status": "invalid_response",
                                    "semantic_valid": False,
                                    "query_digest": query_digest_failed,
                                    "result_digest": result_digest_failed,
                                },
                            ],
                        },
                        "trusted_query_audit": [
                            {
                                "query_id": "successful-pivot",
                                "status": "ok",
                                "semantic_valid": True,
                                "timed_out": False,
                                "query_digest": query_digest_ok,
                                "result_digest": result_digest_ok,
                                "returned_hits": 1,
                                "shards": {
                                    "total": 3,
                                    "successful": 3,
                                    "skipped": 1,
                                    "failed": 0,
                                    "failures": [],
                                },
                            },
                            {
                                "query_id": "failed-pivot",
                                "status": "invalid_response",
                                "semantic_valid": False,
                                "timed_out": False,
                                "query_digest": query_digest_failed,
                                "result_digest": result_digest_failed,
                                "shards": {
                                    "total": 0,
                                    "successful": 0,
                                    "skipped": 0,
                                    "failed": 0,
                                    "failures": [],
                                },
                            },
                        ],
                    }
                ],
                "audit": [],
            }
            executed_round["value"] = result
            return result

        with mock.patch.dict(
            self.runner.os.environ,
            {self.runner.EVALUATION_FREEZE_MEMORY_ENV: "1"},
        ):
            response = self.runner.apply_investigation_query_loop(
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
                            "id": "alert-mixed-evaluation-pivot",
                        },
                    },
                },
                {
                    "investigation_query_requests": [successful, failed],
                    "_analysis_model_route": route,
                },
                object(),
                {"agent_models": {"soc-analyst": route}},
                "soc-analyst",
                harness_runtime=harness,
                model_executor=mock.Mock(
                    return_value={
                        "summary": "One trusted pivot succeeded.",
                        "_analysis_model_route": route,
                    }
                ),
                query_executor=mixed_query_round,
            )

        audit = response["_investigation_query_audit"]
        self.assertEqual(audit["successful_read_only_queries"], 2)
        self.assertTrue(audit["evaluation_requirement_satisfied"])
        self.assertTrue(audit["all_tool_call_bindings_read_only"])
        self.assertFalse(audit["complete"])
        bindings = {
            item["query_id"]: item
            for item in audit["tool_call_bindings"]
        }
        self.assertEqual(bindings["successful-pivot"]["status"], "ok")
        self.assertEqual(
            bindings["failed-pivot"]["status"],
            "invalid_response",
        )
        expected_result_digest = self.harness.digest_json(
            executed_round["value"]["results"][0]
        )
        self.assertEqual(
            bindings["successful-pivot"]["result_digest"],
            expected_result_digest,
        )
        self.assertEqual(
            bindings["failed-pivot"]["result_digest"],
            expected_result_digest,
        )
        with tempfile.TemporaryDirectory() as temporary_root:
            policy = self.harness.HarnessPolicy.from_dict(
                {
                    "schema": self.harness.POLICY_SCHEMA,
                    "version": "test",
                    "enabled": True,
                    "mode": "shadow",
                    "budgets": dict(self.harness.DEFAULT_BUDGETS),
                    "role_capabilities": {
                        role_name: sorted(capabilities)
                        for role_name, capabilities
                        in self.harness.DEFAULT_ROLE_CAPABILITIES.items()
                    },
                    "approval_required": [],
                    "memory": {
                        "require_independent_agreement": True,
                        "shared_requires_human_approval": True,
                    },
                }
            )
            envelope = self.harness.JobEnvelope.from_prompt(
                run_id="partial-batch-cross-layer",
                prompt_package={
                    "alert": {"alert_id": "alert-partial-cross-layer"},
                    "group_id": "group-partial-cross-layer",
                },
                role="soc-analyst",
                assigned_route=route,
                configuration={
                    "reviewer_route": "codex-cli:gpt-5.6-sol:xhigh",
                },
                source_revision="1" * 40,
                policy_version="test",
            )
            durable = self.harness.HarnessRun(
                self.harness.HarnessStore(
                    Path(temporary_root) / "harness.sqlite3"
                ),
                envelope,
                policy,
            )
            durable.query_round(executed_round["value"])
            durable_bindings = {
                item["call_id"]: item
                for item in durable.store.export_trace(
                    durable.run_id
                )["tool_calls"]
            }
        for binding in bindings.values():
            durable_binding = durable_bindings[binding["call_id"]]
            self.assertEqual(durable_binding["status"], binding["status"])
            self.assertEqual(
                durable_binding["request_digest"],
                binding["request_digest"],
            )
            self.assertEqual(
                durable_binding["result_digest"],
                binding["result_digest"],
            )
            self.assertEqual(
                bool(durable_binding["read_only"]),
                binding["read_only"],
            )


    def test_normal_shadow_and_no_harness_do_not_force_query_retry(self) -> None:
        route = "codex-cli:gpt-5.5:high"
        settings = {"agent_models": {"soc-analyst": route}}
        baseline = {
            "summary": "A normal shadow run may conclude without a pivot.",
            "_analysis_model_route": route,
        }
        model_executor = mock.Mock()
        shadow = RecordingHarness([], mode="shadow")

        without_freeze = self.runner.apply_investigation_query_loop(
            {},
            copy.deepcopy(baseline),
            object(),
            settings,
            "soc-analyst",
            harness_runtime=shadow,
            model_executor=model_executor,
        )
        with mock.patch.dict(
            self.runner.os.environ,
            {self.runner.EVALUATION_FREEZE_MEMORY_ENV: "1"},
        ):
            without_harness = self.runner.apply_investigation_query_loop(
                {},
                copy.deepcopy(baseline),
                object(),
                settings,
                "soc-analyst",
                model_executor=model_executor,
            )

        self.assertEqual(without_freeze, baseline)
        self.assertEqual(without_harness, baseline)
        model_executor.assert_not_called()
