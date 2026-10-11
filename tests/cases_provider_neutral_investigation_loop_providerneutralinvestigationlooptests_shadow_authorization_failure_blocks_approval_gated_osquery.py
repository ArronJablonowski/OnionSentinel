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

class ProviderNeutralInvestigationLoopTestsShadowAuthorizationFailureBlocksApprovalGatedOsqueryCases:
    def test_shadow_authorization_failure_blocks_approval_gated_osquery(
        self,
    ) -> None:
        harness = RecordingHarness(
            [],
            mode="shadow",
            fail_authorization=True,
        )
        prompt_package = {
            "investigation_query_capability": {
                "enabled": True,
                "backends": {"osquery": {"enabled": True}},
            },
        }
        request = {
            "query_id": "live-endpoint-authorization-error",
            "backend": "osquery",
            "purpose": "Inspect a bounded endpoint process fact.",
            "parameters": {
                "target_alias": "endpoint-a",
                "query": "SELECT pid FROM processes LIMIT 1",
            },
        }
        query_executor = mock.Mock(
            side_effect=AssertionError("live OSQuery collector was invoked")
        )

        with mock.patch.object(self.runner.sys, "stderr"):
            response = self.runner.apply_investigation_query_loop(
                prompt_package,
                {"investigation_query_requests": [request]},
                object(),
                {
                    "agent_models": {
                        "soc-analyst": "codex-cli:gpt-5.5:medium",
                    }
                },
                "soc-analyst",
                live_osquery_config={
                    "enabled": True,
                    "allowed_target_aliases": ["endpoint-a"],
                },
                harness_runtime=harness,
                model_executor=mock.Mock(
                    return_value={
                        "summary": "Authorization failure stayed closed.",
                    }
                ),
                query_executor=query_executor,
            )

        query_executor.assert_not_called()
        result = response["_investigation_query_audit"]["rounds"][0]["results"][0]
        self.assertEqual(result["status"], "rejected")
        self.assertIn(
            "approval authorization was unavailable",
            result["error"],
        )


    def test_shadow_observation_failure_does_not_change_normal_response(
        self,
    ) -> None:
        template = {
            "investigation_query_capability": {
                "enabled": True,
                "backends": {"elastic": {"enabled": True}},
            },
            "_local_investigation_query_context": {
                "anchor": {
                    "index": ".ds-logs-suricata.alerts-so-2026.07.24-000001",
                    "id": "alert-shadow",
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
            return {
                "schema": self.runner.INVESTIGATION_QUERY_RESULT_SCHEMA,
                "round": round_number,
                "requests": copy.deepcopy(requests),
                "results": [
                    {
                        "query_id": requests[0]["query_id"],
                        "backend": "elastic",
                        "status": "ok",
                        "read_only": True,
                        "query_digest": "c" * 64,
                        "result_digest": "d" * 64,
                        "returned_hits": 2,
                    }
                ],
                "audit": [],
            }

        def execute(prompt_package, harness_runtime=None):
            return self.runner.apply_investigation_query_loop(
                prompt_package,
                {"investigation_query_requests": [self.elastic_request()]},
                object(),
                {
                    "agent_models": {
                        "soc-analyst": "codex-cli:gpt-5.5:medium",
                    }
                },
                "soc-analyst",
                harness_runtime=harness_runtime,
                model_executor=mock.Mock(
                    return_value={"summary": "normal response"}
                ),
                query_executor=query_executor,
            )

        baseline = execute(copy.deepcopy(template))
        events: list[tuple] = []
        shadow = RecordingHarness(
            events,
            mode="shadow",
            fail_authorization=True,
        )
        with mock.patch.object(self.runner.sys, "stderr"):
            observed = execute(copy.deepcopy(template), shadow)

        self.assertEqual(observed, baseline)
        self.assertTrue(
            any(event[0] == "authorize_tool" for event in events)
        )


    def test_result_digest_can_be_recatalogued_after_follow_up_query(
        self,
    ) -> None:
        prompt_package = {
            "case_id": "case-query-result-digest",
            "alert": {
                "alert_id": (
                    ".ds-logs-suricata.alerts-so-2026.07.24-000001:"
                    "alert-result-digest"
                ),
            },
            "investigation_query_capability": {
                "enabled": True,
                "backends": {"elastic": {"enabled": True}},
            },
            "_local_investigation_query_context": {
                "anchor": {
                    "index": ".ds-logs-suricata.alerts-so-2026.07.24-000001",
                    "id": "alert-result-digest",
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
        query_digest = "e" * 64
        result_digest = "f" * 64

        with tempfile.TemporaryDirectory() as temp_name:
            runtime = self.harness.start_harness_run(
                run_id="run-query-result-digest",
                source_revision="1" * 40,
                prompt_package=prompt_package,
                role="soc-analyst",
                assigned_route="codex-cli:gpt-5.5:medium",
                configuration={"test": True},
                policy=policy,
                db_path=Path(temp_name) / "harness.sqlite3",
            )
            self.assertIsNotNone(runtime)

            def query_executor(
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
                    "requests": requests,
                    "results": [
                        {
                            "query_id": requests[0]["query_id"],
                            "backend": "elastic",
                            "pack": "network_flow",
                            "status": "ok",
                            "read_only": True,
                            "query_digest": query_digest,
                            "result_digest": result_digest,
                            "returned_hits": 1,
                            "trusted_query_audit": [
                                {
                                    "query_id": requests[0]["query_id"],
                                    "status": "ok",
                                    "query_digest": query_digest,
                                    "result_digest": result_digest,
                                    "evidence_ref": f"query:{query_digest}",
                                    "returned_hits": 1,
                                }
                            ],
                        }
                    ],
                    "audit": [],
                }

            response = self.runner.apply_investigation_query_loop(
                prompt_package,
                {"investigation_query_requests": [self.elastic_request()]},
                object(),
                {
                    "agent_models": {
                        "soc-analyst": "codex-cli:gpt-5.5:medium",
                    }
                },
                "soc-analyst",
                harness_runtime=runtime,
                model_executor=mock.Mock(
                    return_value={
                        "summary": "digest recatalogued",
                        "_analysis_model_route": (
                            "codex-cli:gpt-5.5:medium"
                        ),
                    }
                ),
                query_executor=query_executor,
            )
            exported = runtime.store.export_trace(runtime.run_id)

        self.assertEqual(response["summary"], "digest recatalogued")
        query_evidence = next(
            item
            for item in exported["evidence"]
            if item["evidence_ref"]
            == f"query:{query_digest}:{result_digest}"
        )
        self.assertEqual(query_evidence["evidence_digest"], result_digest)
        self.assertNotIn(
            f"query:{query_digest}",
            {
                item["evidence_ref"]
                for item in exported["evidence"]
            },
        )


    def test_result_digest_recatalogue_survives_sparse_trusted_audit(
        self,
    ) -> None:
        prompt_package = {
            "case_id": "case-sparse-query-audit",
            "alert": {
                "alert_id": (
                    ".ds-logs-suricata.alerts-so-2026.07.24-000001:"
                    "alert-sparse-query-audit"
                ),
            },
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
                    "id": "alert-sparse-query-audit",
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
        query_digest = "1" * 64
        result_digest = "2" * 64

        with tempfile.TemporaryDirectory() as temp_name:
            runtime = self.harness.start_harness_run(
                run_id="run-sparse-query-audit",
                source_revision="1" * 40,
                prompt_package=prompt_package,
                role="soc-analyst",
                assigned_route="codex-cli:gpt-5.5:medium",
                configuration={"test": True},
                policy=policy,
                db_path=Path(temp_name) / "harness.sqlite3",
            )
            self.assertIsNotNone(runtime)

            def query_executor(
                _package,
                requests,
                *,
                round_number,
                live_osquery_config,
            ):
                self.assertIsNone(live_osquery_config)
                return {
                    "schema": (
                        self.runner.INVESTIGATION_QUERY_RESULT_SCHEMA
                    ),
                    "round": round_number,
                    "requests": requests,
                    "results": [
                        {
                            "query_id": requests[0]["query_id"],
                            "backend": "elastic",
                            "pack": "network_flow",
                            "status": "ok",
                            "read_only": True,
                            "query_digest": query_digest,
                            "result_digest": result_digest,
                            "returned_hits": 0,
                            "trusted_query_audit": [
                                {
                                    "query_id": requests[0]["query_id"],
                                    "status": "ok",
                                    "query_digest": query_digest,
                                    "result_digest": "not-a-digest",
                                    "returned_hits": 0,
                                }
                            ],
                        }
                    ],
                    "audit": [],
                }

            response = self.runner.apply_investigation_query_loop(
                prompt_package,
                {
                    "investigation_query_requests": [
                        self.elastic_request()
                    ]
                },
                object(),
                {
                    "agent_models": {
                        "soc-analyst": "codex-cli:gpt-5.5:medium",
                    }
                },
                "soc-analyst",
                harness_runtime=runtime,
                model_executor=mock.Mock(
                    return_value={
                        "summary": "sparse audit recatalogued",
                        "_analysis_model_route": (
                            "codex-cli:gpt-5.5:medium"
                        ),
                    }
                ),
                query_executor=query_executor,
            )
            exported = runtime.store.export_trace(runtime.run_id)

        self.assertEqual(
            response["summary"],
            "sparse audit recatalogued",
        )
        refs = {
            item["evidence_ref"]: item["evidence_digest"]
            for item in exported["evidence"]
        }
        self.assertEqual(
            refs[f"query:{query_digest}"],
            query_digest,
        )
        self.assertEqual(
            refs[f"query:{query_digest}:{result_digest}"],
            result_digest,
        )


    def test_result_bound_query_references_preserve_full_digests(
        self,
    ) -> None:
        result_digest = "a" * 64
        first_query = "b" * 64
        second_query = "c" * 64
        for namespace in ("pack", "query-id"):
            with self.subTest(namespace=namespace):
                first_ref, first_digest = (
                    self.runner.result_bound_query_reference(
                        first_query.upper(),
                        result_digest.upper(),
                        namespace=namespace,
                        label="long-label-" * 40,
                    )
                )
                second_ref, second_digest = (
                    self.runner.result_bound_query_reference(
                        second_query,
                        result_digest,
                        namespace=namespace,
                        label="long-label-" * 40,
                    )
                )
                self.assertNotEqual(first_ref, second_ref)
                self.assertLessEqual(
                    len(first_ref),
                    self.runner.EVIDENCE_REFERENCE_TEXT_MAX,
                )
                self.assertIn(first_query, first_ref)
                self.assertIn(second_query, second_ref)
                self.assertTrue(first_ref.endswith(result_digest))
                self.assertTrue(second_ref.endswith(result_digest))
                self.assertEqual(first_digest, result_digest)
                self.assertEqual(second_digest, result_digest)

        legacy_ref, legacy_digest = (
            self.runner.result_bound_query_reference(
                first_query.upper(),
                "not-a-digest",
            )
        )
        self.assertEqual(legacy_ref, f"query:{first_query}")
        self.assertEqual(legacy_digest, first_query)
        changed_result_ref, _ = (
            self.runner.result_bound_query_reference(
                first_query,
                "d" * 64,
            )
        )
        self.assertNotEqual(
            changed_result_ref,
            self.runner.result_bound_query_reference(
                first_query,
                result_digest,
            )[0],
        )

        contract = self.runner.evidence_reference_contract(
            {
                "investigation_query_results": {
                    "results": [
                        {
                            "query_id": "query-one",
                            "query_digest": first_query,
                            "result_digest": result_digest,
                            "evidence_ref": f"query:{second_query}",
                            "status": "ok",
                            "returned_hits": 1,
                        }
                    ]
                }
            }
        )
        refs = {item["ref"] for item in contract["references"]}
        self.assertIn(
            f"query:{first_query}:{result_digest}",
            refs,
        )
        self.assertNotIn(f"query:{second_query}", refs)


    def test_rich_query_references_require_strict_bounded_result_counts(
        self,
    ) -> None:
        missing = object()
        invalid_counts = (
            missing,
            True,
            "1",
            1.0,
            1.75,
            -1,
            float("nan"),
            float("inf"),
            object(),
            [],
            2**63,
        )
        for index, returned in enumerate(invalid_counts, 1):
            with self.subTest(returned=repr(returned)):
                query_digest = f"{index:064x}"
                result_digest = f"{index + 100:064x}"
                result = {
                    "query_id": f"strict-count-{index}",
                    "query_digest": query_digest,
                    "result_digest": result_digest,
                    "status": "ok",
                }
                if returned is not missing:
                    result["returned_hits"] = returned
                contract = self.runner.evidence_reference_contract({
                    "investigation_query_results": {
                        "results": [result],
                    },
                })
                reference = (
                    f"query:{query_digest}:{result_digest}"
                )
                catalog = {
                    item["ref"]: item
                    for item in contract["references"]
                }
                self.assertIn(reference, catalog)
                self.assertFalse(catalog[reference]["corroborating"])
                self.assertIsNone(catalog[reference]["returned"])
                self.assertEqual(
                    catalog[reference]["status"],
                    "invalid_result_count",
                )

        maximum = self.runner.MAX_INVESTIGATION_RESULT_COUNT
        query_digest = "e" * 64
        result_digest = "f" * 64
        contract = self.runner.evidence_reference_contract({
            "investigation_query_results": {
                "results": [{
                    "query_id": "strict-count-maximum",
                    "query_digest": query_digest,
                    "result_digest": result_digest,
                    "status": "ok",
                    "returned_hits": maximum,
                }],
            },
        })
        maximum_reference = (
            f"query:{query_digest}:{result_digest}"
        )
        maximum_item = {
            item["ref"]: item
            for item in contract["references"]
        }[maximum_reference]
        self.assertTrue(maximum_item["corroborating"])
        self.assertEqual(maximum_item["returned"], maximum)


    def test_reviewer_preflight_precedes_reviewer_execution(self) -> None:
        events: list[tuple] = []
        harness = RecordingHarness(events)
        primary = {
            "summary": "Primary result.",
            "second_opinion_recommended": True,
            "second_opinion_reason": "Independent validation requested.",
        }
        settings = {
            "agent_models": {
                "soc-analyst": "codex-cli:gpt-5.5:medium",
            },
            "agent_second_opinion_models": {
                "soc-analyst": "ollama:reviewer:latest",
            },
        }

        def reviewer_executor(*_args, **_kwargs):
            events.append(("reviewer_executor",))
            raise RuntimeError("synthetic reviewer stop")

        with (
            mock.patch.object(
                self.runner,
                "analyze_model_route",
                side_effect=reviewer_executor,
            ),
            mock.patch.object(
                self.runner,
                "reconcile_incident_response_report",
            ),
        ):
            response = self.runner.apply_configured_second_opinion(
                {},
                primary,
                type(
                    "Args",
                    (),
                    {
                        "second_opinion_prompt_file": Path(
                            "/tmp/synthetic-reviewer-prompt.md"
                        )
                    },
                )(),
                settings,
                "soc-analyst",
                harness_runtime=harness,
            )

        preflight_position = next(
            index
            for index, event in enumerate(events)
            if event[:3]
            == (
                "preflight_model_call",
                "independent-review-1",
                True,
            )
        )
        execution_position = events.index(("reviewer_executor",))
        self.assertLess(preflight_position, execution_position)
        self.assertEqual(response["_second_opinion"]["status"], "failed")


    def test_loop_reuses_exact_route_and_enforces_round_budget(self) -> None:
        prompt_package = {
            "investigation_query_capability": {
                "enabled": True,
                "backends": {"elastic": {"enabled": True}},
            },
            "_local_investigation_query_context": {
                "anchor": {
                    "index": ".ds-logs-suricata.alerts-so-2026.07.24-000001",
                    "id": "alert-1",
                },
                "discovered_observables": [],
            },
        }
        primary = {"investigation_query_requests": [self.elastic_request("initial")]}
        settings = {
            "agent_models": {"soc-analyst": "codex-cli:gpt-5.6-sol:high"}
        }
        model_calls: list[tuple[str, dict]] = []

        def model_executor(route, package, _args, _settings):
            model_calls.append((route, package["investigation_follow_up"].copy()))
            return {
                "summary": f"round {len(model_calls)}",
                "investigation_query_requests": [
                    {
                        **self.elastic_request(f"next-{len(model_calls)}"),
                        "parameters": {
                            **self.elastic_request()["parameters"],
                            "size": 25 + len(model_calls),
                        },
                    }
                ],
            }

        def query_executor(_package, requests, *, round_number, live_osquery_config):
            return {
                "schema": self.runner.INVESTIGATION_QUERY_RESULT_SCHEMA,
                "round": round_number,
                "requests": requests,
                "results": [
                    {
                        "query_id": requests[0]["query_id"],
                        "backend": "elastic",
                        "status": "ok",
                        "evidence": {"source.ip": "198.51.100.5"},
                    }
                ],
                "audit": [],
            }

        response = self.runner.apply_investigation_query_loop(
            prompt_package,
            primary,
            object(),
            settings,
            "soc-analyst",
            model_executor=model_executor,
            query_executor=query_executor,
        )

        self.assertEqual(len(model_calls), self.runner.MAX_INVESTIGATION_QUERY_ROUNDS)
        self.assertTrue(
            all(call[0] == "codex-cli:gpt-5.6-sol:high" for call in model_calls)
        )
        self.assertEqual(
            response["_investigation_query_audit"]["rounds_completed"],
            self.runner.MAX_INVESTIGATION_QUERY_ROUNDS,
        )
        self.assertEqual(
            response["_investigation_query_audit"]["requests_ignored_or_over_budget"],
            1,
        )
        self.assertNotIn("investigation_query_requests", response)
        self.assertEqual(
            len(prompt_package["investigation_query_results"]["rounds"]),
            self.runner.MAX_INVESTIGATION_QUERY_ROUNDS,
        )


    def test_loop_refreshes_citation_contract_before_follow_up_model_call(
        self,
    ) -> None:
        prompt_package = {
            "investigation_query_capability": {
                "enabled": True,
                "backends": {"elastic": {"enabled": True}},
            },
            "_local_investigation_query_context": {
                "anchor": {
                    "index": ".ds-logs-suricata.alerts-so-2026.07.24-000001",
                    "id": "alert-1",
                }
            },
        }
        query_digest = "a" * 64

        def model_executor(_route, package, _args, _settings):
            refs = {
                item["ref"]
                for item in package["evidence_reference_contract"]["references"]
            }
            self.assertIn(f"query:{query_digest}", refs)
            return {"summary": "The trusted query is now citable."}

        self.runner.apply_investigation_query_loop(
            prompt_package,
            {"investigation_query_requests": [self.elastic_request()]},
            object(),
            {"agent_models": {"soc-analyst": "codex-cli:gpt-5.5:medium"}},
            "soc-analyst",
            model_executor=model_executor,
            query_executor=mock.Mock(
                return_value={
                    "schema": self.runner.INVESTIGATION_QUERY_RESULT_SCHEMA,
                    "round": 1,
                    "requests": [self.elastic_request()],
                    "results": [
                        {
                            "query_id": "pivot-1",
                            "backend": "elastic",
                            "pack": "network_flow",
                            "query_digest": query_digest,
                            "status": "ok",
                            "returned_hits": 1,
                            "total_hits": 1,
                        }
                    ],
                    "audit": [],
                }
            ),
        )


