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

class ProviderNeutralInvestigationLoopTestsInitialModelPreflightPrecedesModelExecutionCases:
    def test_initial_model_preflight_precedes_model_execution(self) -> None:
        events: list[tuple] = []
        harness = RecordingHarness(events)

        def model_executor(*_args, **_kwargs):
            events.append(("initial_model_executor",))
            return {"summary": "Initial analysis completed."}

        settings = {
            "agent_models": {
                "soc-analyst": "codex-cli:gpt-5.6-sol:high",
            }
        }
        with mock.patch.object(
            self.runner,
            "analyze_model_route",
            side_effect=model_executor,
        ):
            response = self.runner.analyze_with_config(
                {"case_id": "case-preflight-order"},
                object(),
                settings=settings,
                harness_runtime=harness,
            )

        self.assertEqual(response["summary"], "Initial analysis completed.")
        preflight_position = next(
            index
            for index, event in enumerate(events)
            if event[:2] == ("preflight_model_call", "primary-initial")
        )
        execution_position = events.index(("initial_model_executor",))
        self.assertLess(preflight_position, execution_position)


    def test_contract_rejection_gets_one_non_widening_repair_batch(
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
                    "id": "alert-contract-repair",
                },
            },
        }
        invalid = self.elastic_request("repair-contract")
        invalid["parameters"]["query_dsl"] = {"match_all": {}}
        model_calls: list[str] = []
        events: list[tuple] = []
        harness = RecordingHarness(events)

        def model_executor(_route, package, *_args):
            if "investigation_query_planning_repair" in package:
                model_calls.append("repair")
                repair = package["investigation_query_planning_repair"]
                self.assertEqual(repair["attempt"], 1)
                self.assertEqual(repair["maximum_attempts"], 1)
                self.assertEqual(
                    [item["query_id"] for item in repair["rejected_queries"]],
                    ["repair-contract"],
                )
                return {
                    "investigation_query_requests": [
                        self.elastic_request("repair-contract")
                    ],
                }
            model_calls.append("synthesis")
            return {"summary": "Repair evidence synthesized."}

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
            harness_runtime=harness,
            model_executor=model_executor,
            query_executor=query_executor,
        )

        query_executor.assert_called_once()
        self.assertEqual(
            query_executor.call_args.kwargs["round_number"],
            2,
        )
        self.assertEqual(model_calls, ["synthesis"])
        self.assertIn(
            ("model_call", "primary-followup-1", False),
            events,
        )
        self.assertFalse(
            any(
                event[:2] == ("model_call", "primary-followup-2")
                for event in events
            )
        )
        audit = response["_investigation_query_audit"]
        self.assertTrue(audit["planning_repair_attempted"])
        self.assertTrue(audit["planning_repair_produced_requests"])
        self.assertEqual(
            audit["query_planning_repair"]["attempts"],
            1,
        )
        self.assertEqual(
            audit["query_planning_repair"]["admitted_repair_requests"],
            1,
        )
        self.assertFalse(
            audit["query_planning_repair"]["scope_widening_allowed"]
        )
        self.assertTrue(
            audit["query_planning_repair"][
                "deterministic_scope_execution"
            ]
        )
        self.assertFalse(
            audit["query_planning_repair"]["used_existing_follow_up_call"]
        )
        self.assertEqual(
            audit["query_planning_repair"]["candidates"][0]["trigger"],
            "contract_rejection",
        )


    def test_reviewer_gets_one_bounded_supplemental_pivot(self) -> None:
        route = "codex-cli:gpt-5.6-sol:xhigh"
        request = self.elastic_request("reviewer-pivot-1")
        prompt_package = {
            "investigation_query_capability": {
                "enabled": True,
                "backends": {"elastic": {"enabled": True}},
            },
            "_local_investigation_query_context": {
                "case_id": "case-reviewer-pivot",
                "anchor": {
                    "index": ".ds-logs-suricata.alerts-so-2026.07.24-000001",
                    "id": "alert-reviewer-pivot",
                },
                "permitted_observables": {
                    "ips": ["192.0.2.10"],
                    "domains": [],
                    "hosts": [],
                    "users": [],
                },
            },
        }
        initial_review = {
            "summary": "One material discriminator remains unresolved.",
            "evidence_gaps": [
                "Determine whether the destination recurred in the alert window."
            ],
            "investigation_query_requests": [request],
        }
        events: list[tuple] = []
        harness = RecordingHarness(
            events,
            remaining_model_calls=1,
            query_rounds_used=2,
            remaining_query_rounds=1,
            remaining_queries=4,
        )
        query_executor = mock.Mock(
            side_effect=lambda _package, requests, **kwargs: (
                self.successful_security_onion_round(
                    requests,
                    round_number=kwargs["round_number"],
                )
            )
        )
        final_review = {
            "summary": "Supplemental evidence reconciled the discriminator.",
            "evidence_gaps": [],
            "investigation_query_requests": [
                self.elastic_request("forbidden-recursive-reviewer-pivot")
            ],
        }

        with (
            mock.patch.object(
                self.runner,
                "execute_investigation_query_batch",
                query_executor,
            ),
            mock.patch.object(
                self.runner,
                "analyze_model_route",
                return_value=final_review,
            ) as model_executor,
            mock.patch.object(
                self.runner,
                "independent_reviewer_package",
                side_effect=lambda package, **_kwargs: {
                    "case_id": "case-reviewer-pivot",
                    "supplemental": package.get(
                        "reviewer_supplemental_context"
                    ),
                    "evidence": package.get(
                        "investigation_query_results"
                    ),
                },
            ),
            mock.patch.object(
                self.runner,
                "validate_reviewer_response",
                side_effect=lambda response, _package: response,
            ),
            mock.patch.object(
                self.runner,
                "validate_response",
                side_effect=lambda response, _package: response,
            ),
        ):
            response, audit = self.runner.apply_reviewer_supplemental_pivot(
                prompt_package,
                initial_review,
                argparse.Namespace(max_prompt_bytes=1_000_000),
                {"agent_models": {"incident-responder": route}},
                "incident-responder",
                route,
                Path("reviewer-prompt.md"),
                live_osquery_config=None,
                enrichment_config=None,
                security_onion_config_path=Path("security-onion.json"),
                investigation_pivot_dir=Path("pivots"),
                harness_runtime=harness,
            )

        self.assertTrue(audit["executed"])
        self.assertEqual(audit["request_count"], 1)
        self.assertEqual(
            audit["query_audit"]["limits"]["max_rounds"], 1
        )
        self.assertEqual(
            audit["query_audit"]["limits"]["max_queries_total"], 4
        )
        query_executor.assert_called_once()
        self.assertEqual(
            query_executor.call_args.kwargs["round_number"], 3
        )
        model_executor.assert_called_once()
        self.assertEqual(
            response["summary"],
            "Supplemental evidence reconciled the discriminator.",
        )
        self.assertIn(
            (
                "model_call",
                "independent-review-supplemental-1",
                True,
            ),
            events,
        )
        self.assertNotIn("investigation_query_requests", response)
        self.assertEqual(audit["recursive_requests_ignored"], 1)


    def test_reviewer_supplemental_pivot_requires_discriminator(self) -> None:
        response, audit = self.runner.apply_reviewer_supplemental_pivot(
            {},
            {
                "summary": "No material gap remains.",
                "investigation_query_requests": [
                    self.elastic_request("unjustified-reviewer-pivot")
                ],
            },
            argparse.Namespace(),
            {},
            "incident-responder",
            "codex-cli:gpt-5.6-sol:xhigh",
            Path("reviewer-prompt.md"),
            live_osquery_config=None,
            enrichment_config=None,
            security_onion_config_path=Path("security-onion.json"),
            investigation_pivot_dir=Path("pivots"),
            harness_runtime=RecordingHarness([]),
        )

        self.assertFalse(audit["executed"])
        self.assertIn("material unresolved discriminator", audit["reason"])
        self.assertNotIn("investigation_query_requests", response)


    def test_reviewer_supplemental_pivot_respects_model_budget(self) -> None:
        response, audit = self.runner.apply_reviewer_supplemental_pivot(
            {},
            {
                "evidence_gaps": ["A material discriminator remains."],
                "investigation_query_requests": [
                    self.elastic_request("budgeted-reviewer-pivot")
                ],
            },
            argparse.Namespace(),
            {},
            "incident-responder",
            "codex-cli:gpt-5.6-sol:xhigh",
            Path("reviewer-prompt.md"),
            live_osquery_config=None,
            enrichment_config=None,
            security_onion_config_path=Path("security-onion.json"),
            investigation_pivot_dir=Path("pivots"),
            harness_runtime=RecordingHarness(
                [], remaining_model_calls=0
            ),
        )

        self.assertFalse(audit["executed"])
        self.assertIn("no model-call budget", audit["reason"])
        self.assertNotIn("investigation_query_requests", response)


    def test_reviewer_supplemental_pivot_respects_query_round_budget(
        self,
    ) -> None:
        response, audit = self.runner.apply_reviewer_supplemental_pivot(
            {},
            {
                "evidence_gaps": ["A material discriminator remains."],
                "investigation_query_requests": [
                    self.elastic_request("round-budget-reviewer-pivot")
                ],
            },
            argparse.Namespace(),
            {},
            "incident-responder",
            "codex-cli:gpt-5.6-sol:xhigh",
            Path("reviewer-prompt.md"),
            live_osquery_config=None,
            enrichment_config=None,
            security_onion_config_path=Path("security-onion.json"),
            investigation_pivot_dir=Path("pivots"),
            harness_runtime=RecordingHarness(
                [],
                remaining_model_calls=1,
                query_rounds_used=3,
                remaining_query_rounds=0,
            ),
        )

        self.assertFalse(audit["executed"])
        self.assertIn("no query-round budget", audit["reason"])
        self.assertNotIn("investigation_query_requests", response)


    def test_malformed_observables_get_trusted_non_widening_repair(
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
                    "id": "alert-observable-repair",
                },
                "permitted_observables": {
                    "ips": ["192.0.2.10"],
                    "domains": [],
                    "hosts": [],
                    "users": [],
                },
            },
        }
        invalid = self.elastic_request("repair-observables")
        invalid["parameters"]["observables"] = [
            {"kind": "ip", "value": "192.0.2.10"},
            {"kind": "ip", "value": "untrusted.example"},
        ]

        def model_executor(_route, package, *_args):
            if "investigation_query_planning_repair" in package:
                rejected = package[
                    "investigation_query_planning_repair"
                ]["rejected_queries"][0]
                self.assertEqual(
                    rejected["observables"],
                    {
                        "ips": ["192.0.2.10"],
                        "domains": [],
                        "hosts": [],
                        "users": [],
                    },
                )
                self.assertEqual(
                    rejected["observable_scope_source"],
                    "trusted_catalog_intersection",
                )
                return {
                    "investigation_query_requests": [
                        self.elastic_request("repair-observables")
                    ],
                }
            return {"summary": "Trusted observable repair synthesized."}

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
        audit = response["_investigation_query_audit"]
        self.assertEqual(
            audit["query_planning_repair"]["admitted_repair_requests"],
            1,
        )
        self.assertEqual(
            audit["query_planning_repair"]["candidates"][0][
                "observable_scope_source"
            ],
            "trusted_catalog_intersection",
        )


    def test_malformed_untrusted_observables_remain_rejected(
        self,
    ) -> None:
        invalid = self.elastic_request("reject-untrusted-observables")
        invalid["parameters"]["observables"] = [
            {"kind": "ip", "value": "203.0.113.99"},
        ]
        scope = self.runner.investigation_query_repair_scope(
            invalid,
            round_number=1,
            position=1,
            authorization_context={
                "permitted_observables": {
                    "ips": ["192.0.2.10"],
                    "domains": [],
                    "hosts": [],
                    "users": [],
                },
            },
        )

        self.assertIsNone(scope)


    def test_empty_observables_recover_only_trusted_event_tuple_ips(
        self,
    ) -> None:
        invalid = self.elastic_request("repair-tuple-observables")
        invalid["parameters"]["observables"] = []
        invalid["parameters"]["event_tuple"] = {
            "source_ip": "192.0.2.10",
            "destination_ip": "198.51.100.20",
            "source_port": 49152,
            "destination_port": 3478,
            "transport": "udp",
        }
        scope = self.runner.investigation_query_repair_scope(
            invalid,
            round_number=1,
            position=1,
            authorization_context={
                "permitted_observables": {
                    "ips": ["192.0.2.10", "198.51.100.20"],
                    "domains": [],
                    "hosts": [],
                    "users": [],
                },
                "permitted_event_tuples": [
                    {
                        "event_tuple": dict(
                            invalid["parameters"]["event_tuple"]
                        ),
                        "role_semantics": "packet_direction",
                        "source": "trusted_context",
                    }
                ],
            },
        )

        self.assertIsNotNone(scope)
        self.assertEqual(
            scope["observable_scope_source"],
            "trusted_event_tuple_intersection",
        )
        self.assertEqual(
            scope["observables"]["ips"],
            ["192.0.2.10", "198.51.100.20"],
        )
        self.assertEqual(
            scope["event_tuple"],
            invalid["parameters"]["event_tuple"],
        )


    def test_empty_observable_object_recovers_trusted_event_tuple_ips(
        self,
    ) -> None:
        invalid = self.elastic_request("repair-empty-object-observables")
        invalid["parameters"]["observables"] = {
            "ips": [],
            "domains": [],
            "hosts": [],
            "users": [],
        }
        invalid["parameters"]["event_tuple"] = {
            "source_ip": "192.0.2.10",
            "destination_ip": "198.51.100.20",
            "source_port": 49152,
            "destination_port": 3478,
            "transport": "udp",
        }
        scope = self.runner.investigation_query_repair_scope(
            invalid,
            round_number=1,
            position=1,
            authorization_context={
                "permitted_observables": {
                    "ips": ["192.0.2.10", "198.51.100.20"],
                    "domains": [],
                    "hosts": [],
                    "users": [],
                },
                "permitted_event_tuples": [
                    {
                        "event_tuple": dict(
                            invalid["parameters"]["event_tuple"]
                        ),
                        "role_semantics": "packet_direction",
                        "source": "trusted_context",
                    }
                ],
            },
        )

        self.assertIsNotNone(scope)
        self.assertEqual(
            scope["observable_scope_source"],
            "trusted_event_tuple_intersection",
        )
        self.assertEqual(
            scope["observables"]["ips"],
            ["192.0.2.10", "198.51.100.20"],
        )
        self.assertEqual(
            scope["event_tuple"],
            invalid["parameters"]["event_tuple"],
        )

        invalid["parameters"]["event_tuple"]["destination_ip"] = (
            "203.0.113.99"
        )
        rejected_scope = self.runner.investigation_query_repair_scope(
            invalid,
            round_number=1,
            position=1,
            authorization_context={
                "permitted_observables": {
                    "ips": ["192.0.2.10", "198.51.100.20"],
                    "domains": [],
                    "hosts": [],
                    "users": [],
                },
                "permitted_event_tuples": [
                    {
                        "event_tuple": {
                            "source_ip": "192.0.2.10",
                            "destination_ip": "198.51.100.20",
                            "source_port": 49152,
                            "destination_port": 3478,
                            "transport": "udp",
                        },
                        "role_semantics": "packet_direction",
                        "source": "trusted_context",
                    }
                ],
            },
        )
        self.assertIsNone(rejected_scope)


    def test_repair_scope_uses_authorized_pack_tuple_projection(
        self,
    ) -> None:
        invalid = self.elastic_request("repair-projected-tuple")
        invalid["parameters"]["pack"] = "zeek_http"
        invalid["parameters"]["observables"] = []
        invalid["parameters"]["event_tuple"] = {
            "source_ip": "192.0.2.10",
            "destination_ip": "198.51.100.20",
            "source_port": 49152,
            "destination_port": 80,
            "transport": "tcp",
            "community_id": "1:trusted-flow=",
            "rule_id": "2013504",
        }
        authorization_context = {
            "permitted_observables": {
                "ips": ["192.0.2.10", "198.51.100.20"],
                "domains": [],
                "hosts": [],
                "users": [],
            },
            "permitted_event_tuples": [
                {
                    "event_tuple": dict(
                        invalid["parameters"]["event_tuple"]
                    ),
                    "role_semantics": "packet_direction",
                    "source": "trusted_context",
                }
            ],
        }
        scope = self.runner.investigation_query_repair_scope(
            invalid,
            round_number=1,
            position=1,
            authorization_context=authorization_context,
        )

        self.assertIsNotNone(scope)
        self.assertNotIn("rule_id", scope["event_tuple"])
        self.assertEqual(
            scope["event_tuple"]["community_id"],
            "1:trusted-flow=",
        )
        repaired = (
            self.runner.investigation_query_request_from_repair_scope(
                scope
            )
        )
        normalized = self.runner.normalize_investigation_query_request(
            repaired,
            round_number=2,
            position=1,
            authorization_context=authorization_context,
        )
        self.runner.validate_investigation_query_repair_scope(
            normalized,
            scope,
        )
        self.assertEqual(
            normalized["parameters"]["event_tuple"],
            scope["event_tuple"],
        )


    def test_deterministic_repair_does_not_ask_model_to_widen_scope(
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
                    "id": "alert-widening-repair",
                },
            },
        }
        invalid = self.elastic_request("repair-widening")
        invalid["parameters"]["query_dsl"] = {"match_all": {}}
        calls = 0

        def model_executor(_route, package, *_args):
            nonlocal calls
            calls += 1
            if "investigation_query_planning_repair" in package:
                widened = self.elastic_request("repair-widening")
                widened["parameters"]["observables"]["ips"].append(
                    "203.0.113.99"
                )
                return {"investigation_query_requests": [widened]}
            return {"summary": "Widening was blocked."}

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
            repaired_request["parameters"]["observables"]["ips"],
            ["192.0.2.10"],
        )
        self.assertEqual(calls, 1)
        audit = response["_investigation_query_audit"]
        self.assertEqual(
            audit["query_planning_repair"]["attempts"],
            1,
        )
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


