from __future__ import annotations

from ai_model_routing_fixtures import (
    BIN_DIR,
    ExitStack,
    PIPELINE_ADAPTERS,
    Path,
    REPO_ROOT,
    RUNNER_PATH,
    ThreadPoolExecutor,
    build_agent_memory_context_contract,
    copy,
    hashlib,
    importlib,
    io,
    json,
    load_runner,
    mock,
    sys,
    tempfile,
    unittest,
)

class AiModelRoutingTestsBoundedAdjudicatorUsesClosedShadowContractCases:
    def test_bounded_adjudicator_uses_closed_shadow_contract(self) -> None:
        prompt_file = Path("/tmp/synthetic-disagreement-adjudicator.md")
        args = type(
            "Args",
            (),
            {"disagreement_adjudicator_prompt_file": prompt_file},
        )()
        settings = self.runner.default_ai_settings()
        settings["enabled_ollama_models"] = [
            "primary:latest",
            "reviewer:latest",
            "adjudicator:latest",
        ]
        settings["agent_models"]["soc-analyst"] = "ollama:primary:latest"
        settings["agent_second_opinion_models"]["soc-analyst"] = (
            "ollama:reviewer:latest"
        )
        settings["agent_adjudicator_models"]["soc-analyst"] = (
            "ollama:adjudicator:latest"
        )
        comparison = {
            "primary": {"detection_outcome": "inconclusive"},
            "reviewer": {"detection_outcome": "true_positive_suspicious"},
            "disputed_fields": [
                {
                    "field": "detection_outcome",
                    "primary": "inconclusive",
                    "reviewer": "true_positive_suspicious",
                    "material": True,
                }
            ],
            "material_disagreement": True,
        }
        phases: list[tuple[str, str, str]] = []

        def adjudicated(route, package, *unused_args, **unused_kwargs):
            contract = package["adjudication_contract"]
            return {
                "adjudication_case_id": contract["case_id"],
                "adjudication_evidence_hash": contract["evidence_hash"],
                "decision": "unresolved",
                "confidence": "medium",
                "confidence_score": 0.55,
                "resolved_fields": [],
                "remaining_disagreements": ["detection_outcome"],
                "evidence_used": ["alert:synthetic-adjudication"],
                "rationale": "The bounded alert evidence does not distinguish the positions.",
                "additional_evidence_needed": [
                    (
                        "Microsoft Update Assistant executable path, signing "
                        "status, hash, and command line."
                    )
                ],
            }

        with mock.patch.object(
            self.runner,
            "analyze_model_route",
            side_effect=adjudicated,
        ) as analyze:
            prompt_package = {
                "alert": {"alert_id": "synthetic-adjudication"},
                **self.trusted_endpoint_executable_prompt(),
            }
            result = self.runner.run_bounded_disagreement_adjudication(
                prompt_package,
                self.complete_response(),
                self.complete_response(),
                comparison,
                args,
                settings,
                "soc-analyst",
                phase_callback=lambda phase, route, trigger: phases.append(
                    (phase, route, trigger)
                ),
            )

        analyze.assert_called_once()
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["decision"], "unresolved")
        self.assertEqual(result["mode"], "shadow")
        self.assertFalse(result["automation_authorized"])
        self.assertTrue(result["human_adjudication_required"])
        self.assertEqual(
            result["response"]["additional_evidence_needed"],
            [
                (
                    "Microsoft Update Assistant signing status, hash, and "
                    "command line."
                )
            ],
        )
        self.assertEqual(analyze.call_args.args[0], "ollama:adjudicator:latest")
        self.assertTrue(analyze.call_args.kwargs["independent_review"])
        self.assertEqual(analyze.call_args.kwargs["system_prompt_file"], prompt_file)
        self.assertNotIn(
            "second_opinion_review",
            analyze.call_args.args[1],
        )
        self.assertEqual(phases[0][0], "disagreement_adjudication")


    def test_harnessed_adjudicator_reuses_frozen_reviewer_route(self) -> None:
        prompt_file = Path("/tmp/synthetic-disagreement-adjudicator.md")
        args = type(
            "Args",
            (),
            {"disagreement_adjudicator_prompt_file": prompt_file},
        )()
        settings = self.runner.default_ai_settings()
        settings["enabled_ollama_models"] = [
            "primary:latest",
            "reviewer:latest",
            "adjudicator:latest",
        ]
        settings["agent_models"]["incident-responder"] = (
            "ollama:primary:latest"
        )
        settings["agent_second_opinion_models"]["incident-responder"] = (
            "ollama:reviewer:latest"
        )
        settings["agent_adjudicator_models"]["incident-responder"] = (
            "ollama:adjudicator:latest"
        )
        comparison = {
            "primary": {"detection_outcome": "inconclusive"},
            "reviewer": {"detection_outcome": "true_positive_suspicious"},
            "disputed_fields": [
                {
                    "field": "detection_outcome",
                    "primary": "inconclusive",
                    "reviewer": "true_positive_suspicious",
                    "material": True,
                }
            ],
            "material_disagreement": True,
        }

        class Harness:
            envelope = type(
                "Envelope",
                (),
                {"assigned_reviewer_route": "ollama:reviewer:latest"},
            )()

            def __init__(self) -> None:
                self.preflights = []
                self.calls = []

            def preflight_model_call(self, **kwargs) -> None:
                self.preflights.append(kwargs)

            def model_call(self, **kwargs) -> None:
                self.calls.append(kwargs)

        harness = Harness()

        def adjudicated(route, package, *unused_args, **unused_kwargs):
            contract = package["adjudication_contract"]
            return {
                "_analysis_model_route": route,
                "adjudication_case_id": contract["case_id"],
                "adjudication_evidence_hash": contract["evidence_hash"],
                "decision": "unresolved",
                "confidence": "medium",
                "confidence_score": 0.55,
                "resolved_fields": [],
                "remaining_disagreements": ["detection_outcome"],
                "evidence_used": ["alert:synthetic-harness-adjudication"],
                "rationale": "The bounded evidence does not resolve the disagreement.",
                "additional_evidence_needed": ["Collect endpoint evidence."],
            }

        with mock.patch.object(
            self.runner,
            "analyze_model_route",
            side_effect=adjudicated,
        ) as analyze:
            result = self.runner.run_bounded_disagreement_adjudication(
                {"alert": {"alert_id": "synthetic-harness-adjudication"}},
                self.complete_response(),
                self.complete_response(),
                comparison,
                args,
                settings,
                "incident-responder",
                harness_runtime=harness,
            )

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["route_source"], "frozen_reviewer_route")
        self.assertEqual(
            analyze.call_args.args[0], "ollama:reviewer:latest"
        )
        self.assertEqual(
            harness.preflights[0]["requested_route"],
            "ollama:reviewer:latest",
        )
        self.assertTrue(harness.preflights[0]["independent_review"])
        self.assertEqual(
            harness.calls[0]["purpose"],
            "bounded disagreement adjudication",
        )


    def test_adjudicator_rejects_a_synthetic_compromise_position(self) -> None:
        package = {
            "adjudication_contract": {
                "case_id": "case-1",
                "evidence_hash": "a" * 64,
                "allowed_decisions": [
                    "primary_supported",
                    "reviewer_supported",
                    "unresolved",
                ],
                "disputed_fields": ["detection_outcome"],
                "material_fields": ["detection_outcome"],
            },
            "evidence_reference_contract": {
                "references": [
                    {"ref": "alert:case-1", "corroborating": True},
                ],
            },
        }
        response = {
            "adjudication_case_id": "case-1",
            "adjudication_evidence_hash": "a" * 64,
            "decision": "compromise_consensus",
            "confidence": "medium",
            "confidence_score": 0.5,
            "resolved_fields": [],
            "remaining_disagreements": ["detection_outcome"],
            "evidence_used": ["alert:case-1"],
            "rationale": "Synthetic compromise is outside the contract.",
            "additional_evidence_needed": [],
        }

        with self.assertRaisesRegex(
            self.runner.DisagreementAdjudicationValidationError,
            "closed vocabulary",
        ):
            self.runner.validate_disagreement_adjudication(response, package)


    def test_ollama_second_opinion_uses_explicit_independent_review_task(self) -> None:
        args = type("Args", (), {})()
        prompt_package = {
            "alert": {"rule_name": "Synthetic TLS alert"},
            "response_schema": {"type": "object"},
        }

        with (
            mock.patch.object(
                self.runner,
                "_ollama_request",
                return_value={"summary": "Independent review"},
            ) as request,
            mock.patch.object(self.runner, "_unload_ollama_model"),
        ):
            result = self.runner._ollama_chat_for_model(
                prompt_package,
                args,
                {},
                "reviewer:latest",
                independent_review=True,
            )

        self.assertEqual(result["summary"], "Independent review")
        evidence = request.call_args.args[0]
        task = request.call_args.args[3]
        self.assertNotIn("primary_analysis", json.dumps(evidence))
        self.assertIn("Independently analyze", task)
        self.assertIn("intentionally been withheld", task)
        self.assertIn("do not request another opinion", task)


    def test_low_confidence_primary_runs_configured_second_opinion(self) -> None:
        reviewer_prompt = Path("/tmp/synthetic-soc-reviewer-prompt.md")
        args = type("Args", (), {"second_opinion_prompt_file": reviewer_prompt})()
        settings = self.runner.default_ai_settings()
        settings["enabled_ollama_models"] = ["primary:latest", "reviewer:latest"]
        settings["agent_models"]["soc-analyst"] = "ollama:primary:latest"
        settings["agent_second_opinion_models"]["soc-analyst"] = "ollama:reviewer:latest"
        primary = self.runner.validate_response(self.complete_response(
            confidence="low",
            confidence_score=0.3,
            detection_outcome="inconclusive",
            summary="Primary assessment",
        ))
        secondary = self.complete_response(
            confidence="high",
            confidence_score=0.9,
            detection_outcome="true_positive_suspicious",
            event_status="observed",
            detection_validity="matched_intent",
            activity_disposition="suspicious",
            handling="escalate",
            duplicate_of=None,
            hypotheses=[],
            evidence_used=["alert", "alert:synthetic-review"],
            bluf="True Positive - Suspicious: independent review.",
            summary="Independent review",
            escalation_needed=True,
        )
        phases: list[tuple[str, str, str]] = []

        def reviewed_response(route, review_package, *unused_args, **unused_kwargs):
            contract = review_package["review_contract"]
            return {
                **secondary,
                "review_case_id": contract["case_id"],
                "review_evidence_hash": contract["evidence_hash"],
                "observables_used": [],
            }

        with mock.patch.object(self.runner, "analyze_model_route", side_effect=reviewed_response) as analyze:
            result = self.runner.apply_configured_second_opinion(
                {"alert": {"alert_id": "synthetic-review"}},
                primary,
                args,
                settings,
                "soc-analyst",
                phase_callback=lambda phase, route, trigger: phases.append((phase, route, trigger)),
            )

        analyze.assert_called_once()
        self.assertEqual(analyze.call_args.args[0], "ollama:reviewer:latest")
        self.assertEqual(
            analyze.call_args.args[1]["second_opinion_review"]["mode"],
            "blind_independent",
        )
        self.assertIs(analyze.call_args.args[2], args)
        self.assertIs(analyze.call_args.args[3], settings)
        self.assertEqual(analyze.call_args.kwargs["system_prompt_file"], reviewer_prompt)
        self.assertTrue(analyze.call_args.kwargs["independent_review"])
        self.assertEqual(result["_second_opinion"]["status"], "completed")
        self.assertEqual(result["_second_opinion"]["response"]["confidence"], "medium")
        self.assertEqual(
            result["_second_opinion"]["response"]["_confidence_calibration"][
                "evidence_signals"
            ]["corroborating_evidence_source_count"],
            1,
        )
        self.assertFalse(result["_second_opinion"]["response"]["second_opinion_recommended"])
        self.assertEqual(
            result["_second_opinion"]["comparison"]["agreement"],
            "material_disagreement",
        )
        self.assertFalse(
            result["_second_opinion"]["automation_authorization"][
                "authorized"
            ]
        )
        self.assertEqual(
            result["_second_opinion"]["automation_authorization"][
                "reason_code"
            ],
            "material_disagreement",
        )
        self.assertEqual(result["final_disposition_status"], "disputed_pending_human")
        self.assertTrue(result["escalation_needed"])
        self.assertEqual(result["detection_outcome"], "inconclusive")
        self.assertEqual(result["activity_disposition"], "unknown")
        self.assertEqual(result["handling"], "investigate")
        self.assertEqual(result["confidence"], "low")
        self.assertLessEqual(result["confidence_score"], 0.39)
        self.assertTrue(result["bluf"].startswith("DISPUTED"))
        self.assertTrue(result["_material_disagreement_gate"]["applied"])
        self.assertEqual(result["tuning_recommendation"], "needs_more_data")
        self.assertEqual(result["recommended_tuning_actions"], [])
        self.assertEqual(result["memory_candidates"], [])
        self.assertTrue(result["_automation_controls"]["tuning_blocked"])
        self.assertTrue(result["_automation_controls"]["memory_writeback_blocked"])
        self.assertEqual(
            phases,
            [
                (
                    "second_opinion",
                    "ollama:reviewer:latest",
                    "The primary model reported low confidence.",
                ),
                (
                    "post_processing",
                    "",
                    "The primary model reported low confidence.",
                ),
            ],
        )


    def test_reviewer_foreign_case_retries_once_then_fails_closed(self) -> None:
        args = type(
            "Args",
            (),
            {"second_opinion_prompt_file": Path("/tmp/reviewer.md")},
        )()
        settings = self.runner.default_ai_settings()
        settings["enabled_ollama_models"] = ["primary:latest", "reviewer:latest"]
        settings["agent_models"]["soc-analyst"] = "ollama:primary:latest"
        settings["agent_second_opinion_models"]["soc-analyst"] = "ollama:reviewer:latest"
        primary = self.runner.validate_response(
            self.complete_response(
                confidence="low",
                confidence_score=0.3,
                handling="contain",
                memory_candidates=[
                    {
                        "scope": "agent",
                        "category": "investigation_pivot",
                        "finding": "Synthetic reusable lesson with enough bounded detail.",
                        "use_when": "A later synthetic alert needs the same discriminator.",
                        "evidence_basis": ["Synthetic evidence."],
                        "confidence": "medium",
                        "tags": ["synthetic"],
                        "ttl_days": 30,
                    }
                ],
            )
        )
        invalid = {
            **self.complete_response(),
            "event_status": "observed",
            "detection_validity": "matched_intent",
            "activity_disposition": "suspicious",
            "handling": "escalate",
            "duplicate_of": None,
            "confidence_score": 0.9,
            "hypotheses": [],
            "review_case_id": "foreign-case",
            "review_evidence_hash": "b" * 64,
            "observables_used": [{"kind": "ip", "value": "10.0.0.50"}],
        }

        with mock.patch.object(
            self.runner,
            "analyze_model_route",
            return_value=invalid,
        ) as analyze:
            result = self.runner.apply_configured_second_opinion(
                {"alert": {"alert_id": "current-case", "source_ip": "192.0.2.10"}},
                primary,
                args,
                settings,
                "soc-analyst",
            )

        self.assertEqual(analyze.call_count, 2)
        self.assertEqual(result["_second_opinion"]["status"], "failed")
        self.assertEqual(result["final_disposition_status"], "review_required_failed")
        self.assertEqual(result["confidence"], "low")
        self.assertLessEqual(result["confidence_score"], 0.39)
        self.assertEqual(result["handling"], "investigate")
        self.assertEqual(result["memory_candidates"], [])
        self.assertTrue(result["_automation_controls"]["automatic_closure_blocked"])
        self.assertTrue(result["_automation_controls"]["containment_blocked"])
        self.assertTrue(result["_automation_controls"]["memory_writeback_blocked"])


    def test_reviewer_invalid_evidence_retries_once_then_fails_closed(self) -> None:
        args = type(
            "Args",
            (),
            {"second_opinion_prompt_file": Path("/tmp/reviewer.md")},
        )()
        settings = self.runner.default_ai_settings()
        settings["enabled_ollama_models"] = ["primary:latest", "reviewer:latest"]
        settings["agent_models"]["soc-analyst"] = "ollama:primary:latest"
        settings["agent_second_opinion_models"]["soc-analyst"] = "ollama:reviewer:latest"
        primary = self.runner.validate_response(
            self.complete_response(
                confidence="low",
                confidence_score=0.3,
                handling="contain",
            )
        )

        def invalid_response(_route, review_package, *_args, **_kwargs):
            contract = review_package["review_contract"]
            return {
                **self.complete_response(
                    confidence="high",
                    confidence_score=0.9,
                    evidence_used=["query:invented-digest"],
                ),
                "event_status": "observed",
                "detection_validity": "matched_intent",
                "activity_disposition": "suspicious",
                "handling": "escalate",
                "duplicate_of": None,
                "hypotheses": [],
                "review_case_id": contract["case_id"],
                "review_evidence_hash": contract["evidence_hash"],
                "observables_used": [],
            }

        with mock.patch.object(
            self.runner,
            "analyze_model_route",
            side_effect=invalid_response,
        ) as analyze:
            result = self.runner.apply_configured_second_opinion(
                {"alert": {"alert_id": "current-case"}},
                primary,
                args,
                settings,
                "soc-analyst",
            )

        self.assertEqual(analyze.call_count, 2)
        self.assertEqual(result["_second_opinion"]["status"], "failed")
        self.assertIn(
            "outside the current contract",
            result["_second_opinion"]["error"],
        )
        self.assertEqual(result["final_disposition_status"], "review_required_failed")
        self.assertTrue(result["_automation_controls"]["automatic_closure_blocked"])
        self.assertTrue(result["_automation_controls"]["containment_blocked"])


    def test_controlled_evaluation_reviewer_gate_allows_first_or_repaired_response(
        self,
    ) -> None:
        args = type(
            "Args",
            (),
            {"second_opinion_prompt_file": Path("/tmp/reviewer.md")},
        )()
        settings = self.runner.default_ai_settings()
        settings["enabled_ollama_models"] = [
            "primary:latest",
            "reviewer:latest",
        ]
        settings["agent_models"]["soc-analyst"] = "ollama:primary:latest"
        settings["agent_second_opinion_models"][
            "soc-analyst"
        ] = "ollama:reviewer:latest"
        prompt_package = {"alert": {"alert_id": "evaluation-review-case"}}

        def candidate(review_package, *, valid):
            contract = review_package["review_contract"]
            return {
                **self.complete_response(
                    confidence="high",
                    confidence_score=0.9,
                    evidence_used=[
                        "alert",
                        "alert:evaluation-review-case",
                    ],
                    event_status="unknown",
                    detection_validity="unknown",
                    activity_disposition="unknown",
                    handling="investigate",
                    duplicate_of=None,
                    hypotheses=[],
                ),
                "review_case_id": (
                    contract["case_id"] if valid else "foreign-case"
                ),
                "review_evidence_hash": contract["evidence_hash"],
                "observables_used": [],
            }

        for repaired in (False, True):
            with self.subTest(repaired=repaired):
                primary = self.runner.validate_response(
                    self.complete_response(
                        confidence="low",
                        confidence_score=0.3,
                        detection_outcome="inconclusive",
                    ),
                    prompt_package,
                )
                trigger = self.runner.second_opinion_trigger(
                    primary,
                    prompt_package,
                )
                calls = 0

                def reviewed_response(
                    _route,
                    review_package,
                    *_args,
                    **_kwargs,
                ):
                    nonlocal calls
                    calls += 1
                    return candidate(
                        review_package,
                        valid=not repaired or calls == 2,
                    )

                with mock.patch.object(
                    self.runner,
                    "analyze_model_route",
                    side_effect=reviewed_response,
                ):
                    response = self.runner.apply_configured_second_opinion(
                        prompt_package,
                        primary,
                        args,
                        settings,
                        "soc-analyst",
                    )

                reviewer = (
                    self.runner.precommit_controlled_evaluation_reviewer_gate(
                        prompt_package,
                        response,
                        settings,
                        "soc-analyst",
                        trigger_reason=trigger,
                        freeze_enabled=True,
                    )
                )
                self.assertIs(
                    reviewer,
                    response["_second_opinion"]["response"],
                )
                self.assertEqual(calls, 2 if repaired else 1)
                self.assertEqual(
                    response["_second_opinion"]["attempts"],
                    2 if repaired else 1,
                )
                self.assertEqual(
                    len(response["_second_opinion"]["validation_failures"]),
                    1 if repaired else 0,
                )
