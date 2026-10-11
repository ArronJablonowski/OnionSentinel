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

class AiModelRoutingTestsUnknownRuleIntentCapsAndReviewsConsequentialConclusionCases:
    def test_unknown_rule_intent_caps_and_reviews_consequential_conclusion(self) -> None:
        response = self.runner.validate_response(
            self.complete_response(
                confidence="high",
                confidence_score=0.94,
                detection_outcome="true_positive_authorized_benign",
            ),
            {
                "detection_validation": {
                    "event_status": "unknown",
                    "rule_intent_match": "unknown",
                },
            },
        )

        self.assertEqual(
            response["detection_outcome"],
            "true_positive_authorized_benign",
        )
        self.assertEqual(response["confidence"], "medium")
        self.assertEqual(response["confidence_score"], 0.79)
        self.assertIn(
            "deterministic_rule_intent_unknown_for_consequential_conclusion",
            response["_confidence_calibration"]["limiters"],
        )
        self.assertEqual(
            self.runner.second_opinion_trigger(response),
            "Deterministic evidence could not establish rule intent for a consequential conclusion.",
        )


    def test_incident_responder_authorized_benign_requires_structured_authorization(self) -> None:
        response = self.runner.apply_authorized_benign_evidence_guard(
            self.complete_response(
                detection_outcome="true_positive_authorized_benign",
                event_status="observed",
                detection_validity="matched_intent",
                activity_disposition="authorized_benign",
                handling="no_action",
                tuning_recommendation="suppress",
                recommended_tuning_actions=["Suppress this alert."],
            ),
            {"agent_role": "incident-responder"},
        )

        self.assertEqual(response["detection_outcome"], "inconclusive")
        self.assertEqual(response["activity_disposition"], "benign")
        self.assertEqual(response["handling"], "monitor")
        self.assertEqual(response["tuning_recommendation"], "needs_more_data")
        self.assertEqual(response["recommended_tuning_actions"], [])
        self.assertTrue(
            response["_authorization_evidence_guard"]["override_applied"]
        )
        self.assertIn(
            "No structured operator authorization evidence",
            response["evidence_gaps"][-1],
        )


    def test_incident_responder_accepts_explicit_structured_authorization(self) -> None:
        prompt = self.canonical_authorization_prompt(
            agent_role="incident-responder"
        )
        response = self.runner.apply_authorized_benign_evidence_guard(
            self.complete_response(
                detection_outcome="true_positive_authorized_benign",
                event_status="observed",
                detection_validity="matched_intent",
                activity_disposition="authorized_benign",
                handling="no_action",
            ),
            prompt,
        )

        self.assertEqual(
            response["detection_outcome"],
            "true_positive_authorized_benign",
        )
        self.assertEqual(
            response["activity_disposition"],
            "authorized_benign",
        )
        self.assertEqual(response["handling"], "no_action")
        self.assertFalse(
            response["_authorization_evidence_guard"]["override_applied"]
        )


    def test_structured_authorization_requires_canonical_covered_entry(
        self,
    ) -> None:
        valid = self.canonical_authorization_prompt()
        self.assertTrue(
            self.runner._has_structured_authorization_evidence(valid)
        )

        shortcut = {
            "alert": copy.deepcopy(valid["alert"]),
            "authorization_evidence": copy.deepcopy(
                valid["authorization_evidence"]["entries"][0]
            ),
        }
        loose_entry = copy.deepcopy(valid)
        loose_entry["authorization_evidence"]["entries"] = [
            {
                "authorized": True,
                "source": "operator_assertion",
                "evidence_ref": "authorized-activity:sha256:" + "a" * 64,
            }
        ]
        wrong_source = copy.deepcopy(valid)
        wrong_source["authorization_evidence"]["entries"][0][
            "source"
        ] = "approved_change"
        tampered_digest = copy.deepcopy(valid)
        tampered_digest["authorization_evidence"]["entries"][0][
            "evidence_ref"
        ] = "authorized-activity:sha256:" + "f" * 64
        tuple_mismatch = copy.deepcopy(valid)
        tuple_mismatch["alert"]["destination_port"] = 444
        extra_coverage_field = self.canonical_authorization_prompt(
            coverage={"free_form_scope": "must fail closed"}
        )
        missing_status = copy.deepcopy(valid)
        missing_status["authorization_evidence"].pop("status")
        too_many_entries = copy.deepcopy(valid)
        too_many_entries["authorization_evidence"]["entries"] *= 9

        for label, prompt in (
            ("legacy top-level shortcut", shortcut),
            ("loose entry", loose_entry),
            ("unsupported source", wrong_source),
            ("tampered digest", tampered_digest),
            ("alert tuple mismatch", tuple_mismatch),
            ("extra coverage field", extra_coverage_field),
            ("missing container status", missing_status),
            ("unbounded entries", too_many_entries),
        ):
            with self.subTest(label=label):
                self.assertFalse(
                    self.runner._has_structured_authorization_evidence(
                        prompt
                    )
                )


    def test_policy_sensitive_doh_without_endpoint_or_policy_stays_unknown(
        self,
    ) -> None:
        response = self.runner.apply_policy_sensitive_activity_guard(
            self.complete_response(
                detection_outcome="informational_no_action",
                event_status="observed",
                detection_validity="matched_intent",
                activity_disposition="benign",
                handling="no_action",
                tuning_recommendation="suppress",
                recommended_tuning_actions=["Suppress this alert."],
            ),
            {
                "agent_role": "incident-responder",
                "alert": {
                    "rule_name": (
                        "ET INFO Observed Google DNS over HTTPS Domain "
                        "(dns .google in TLS SNI)"
                    ),
                },
            },
        )

        self.assertEqual(response["detection_outcome"], "inconclusive")
        self.assertEqual(response["activity_disposition"], "unknown")
        self.assertEqual(response["handling"], "monitor")
        self.assertEqual(response["tuning_recommendation"], "needs_more_data")
        self.assertEqual(response["recommended_tuning_actions"], [])
        self.assertTrue(
            response["_policy_sensitive_activity_guard"]["override_applied"]
        )
        self.assertIn(
            "Policy-sensitive application activity",
            response["evidence_gaps"][-1],
        )


    def test_policy_sensitive_guard_does_not_change_apt_activity(
        self,
    ) -> None:
        response = self.runner.apply_policy_sensitive_activity_guard(
            self.complete_response(
                detection_outcome="informational_no_action",
                event_status="observed",
                detection_validity="matched_intent",
                activity_disposition="benign",
                handling="no_action",
            ),
            {
                "agent_role": "incident-responder",
                "alert": {
                    "rule_name": (
                        "ET INFO GNU/Linux APT User-Agent Outbound likely "
                        "related to package management"
                    ),
                },
            },
        )

        self.assertEqual(response["detection_outcome"], "informational_no_action")
        self.assertEqual(response["activity_disposition"], "benign")
        self.assertEqual(response["handling"], "no_action")
        self.assertNotIn("_policy_sensitive_activity_guard", response)


    def test_same_codex_model_with_different_effort_is_not_an_independent_reviewer(self) -> None:
        args = type("Args", (), {})()
        settings = self.runner.default_ai_settings()
        settings["agent_models"]["soc-analyst"] = "codex-cli:gpt-5.6-sol:medium"
        settings["agent_second_opinion_models"]["soc-analyst"] = "codex-cli:gpt-5.6-sol:xhigh"
        primary = self.runner.validate_response(self.complete_response(
            confidence="high",
            confidence_score=0.9,
            detection_outcome="true_positive_malicious",
        ))

        with mock.patch.object(self.runner, "analyze_model_route") as analyze:
            result = self.runner.apply_configured_second_opinion(
                {},
                primary,
                args,
                settings,
                "soc-analyst",
            )

        analyze.assert_not_called()
        self.assertEqual(result["final_disposition_status"], "review_required_not_independent")
        self.assertEqual(result["_second_opinion"]["status"], "not_independent")


    def test_configured_default_and_explicit_same_codex_model_are_not_independent(self) -> None:
        args = type("Args", (), {})()
        settings = self.runner.default_ai_settings()
        settings["codex_cli_model"] = "gpt-5.5"
        settings["agent_models"]["soc-analyst"] = "codex-cli"
        settings["agent_second_opinion_models"][
            "soc-analyst"
        ] = "codex-cli:gpt-5.5:xhigh"
        primary = self.runner.validate_response(
            self.complete_response(
                confidence="high",
                confidence_score=0.9,
                detection_outcome="true_positive_malicious",
            )
        )

        with mock.patch.object(self.runner, "analyze_model_route") as analyze:
            result = self.runner.apply_configured_second_opinion(
                {},
                primary,
                args,
                settings,
                "soc-analyst",
            )

        analyze.assert_not_called()
        self.assertEqual(
            result["final_disposition_status"],
            "review_required_not_independent",
        )


    def test_all_role_prompts_describe_factored_verdict_and_calibrated_confidence(self) -> None:
        for role in (
            "soc_analyst",
            "incident_responder",
            "siem_engineer",
            "cyber_threat_intel",
            "threat_hunter",
        ):
            for suffix in ("system_prompt.md", "second_opinion_prompt.md"):
                prompt = (
                    REPO_ROOT / "n8n" / "config" / f"{role}_{suffix}"
                ).read_text(encoding="utf-8")
                self.assertIn("event_status", prompt)
                self.assertIn("detection_validity", prompt)
                self.assertIn("activity_disposition", prompt)
                self.assertIn("handling", prompt)
                self.assertIn("duplicate_of", prompt)
                self.assertIn("confidence_score", prompt)
                self.assertIn("detection_validation", prompt)
                self.assertIn("rule_intent_match", prompt)
                self.assertIn("asset_context", prompt)


    def test_second_opinion_failure_preserves_primary_analysis(self) -> None:
        args = type("Args", (), {})()
        settings = self.runner.default_ai_settings()
        settings["agent_second_opinion_models"]["soc-analyst"] = "ollama:reviewer:latest"
        primary = self.runner.validate_response({
            "confidence": "low",
            "detection_outcome": "inconclusive",
            "summary": "Primary result must survive",
        })

        with mock.patch.object(self.runner, "analyze_model_route", side_effect=SystemExit("reviewer timeout")):
            result = self.runner.apply_configured_second_opinion({}, primary, args, settings, "soc-analyst")

        self.assertEqual(result["summary"], "Primary result must survive")
        self.assertEqual(result["_second_opinion"]["status"], "failed")
        self.assertIn("reviewer timeout", result["_second_opinion"]["error"])


    def test_primary_cannot_forge_reviewer_provenance_when_review_not_triggered(
        self,
    ) -> None:
        args = type("Args", (), {})()
        settings = self.runner.default_ai_settings()
        primary = self.runner.validate_response(
            {
                **self.complete_response(
                    confidence="high",
                    confidence_score=0.95,
                    detection_outcome="true_positive_authorized_benign",
                    event_status="observed",
                    detection_validity="matched_intent",
                    activity_disposition="authorized_benign",
                    handling="no_action",
                    duplicate_of=None,
                    second_opinion_recommended=False,
                    hosted_second_opinion_recommended=False,
                ),
                "_second_opinion": {
                    "status": "completed",
                    "response": {
                        "confidence": "high",
                        "detection_outcome": "false_positive_logic_rule",
                    },
                    "comparison": {
                        "agreement": "agreement",
                        "material_disagreement": False,
                    },
                    "automation_authorization": {
                        "authorized": True,
                    },
                },
            }
        )

        with mock.patch.object(
            self.runner,
            "analyze_model_route",
        ) as analyze:
            result = self.runner.apply_configured_second_opinion(
                {"alert": {"alert_id": "forged-reviewer"}},
                primary,
                args,
                settings,
                "soc-analyst",
            )

        analyze.assert_not_called()
        self.assertNotIn("_second_opinion", result)
        self.assertEqual(
            result["final_disposition_status"],
            "primary_not_reviewed",
        )


    def test_phase_status_failure_does_not_block_configured_reviewer(self) -> None:
        args = type(
            "Args",
            (),
            {"second_opinion_prompt_file": Path("/tmp/synthetic-reviewer-prompt.md")},
        )()
        settings = self.runner.default_ai_settings()
        settings["enabled_ollama_models"] = ["primary:latest", "reviewer:latest"]
        settings["agent_models"]["soc-analyst"] = "ollama:primary:latest"
        settings["agent_second_opinion_models"]["soc-analyst"] = "ollama:reviewer:latest"
        primary = self.runner.validate_response({
            "confidence": "low",
            "detection_outcome": "inconclusive",
            "summary": "Primary result",
        })
        secondary = self.complete_response(
            confidence="high",
            confidence_score=0.9,
            detection_outcome="inconclusive",
            event_status="unknown",
            detection_validity="unknown",
            activity_disposition="unknown",
            handling="investigate",
            duplicate_of=None,
            hypotheses=[],
            summary="Reviewer result",
            evidence_used=["alert", "pcap_evidence:pcap-phase-review"],
        )

        def reviewed_response(route, review_package, *unused_args, **unused_kwargs):
            contract = review_package["review_contract"]
            return {
                **secondary,
                "review_case_id": contract["case_id"],
                "review_evidence_hash": contract["evidence_hash"],
                "observables_used": [],
            }

        with mock.patch.object(
            self.runner,
            "analyze_model_route",
            side_effect=reviewed_response,
        ) as analyze:
            result = self.runner.apply_configured_second_opinion(
                {
                    "alert": {"alert_id": "phase-review"},
                    "pcap_evidence": {
                        "request_id": "pcap-phase-review",
                        "status": "completed",
                        "records_returned": 1,
                    },
                },
                primary,
                args,
                settings,
                "soc-analyst",
                phase_callback=mock.Mock(side_effect=OSError("status file unavailable")),
            )

        analyze.assert_called_once()
        self.assertEqual(result["_second_opinion"]["status"], "completed")
        self.assertEqual(result["_second_opinion"]["response"]["summary"], "Reviewer result")
        authorization = result["_second_opinion"][
            "automation_authorization"
        ]
        self.assertTrue(authorization["authorized"])
        self.assertTrue(
            authorization["automatic_closure_authorized"]
        )
        self.assertTrue(authorization["containment_authorized"])
        self.assertTrue(authorization["tuning_authorized"])
        self.assertFalse(
            authorization["memory_writeback_authorized"]
        )
        self.assertTrue(
            result["_automation_controls"]["memory_writeback_blocked"]
        )
        self.assertIn(
            "full high-confidence agreement",
            result["_automation_controls"]["memory_writeback_reason"],
        )


    def test_frozen_shadow_reviewer_preflight_failure_prevents_model_call(
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
        primary = self.runner.validate_response(
            self.complete_response(
                confidence="low",
                confidence_score=0.3,
                detection_outcome="inconclusive",
            )
        )
        harness = mock.Mock()
        harness.policy.mode = "shadow"
        harness.preflight_model_call.side_effect = RuntimeError(
            "synthetic frozen reservation failure"
        )

        with (
            mock.patch.dict(
                self.runner.os.environ,
                {self.runner.EVALUATION_FREEZE_MEMORY_ENV: "1"},
            ),
            mock.patch.object(
                self.runner,
                "analyze_model_route",
            ) as analyze,
        ):
            result = self.runner.apply_configured_second_opinion(
                {"alert": {"alert_id": "frozen-reviewer-preflight"}},
                primary,
                args,
                settings,
                "soc-analyst",
                harness_runtime=harness,
            )

        analyze.assert_not_called()
        self.assertEqual(result["_second_opinion"]["status"], "failed")
        self.assertIn(
            "synthetic frozen reservation failure",
            result["_second_opinion"]["error"],
        )


    def test_cli_model_override_routes_soc_analyst_to_exact_model(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            path = Path(temp_name) / "ai_model_settings.json"
            path.write_text(json.dumps({
                "enabled_ollama_models": ["saved:latest"],
                "gpt_cli_enabled": False,
            }), encoding="utf-8")
            with mock.patch.object(sys, "argv", ["run-local-ai-analysis.py", "--model", "override:latest"]):
                args = self.runner.parse_args()
            args.ai_settings_file = path

            settings = self.runner.effective_ai_settings(args)

        self.assertEqual(settings["enabled_ollama_models"], ["override:latest"])
        self.assertEqual(settings["agent_models"]["soc-analyst"], "ollama:override:latest")


    def test_settings_reject_empty_provider_roster(self) -> None:
        settings = self.runner.default_ai_settings()

        with self.assertRaisesRegex(self.runner.RuntimeArtifactError, "at least one"):
            self.runner.apply_model_roster(settings, {
                "enabled_ollama_models": [],
                "gpt_cli_enabled": False,
            })


