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

class AiModelRoutingTestsReviewerForeignIpRetryPromptIsValueFreeCases:
    def test_reviewer_foreign_ip_retry_prompt_is_value_free(self) -> None:
        args = type(
            "Args",
            (),
            {"second_opinion_prompt_file": Path("/tmp/reviewer.md")},
        )()
        settings = self.runner.default_ai_settings()
        settings["enabled_ollama_models"] = ["primary:latest", "reviewer:latest"]
        settings["agent_models"]["soc-analyst"] = "ollama:primary:latest"
        settings["agent_second_opinion_models"][
            "soc-analyst"
        ] = "ollama:reviewer:latest"
        primary = self.runner.validate_response(
            self.complete_response(confidence="low", confidence_score=0.3)
        )
        foreign_ip = "203.0.113.77"
        repair_prompt_serializations: list[str] = []
        attempts = 0

        def reviewed_response(_route, review_package, *_args, **_kwargs):
            nonlocal attempts
            attempts += 1
            contract = review_package["review_contract"]
            if attempts == 2:
                repair_prompt_serializations.append(
                    json.dumps(
                        review_package,
                        sort_keys=True,
                        separators=(",", ":"),
                        default=str,
                    )
                )
            return {
                **self.complete_response(
                    confidence="high",
                    confidence_score=0.9,
                    evidence_used=["alert", "alert:ip-case"],
                    summary=(
                        f"The supplied evidence proves contact with {foreign_ip}."
                        if attempts == 1
                        else "The supplied evidence remains suspicious."
                    ),
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
            side_effect=reviewed_response,
        ) as analyze:
            result = self.runner.apply_configured_second_opinion(
                {
                    "alert": {
                        "alert_id": "ip-case",
                        "source_ip": "192.0.2.10",
                    }
                },
                primary,
                args,
                settings,
                "soc-analyst",
            )

        self.assertEqual(analyze.call_count, 2)
        self.assertEqual(result["_second_opinion"]["status"], "completed")
        self.assertEqual(len(repair_prompt_serializations), 1)
        self.assertNotIn(foreign_ip, repair_prompt_serializations[0])
        repair = json.loads(repair_prompt_serializations[0])[
            "review_contract_repair"
        ]
        self.assertIn(
            "outside review_contract.allowed_observables",
            repair["validation_errors"],
        )
        self.assertIn(
            "do not repeat",
            " ".join(repair["field_guidance"]).lower(),
        )


    def test_grounded_medium_confidence_agreement_cannot_unblock_automation(self) -> None:
        args = type(
            "Args",
            (),
            {"second_opinion_prompt_file": Path("/tmp/reviewer.md")},
        )()
        settings = self.runner.default_ai_settings()
        settings["enabled_ollama_models"] = ["primary:latest", "reviewer:latest"]
        settings["agent_models"]["soc-analyst"] = "ollama:primary:latest"
        settings["agent_second_opinion_models"]["soc-analyst"] = "ollama:reviewer:latest"
        verdict = {
            "detection_outcome": "inconclusive",
            "event_status": "unknown",
            "detection_validity": "unknown",
            "activity_disposition": "unknown",
            "handling": "investigate",
            "duplicate_of": None,
            "hypotheses": [],
            "escalation_needed": False,
        }
        primary = self.runner.validate_response(
            self.complete_response(
                **verdict,
                confidence="low",
                confidence_score=0.3,
            )
        )

        def reviewed_response(_route, review_package, *_args, **_kwargs):
            contract = review_package["review_contract"]
            return {
                **self.complete_response(
                    **verdict,
                    confidence="medium",
                    confidence_score=0.65,
                    evidence_used=["alert", "alert:current-case"],
                ),
                "review_case_id": contract["case_id"],
                "review_evidence_hash": contract["evidence_hash"],
                "observables_used": [],
            }

        with mock.patch.object(
            self.runner,
            "analyze_model_route",
            side_effect=reviewed_response,
        ):
            result = self.runner.apply_configured_second_opinion(
                {"alert": {"alert_id": "current-case"}},
                primary,
                args,
                settings,
                "soc-analyst",
            )

        self.assertEqual(result["_second_opinion"]["status"], "completed")
        self.assertNotIn("error", result["_second_opinion"])
        self.assertEqual(
            result["_second_opinion"]["comparison"]["agreement"],
            "partial_disagreement",
        )
        authorization = result["_second_opinion"][
            "automation_authorization"
        ]
        self.assertFalse(authorization["authorized"])
        self.assertEqual(
            authorization["reason_code"],
            "reviewer_confidence_below_automation_threshold",
        )
        self.assertFalse(
            authorization["automatic_closure_authorized"]
        )
        self.assertFalse(authorization["containment_authorized"])
        self.assertFalse(authorization["tuning_authorized"])
        self.assertFalse(
            authorization["memory_writeback_authorized"]
        )
        self.assertEqual(
            result["final_disposition_status"],
            "review_completed_not_authorized",
        )
        self.assertEqual(result["confidence"], "low")
        self.assertLessEqual(result["confidence_score"], 0.39)
        self.assertFalse(result["escalation_needed"])
        self.assertEqual(
            result["tuning_recommendation"],
            "needs_more_data",
        )
        self.assertEqual(result["recommended_tuning_actions"], [])
        self.assertEqual(result["memory_candidates"], [])
        self.assertTrue(result["_automation_controls"]["automatic_closure_blocked"])
        self.assertTrue(result["_automation_controls"]["containment_blocked"])
        self.assertTrue(result["_automation_controls"]["tuning_blocked"])
        self.assertTrue(result["_automation_controls"]["memory_writeback_blocked"])


    def test_medium_review_of_consequential_primary_blocks_every_control(
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
        verdict = {
            "detection_outcome": "true_positive_suspicious",
            "event_status": "observed",
            "detection_validity": "matched_intent",
            "activity_disposition": "suspicious",
            "handling": "contain",
            "duplicate_of": None,
            "hypotheses": [],
            "escalation_needed": True,
            "tuning_recommendation": "suppress",
            "recommended_tuning_actions": [
                "Suppress this synthetic detection."
            ],
        }
        primary = self.runner.validate_response(
            self.complete_response(
                **verdict,
                confidence="high",
                confidence_score=0.9,
            )
        )

        def reviewed_response(
            _route,
            review_package,
            *_args,
            **_kwargs,
        ):
            contract = review_package["review_contract"]
            return {
                **self.complete_response(
                    **verdict,
                    confidence="medium",
                    confidence_score=0.65,
                    evidence_used=["alert", "alert:consequential-case"],
                ),
                "review_case_id": contract["case_id"],
                "review_evidence_hash": contract["evidence_hash"],
                "observables_used": [],
            }

        with mock.patch.object(
            self.runner,
            "analyze_model_route",
            side_effect=reviewed_response,
        ):
            result = self.runner.apply_configured_second_opinion(
                {"alert": {"alert_id": "consequential-case"}},
                primary,
                args,
                settings,
                "soc-analyst",
            )

        self.assertEqual(result["_second_opinion"]["status"], "completed")
        authorization = result["_second_opinion"][
            "automation_authorization"
        ]
        self.assertFalse(authorization["authorized"])
        self.assertTrue(
            authorization["consequential_automation_requested"]
        )
        self.assertEqual(
            result["final_disposition_status"],
            "review_completed_not_authorized",
        )
        self.assertEqual(result["handling"], "investigate")
        self.assertEqual(
            result["tuning_recommendation"],
            "needs_more_data",
        )
        self.assertEqual(result["recommended_tuning_actions"], [])
        self.assertEqual(result["memory_candidates"], [])
        for key in (
            "automatic_closure_blocked",
            "containment_blocked",
            "tuning_blocked",
            "memory_writeback_blocked",
            "requires_human_review",
        ):
            self.assertTrue(result["_automation_controls"][key])


    def test_saved_response_required_review_fails_closed(self) -> None:
        saved_input = self.complete_response(
                confidence="high",
                confidence_score=0.9,
                detection_outcome="true_positive_suspicious",
                event_status="observed",
                detection_validity="matched_intent",
                activity_disposition="suspicious",
                handling="contain",
                escalation_needed=False,
                memory_candidates=[
                    {
                        "scope": "agent",
                        "category": "response_lesson",
                        "confidence": "high",
                        "finding": "Synthetic containment pattern must remain review-gated.",
                        "use_when": "When the same synthetic alert recurs.",
                        "evidence_basis": ["alert:synthetic-saved-response"],
                    }
                ],
                _second_opinion={
                    "status": "completed",
                    "response": {"confidence": "high"},
                    "comparison": {
                        "agreement": "agreement",
                        "material_disagreement": False,
                    },
                },
                _analysis_model="spoofed-model",
                _analysis_model_path="frontier-codex-cli",
                _analysis_model_route="codex-cli:spoofed-model:xhigh",
                _analysis_provider="codex-cli",
                _automation_controls={"memory_writeback_blocked": False},
            )
        sanitized = self.runner.sanitize_saved_response_input(saved_input)
        self.assertFalse(any(key.startswith("_") for key in sanitized))
        primary = self.runner.validate_response(
            sanitized
        )
        self.assertTrue(primary["memory_candidates"])

        result = self.runner.apply_saved_response_review_gate(
            {"alert": {"alert_id": "synthetic-saved-response"}},
            primary,
        )

        self.assertEqual(result["final_disposition_status"], "review_required_failed")
        self.assertEqual(result["confidence"], "low")
        self.assertLessEqual(result["confidence_score"], 0.39)
        self.assertEqual(result["handling"], "investigate")
        self.assertEqual(result["memory_candidates"], [])
        self.assertEqual(
            result["_analysis_input_mode"],
            self.runner.SAVED_RESPONSE_INPUT_MODE,
        )
        self.assertNotIn("_analysis_model", result)
        self.assertNotIn("_analysis_model_path", result)
        self.assertNotIn("_analysis_model_route", result)
        self.assertNotIn("_analysis_provider", result)
        self.assertEqual(result["_second_opinion"]["status"], "review_required_failed")
        self.assertIn("consequential", result["_second_opinion"]["trigger"].lower())
        self.assertTrue(result["_automation_controls"]["automatic_closure_blocked"])
        self.assertTrue(result["_automation_controls"]["containment_blocked"])
        self.assertTrue(result["_automation_controls"]["tuning_blocked"])
        self.assertTrue(result["_automation_controls"]["memory_writeback_blocked"])

        settings = self.runner.default_ai_settings()
        settings["agent_models"]["soc-analyst"] = "ollama:assigned-only"
        log_record = self.runner.build_llm_log_record(
            run_id="synthetic-saved-response",
            status="success",
            started_at="2026-07-24  10:00:00-06:00",
            finished_at="2026-07-24  10:00:01-06:00",
            runtime_seconds=1,
            prompt_path=Path("/tmp/synthetic-prompt.json"),
            prompt_package={
                "agent_role": "soc-analyst",
                "alert": {"alert_id": "synthetic-saved-response"},
            },
            settings=settings,
            response=result,
            json_path=Path("/tmp/synthetic-result.json"),
            md_path=Path("/tmp/synthetic-result.md"),
            resource_monitor=self.runner.SystemResourceMonitor(),
        )
        self.assertEqual(log_record["input_mode"], "saved_response")
        self.assertFalse(log_record["model_started"])
        self.assertEqual(log_record["model"], "")
        self.assertEqual(log_record["model_path"], "")
        self.assertEqual(log_record["model_route"], "")
        self.assertEqual(log_record["assigned_model"], "assigned-only")

        index_payload = self.runner.analysis_index_payload(
            "synthetic-saved-response",
            {"agent_role": "soc-analyst", "alert": {"alert_id": "saved-alert"}},
            result,
            "",
            "2026-07-24  10:00:00-06:00",
            "2026-07-24  10:00:01-06:00",
            Path("/tmp/synthetic-result.json"),
        )
        self.assertIsNone(index_payload["model"])
        self.assertIsNone(index_payload["model_path"])
        self.assertIsNone(index_payload["provider"])
        self.assertIsNone(index_payload["harness"])
        self.assertEqual(index_payload["input_mode"], "saved_response")

        observed_payload = self.runner.analysis_index_payload(
            "synthetic-hermes-response",
            {"agent_role": "soc-analyst", "alert": {"alert_id": "observed"}},
            {
                "_analysis_model": "gpt-5.6-sol",
                "_analysis_model_path": "hermes-agent",
                "_analysis_provider": "openai-codex",
                "_analysis_harness": "hermes-agent",
            },
            "",
            "2026-07-24  10:00:00-06:00",
            "2026-07-24  10:00:01-06:00",
            Path("/tmp/synthetic-hermes-result.json"),
        )
        self.assertEqual(observed_payload["provider"], "openai-codex")
        self.assertEqual(observed_payload["harness"], "hermes-agent")


    def test_comparison_distinguishes_full_advisory_and_material_disagreement(self) -> None:
        primary = {
            "detection_outcome": "true_positive_suspicious",
            "confidence": "high",
            "escalation_needed": True,
            "tuning_recommendation": "Keep enabled",
            "correlation_assessment": {"correlation_found": True},
        }
        full = self.runner.compare_analysis_results(primary, dict(primary))
        self.assertEqual(full["agreement"], "agreement")
        self.assertFalse(full["material_disagreement"])

        advisory_reviewer = {
            **primary,
            "confidence": "medium",
            "tuning_recommendation": "Monitor before tuning",
        }
        advisory = self.runner.compare_analysis_results(primary, advisory_reviewer)
        self.assertEqual(advisory["agreement"], "partial_disagreement")
        self.assertFalse(advisory["material_disagreement"])
        self.assertTrue(all(not item["material"] for item in advisory["disputed_fields"]))

        material_reviewer = {**primary, "escalation_needed": False}
        material = self.runner.compare_analysis_results(primary, material_reviewer)
        self.assertEqual(material["agreement"], "material_disagreement")
        self.assertTrue(material["material_disagreement"])
        self.assertIn("escalation_needed", {item["field"] for item in material["disputed_fields"]})


    def test_tuning_only_material_disagreement_preserves_agreed_verdict(
        self,
    ) -> None:
        primary = self.complete_response(
            confidence="medium",
            confidence_score=0.68,
            detection_outcome="informational_no_action",
            event_status="observed",
            detection_validity="matched_intent",
            activity_disposition="benign",
            handling="no_action",
            escalation_needed=False,
            tuning_recommendation="suppress",
            bluf="Informational package-management activity.",
            summary="The activity is benign but not formally authorized.",
        )
        reviewer = {
            **primary,
            "tuning_recommendation": "none",
        }
        comparison = self.runner.compare_analysis_results(
            primary,
            reviewer,
        )

        self.assertTrue(comparison["material_disagreement"])
        result = self.runner.apply_material_disagreement_gate(
            primary,
            reviewer,
            comparison,
        )

        self.assertEqual(result["detection_outcome"], "informational_no_action")
        self.assertEqual(result["activity_disposition"], "benign")
        self.assertEqual(result["handling"], "no_action")
        self.assertEqual(result["confidence"], "medium")
        self.assertFalse(result["escalation_needed"])
        self.assertTrue(result["bluf"].startswith("DISPUTED TUNING"))
        self.assertEqual(
            result["_material_disagreement_gate"]["scope"],
            "control_only",
        )
        self.assertTrue(
            result["_material_disagreement_gate"]["verdict_preserved"]
        )


    def test_monitor_vs_no_action_is_advisory_for_authorized_activity(
        self,
    ) -> None:
        primary = self.complete_response(
            detection_outcome="inconclusive",
            event_status="observed",
            detection_validity="unknown",
            activity_disposition="authorized_benign",
            handling="monitor",
            duplicate_of=None,
            escalation_needed=False,
        )
        reviewer = {**primary, "handling": "no_action"}

        comparison = self.runner.compare_analysis_results(
            primary,
            reviewer,
        )

        self.assertEqual(comparison["agreement"], "partial_disagreement")
        self.assertFalse(comparison["material_disagreement"])
        handling = next(
            item
            for item in comparison["disputed_fields"]
            if item["field"] == "handling"
        )
        self.assertFalse(handling["material"])


    def test_monitor_vs_no_action_remains_material_for_suspicious_activity(
        self,
    ) -> None:
        primary = self.complete_response(
            detection_outcome="true_positive_suspicious",
            event_status="observed",
            detection_validity="matched_intent",
            activity_disposition="suspicious",
            handling="monitor",
            duplicate_of=None,
            escalation_needed=False,
        )
        reviewer = {**primary, "handling": "no_action"}

        comparison = self.runner.compare_analysis_results(
            primary,
            reviewer,
        )

        self.assertTrue(comparison["material_disagreement"])


    def test_valid_shadow_adjudication_projects_truth_but_not_authority(
        self,
    ) -> None:
        primary = self.complete_response(
            detection_outcome="inconclusive",
            event_status="observed",
            detection_validity="unknown",
            activity_disposition="authorized_benign",
            handling="monitor",
            duplicate_of=None,
            escalation_needed=False,
        )
        reviewer = {
            **primary,
            "activity_disposition": "unknown",
            "handling": "investigate",
        }
        adjudication = {
            "status": "completed",
            "mode": "shadow",
            "automation_authorized": False,
            "response": {
                "decision": "primary_supported",
                "resolved_fields": [
                    "activity_disposition",
                    "handling",
                ],
                "remaining_disagreements": [],
                "_adjudication_contract_validation": {
                    "valid": True,
                    "automation_authorized": False,
                },
            },
        }

        applied = self.runner.apply_analytical_adjudication_projection(
            primary,
            reviewer,
            adjudication,
        )

        self.assertTrue(applied)
        self.assertEqual(primary["activity_disposition"], "authorized_benign")
        projection = primary["_analytical_adjudication_projection"]
        self.assertFalse(projection["automation_authorized"])
        self.assertTrue(projection["human_adjudication_required"])


    def test_case_disagreement_replaces_contradictory_action_text(self) -> None:
        primary = self.complete_response(
            detection_outcome="inconclusive",
            activity_disposition="unknown",
            handling="monitor",
            recommended_next_steps=[
                "Close as informational/no-action.",
                "Suppress the rule immediately.",
            ],
        )
        reviewer = self.complete_response(
            detection_outcome="true_positive_suspicious",
            activity_disposition="suspicious",
            handling="investigate",
        )
        comparison = self.runner.compare_analysis_results(primary, reviewer)

        result = self.runner.apply_material_disagreement_gate(
            primary, reviewer, comparison
        )

        self.assertEqual(result["handling"], "investigate")
        joined = " ".join(result["recommended_next_steps"]).lower()
        self.assertNotIn("close as informational", joined)
        self.assertNotIn("suppress the rule", joined)
        self.assertIn("do not close, contain, tune", joined)


    def test_reviewer_memory_requires_high_confidence_full_agreement(self) -> None:
        completed = {
            "status": "completed",
            "response": {"confidence": "high", "memory_candidates": [{"finding": "synthetic"}]},
            "comparison": {"agreement": "agreement", "material_disagreement": False},
        }
        self.assertEqual(
            self.runner.second_opinion_memory_eligibility(completed),
            (True, "high-confidence independent agreement"),
        )

        for mutation, expected in (
            ({"response": {"confidence": "medium"}}, "confidence"),
            ({"comparison": {"agreement": "partial_disagreement", "material_disagreement": False}}, "agree"),
            ({"comparison": {"agreement": "material_disagreement", "material_disagreement": True}}, "agree"),
        ):
            candidate = {**completed, **mutation}
            eligible, reason = self.runner.second_opinion_memory_eligibility(candidate)
            self.assertFalse(eligible)
            self.assertIn(expected, reason)


    def test_memory_writeback_is_staged_until_authoritative_commit(self) -> None:
        candidate = {
            "scope": "agent",
            "category": "investigation_pivot",
            "finding": (
                "Correlate TLS SNI with certificate and destination history."
            ),
            "use_when": "A later TLS alert has the same infrastructure.",
            "evidence_basis": ["Zeek and alert evidence independently agreed."],
            "confidence": "medium",
            "tags": ["tls", "zeek"],
            "ttl_days": 30,
        }
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            role_memory = root / "role.md"
            shared_memory = root / "shared.md"
            receipt_dir = root / "receipts"
            role_memory.write_text("# Role Memory\n", encoding="utf-8")
            shared_memory.write_text("# Shared Memory\n", encoding="utf-8")

            plan = self.runner.memory_writeback_plan(
                [candidate],
                allowed=True,
                eligibility_reason="eligible after authoritative commit",
            )
            self.assertEqual(
                plan["persistence_status"],
                "pending_authoritative_commit",
            )
            self.assertNotIn(
                "ONION_SENTINEL_MANAGED_MEMORY_START",
                role_memory.read_text(encoding="utf-8"),
            )

            receipt, receipt_path = (
                self.runner.persist_postcommit_memory_writeback(
                    analysis_id="postcommit-memory-test",
                    agent_role="soc-analyst",
                    role_memory_file=role_memory,
                    shared_memory_file=shared_memory,
                    source_artifact="/tmp/synthetic-analysis.json",
                    primary_candidates=[candidate],
                    primary_allowed=True,
                    primary_reason="eligible after authoritative commit",
                    reviewer_candidates=[],
                    reviewer_allowed=False,
                    reviewer_reason="reviewer did not complete",
                    receipt_dir=receipt_dir,
                )
            )
            self.assertTrue(receipt["ok"])
            self.assertEqual(receipt["primary"]["status"], "persisted")
            self.assertEqual(receipt["reviewer"]["status"], "blocked")
            self.assertIsNotNone(receipt_path)
            assert receipt_path is not None
            self.assertEqual(receipt_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(receipt_dir.stat().st_mode & 0o777, 0o700)
            receipt_text = receipt_path.read_text(encoding="utf-8")
            self.assertNotIn(candidate["finding"], receipt_text)
            self.assertIn(
                "ONION_SENTINEL_MANAGED_MEMORY_START",
                role_memory.read_text(encoding="utf-8"),
            )


    def test_blocked_postcommit_memory_plan_never_mutates_memory(self) -> None:
        candidate = {
            "scope": "agent",
            "category": "investigation_pivot",
            "finding": "Treat a prior model claim only as a lead.",
            "use_when": "A related alert is investigated.",
            "evidence_basis": ["One prior model observation."],
            "confidence": "medium",
            "tags": ["lead"],
            "ttl_days": 30,
        }
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            role_memory = root / "role.md"
            shared_memory = root / "shared.md"
            role_memory.write_text("# Role Memory\n", encoding="utf-8")
            shared_memory.write_text("# Shared Memory\n", encoding="utf-8")
            before = role_memory.read_bytes()

            receipt, _ = self.runner.persist_postcommit_memory_writeback(
                analysis_id="blocked-memory-test",
                agent_role="soc-analyst",
                role_memory_file=role_memory,
                shared_memory_file=shared_memory,
                source_artifact="/tmp/synthetic-analysis.json",
                primary_candidates=[candidate],
                primary_allowed=False,
                primary_reason="explicit human approval is required",
                reviewer_candidates=[],
                reviewer_allowed=False,
                reviewer_reason="reviewer did not complete",
                receipt_dir=root / "receipts",
            )
            self.assertEqual(receipt["primary"]["status"], "blocked")
            self.assertEqual(role_memory.read_bytes(), before)


    def test_confident_primary_does_not_spend_second_model_call(self) -> None:
        args = type("Args", (), {})()
        settings = self.runner.default_ai_settings()
        settings["agent_second_opinion_models"]["soc-analyst"] = "ollama:reviewer:latest"
        primary = self.runner.validate_response(self.complete_response(
            confidence="high",
            confidence_score=0.9,
            detection_outcome="true_positive_authorized_benign",
            summary="Supported conclusion",
        ))
        phases: list[tuple[str, str, str]] = []

        with mock.patch.object(self.runner, "analyze_model_route") as analyze:
            result = self.runner.apply_configured_second_opinion(
                {},
                primary,
                args,
                settings,
                "soc-analyst",
                phase_callback=lambda phase, route, trigger: phases.append((phase, route, trigger)),
            )

        self.assertIs(result, primary)
        self.assertNotIn("_second_opinion", result)
        analyze.assert_not_called()
        self.assertEqual(phases, [("post_processing", "", "")])


