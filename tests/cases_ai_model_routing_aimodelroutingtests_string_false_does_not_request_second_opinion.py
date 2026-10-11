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

class AiModelRoutingTestsStringFalseDoesNotRequestSecondOpinionCases:
    def test_string_false_does_not_request_second_opinion(self) -> None:
        response = self.runner.validate_response(self.complete_response(
            confidence="high",
            confidence_score=0.9,
            detection_outcome="informational_no_action",
            second_opinion_recommended="false",
            hosted_second_opinion_recommended="false",
        ))

        self.assertFalse(response["second_opinion_recommended"])
        self.assertFalse(response["hosted_second_opinion_recommended"])
        self.assertEqual(self.runner.second_opinion_trigger(response), "")


    def test_manual_incident_reanalysis_requires_independent_review(self) -> None:
        response = self.runner.validate_response(self.complete_response(
            confidence="high",
            confidence_score=0.9,
            detection_outcome="informational_no_action",
            second_opinion_recommended=False,
            hosted_second_opinion_recommended=False,
        ))

        self.assertEqual(
            self.runner.second_opinion_trigger(
                response,
                {
                    "agent_role": "incident-responder",
                    "manual_reanalysis": True,
                },
            ),
            (
                "Manual Incident Responder reanalysis requires an independent "
                "second opinion."
            ),
        )
        self.assertEqual(
            self.runner.second_opinion_trigger(
                response,
                {
                    "agent_role": "soc-analyst",
                    "manual_reanalysis": True,
                },
            ),
            "",
        )


    def test_legacy_outcome_derives_canonical_factored_verdict(self) -> None:
        response = self.runner.validate_response(self.complete_response(
            confidence="high",
            confidence_score=0.92,
            detection_outcome="true_positive_malicious",
            escalation_needed=True,
        ))

        self.assertEqual(response["detection_outcome"], "true_positive_malicious")
        self.assertEqual(response["event_status"], "observed")
        self.assertEqual(response["detection_validity"], "matched_intent")
        self.assertEqual(response["activity_disposition"], "malicious")
        self.assertEqual(response["handling"], "contain")
        self.assertIsNone(response["duplicate_of"])
        self.assertEqual(response["_verdict_validation"]["source"], "legacy_derived")
        self.assertFalse(response["_verdict_validation"]["material_contradiction"])
        self.assertEqual(response["confidence"], "high")
        self.assertEqual(response["confidence_score"], 0.92)


    def test_complete_factored_verdict_supersedes_stale_legacy_label(self) -> None:
        response = self.runner.validate_response(self.complete_response(
            confidence="high",
            confidence_score=0.95,
            detection_outcome="true_positive_authorized_benign",
            event_status="observed",
            detection_validity="matched_intent",
            activity_disposition="suspicious",
            handling="investigate",
            duplicate_of=None,
        ))

        self.assertEqual(response["detection_outcome"], "true_positive_suspicious")
        validation = response["_verdict_validation"]
        self.assertEqual(validation["source"], "model_factored")
        self.assertFalse(validation["material_contradiction"])
        self.assertEqual(validation["contradictions"], [])
        self.assertIn("factored verdict derives", validation["warnings"][0])
        self.assertEqual(response["activity_disposition"], "suspicious")
        self.assertEqual(response["confidence"], "high")
        self.assertEqual(response["confidence_score"], 0.95)


    def test_partial_factored_legacy_mismatch_remains_material(self) -> None:
        response = self.runner.validate_response(self.complete_response(
            confidence="high",
            confidence_score=0.95,
            detection_outcome="true_positive_authorized_benign",
            activity_disposition="suspicious",
        ))

        validation = response["_verdict_validation"]
        self.assertTrue(validation["material_contradiction"])
        self.assertIn("factored verdict derives", validation["contradictions"][0])
        self.assertEqual(response["confidence"], "low")
        self.assertEqual(response["confidence_score"], 0.39)


    def test_confidence_calibration_uses_evidence_caps(self) -> None:
        uncited = self.runner.validate_response(self.complete_response(
            confidence="high",
            confidence_score=0.94,
            detection_outcome="true_positive_suspicious",
            evidence_used=[],
        ))
        contradictory = self.runner.validate_response(self.complete_response(
            confidence="high",
            confidence_score=0.94,
            detection_outcome="true_positive_suspicious",
            correlation_assessment={
                "correlation_found": False,
                "confidence": "low",
                "related_groups": [],
                "shared_evidence": [],
                "contradicting_evidence": ["The endpoint baseline conflicts with the network hypothesis."],
                "attack_chain_hypothesis": "",
                "recommended_pivots": [],
            },
        ))

        self.assertEqual(uncited["confidence"], "medium")
        self.assertEqual(uncited["confidence_score"], 0.69)
        self.assertIn(
            "no_valid_corroborating_evidence",
            uncited["_confidence_calibration"]["limiters"],
        )
        self.assertEqual(contradictory["confidence"], "medium")
        self.assertEqual(contradictory["confidence_score"], 0.69)
        self.assertIn(
            "unresolved_contradicting_evidence",
            contradictory["_confidence_calibration"]["limiters"],
        )


    def test_empty_query_container_cannot_bypass_corroboration_cap(self) -> None:
        prompt = {
            "investigation_query_results": {
                "rounds": [
                    {
                        "results": [
                            {
                                "query_id": "zero-hit",
                                "query_digest": "a" * 64,
                                "pack": "network_flow",
                                "status": "ok",
                                "returned_hits": 0,
                                "total_hits": 0,
                            }
                        ]
                    }
                ]
            }
        }
        self.runner.attach_evidence_reference_contract(prompt)
        catalog = {
            item["ref"]: item
            for item in prompt["evidence_reference_contract"]["references"]
        }
        self.assertNotIn("investigation_query_results", catalog)
        query_ref = f"query:{'a' * 64}"
        self.assertIn(query_ref, catalog)
        self.assertFalse(catalog[query_ref]["corroborating"])

        response = self.runner.validate_response(
            self.complete_response(
                confidence="high",
                confidence_score=0.94,
                detection_outcome="inconclusive",
                evidence_used=[query_ref],
            ),
            prompt,
        )
        self.assertEqual(response["confidence_score"], 0.69)
        self.assertIn(
            "no_valid_corroborating_evidence",
            response["_confidence_calibration"]["limiters"],
        )


    def test_evidence_contract_exports_only_valid_exact_authorization_ref(
        self,
    ) -> None:
        prompt = self.canonical_authorization_prompt()
        expected = prompt["authorization_evidence"]["entries"][0][
            "evidence_ref"
        ]

        contract = self.runner.evidence_reference_contract(prompt)
        catalog = {item["ref"]: item for item in contract["references"]}

        self.assertIn(expected, catalog)
        self.assertTrue(catalog[expected]["corroborating"])
        self.assertEqual(
            catalog[expected]["source_class"],
            "authorization_evidence",
        )
        self.assertNotIn("authorization_evidence", catalog)

        tampered = copy.deepcopy(prompt)
        tampered["authorization_evidence"]["entries"][0][
            "evidence_ref"
        ] = "authorized-activity:sha256:" + "f" * 64
        tampered_catalog = {
            item["ref"]: item
            for item in self.runner.evidence_reference_contract(tampered)[
                "references"
            ]
        }
        self.assertNotIn(
            tampered["authorization_evidence"]["entries"][0][
                "evidence_ref"
            ],
            tampered_catalog,
        )
        self.assertNotIn("authorization_evidence", tampered_catalog)


    def test_two_citations_from_one_source_cannot_reach_high_confidence(self) -> None:
        prompt = {"alert": {"alert_id": "same-source-alert"}}
        self.runner.attach_evidence_reference_contract(prompt)
        response = self.runner.validate_response(
            self.complete_response(
                confidence="high",
                confidence_score=0.94,
                evidence_used=["alert", "alert:same-source-alert"],
            ),
            prompt,
        )

        self.assertEqual(response["confidence"], "medium")
        self.assertEqual(response["confidence_score"], 0.79)
        self.assertIn(
            "single_valid_corroborating_evidence_source",
            response["_confidence_calibration"]["limiters"],
        )
        self.assertEqual(
            response["_confidence_calibration"]["evidence_signals"][
                "corroborating_evidence_source_count"
            ],
            1,
        )


    def test_review_trigger_covers_controls_and_high_severity_closures(self) -> None:
        containment = self.runner.validate_response(self.complete_response(
            confidence="high",
            confidence_score=0.9,
            detection_outcome="true_positive_malicious",
        ))
        suppression = self.runner.validate_response(
            self.complete_response(
                confidence="high",
                confidence_score=0.9,
                detection_outcome="true_positive_suspicious",
                detection_validity="matched_intent",
                activity_disposition="suspicious",
                tuning_recommendation="suppress",
            ),
            self.canonical_authorization_prompt(),
        )
        closure = self.runner.validate_response(self.complete_response(
            confidence="high",
            confidence_score=0.9,
            detection_outcome="true_positive_authorized_benign",
        ))

        self.assertEqual(
            self.runner.second_opinion_trigger(containment),
            "The primary model recommended a consequential response action.",
        )
        self.assertEqual(
            self.runner.second_opinion_trigger(suppression),
            "The primary model recommended suppressing or dropping detection signal.",
        )
        self.assertEqual(
            self.runner.second_opinion_trigger(
                closure,
                {"alert": {"triage_level": "high"}},
            ),
            "A high-severity detection received a consequential closure disposition.",
        )


    def test_tuning_coherence_guard_downgrades_each_unsafe_context(self) -> None:
        authorized_prompt = self.canonical_authorization_prompt()
        cases = (
            (
                "unknown detection validity",
                {
                    "detection_validity": "unknown",
                    "activity_disposition": "benign",
                    "evidence_gaps": [],
                },
                authorized_prompt,
                "detection_validity_unknown",
            ),
            (
                "unknown activity disposition",
                {
                    "detection_validity": "matched_intent",
                    "activity_disposition": "unknown",
                    "evidence_gaps": [],
                },
                authorized_prompt,
                "activity_disposition_unknown",
            ),
            (
                "material evidence gap",
                {
                    "detection_validity": "matched_intent",
                    "activity_disposition": "benign",
                    "evidence_gaps": ["Endpoint attribution is unavailable."],
                },
                authorized_prompt,
                "material_evidence_gaps",
            ),
            (
                "missing structured authorization",
                {
                    "detection_validity": "matched_intent",
                    "activity_disposition": "benign",
                    "evidence_gaps": [],
                },
                {},
                "structured_authorization_missing",
            ),
        )
        for label, overrides, prompt, expected_reason in cases:
            with self.subTest(label=label):
                response = self.runner.validate_response(
                    self.complete_response(
                        detection_outcome="informational_no_action",
                        handling="no_action",
                        tuning_recommendation="suppress",
                        recommended_tuning_actions=[
                            "Suppress this synthetic signal."
                        ],
                        **overrides,
                    ),
                    prompt,
                )
                self.assertEqual(
                    response["tuning_recommendation"],
                    "needs_more_data",
                )
                self.assertEqual(response["recommended_tuning_actions"], [])
                guard = response["_tuning_coherence_guard"]
                self.assertTrue(guard["downgrade_applied"])
                self.assertTrue(guard["invalid_for_context"])
                self.assertIn(expected_reason, guard["blocking_reasons"])
                self.assertFalse(guard["automatic_tuning_authorized"])
                self.assertTrue(
                    response["_automation_controls"]["tuning_blocked"]
                )
                self.assertIn(
                    "Suppress/drop tuning is not decision-ready",
                    response["evidence_gaps"][-1],
                )
                self.assertLessEqual(len(guard["blocking_reasons"]), 8)
                self.assertLessEqual(
                    len(guard["material_evidence_gap_signals"]),
                    12,
                )


    def test_coherent_tuning_remains_advisory_and_never_auto_authorized(
        self,
    ) -> None:
        prompt = self.canonical_authorization_prompt()
        response = self.runner.validate_response(
            self.complete_response(
                confidence="high",
                confidence_score=0.9,
                detection_outcome="informational_no_action",
                detection_validity="matched_intent",
                activity_disposition="benign",
                handling="no_action",
                evidence_gaps=[],
                tuning_recommendation="drop",
                recommended_tuning_actions=[
                    "Submit this drop proposal for human approval."
                ],
            ),
            prompt,
        )

        self.assertEqual(response["tuning_recommendation"], "drop")
        guard = response["_tuning_coherence_guard"]
        self.assertFalse(guard["downgrade_applied"])
        self.assertFalse(guard["automatic_tuning_authorized"])
        self.assertTrue(guard["human_approval_required"])
        self.assertTrue(response["_automation_controls"]["tuning_blocked"])
        comparison = self.runner.compare_analysis_results(
            response,
            dict(response),
        )
        authorization = self.runner.reviewer_automation_authorization(
            response,
            dict(response),
            comparison,
        )
        self.assertTrue(authorization["authorized"])
        self.assertTrue(authorization["control_tuning_requested"])
        self.assertFalse(authorization["tuning_authorized"])


    def test_reviewer_authorization_remembers_downgraded_control_request(
        self,
    ) -> None:
        prompt = {
            "alert": self.canonical_authorization_prompt()["alert"],
        }
        response = self.runner.validate_response(
            self.complete_response(
                confidence="high",
                confidence_score=0.9,
                detection_outcome="true_positive_suspicious",
                event_status="observed",
                detection_validity="matched_intent",
                activity_disposition="suspicious",
                handling="investigate",
                evidence_gaps=[],
                tuning_recommendation="suppress",
            ),
            prompt,
        )
        self.assertEqual(
            response["tuning_recommendation"],
            "needs_more_data",
        )
        self.assertEqual(
            response["_tuning_coherence_guard"]["requested_tuning"],
            "suppress",
        )
        comparison = self.runner.compare_analysis_results(
            response,
            dict(response),
        )
        authorization = self.runner.reviewer_automation_authorization(
            response,
            dict(response),
            comparison,
        )
        self.assertTrue(authorization["authorized"])
        self.assertTrue(authorization["control_tuning_requested"])
        self.assertFalse(authorization["tuning_authorized"])


    def test_final_tuning_guard_downgrades_unresolved_reviewer_disagreement(
        self,
    ) -> None:
        prompt = self.canonical_authorization_prompt()
        response = self.runner.validate_response(
            self.complete_response(
                detection_outcome="informational_no_action",
                detection_validity="matched_intent",
                activity_disposition="benign",
                handling="no_action",
                evidence_gaps=[],
                tuning_recommendation="suppress",
            ),
            prompt,
        )
        response["_second_opinion"] = {
            "status": "completed",
            "comparison": {
                "agreement": "material_disagreement",
                "material_disagreement": True,
            },
        }

        guarded = self.runner.apply_tuning_coherence_guard(
            response,
            prompt,
        )
        guarded = self.runner.apply_tuning_coherence_guard(
            guarded,
            prompt,
        )

        self.assertEqual(
            guarded["tuning_recommendation"],
            "needs_more_data",
        )
        audit = guarded["_tuning_coherence_guard"]
        self.assertEqual(audit["requested_tuning"], "suppress")
        self.assertIn(
            "reviewer_material_disagreement_unresolved",
            audit["blocking_reasons"],
        )
        self.assertTrue(
            audit["reviewer_material_disagreement_unresolved"]
        )
        self.assertEqual(
            guarded["evidence_gaps"].count(
                "Suppress/drop tuning is not decision-ready because deterministic "
                "coherence checks found unresolved evidence, authorization, or "
                "independent-review requirements."
            ),
            1,
        )


    def test_independent_reviewer_package_removes_model_anchoring_context(self) -> None:
        package = {
            "instructions": {
                "role": "primary system prompt",
                "grounding": [
                    "Use current evidence.",
                    "Use prior_analyses as context.",
                    "Review previous_correlation.",
                ],
                "task": "Classify the alert.",
            },
            "prior_analyses": [{"detection_outcome": "true_positive_malicious"}],
            "correlated_alert_context": {
                "candidates": [{
                    "group_id": "related",
                    "correlation_reasons": [
                        "shared host: workstation",
                        "previous correlation record exists",
                    ],
                    "prior_analysis": {"summary": "Prior model conclusion"},
                    "previous_correlation": {"model_hypothesis": "Prior chain"},
                    "shared_observables": [{"type": "host", "value": "workstation"}],
                }],
            },
            "agent_memory": {
                "role_memory": {
                    "manual_notes": "Operator-approved environment note.",
                    "records": [
                        {"status": "model-observed", "finding": "Model claim"},
                        {"status": "operator-confirmed", "finding": "Confirmed context"},
                    ],
                },
                "shared_memory": {
                    "records": [{"status": "model-observed", "finding": "Shared model claim"}],
                },
            },
            "alert": {"alert_id": "synthetic"},
            "detection_validation": {
                "schema": "onion-sentinel-detection-validation-v1",
                "event_status": "observed",
                "rule_intent_match": "mismatch",
            },
            "asset_context": {
                "matched_assets": [
                    {
                        "asset_id": "private-owner",
                        "owner_ref": "sensitive-team-alias",
                        "share_with_hosted_models": False,
                    },
                    {
                        "asset_id": "shared-owner",
                        "owner_ref": "approved-team-alias",
                        "share_with_hosted_models": True,
                    },
                ],
            },
        }

        sanitized = self.runner.independent_reviewer_package(package)

        self.assertNotIn("role", sanitized["instructions"])
        self.assertNotIn("prior_analyses", sanitized)
        self.assertEqual(sanitized["instructions"]["grounding"], ["Use current evidence."])
        candidate = sanitized["correlated_alert_context"]["candidates"][0]
        self.assertNotIn("prior_analysis", candidate)
        self.assertNotIn("previous_correlation", candidate)
        self.assertEqual(candidate["correlation_reasons"], ["shared host: workstation"])
        self.assertEqual(
            sanitized["agent_memory"]["role_memory"]["records"],
            [{"status": "operator-confirmed", "finding": "Confirmed context"}],
        )
        self.assertEqual(sanitized["agent_memory"]["shared_memory"]["records"], [])
        self.assertEqual(
            sanitized["detection_validation"],
            package["detection_validation"],
        )
        private_asset, shared_asset = sanitized["asset_context"]["matched_assets"]
        self.assertNotIn("owner_ref", private_asset)
        self.assertEqual(shared_asset["owner_ref"], "approved-team-alias")
        self.assertEqual(
            package["asset_context"]["matched_assets"][0]["owner_ref"],
            "sensitive-team-alias",
        )
        self.assertIn("prior_analyses", package)
        self.assertIn("role", package["instructions"])


    def test_reviewer_memory_contract_rebinds_to_confirmed_versions_only(self) -> None:
        package = {
            "agent_role": "soc-analyst",
            "alert": {"alert_id": "review-memory-alert"},
            "_local_investigation_query_context": {
                "case_id": "review-memory-case",
            },
            "evidence_reference_contract": {
                "schema": "onion-sentinel-evidence-reference-contract-v1",
                "references": [],
            },
            "agent_memory": {
                "role_memory": {
                    "records": [
                        {"id": "confirmed", "version": 3, "status": "operator-confirmed"},
                        {"id": "model-only", "version": 8, "status": "model-observed"},
                    ],
                    "snapshot": {
                        "schema": "onion-sentinel-agent-memory-snapshot-v1",
                        "source_digest": "1" * 64,
                        "selected_records_digest": "2" * 64,
                        "selected_record_versions": [
                            {"id": "confirmed", "version": 3},
                            {"id": "model-only", "version": 8},
                        ],
                    },
                },
                "shared_memory": {
                    "records": [
                        {"id": "shared-model", "version": 5, "status": "model-observed"},
                    ],
                    "snapshot": {
                        "schema": "onion-sentinel-agent-memory-snapshot-v1",
                        "source_digest": "3" * 64,
                        "selected_records_digest": "4" * 64,
                        "selected_record_versions": [
                            {"id": "shared-model", "version": 5},
                        ],
                    },
                },
            },
        }
        self.runner.attach_agent_memory_context_contract(
            package,
            evaluation_frozen=True,
        )
        primary_digest = package["memory_context_contract"]["contract_digest"]

        reviewer = self.runner.independent_reviewer_package(package)

        contract = reviewer["memory_context_contract"]
        self.assertEqual(
            contract["layers"]["durable_analyst_memory"]["selected_record_versions"],
            [{"id": "confirmed", "version": 3}],
        )
        self.assertEqual(
            contract["layers"]["shared_cross_agent_knowledge"]["selected_record_versions"],
            [],
        )
        self.assertTrue(contract["evaluation_frozen"])
        self.assertNotEqual(contract["contract_digest"], primary_digest)
        self.assertEqual(contract["case_id"], "review-memory-case")
        self.assertNotIn(
            "prior_analyses",
            [
                item["name"]
                for item in contract["layers"]["case_local_working_memory"]["sections"]
            ],
        )
        self.assertEqual(
            contract,
            build_agent_memory_context_contract(
                reviewer,
                evaluation_frozen=True,
            ),
        )


    def test_hosted_model_copy_redacts_only_unshared_asset_owners(self) -> None:
        package = {
            "detection_validation": {
                "schema": "onion-sentinel-detection-validation-v1",
                "event_status": "observed",
                "rule_intent_match": "match",
                "marker": {
                    "hex": "73656e736974697665",
                    "printable": "sensitive",
                    "raw_rule": "content secret",
                    "sha256": "a" * 64,
                    "length": 9,
                },
            },
            "asset_context": {
                "matched_assets": [
                    {
                        "asset_id": "private",
                        "owner_ref": "private-owner",
                        "share_with_hosted_models": False,
                    },
                    {
                        "asset_id": "shared",
                        "owner_ref": "shared-owner",
                        "share_with_hosted_models": True,
                    },
                ],
            },
        }

        local_copy = self.runner.model_safe_copy(package)
        hosted_copy = self.runner.model_safe_copy(package, hosted=True)

        self.assertEqual(
            local_copy["asset_context"]["matched_assets"][0]["owner_ref"],
            "private-owner",
        )
        self.assertNotIn(
            "owner_ref",
            hosted_copy["asset_context"]["matched_assets"][0],
        )
        self.assertEqual(
            hosted_copy["asset_context"]["matched_assets"][1]["owner_ref"],
            "shared-owner",
        )
        hosted_marker = hosted_copy["detection_validation"]["marker"]
        self.assertNotIn("hex", hosted_marker)
        self.assertNotIn("printable", hosted_marker)
        self.assertNotIn("raw_rule", hosted_marker)
        self.assertEqual(hosted_marker["length"], 9)
        self.assertIn("hex", local_copy["detection_validation"]["marker"])


