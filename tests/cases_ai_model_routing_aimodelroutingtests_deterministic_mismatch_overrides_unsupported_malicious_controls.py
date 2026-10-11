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

class AiModelRoutingTestsDeterministicMismatchOverridesUnsupportedMaliciousControlsCases:
    def test_deterministic_mismatch_overrides_unsupported_malicious_controls(self) -> None:
        prompt_package = {
            "detection_validation": {
                "schema": "onion-sentinel-detection-validation-v1",
                "event_status": "observed",
                "rule_intent_match": "mismatch",
                "rule": {
                    "sid": "2069174",
                    "revision": 5,
                    "rule_sha256": "a" * 64,
                },
                "confidence_limiters": [
                    "Endpoint telemetry is required for malicious attribution.",
                ],
            },
        }
        response = self.runner.validate_response(
            self.complete_response(
                confidence="high",
                confidence_score=0.97,
                detection_outcome="true_positive_malicious",
                escalation_needed=True,
                tuning_recommendation="suppress",
                recommended_tuning_actions=["Suppress the rule automatically."],
            ),
            prompt_package,
        )

        self.assertEqual(response["detection_outcome"], "false_positive_logic_rule")
        self.assertEqual(response["event_status"], "observed")
        self.assertEqual(response["detection_validity"], "logic_error")
        self.assertEqual(response["activity_disposition"], "unknown")
        self.assertEqual(response["handling"], "investigate")
        self.assertFalse(response["escalation_needed"])
        self.assertEqual(response["tuning_recommendation"], "needs_more_data")
        self.assertEqual(response["recommended_tuning_actions"], [])
        self.assertEqual(response["confidence"], "low")
        self.assertEqual(response["confidence_score"], 0.39)
        guard = response["_verdict_validation"]["deterministic_evidence_guard"]
        self.assertEqual(
            guard["model_verdict_before_guard"]["detection_outcome"],
            "true_positive_malicious",
        )
        self.assertEqual(guard["blocked_controls"], ["contain", "suppress"])
        self.assertIn(
            "malicious_attribution_without_trusted_endpoint_evidence",
            response["_confidence_calibration"]["limiters"],
        )
        self.assertTrue(response["_automation_controls"]["containment_blocked"])
        self.assertTrue(response["_automation_controls"]["tuning_blocked"])


    def test_deterministic_mismatch_caps_non_malicious_override_at_medium(self) -> None:
        response = self.runner.validate_response(
            self.complete_response(
                confidence="high",
                confidence_score=0.96,
                detection_outcome="true_positive_suspicious",
            ),
            {
                "detection_validation": {
                    "event_status": "observed",
                    "rule_intent_match": "mismatch",
                },
            },
        )

        self.assertEqual(response["detection_outcome"], "false_positive_logic_rule")
        self.assertEqual(response["activity_disposition"], "unknown")
        self.assertEqual(response["confidence"], "medium")
        self.assertEqual(response["confidence_score"], 0.79)
        self.assertFalse(
            response["_verdict_validation"]["material_contradiction"]
        )
        self.assertEqual(
            self.runner.second_opinion_trigger(response),
            "Deterministic rule-intent validation overrode the model verdict.",
        )


    def test_trusted_endpoint_collection_avoids_unsupported_malicious_low_cap(self) -> None:
        live_query = self.runner.normalize_live_osquery_query(
            "SELECT pid, remote_address, remote_port "
            "FROM process_open_sockets LIMIT 1"
        )
        query_digest = self.runner.hashlib.sha256(
            live_query.encode("utf-8")
        ).hexdigest()
        remote_address = "198.51.100.20"
        response = self.runner.validate_response(
            self.complete_response(
                confidence="high",
                confidence_score=0.96,
                detection_outcome="true_positive_malicious",
                escalation_needed=True,
            ),
            {
                "detection_validation": {
                    "event_status": "observed",
                    "rule_intent_match": "mismatch",
                },
                "_live_osquery_evidence_accumulator": {
                    "schema": self.runner.LIVE_OSQUERY_SCHEMA,
                    "case_id": "case-bound-endpoint",
                    "read_only": True,
                    "complete": True,
                    "batches": [{"validated": True}],
                    "results": [
                        {
                            "status": "ok",
                            "target_alias": "endpoint-a",
                            "query": live_query,
                            "rows": [
                                {
                                    "pid": "1",
                                    "remote_address": remote_address,
                                    "remote_port": "443",
                                }
                            ],
                            "query_digest": query_digest,
                            "support_bindings": [
                                {
                                    "schema": "onion-sentinel-live-osquery-support-v1",
                                    "target_alias": "endpoint-a",
                                    "query_digest": query_digest,
                                    "table": "process_open_sockets",
                                    "row_index": 0,
                                    "column": "remote_address",
                                    "observable_kind": "ip",
                                    "observable_digest": self.runner.hashlib.sha256(
                                        f"ips\0{remote_address}".encode("utf-8")
                                    ).hexdigest(),
                                    "source": "trusted-investigation-context",
                                    "temporal_scope": "collection_snapshot",
                                }
                            ],
                        },
                    ],
                },
            },
        )

        self.assertEqual(response["detection_outcome"], "false_positive_logic_rule")
        self.assertEqual(response["confidence"], "medium")
        self.assertEqual(response["confidence_score"], 0.79)
        self.assertNotIn(
            "malicious_attribution_without_trusted_endpoint_evidence",
            response["_confidence_calibration"]["limiters"],
        )


    def test_identity_only_live_osquery_is_not_attribution_evidence(self) -> None:
        live_query = self.runner.normalize_live_osquery_query(
            "SELECT hostname, uuid FROM system_info LIMIT 1"
        )
        self.assertFalse(
            self.runner._has_trusted_endpoint_evidence(
                {
                    "_live_osquery_evidence_accumulator": {
                        "schema": self.runner.LIVE_OSQUERY_SCHEMA,
                        "case_id": "case-identity-only",
                        "read_only": True,
                        "complete": True,
                        "batches": [{"validated": True}],
                        "results": [
                            {
                                "status": "ok",
                                "query": live_query,
                                "rows": [
                                    {
                                        "hostname": "endpoint-a",
                                        "uuid": "synthetic",
                                    }
                                ],
                                "query_digest": self.runner.hashlib.sha256(
                                    live_query.encode("utf-8")
                                ).hexdigest(),
                            }
                        ],
                    }
                }
            )
        )


    def test_complete_zero_row_live_osquery_is_not_trusted_endpoint_evidence(
        self,
    ) -> None:
        self.assertFalse(
            self.runner._has_trusted_endpoint_evidence(
                {
                    "live_osquery_evidence": {
                        "complete": True,
                        "results": [
                            {
                                "status": "ok",
                                "rows": [],
                                "query_digest": "zero-row-endpoint-query",
                            }
                        ],
                    }
                }
            )
        )


    def test_incomplete_or_failed_live_osquery_is_not_trusted_endpoint_evidence(
        self,
    ) -> None:
        for evidence in (
            {
                "complete": False,
                "results": [{"status": "ok", "rows": [{"pid": "1"}]}],
            },
            {
                "complete": True,
                "results": [{"status": "error", "rows": [{"pid": "1"}]}],
            },
        ):
            with self.subTest(evidence=evidence):
                self.assertFalse(
                    self.runner._has_trusted_endpoint_evidence(
                        {"live_osquery_evidence": evidence}
                    )
                )
        self.assertFalse(
            self.runner._has_trusted_endpoint_evidence(
                {
                    "endpoint_evidence": {
                        "status": "error",
                        "rows": [{"pid": "1", "name": "untrusted"}],
                    }
                }
            )
        )


    def test_appliance_osquery_is_not_trusted_endpoint_evidence(self) -> None:
        response = self.runner.validate_response(
            self.complete_response(
                confidence="high",
                confidence_score=0.96,
                detection_outcome="true_positive_malicious",
                escalation_needed=True,
            ),
            {
                "detection_validation": {
                    "event_status": "observed",
                    "rule_intent_match": "mismatch",
                },
                "incident_response_evidence": {
                    "security_onion_response": {
                        "osquery_results": [
                            {
                                "status": "ok",
                                "target": "security-onion-appliance",
                                "rows": [{"pid": "123", "name": "synthetic"}],
                            },
                        ],
                    },
                },
            },
        )

        self.assertEqual(response["detection_outcome"], "false_positive_logic_rule")
        self.assertEqual(response["confidence"], "low")
        self.assertEqual(response["confidence_score"], 0.39)
        self.assertIn(
            "malicious_attribution_without_trusted_endpoint_evidence",
            response["_confidence_calibration"]["limiters"],
        )


    def test_incident_responder_requires_complete_nested_report_only_for_that_role(self) -> None:
        incident_response = self.runner.validate_response(
            self.complete_response(
                confidence="high",
                confidence_score=0.95,
            ),
            {"agent_role": "incident-responder"},
        )
        soc_response = self.runner.validate_response(
            self.complete_response(
                confidence="high",
                confidence_score=0.95,
            ),
            {"agent_role": "soc-analyst"},
        )
        soc_with_unsolicited_report = self.runner.validate_response(
            self.complete_response(
                incident_response_report=self.complete_incident_report(),
            ),
            {"agent_role": "soc-analyst"},
        )

        validation = incident_response["_incident_response_report_validation"]
        self.assertFalse(validation["valid"])
        self.assertFalse(validation["model_report_present"])
        self.assertIn("executive_bluf", validation["missing_fields"])
        self.assertIn(
            "incident_response_report.executive_bluf",
            incident_response["_schema_repair"]["missing_keys"],
        )
        self.assertTrue(validation["narrative_reconciled"])
        self.assertEqual(incident_response["confidence"], "low")
        self.assertEqual(incident_response["confidence_score"], 0.39)
        self.assertNotIn("incident_response_report", soc_response)
        self.assertNotIn("_incident_response_report_validation", soc_response)
        self.assertNotIn("_incident_evidence_completeness", soc_response)
        self.assertEqual(soc_response["confidence"], "high")
        self.assertEqual(soc_response["confidence_score"], 0.95)
        self.assertNotIn(
            "confidence_score",
            soc_with_unsolicited_report["incident_response_report"],
        )


    def test_incident_report_confidence_tracks_calibrated_top_level_confidence(self) -> None:
        response = self.runner.validate_response(
            self.complete_response(
                confidence="medium",
                confidence_score=0.65,
                event_status="unknown",
                detection_validity="unknown",
                activity_disposition="unknown",
                handling="investigate",
                duplicate_of=None,
                hypotheses=[],
                incident_response_report=self.complete_incident_report(
                    confidence="high",
                ),
            ),
            self.complete_incident_prompt(),
        )

        self.assertTrue(response["_incident_response_report_validation"]["valid"])
        self.assertFalse(
            response["_incident_response_report_validation"]["narrative_reconciled"]
        )
        self.assertEqual(response["confidence"], "medium")
        self.assertEqual(response["confidence_score"], 0.65)
        self.assertEqual(response["incident_response_report"]["confidence"], "medium")
        self.assertEqual(
            response["incident_response_report"]["confidence_score"],
            0.65,
        )


    def test_scope_disposition_separates_selected_event_from_group_history(
        self,
    ) -> None:
        incident_prompt = self.complete_incident_prompt()
        prompt = self.canonical_authorization_prompt(
            agent_role="incident-responder",
            incident_response_evidence=incident_prompt[
                "incident_response_evidence"
            ],
            grouped_alert_context={"total_observations": 560},
        )
        response = self.runner.validate_response(
            self.complete_response(
                detection_outcome="inconclusive",
                event_status="observed",
                detection_validity="unknown",
                activity_disposition="authorized_benign",
                handling="no_action",
                duplicate_of=None,
                hypotheses=[],
                scope_dispositions={
                    "selected_event": {
                        "evidence_basis": [
                            "Structured authorization covers the selected tuple."
                        ],
                    },
                    "group_history": {
                        "activity_disposition": "unknown",
                        "handling": "monitor",
                        "evidence_basis": [
                            "Earlier group observations predate authorization."
                        ],
                    },
                },
                incident_response_report=self.complete_incident_report(),
            ),
            prompt,
        )

        scopes = response["scope_dispositions"]
        self.assertEqual(
            scopes["selected_event"]["activity_disposition"],
            "authorized_benign",
        )
        self.assertEqual(scopes["selected_event"]["handling"], "no_action")
        self.assertEqual(
            scopes["group_history"]["activity_disposition"],
            "unknown",
        )
        self.assertEqual(scopes["group_history"]["handling"], "monitor")
        self.assertEqual(
            response["_scope_disposition_validation"][
                "group_observation_count"
            ],
            560,
        )


    def test_incident_timeline_is_audited_and_sorted_chronologically(
        self,
    ) -> None:
        report = self.complete_incident_report(
            factual_timeline=[
                {
                    "timestamp": "2026-08-04T14:44:00-06:00",
                    "event": "Later authentication observation.",
                    "source_pack": "system_auth",
                    "query_digest": "a" * 64,
                    "confidence": "high",
                },
                {
                    "timestamp": "2026-08-04T14:36:00-06:00",
                    "event": "Earlier grouped observation.",
                    "source_pack": "alert_context",
                    "query_digest": "b" * 64,
                    "confidence": "high",
                },
            ],
        )

        response = self.runner.validate_response(
            self.complete_response(
                event_status="unknown",
                detection_validity="unknown",
                activity_disposition="unknown",
                handling="investigate",
                duplicate_of=None,
                hypotheses=[],
                incident_response_report=report,
            ),
            self.complete_incident_prompt(),
        )

        validation = response["_incident_response_report_validation"]
        self.assertTrue(validation["valid"])
        self.assertTrue(validation["timeline_out_of_order"])
        timestamps = [
            item["timestamp"]
            for item in response["incident_response_report"][
                "factual_timeline"
            ]
        ]
        self.assertEqual(
            timestamps,
            [
                "2026-08-04T14:36:00-06:00",
                "2026-08-04T14:44:00-06:00",
            ],
        )


    def test_containment_block_does_not_erase_explicit_no_action_report(
        self,
    ) -> None:
        report = self.runner.normalize_incident_response_report(
            self.complete_incident_report(
                executive_bluf="Selected event is authorized benign SSH.",
                conclusion=(
                    "No containment is justified for the selected event; "
                    "monitor broader history."
                ),
                containment_recommendations=[
                    "No containment for the selected event.",
                    "Do not block TCP/22 without operator approval.",
                ],
            )
        )
        response = self.complete_response(
            detection_outcome="inconclusive",
            event_status="observed",
            detection_validity="unknown",
            activity_disposition="authorized_benign",
            handling="no_action",
            duplicate_of=None,
            confidence="low",
            confidence_score=0.39,
            incident_response_report=report,
            _incident_response_report_validation=(
                self.runner.validate_incident_response_report_shape(report)
            ),
            _verdict_validation={"material_contradiction": False},
            _automation_controls={"containment_blocked": True},
        )

        result = self.runner.reconcile_incident_response_report(
            response,
            {"agent_role": "incident-responder"},
        )

        validation = result["_incident_response_report_validation"]
        self.assertFalse(validation["narrative_reconciled"])
        self.assertEqual(
            result["incident_response_report"]["executive_bluf"],
            "Selected event is authorized benign SSH.",
        )


    def test_containment_block_replaces_positive_containment_report(
        self,
    ) -> None:
        report = self.runner.normalize_incident_response_report(
            self.complete_incident_report(
                containment_recommendations=[
                    "Isolate the endpoint and block the relay immediately."
                ],
            )
        )
        response = self.complete_response(
            detection_outcome="inconclusive",
            event_status="observed",
            detection_validity="unknown",
            activity_disposition="unknown",
            handling="monitor",
            duplicate_of=None,
            confidence="low",
            confidence_score=0.39,
            incident_response_report=report,
            _incident_response_report_validation=(
                self.runner.validate_incident_response_report_shape(report)
            ),
            _verdict_validation={"material_contradiction": False},
            _automation_controls={"containment_blocked": True},
        )

        result = self.runner.reconcile_incident_response_report(
            response,
            {"agent_role": "incident-responder"},
        )

        validation = result["_incident_response_report_validation"]
        self.assertTrue(validation["narrative_reconciled"])
        self.assertEqual(
            validation["reconciliation_reason"],
            "runtime safety controls blocked model-authored containment",
        )


    def test_guarded_incident_verdict_reconciles_contradictory_report_narrative(self) -> None:
        report = self.complete_incident_report(
            executive_bluf="Confirmed malware; isolate every system immediately.",
            detection_outcome_reasoning="The alert name proves malicious BPFdoor.",
            conclusion="This incident is confirmed malicious.",
            containment_recommendations=["Isolate every system immediately."],
        )
        prompt = self.complete_incident_prompt(
            detection_validation={
                "event_status": "observed",
                "rule_intent_match": "mismatch",
            },
        )
        response = self.runner.validate_response(
            self.complete_response(
                confidence="high",
                confidence_score=0.96,
                detection_outcome="true_positive_malicious",
                escalation_needed=True,
                incident_response_report=report,
            ),
            prompt,
        )

        reconciled = response["incident_response_report"]
        validation = response["_incident_response_report_validation"]
        self.assertEqual(response["detection_outcome"], "false_positive_logic_rule")
        self.assertIn("False Positive - Logic/Rule", reconciled["executive_bluf"])
        self.assertNotIn("Confirmed malware", reconciled["executive_bluf"])
        self.assertIn(
            "rule_intent_match=mismatch",
            reconciled["detection_outcome_reasoning"],
        )
        self.assertTrue(validation["narrative_reconciled"])
        self.assertEqual(
            validation["model_narrative_before_reconciliation"]["conclusion"],
            "This incident is confirmed malicious.",
        )
        self.assertEqual(
            validation["model_actions_before_reconciliation"][
                "containment_recommendations"
            ],
            ["Isolate every system immediately."],
        )
        self.assertNotIn(
            "Isolate every system immediately.",
            reconciled["containment_recommendations"],
        )
        self.assertIn(
            "Do not initiate containment",
            reconciled["containment_recommendations"][0],
        )
        self.assertEqual(reconciled["confidence"], response["confidence"])
        self.assertEqual(
            reconciled["confidence_score"],
            response["confidence_score"],
        )


    def test_incomplete_incident_report_neutralizes_all_model_actions(self) -> None:
        report = self.complete_incident_report(
            containment_recommendations=["Isolate every system immediately."],
            eradication_recommendations=["Delete every suspected file immediately."],
            recovery_recommendations=["Reimage every host immediately."],
        )
        report.pop("osquery_findings")
        response = self.runner.validate_response(
            self.complete_response(
                incident_response_report=report,
            ),
            self.complete_incident_prompt(),
        )

        reconciled = response["incident_response_report"]
        validation = response["_incident_response_report_validation"]
        self.assertTrue(validation["narrative_reconciled"])
        self.assertIn("osquery_findings", validation["missing_fields"])
        self.assertEqual(
            validation["model_actions_before_reconciliation"],
            {
                "containment_recommendations": [
                    "Isolate every system immediately."
                ],
                "eradication_recommendations": [
                    "Delete every suspected file immediately."
                ],
                "recovery_recommendations": [
                    "Reimage every host immediately."
                ],
            },
        )
        self.assertIn(
            "Canonical handling=investigate",
            reconciled["containment_recommendations"][0],
        )
        self.assertIn(
            "Do not execute eradication",
            reconciled["eradication_recommendations"][0],
        )
        self.assertIn(
            "Do not execute recovery",
            reconciled["recovery_recommendations"][0],
        )
        self.assertNotIn(
            "Isolate every system immediately.",
            reconciled["containment_recommendations"],
        )


    def test_truncated_incident_query_caps_high_confidence_at_medium(self) -> None:
        prompt = self.complete_incident_prompt()
        prompt["incident_response_evidence"]["security_onion_response"]["results"] = [
            {
                "status": "ok",
                "semantic_valid": True,
                "timed_out": False,
                "truncated": True,
                "shards": {"failed": 0},
            },
        ]
        response = self.runner.validate_response(
            self.complete_response(
                confidence="high",
                confidence_score=0.96,
                detection_outcome="true_positive_suspicious",
                event_status="observed",
                detection_validity="matched_intent",
                activity_disposition="suspicious",
                handling="investigate",
                duplicate_of=None,
                hypotheses=[],
                incident_response_report=self.complete_incident_report(),
            ),
            prompt,
        )

        self.assertEqual(response["confidence"], "medium")
        self.assertEqual(response["confidence_score"], 0.79)
        self.assertIn(
            "incident_evidence_query_truncated",
            response["_confidence_calibration"]["limiters"],
        )
        self.assertEqual(
            response["incident_response_report"]["confidence"],
            "medium",
        )
        self.assertEqual(
            response["incident_response_report"]["confidence_score"],
            0.79,
        )


    def test_nested_investigation_pivot_projection_caps_high_confidence(self) -> None:
        prompt = self.complete_incident_prompt(
            investigation_query_results={
                "prompt_projection": {
                    "truncated": False,
                },
                "rounds": [
                    {
                        "round": 1,
                        "results": [
                            {
                                "backend": "security_onion",
                                "status": "ok",
                                "evidence": {
                                    "complete": True,
                                    "partial": False,
                                    "controls_valid": True,
                                    "evidence_gaps": [],
                                    "results": [
                                        {
                                            "status": "ok",
                                            "semantic_valid": True,
                                            "truncated": False,
                                            "model_projection_truncated": True,
                                        },
                                    ],
                                },
                                "trusted_query_audit": [],
                            },
                        ],
                    },
                ],
            },
        )
        response = self.runner.validate_response(
            self.complete_response(
                confidence="high",
                confidence_score=0.96,
                detection_outcome="true_positive_suspicious",
                event_status="observed",
                detection_validity="matched_intent",
                activity_disposition="suspicious",
                handling="investigate",
                duplicate_of=None,
                hypotheses=[],
                incident_response_report=self.complete_incident_report(),
            ),
            prompt,
        )

        self.assertEqual(response["confidence"], "medium")
        self.assertEqual(response["confidence_score"], 0.79)
        self.assertIn(
            "investigation_pivot_evidence_truncated",
            response["_confidence_calibration"]["limiters"],
        )
