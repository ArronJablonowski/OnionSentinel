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

class AiModelRoutingTestsControlledEvaluationTwoInvalidReviewsStopBeforeResultCommitCases:
    def test_controlled_evaluation_two_invalid_reviews_stop_before_result_commit(
        self,
    ) -> None:
        settings = self.runner.default_ai_settings()
        settings["enabled_ollama_models"] = [
            "primary:latest",
            "reviewer:latest",
        ]
        settings["agent_models"]["soc-analyst"] = "ollama:primary:latest"
        settings["agent_second_opinion_models"][
            "soc-analyst"
        ] = "ollama:reviewer:latest"
        primary = self.complete_response(
            confidence="low",
            confidence_score=0.3,
            detection_outcome="inconclusive",
        )

        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            prompt_path = root / "prompt.json"
            out_dir = root / "results"
            prompt_path.write_text(
                json.dumps(
                    {
                        "package_type": "soc-ai-investigation-prompt",
                        "agent_role": "soc-analyst",
                        "alert": {"alert_id": "two-invalid-reviews"},
                    }
                ),
                encoding="utf-8",
            )
            args = self.runner.argparse.Namespace(
                flush_index_only=False,
                alert_store_url="http://127.0.0.1:8766",
                generate_prompt=False,
                prompt_package=prompt_path,
                prompt_dir=root,
                max_prompt_bytes=self.runner.DEFAULT_MAX_PROMPT_BYTES,
                response_json=None,
                max_response_bytes=self.runner.DEFAULT_MAX_JSON_ARTIFACT_BYTES,
                investigation_harness_policy=root / "policy.json",
                investigation_harness_db=root / "harness.sqlite3",
                reanalysis_attempt_id="controlled-evaluation-attempt",
                second_opinion_prompt_file=root / "reviewer.md",
                system_prompt_file=root / "primary.md",
                out_dir=out_dir,
                stdout=False,
            )
            policy = mock.Mock(enabled=True, mode="shadow")
            harness = mock.Mock()
            harness.policy.mode = "shadow"
            monitor = mock.Mock()

            def invalid_reviewer(
                _route,
                review_package,
                *_args,
                **_kwargs,
            ):
                contract = review_package["review_contract"]
                return {
                    **self.complete_response(
                        evidence_used=[
                            "alert",
                            "alert:two-invalid-reviews",
                        ],
                        event_status="unknown",
                        detection_validity="unknown",
                        activity_disposition="unknown",
                        handling="investigate",
                        duplicate_of=None,
                        hypotheses=[],
                    ),
                    "review_case_id": "foreign-case",
                    "review_evidence_hash": contract["evidence_hash"],
                    "observables_used": [],
                }

            with ExitStack() as stack:
                stack.enter_context(
                    mock.patch.dict(
                        self.runner.os.environ,
                        {self.runner.EVALUATION_FREEZE_MEMORY_ENV: "1"},
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        self.runner,
                        "parse_args",
                        return_value=args,
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        self.runner,
                        "flush_analysis_index_queue",
                        return_value=(0, 0, 0),
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        self.runner,
                        "effective_ai_settings",
                        return_value=settings,
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        self.runner,
                        "prepare_live_osquery_context",
                        return_value=None,
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        self.runner,
                        "attach_agent_memory_context_contract",
                        side_effect=lambda value, **_kwargs: value,
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        self.runner,
                        "load_investigation_harness_policy",
                        return_value=policy,
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        self.runner,
                        "should_start_onion_sentinel_harness",
                        return_value=(True, "synthetic"),
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        self.runner,
                        "start_harness_run",
                        return_value=harness,
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        self.runner,
                        "SystemResourceMonitor",
                        return_value=monitor,
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        self.runner,
                        "active_analysis_record_path",
                        return_value=root / "active.json",
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        self.runner,
                        "build_llm_log_record",
                        return_value={},
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        self.runner,
                        "publish_current_analysis_phase",
                        return_value={},
                    )
                )
                stack.enter_context(
                    mock.patch.object(self.runner, "atomic_write_json")
                )
                stack.enter_context(
                    mock.patch.object(self.runner, "append_jsonl")
                )
                stack.enter_context(
                    mock.patch.object(
                        self.runner,
                        "analyze_with_config",
                        return_value=primary,
                    )
                )
                analyze = stack.enter_context(
                    mock.patch.object(
                        self.runner,
                        "analyze_model_route",
                        side_effect=invalid_reviewer,
                    )
                )
                write = stack.enter_context(
                    mock.patch.object(PIPELINE_ADAPTERS, "write_outputs")
                )
                queue = stack.enter_context(
                    mock.patch.object(
                        self.runner,
                        "queue_analysis_index",
                    )
                )
                commit = stack.enter_context(
                    mock.patch.object(
                        self.runner,
                        "post_analysis_index",
                    )
                )
                stack.enter_context(
                    self.assertRaisesRegex(
                        self.runner.ControlledEvaluationReviewerGateError,
                        "produced no validated response",
                    )
                )
                self.runner.main()

            self.assertEqual(analyze.call_count, 2)
            write.assert_not_called()
            queue.assert_not_called()
            commit.assert_not_called()
            self.assertFalse(out_dir.exists())

        # Outside a frozen evaluation the same advisory failure remains
        # production-compatible and does not raise the precommit exception.
        reviewer = self.runner.precommit_controlled_evaluation_reviewer_gate(
            {"alert": {"alert_id": "two-invalid-reviews"}},
            {
                "_second_opinion": {
                    "status": "failed",
                    "trigger": "synthetic",
                }
            },
            settings,
            "soc-analyst",
            trigger_reason="synthetic",
            freeze_enabled=False,
        )
        self.assertIsNone(reviewer)


    def test_elasticsearch_alert_id_suffix_is_not_a_community_id(self) -> None:
        alert_id = (
            ".ds-logs-suricata.alerts-so-2026.07.24-000001-"
            "000535:XuBJm58BIwAfe8Cpckf6"
        )
        prompt_package = self.runner.independent_reviewer_package(
            {"alert": {"alert_id": alert_id}}
        )
        contract = prompt_package["review_contract"]
        response = {
            **self.complete_response(
                summary=f"Reviewed Elasticsearch alert document {alert_id}.",
                evidence_used=["alert", f"alert:{alert_id}"],
                event_status="unknown",
                detection_validity="unknown",
                activity_disposition="unknown",
                handling="investigate",
                duplicate_of=None,
                hypotheses=[],
            ),
            "review_case_id": contract["case_id"],
            "review_evidence_hash": contract["evidence_hash"],
            "observables_used": [],
        }

        validated = self.runner.validate_reviewer_response(
            response,
            prompt_package,
        )

        self.assertTrue(validated["_review_contract_validation"]["valid"])
        community_id = "1:Y9R9syXYWvDIRM6pRrzmcXHA1c4="
        self.assertEqual(
            self.runner.REVIEW_COMMUNITY_ID_RE.findall(community_id),
            [community_id],
        )
        self.assertEqual(
            self.runner.REVIEW_COMMUNITY_ID_RE.findall(
                "01:Y9R9syXYWvDIRM6pRrzmcXHA1c4="
            ),
            [],
        )
        self.assertEqual(
            self.runner.REVIEW_COMMUNITY_ID_RE.findall(
                "1:Y9R9syXYWvDIRM6pRrzmcXHA1c5="
            ),
            [],
        )
        self.assertEqual(
            self.runner.REVIEW_COMMUNITY_ID_RE.findall(alert_id),
            [],
        )


    def test_dns_query_schema_path_is_not_a_foreign_domain(self) -> None:
        prompt_package = self.runner.independent_reviewer_package(
            {"alert": {"alert_id": "dns-query-schema-path"}}
        )
        contract = prompt_package["review_contract"]
        response = {
            **self.complete_response(
                summary=(
                    "The dns.query field was unavailable, so the event "
                    "remains inconclusive."
                ),
                evidence_used=[
                    "alert",
                    "alert:dns-query-schema-path",
                ],
                event_status="unknown",
                detection_validity="unknown",
                activity_disposition="unknown",
                handling="investigate",
                duplicate_of=None,
                hypotheses=[],
            ),
            "review_case_id": contract["case_id"],
            "review_evidence_hash": contract["evidence_hash"],
            "observables_used": [],
        }

        validated = self.runner.validate_reviewer_response(
            response,
            prompt_package,
        )

        self.assertTrue(validated["_review_contract_validation"]["valid"])


    def test_reviewed_query_field_paths_are_not_foreign_domains(self) -> None:
        prompt_package = self.runner.independent_reviewer_package(
            {"alert": {"alert_id": "reviewed-query-field-paths"}}
        )
        contract = prompt_package["review_contract"]
        response = {
            **self.complete_response(
                summary=(
                    "The dns.query, dns.query.name, tls.server.name, "
                    "http.virtual_host, and network.community_id fields were "
                    "checked without asserting new observable values."
                ),
                evidence_used=[
                    "alert",
                    "alert:reviewed-query-field-paths",
                ],
                event_status="unknown",
                detection_validity="unknown",
                activity_disposition="unknown",
                handling="investigate",
                duplicate_of=None,
                hypotheses=[],
            ),
            "review_case_id": contract["case_id"],
            "review_evidence_hash": contract["evidence_hash"],
            "observables_used": [],
        }

        validated = self.runner.validate_reviewer_response(
            response,
            prompt_package,
        )

        self.assertTrue(validated["_review_contract_validation"]["valid"])
        for field in (
            "dns.query",
            "dns.query.name",
            "tls.server.name",
            "http.virtual_host",
            "network.community_id",
        ):
            self.assertIn(field, self.runner.REVIEW_KNOWN_FIELD_PATHS)


    def test_foreign_community_retry_records_bounded_attempt_telemetry(
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
        allowed_community_id = "1:gVOca2cr2eIKwoIKZ8QnLwW2gqU="
        foreign_community_id = "1:Y9R9syXYWvDIRM6pRrzmcXHA1c4="
        repair_packages: list[dict] = []
        repair_prompt_serializations: list[str] = []

        def invalid_response(_route, review_package, *_args, **_kwargs):
            if isinstance(review_package.get("review_contract_repair"), dict):
                repair_packages.append(
                    json.loads(
                        json.dumps(
                            review_package["review_contract_repair"]
                        )
                    )
                )
                repair_prompt_serializations.append(
                    json.dumps(
                        review_package,
                        sort_keys=True,
                        separators=(",", ":"),
                        default=str,
                    )
                )
            contract = review_package["review_contract"]
            return {
                **self.complete_response(
                    confidence="high",
                    confidence_score=0.9,
                    evidence_used=["alert", "alert:community-id-case"],
                    summary=(
                        "The supplied evidence included Community ID "
                        f"{foreign_community_id}."
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
            side_effect=invalid_response,
        ) as analyze:
            result = self.runner.apply_configured_second_opinion(
                {
                    "alert": {
                        "alert_id": "community-id-case",
                        "community_id": allowed_community_id,
                    },
                },
                primary,
                args,
                settings,
                "soc-analyst",
            )

        self.assertEqual(analyze.call_count, 2)
        self.assertEqual(result["_second_opinion"]["status"], "failed")
        self.assertEqual(result["_second_opinion"]["attempts"], 2)
        failures = result["_second_opinion"]["validation_failures"]
        self.assertEqual(len(failures), 2)
        self.assertEqual(
            [failure["attempt"] for failure in failures],
            [1, 2],
        )
        self.assertEqual(
            [failure["call_id"] for failure in failures],
            ["independent-review-1", "independent-review-2"],
        )
        self.assertNotEqual(
            failures[0]["input_digest"],
            failures[1]["input_digest"],
        )
        self.assertEqual(
            failures[0]["output_digest"],
            failures[1]["output_digest"],
        )
        for failure in failures:
            self.assertEqual(
                failure["schema"],
                self.runner.REVIEW_VALIDATION_FAILURE_SCHEMA,
            )
            self.assertEqual(failure["status"], "validation-failed")
            self.assertIn("foreign community ID", failure["message"])
            self.assertIn(foreign_community_id, failure["message"])
            self.assertRegex(failure["input_digest"], r"^[a-f0-9]{64}$")
            self.assertRegex(failure["output_digest"], r"^[a-f0-9]{64}$")
            self.assertLessEqual(
                len(failure["message"]),
                self.runner.REVIEW_VALIDATION_MESSAGE_MAX,
            )
            self.assertNotIn("response", failure)
            self.assertNotIn("candidate", failure)

        self.assertEqual(len(repair_packages), 1)
        repair = repair_packages[0]
        self.assertIn(
            "outside review_contract.allowed_observables",
            repair["validation_errors"],
        )
        self.assertNotIn(
            foreign_community_id,
            repair["validation_errors"],
        )
        guidance = " ".join(repair["field_guidance"])
        self.assertIn("Elastic index/document identifiers", guidance)
        self.assertIn("not Community IDs", guidance)
        self.assertIn("allowed_observables", guidance)
        self.assertIn("do not repeat", guidance.lower())
        self.assertEqual(len(repair_prompt_serializations), 1)
        self.assertNotIn(
            foreign_community_id,
            repair_prompt_serializations[0],
        )


    def test_reviewer_repair_category_does_not_echo_foreign_domain(self) -> None:
        rejected = "discord.com"
        category = self.runner.reviewer_repair_error_category(
            "reviewer used foreign observables: domain:"
            + rejected
            + "; reviewer introduced foreign domain or FQDN value(s): "
            + rejected
        )

        self.assertIn(
            "outside review_contract.allowed_observables",
            category,
        )
        self.assertNotIn(rejected, category)
        guidance = " ".join(
            self.runner.reviewer_repair_guidance(
                "reviewer used foreign observables: domain:"
                + rejected
                + "; reviewer introduced foreign domain or FQDN value(s): "
                + rejected
            )
        )
        self.assertNotIn(rejected, guidance)
        self.assertIn("do not repeat", guidance.lower())


    def test_reviewer_observable_overflow_cannot_hide_foreign_host(self) -> None:
        review_package = self.runner.independent_reviewer_package(
            {
                "alert": {
                    "alert_id": "observable-overflow-case",
                    "host": "allowedhost",
                },
            }
        )
        contract = review_package["review_contract"]
        allowed_host = next(
            item
            for item in contract["allowed_observables"]
            if item["kind"] == "host"
        )
        response = {
            **self.complete_response(
                summary="The endpoint foreignhost performed the material activity.",
                evidence_used=["alert", "alert:observable-overflow-case"],
                confidence="high",
                confidence_score=0.9,
            ),
            "event_status": "unknown",
            "detection_validity": "unknown",
            "activity_disposition": "unknown",
            "handling": "investigate",
            "duplicate_of": None,
            "hypotheses": [],
            "review_case_id": contract["case_id"],
            "review_evidence_hash": contract["evidence_hash"],
            # Duplicate valid entries previously filled the validated prefix,
            # allowing the foreign final entry into the full-list membership set.
            "observables_used": [
                dict(allowed_host)
                for _ in range(self.runner.REVIEW_OBSERVABLE_MAX)
            ] + [{"kind": "host", "value": "foreignhost"}],
        }

        with self.assertRaisesRegex(
            self.runner.ReviewerValidationError,
            "observables_used exceeds the maximum",
        ):
            self.runner.validate_reviewer_response(response, review_package)


    def test_reviewer_consequential_arrays_reject_overflow(self) -> None:
        review_package = self.runner.independent_reviewer_package(
            {"alert": {"alert_id": "review-array-overflow-case"}}
        )
        contract = review_package["review_contract"]
        base = {
            **self.complete_response(
                evidence_used=["alert", "alert:review-array-overflow-case"],
            ),
            "event_status": "unknown",
            "detection_validity": "unknown",
            "activity_disposition": "unknown",
            "handling": "investigate",
            "duplicate_of": None,
            "hypotheses": [],
            "review_case_id": contract["case_id"],
            "review_evidence_hash": contract["evidence_hash"],
            "observables_used": [],
        }

        for field, value, expected in (
            (
                "evidence_used",
                ["alert"] * (self.runner.REVIEW_EVIDENCE_USED_MAX + 1),
                "evidence_used exceeds the maximum",
            ),
            (
                "hypotheses",
                [{}] * (self.runner.REVIEW_HYPOTHESES_MAX + 1),
                "hypotheses exceeds the maximum",
            ),
        ):
            with self.subTest(field=field):
                with self.assertRaisesRegex(
                    self.runner.ReviewerValidationError,
                    expected,
                ):
                    self.runner.validate_reviewer_response(
                        {**base, field: value},
                        review_package,
                    )


    def test_reviewer_foreign_narrative_domain_fails_closed(self) -> None:
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
            self.complete_response(confidence="low", confidence_score=0.3)
        )
        repair_prompt_serializations: list[str] = []

        def invalid_response(_route, review_package, *_args, **_kwargs):
            if isinstance(review_package.get("review_contract_repair"), dict):
                repair_prompt_serializations.append(
                    json.dumps(
                        review_package,
                        sort_keys=True,
                        separators=(",", ":"),
                        default=str,
                    )
                )
            contract = review_package["review_contract"]
            return {
                **self.complete_response(
                    confidence="high",
                    confidence_score=0.9,
                    evidence_used=["alert", "alert:domain-case"],
                    summary="The supplied evidence proves contact with foreign.example.",
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
                {
                    "alert": {
                        "alert_id": "domain-case",
                        "domain": "allowed.example",
                    }
                },
                primary,
                args,
                settings,
                "soc-analyst",
            )

        self.assertEqual(analyze.call_count, 2)
        self.assertEqual(result["_second_opinion"]["status"], "failed")
        self.assertIn(
            "foreign domain or FQDN",
            result["_second_opinion"]["error"],
        )
        self.assertEqual(result["final_disposition_status"], "review_required_failed")
        self.assertEqual(len(repair_prompt_serializations), 1)
        self.assertNotIn(
            "foreign.example",
            repair_prompt_serializations[0],
        )
