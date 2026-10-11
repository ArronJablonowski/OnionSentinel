from __future__ import annotations

from onion_sentinel_harness_fixtures import (
    HARNESS,
    MODULE_PATH,
    Path,
    ROOT,
    SPEC,
    contextlib,
    dataclasses,
    gc,
    importlib,
    inspect,
    json,
    mock,
    os,
    sqlite3,
    stat,
    subprocess,
    sys,
    tempfile,
    threading,
    unittest,
    warnings,
)

class OnionSentinelHarnessTestsQueryRoundResolvesDigestBoundNestedStatusInPartialBatchCases:
    def test_query_round_resolves_digest_bound_nested_status_in_partial_batch(
        self,
    ) -> None:
        run = self.make_run("query-partial-batch-semantics")
        query_digest_ok = "a" * 64
        result_digest_ok = "b" * 64
        query_digest_failed = "c" * 64
        result_digest_failed = "d" * 64
        query_digest_ok_two = "1" * 64
        result_digest_ok_two = "2" * 64
        query_digest_failed_two = "3" * 64
        result_digest_failed_two = "4" * 64
        batch_result = {
            "backend": "security_onion",
            "query_ids": [
                "successful-pivot",
                "failed-pivot",
                "successful-pivot-two",
                "failed-pivot-two",
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
                        "returned_hits": 2,
                    },
                    {
                        "query_id": "failed-pivot",
                        "status": "invalid_response",
                        "semantic_valid": False,
                        "query_digest": query_digest_failed,
                        "result_digest": result_digest_failed,
                    },
                    {
                        "query_id": "successful-pivot-two",
                        "status": "ok",
                        "semantic_valid": True,
                        "query_digest": query_digest_ok_two,
                        "result_digest": result_digest_ok_two,
                        "returned_hits": 0,
                    },
                    {
                        "query_id": "failed-pivot-two",
                        "status": "invalid_response",
                        "semantic_valid": False,
                        "query_digest": query_digest_failed_two,
                        "result_digest": result_digest_failed_two,
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
                    "returned_hits": 2,
                    "shards": {
                        "total": 4,
                        "successful": 4,
                        "skipped": 2,
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
                {
                    "query_id": "successful-pivot-two",
                    "status": "ok",
                    "semantic_valid": True,
                    "timed_out": False,
                    "query_digest": query_digest_ok_two,
                    "result_digest": result_digest_ok_two,
                    "returned_hits": 0,
                    "shards": {
                        "total": 2,
                        "successful": 2,
                        "skipped": 0,
                        "failed": 0,
                        "failures": [],
                    },
                },
                {
                    "query_id": "failed-pivot-two",
                    "status": "invalid_response",
                    "semantic_valid": False,
                    "timed_out": False,
                    "query_digest": query_digest_failed_two,
                    "result_digest": result_digest_failed_two,
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
        run.query_round(
            {
                "round": 1,
                "requests": [
                    {
                        "query_id": "successful-pivot",
                        "backend": "elastic",
                        "purpose": "Validate the exact network event.",
                    },
                    {
                        "query_id": "failed-pivot",
                        "backend": "elastic",
                        "purpose": "Test a second discriminator.",
                    },
                    {
                        "query_id": "successful-pivot-two",
                        "backend": "elastic",
                        "purpose": "Measure exact prevalence.",
                    },
                    {
                        "query_id": "failed-pivot-two",
                        "backend": "elastic",
                        "purpose": "Test an unsupported field response.",
                    },
                ],
                "results": [batch_result],
            }
        )

        calls = {
            item["call_id"]: item
            for item in run.store.export_trace(run.run_id)["tool_calls"]
        }
        successful = calls["round-1-successful-pivot"]
        failed = calls["round-1-failed-pivot"]
        successful_two = calls["round-1-successful-pivot-two"]
        failed_two = calls["round-1-failed-pivot-two"]
        self.assertEqual(successful["status"], "ok")
        self.assertEqual(successful["coverage"], "bounded-result")
        self.assertEqual(successful["truncated"], 0)
        self.assertEqual(failed["status"], "invalid_response")
        self.assertEqual(failed["coverage"], "evidence-gap")
        self.assertEqual(successful_two["status"], "ok")
        self.assertEqual(successful_two["coverage"], "exact-zero")
        self.assertEqual(failed_two["status"], "invalid_response")
        self.assertEqual(
            successful["result_digest"],
            HARNESS.digest_json(batch_result),
        )
        self.assertEqual(failed["result_digest"], successful["result_digest"])
        self.assertEqual(
            successful_two["result_digest"],
            successful["result_digest"],
        )
        self.assertEqual(failed_two["result_digest"], successful["result_digest"])

        mismatched = json.loads(json.dumps(batch_result))
        mismatched["trusted_query_audit"][0]["result_digest"] = "f" * 64
        status, observation = HARNESS.resolve_query_binding(
            mismatched,
            "successful-pivot",
        )
        self.assertEqual(status, "partial")
        self.assertIs(observation, mismatched)

        malformed_cases = []

        def malformed(label, mutate):
            candidate = json.loads(json.dumps(batch_result))
            mutate(candidate)
            malformed_cases.append((label, candidate))

        malformed(
            "model evidence is not read-only",
            lambda item: item["evidence"].__setitem__("read_only", False),
        )
        malformed(
            "partial flag is inconsistent",
            lambda item: item["evidence"].__setitem__("partial", False),
        )
        malformed(
            "complete flag is inconsistent",
            lambda item: item["evidence"].__setitem__("complete", True),
        )
        malformed(
            "controls are invalid",
            lambda item: item["evidence"].__setitem__(
                "controls_valid",
                False,
            ),
        )
        malformed(
            "response digest is malformed",
            lambda item: item.__setitem__(
                "security_onion_response_digest",
                "not-a-digest",
            ),
        )
        malformed(
            "outer query ids are duplicated",
            lambda item: item["query_ids"].append("successful-pivot"),
        )
        malformed(
            "nested query coverage is incomplete",
            lambda item: item["evidence"]["results"].pop(),
        )
        malformed(
            "audit query coverage is incomplete",
            lambda item: item["trusted_query_audit"].pop(),
        )
        malformed(
            "nested status is outside the closed broker contract",
            lambda item: (
                item["evidence"]["results"][0].__setitem__(
                    "status",
                    "unknown",
                ),
                item["evidence"]["results"][0].__setitem__(
                    "semantic_valid",
                    False,
                ),
                item["trusted_query_audit"][0].__setitem__(
                    "status",
                    "unknown",
                ),
                item["trusted_query_audit"][0].__setitem__(
                    "semantic_valid",
                    False,
                ),
            ),
        )
        malformed(
            "semantic validity contradicts success",
            lambda item: item["evidence"]["results"][0].__setitem__(
                "semantic_valid",
                False,
            ),
        )
        malformed(
            "successful query timed out",
            lambda item: item["trusted_query_audit"][0].__setitem__(
                "timed_out",
                True,
            ),
        )
        malformed(
            "successful shard coverage is incomplete",
            lambda item: item["trusted_query_audit"][0]["shards"].__setitem__(
                "successful",
                3,
            ),
        )
        malformed(
            "successful shard count is zero",
            lambda item: (
                item["trusted_query_audit"][0]["shards"].__setitem__(
                    "total",
                    0,
                ),
                item["trusted_query_audit"][0]["shards"].__setitem__(
                    "successful",
                    0,
                ),
                item["trusted_query_audit"][0]["shards"].__setitem__(
                    "skipped",
                    0,
                ),
            ),
        )
        malformed(
            "successful query has failed shards",
            lambda item: (
                item["trusted_query_audit"][0]["shards"].__setitem__(
                    "failed",
                    1,
                ),
                item["trusted_query_audit"][0]["shards"].__setitem__(
                    "failures",
                    [{"reason": "synthetic"}],
                ),
            ),
        )
        for label, candidate in malformed_cases:
            with self.subTest(label=label):
                status, _observation = HARNESS.resolve_query_binding(
                    candidate,
                    "successful-pivot",
                )
                self.assertEqual(status, "partial")

        ordinary = {
            "query_id": "ordinary",
            "backend": "elastic",
            "status": "ok",
            "read_only": True,
        }
        status, observation = HARNESS.resolve_query_binding(
            ordinary,
            "ordinary",
        )
        self.assertEqual(status, "ok")
        self.assertIs(observation, ordinary)


    def test_query_round_scopes_truncation_within_complete_batch(self) -> None:
        run = self.make_run("query-complete-batch-truncation-semantics")
        query_digests = ["a" * 64, "c" * 64]
        result_digests = ["b" * 64, "d" * 64]
        query_ids = ["complete-pivot", "projected-pivot"]
        nested_results = []
        trusted_audits = []
        for index, query_id in enumerate(query_ids):
            projection_truncated = query_id == "projected-pivot"
            nested_results.append(
                {
                    "query_id": query_id,
                    "status": "ok",
                    "semantic_valid": True,
                    "query_digest": query_digests[index],
                    "result_digest": result_digests[index],
                    "returned_hits": 22 if projection_truncated else 1,
                    "model_projection_truncated": projection_truncated,
                }
            )
            trusted_audits.append(
                {
                    **nested_results[-1],
                    "timed_out": False,
                    "shards": {
                        "total": 2,
                        "successful": 2,
                        "skipped": 0,
                        "failed": 0,
                        "failures": [],
                    },
                }
            )
        batch_result = {
            "backend": "security_onion",
            "query_ids": query_ids,
            "status": "ok",
            "read_only": True,
            "security_onion_response_digest": "e" * 64,
            "evidence": {
                "complete": True,
                "partial": False,
                "read_only": True,
                "controls_valid": True,
                "results": nested_results,
            },
            "trusted_query_audit": trusted_audits,
        }
        run.query_round(
            {
                "round": 1,
                "requests": [
                    {
                        "query_id": query_id,
                        "backend": "elastic",
                        "purpose": "Test per-query truncation semantics.",
                    }
                    for query_id in query_ids
                ],
                "results": [batch_result],
            }
        )

        calls = {
            item["call_id"]: item
            for item in run.store.export_trace(run.run_id)["tool_calls"]
        }
        self.assertEqual(calls["round-1-complete-pivot"]["status"], "ok")
        self.assertEqual(calls["round-1-complete-pivot"]["truncated"], 0)
        self.assertEqual(calls["round-1-projected-pivot"]["status"], "ok")
        self.assertEqual(calls["round-1-projected-pivot"]["truncated"], 1)


    def test_changed_evidence_manifest_can_be_recatalogued_idempotently(
        self,
    ) -> None:
        run = self.make_run("recatalogue-run")
        original = self.prompt_package()
        self.assertEqual(run.catalogue_prompt_evidence(original), 2)

        changed = json.loads(json.dumps(original))
        changed["evidence_reference_contract"]["references"].append(
            {
                "ref": "elastic:event-99",
                "source": "security-onion-events",
                "source_class": "elastic_event",
                "status": "available",
                "returned": 1,
                "corroborating": True,
            }
        )
        self.assertEqual(run.catalogue_prompt_evidence(changed), 3)
        self.assertEqual(run.catalogue_prompt_evidence(changed), 3)

        trace = run.store.export_trace(run.run_id)
        catalogue_events = [
            event
            for event in trace["events"]
            if event["event_type"] == "evidence.catalogued"
        ]
        self.assertEqual(len(catalogue_events), 2)
        self.assertEqual(
            len(
                {
                    event["payload"]["manifest_digest"]
                    for event in catalogue_events
                }
            ),
            2,
        )
        self.assertEqual(len(trace["evidence"]), 3)
        self.assertTrue(trace["integrity"]["valid"])


    def test_run_identity_is_bound_to_exact_policy_digest(self) -> None:
        policy = HARNESS.HarnessPolicy.from_dict(self.policy_document())
        run = self.make_run("policy-bound-run", policy=policy)
        self.assertEqual(
            run.store.snapshot(run.run_id)["policy_digest"],
            policy.digest,
        )
        changed_policy = dataclasses.replace(
            policy,
            budgets={
                **policy.budgets,
                "max_model_calls": policy.budgets["max_model_calls"] + 1,
            },
        )
        with self.assertRaisesRegex(
            HARNESS.HarnessIntegrityError,
            "different job or policy",
        ):
            HARNESS.HarnessRun(
                run.store,
                self.envelope(run.run_id),
                changed_policy,
            )


    def test_preflight_and_tool_approval_replay_without_collision(self) -> None:
        run = self.make_run("approval-replay-run")
        run.preflight_model_call(
            call_id="stable-model-call",
            input_value={"rows": [{"id": 1}]},
            requested_route=run.envelope.assigned_route,
            purpose="stable replay test",
        )
        run.preflight_model_call(
            call_id="stable-model-call",
            input_value={"rows": [{"id": 1}]},
            requested_route=run.envelope.assigned_route,
            purpose="stable replay test",
        )
        denied = run.authorize_tool(
            round_number=1,
            query_id="live-host-query",
            backend="osquery",
        )
        approved = run.authorize_tool(
            round_number=1,
            query_id="live-host-query",
            backend="osquery",
            approved=True,
        )
        self.assertFalse(denied.allowed)
        self.assertTrue(approved.allowed)
        trace = run.store.export_trace(run.run_id)
        self.assertEqual(
            sum(
                event["event_type"] == "policy.budget"
                for event in trace["events"]
            ),
            1,
        )
        self.assertEqual(
            sum(
                event["event_type"] == "policy.tool-authorization"
                for event in trace["events"]
            ),
            2,
        )
        self.assertTrue(trace["integrity"]["valid"])


    def test_hypothesis_provenance_demotes_unsupported_claims(self) -> None:
        run = self.make_run("hypothesis-run")
        run.catalogue_prompt_evidence(self.prompt_package())
        result = run.store.record_hypotheses(
            run.run_id,
            [
                {
                    "id": "known",
                    "statement": "Known evidence supports this.",
                    "status": "supported",
                    "supporting_evidence": ["alert:42"],
                },
                {
                    "id": "unknown",
                    "statement": "Unknown evidence cannot support this.",
                    "status": "supported",
                    "supporting_evidence": ["fabricated:ref"],
                },
                "invalid",
            ],
            revision=1,
        )
        self.assertEqual(result, {"accepted": 2, "rejected": 1})
        statuses = {
            item["hypothesis_id"]: item["status"]
            for item in run.store.export_trace(run.run_id)["hypotheses"]
        }
        self.assertEqual(statuses, {"known": "supported", "unknown": "unresolved"})


    def test_hypothesis_revision_collision_is_rejected_and_secrets_are_redacted(
        self,
    ) -> None:
        run = self.make_run("hypothesis-collision-run")
        run.catalogue_prompt_evidence(self.prompt_package())
        hypothesis = {
            "id": "credential-lead",
            "statement": "Observed password=do-not-store-this",
            "status": "supported",
            "supporting_evidence": ["alert:42"],
            "next_discriminator": (
                "Use Bearer abcdefghijklmnopqrstuvwxyz0123456789 to pivot"
            ),
        }
        self.assertEqual(
            run.store.record_hypotheses(
                run.run_id,
                [hypothesis],
                revision=1,
            ),
            {"accepted": 1, "rejected": 0},
        )
        self.assertEqual(
            run.store.record_hypotheses(
                run.run_id,
                [hypothesis],
                revision=1,
            ),
            {"accepted": 1, "rejected": 0},
        )

        with self.assertRaisesRegex(
            HARNESS.HarnessIntegrityError,
            "revision collides with different content",
        ):
            run.store.record_hypotheses(
                run.run_id,
                [
                    {
                        **hypothesis,
                        "statement": "A materially different safe hypothesis.",
                    }
                ],
                revision=1,
            )

        trace = run.store.export_trace(run.run_id)
        stored = trace["hypotheses"][0]
        self.assertEqual(stored["statement"], "[redacted-sensitive-value]")
        self.assertEqual(
            stored["next_discriminator"],
            "[redacted-sensitive-value]",
        )
        serialized = json.dumps(trace, sort_keys=True)
        self.assertNotIn("do-not-store-this", serialized)
        self.assertNotIn(
            "abcdefghijklmnopqrstuvwxyz0123456789",
            serialized,
        )
        self.assertEqual(
            sum(
                event["event_type"] == "hypotheses.updated"
                for event in trace["events"]
            ),
            1,
        )
        self.assertTrue(trace["integrity"]["valid"])


    def test_memory_promotion_requires_clean_provenance_confidence_and_review(
        self,
    ) -> None:
        policy = HARNESS.HarnessPolicy.from_dict(self.policy_document())
        role = HARNESS.AgentRole.SOC_ANALYST.value
        valid = self.response()

        blocked = {
            **valid,
            "_automation_controls": {
                "memory_writeback_blocked": True,
                "reason": "untrusted prompt injection content",
            },
        }
        self.assertFalse(
            HARNESS.memory_promotion_decision(
                policy,
                blocked,
                role=role,
                has_shared_candidates=False,
            ).allowed
        )

        invalid_refs = {
            **valid,
            "_evidence_reference_validation": {
                **valid["_evidence_reference_validation"],
                "invalid_refs": ["fabricated:ref"],
            },
        }
        self.assertIn(
            "unresolved evidence",
            HARNESS.memory_promotion_decision(
                policy,
                invalid_refs,
                role=role,
                has_shared_candidates=False,
            ).reason,
        )

        one_source = {
            **valid,
            "_evidence_reference_validation": {
                "invalid_refs": [],
                "corroborating_source_classes": ["suricata_alert"],
            },
        }
        self.assertIn(
            "fewer than two",
            HARNESS.memory_promotion_decision(
                policy,
                one_source,
                role=role,
                has_shared_candidates=False,
            ).reason,
        )

        low_confidence = {**valid, "confidence": "medium", "confidence_score": 0.79}
        self.assertIn(
            "confidence",
            HARNESS.memory_promotion_decision(
                policy,
                low_confidence,
                role=role,
                has_shared_candidates=False,
            ).reason,
        )

        no_review = {**valid, "_second_opinion": {"status": "not-run"}}
        self.assertIn(
            "reviewer",
            HARNESS.memory_promotion_decision(
                policy,
                no_review,
                role=role,
                has_shared_candidates=False,
            ).reason,
        )

        needs_approval = HARNESS.memory_promotion_decision(
            policy,
            valid,
            role=role,
            has_shared_candidates=False,
        )
        self.assertFalse(needs_approval.allowed)
        self.assertTrue(needs_approval.requires_approval)
        self.assertFalse(
            HARNESS.policy_decision_is_effective("shadow", needs_approval)
        )

        shared_needs_approval = HARNESS.memory_promotion_decision(
            policy,
            valid,
            role=role,
            has_shared_candidates=True,
        )
        self.assertFalse(shared_needs_approval.allowed)
        self.assertTrue(shared_needs_approval.requires_approval)
        self.assertIn("shared memory", shared_needs_approval.reason)

        approved = HARNESS.memory_promotion_decision(
            policy,
            valid,
            role=role,
            has_shared_candidates=True,
            human_approved=True,
        )
        self.assertTrue(approved.allowed)
        self.assertTrue(approved.requires_approval)
