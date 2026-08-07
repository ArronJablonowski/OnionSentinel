from __future__ import annotations

import hashlib
import json
import unittest

from n8n.onion_sentinel.analysis.query import audit, engine, outcomes, state, stopping


SUCCESS = frozenset({"ok", "success", "completed", "complete", "succeeded"})


def digest_json(value) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), default=str
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class QueryPipelineAcceptanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.audit_policy = audit.Policy(
            maximum_queries_per_round=4,
            success_statuses=SUCCESS,
            nonexecution_statuses=frozenset(
                {"rejected", "denied", "blocked", "unauthorized", "forbidden"}
            ),
        )
        self.audit_dependencies = audit.Dependencies(
            digest_json=digest_json,
            resolve_binding=lambda result, _query_id: (
                str(result.get("status") or "unknown"),
                None,
            ),
        )
        self.outcome_policy = outcomes.Policy(success_statuses=SUCCESS)

    def bindings(self, round_result):
        return audit.tool_call_bindings(
            round_result,
            policy=self.audit_policy,
            dependencies=self.audit_dependencies,
        )

    def test_success_fixture_is_complete_bound_and_gap_free(self) -> None:
        round_result = {
            "round": 1,
            "requests": [{"query_id": "q-success", "backend": "security_onion"}],
            "results": [{
                "query_id": "q-success",
                "backend": "security_onion",
                "status": "ok",
                "read_only": True,
            }],
        }
        bindings = self.bindings(round_result)
        binding_summary = audit.binding_summary(
            bindings, queries_admitted=1, policy=self.audit_policy
        )
        outcome = outcomes.summary(
            [round_result], queries_admitted=1, policy=self.outcome_policy
        )
        self.assertTrue(binding_summary["complete"])
        self.assertEqual(outcome["successful_queries"], 1)
        self.assertEqual(outcome["evidence_gaps"], [])

    def test_empty_fixture_stops_without_inventing_failure_or_gap(self) -> None:
        decision = stopping.round_entry([])
        outcome = outcomes.summary(
            [], queries_admitted=0, policy=self.outcome_policy
        )
        self.assertTrue(decision.stop)
        self.assertEqual(outcome["queries_accounted"], 0)
        self.assertFalse(outcome["zero_success"])
        self.assertEqual(outcome["evidence_gaps"], [])

    def test_repair_fixture_preserves_failure_and_resolves_terminal_state(self) -> None:
        repair = stopping.schedule_repair(
            [{"scope": {"query_id": "q-repair"}}],
            already_attempted=False,
            remaining_rounds=1,
            remaining_queries=1,
            maximum_queries_per_round=4,
        )
        bindings = [
            {"query_id": "q-repair", "normalized_status": "rejected", "read_only": True},
            {"query_id": "q-repair", "normalized_status": "ok", "read_only": True},
        ]
        rounds = [
            {"results": [{"query_id": "q-repair", "status": "rejected"}]},
            {"results": [{"query_id": "q-repair", "status": "ok"}]},
        ]
        self.assertTrue(repair.scheduled)
        self.assertTrue(audit.binding_summary(
            bindings, queries_admitted=2, policy=self.audit_policy
        )["complete"])
        result = outcomes.summary(
            rounds, queries_admitted=2, policy=self.outcome_policy
        )
        self.assertEqual(result["resolved_retry_query_ids"], ["q-repair"])
        self.assertEqual(result["evidence_gaps"], [])

    def test_budget_fixture_caps_admission_and_stops_after_exhaustion(self) -> None:
        initial = engine.begin(state.Limits(rounds=2, queries=1, queries_per_round=1))
        transition = engine.admit_round(
            initial,
            [{"query_id": "q-1"}, {"query_id": "q-2"}],
            round_number=1,
        )
        decision = stopping.after_follow_up(
            transition.remaining.rounds, transition.remaining.queries
        )
        self.assertEqual(
            [item["query_id"] for item in transition.admitted_requests], ["q-1"]
        )
        self.assertEqual(transition.state.requests_ignored, 1)
        self.assertTrue(decision.stop)
        self.assertEqual(decision.reason, stopping.NO_QUERY_REASON)

    def test_backend_unavailable_fixture_is_rejected_and_first_class_gap(self) -> None:
        round_result = {
            "round": 1,
            "results": [{
                "query_id": "q-unavailable",
                "backend": "security_onion",
                "status": "rejected",
                "read_only": True,
            }],
        }
        binding_summary = audit.binding_summary(
            self.bindings(round_result),
            queries_admitted=1,
            policy=self.audit_policy,
        )
        outcome = outcomes.summary(
            [round_result], queries_admitted=1, policy=self.outcome_policy
        )
        self.assertFalse(binding_summary["complete"])
        self.assertTrue(outcome["zero_success"])
        self.assertIn("no follow-up query evidence", outcome["evidence_gaps"][0])

    def test_malformed_fixture_fails_closed_as_unresolved_error(self) -> None:
        round_result = {
            "round": 1,
            "requests": [{"query_id": "q-malformed", "backend": "security_onion"}],
            "results": [{
                "query_id": "q-malformed",
                "backend": "security_onion",
                "status": "invalid_response",
                "read_only": True,
            }],
        }
        result = outcomes.summary(
            [round_result], queries_admitted=1, policy=self.outcome_policy
        )
        self.assertEqual(result["error_queries"], 1)
        self.assertEqual(result["unresolved_non_success_attempts"], 1)
        self.assertTrue(result["zero_success"])

    def test_stopping_fixture_prioritizes_round_exhaustion_deterministically(self) -> None:
        decision = stopping.after_follow_up(0, 0)
        self.assertTrue(decision.stop)
        self.assertEqual(decision.reason, stopping.NO_ROUND_REASON)


if __name__ == "__main__":
    unittest.main()
