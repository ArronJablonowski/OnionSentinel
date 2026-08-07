from __future__ import annotations

import copy
import unittest

from n8n.onion_sentinel.analysis.query import repair_stage, stopping


class QueryRepairStagePackageTests(unittest.TestCase):
    def dependencies(self):
        return repair_stage.Dependencies(
            canonical_digest=lambda value: f"scope:{value['query_id']}",
            error_digest=lambda value: f"error:{value}",
            prompt_entry=lambda scope, **kwargs: {
                "query_id": scope["query_id"], **kwargs
            },
            request_from_scope=lambda scope: {
                "query_id": scope["query_id"],
                "backend": scope["backend"],
                "parameters": {"pack": scope["pack"]},
            },
        )

    def item(self, query_id="q-1"):
        return {
            "scope": {
                "query_id": query_id,
                "backend": "elastic",
                "pack": "network_flow",
                "event_tuple": {"source_ip": "192.0.2.1"},
                "observable_scope_source": "trusted_catalog_intersection",
            },
            "reason": "invalid request",
            "trigger": "contract_rejection",
        }

    def test_scheduled_repair_builds_exact_bounded_artifacts(self):
        item = self.item()
        snapshot = copy.deepcopy(item)
        result = repair_stage.build(
            stopping.RepairDecision((item,), (item,), True, ""),
            remaining_queries=4,
            dependencies=self.dependencies(),
        )
        self.assertTrue(result.scheduled)
        self.assertEqual(result.pending_scopes["q-1"], item["scope"])
        self.assertIsNot(result.pending_scopes["q-1"], item["scope"])
        self.assertEqual(result.requests[0]["query_id"], "q-1")
        self.assertEqual(result.prompt["remaining_queries"], 1)
        self.assertEqual(result.prompt["maximum_attempts"], 1)
        self.assertIn("must not increase", result.prompt["instruction"])
        self.assertEqual(item, snapshot)

    def test_audit_is_built_for_all_considered_not_only_admitted_candidates(self):
        first, second = self.item("q-1"), self.item("q-2")
        result = repair_stage.build(
            stopping.RepairDecision((first, second), (first,), True, ""),
            remaining_queries=1,
            dependencies=self.dependencies(),
        )
        self.assertEqual(
            [item["query_id"] for item in result.audit_candidates],
            ["q-1", "q-2"],
        )
        self.assertEqual(result.audit_candidates[0]["original_event_tuple_fields"], [
            "source_ip"
        ])
        self.assertEqual(len(result.requests), 1)

    def test_unscheduled_repair_has_no_execution_artifacts_and_retains_reason(self):
        item = self.item()
        result = repair_stage.build(
            stopping.RepairDecision(
                (item,), (), False, stopping.NO_QUERY_REASON
            ),
            remaining_queries=0,
            dependencies=self.dependencies(),
        )
        self.assertFalse(result.scheduled)
        self.assertEqual(result.not_attempted_reason, stopping.NO_QUERY_REASON)
        self.assertIsNone(result.prompt)
        self.assertEqual(result.requests, ())
        self.assertEqual(result.pending_scopes, {})

    def test_unconsidered_decision_does_not_publish_a_reason(self):
        result = repair_stage.build(
            stopping.RepairDecision((), (), False, "irrelevant"),
            remaining_queries=2,
            dependencies=self.dependencies(),
        )
        self.assertEqual(result.audit_candidates, ())
        self.assertEqual(result.not_attempted_reason, "")


if __name__ == "__main__":
    unittest.main()
