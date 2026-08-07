from __future__ import annotations

import unittest

from n8n.onion_sentinel.analysis.query import finalization, state


class EngineState:
    def __init__(self, admitted=1, ignored=0, terminal=0, repaired=False):
        self.limits = state.Limits(rounds=2, queries=8, queries_per_round=4)
        self.queries_admitted = admitted
        self.requests_ignored = ignored
        self.terminal_requests_ignored = terminal
        self.repair_attempted = repaired


class QueryFinalizationPackageTests(unittest.TestCase):
    class ContractError(ValueError):
        pass

    def setUp(self):
        self.gaps = []

    def dependencies(self, requirement=True):
        def ignore(current, count):
            return EngineState(
                current.queries_admitted,
                current.requests_ignored + count,
                current.terminal_requests_ignored + count,
                current.repair_attempted,
            )

        return finalization.Dependencies(
            pop_requests=lambda response: response.pop(
                "investigation_query_requests", []
            ),
            ignore_terminal=ignore,
            outcome_summary=lambda rounds, **_kwargs: {
                "round_count": len(rounds),
                "evidence_gaps": ["bounded gap"],
            },
            round_audit=lambda item: {
                "round": item["round"],
                "tool_call_bindings": [{"query_id": "q-1"}],
            },
            binding_summary=lambda _bindings, **_kwargs: {
                "read_only": True,
                "all_tool_call_bindings_read_only": True,
                "successful_read_only_queries": 1,
                "complete": True,
                "evaluation_requirement_satisfied": requirement,
            },
            canonical_digest=lambda _value: "d" * 64,
            append_gaps=lambda _response, gaps: self.gaps.extend(gaps),
        )

    def invoke(self, response=None, engine_state=None, requirement=True, required=False):
        return finalization.finalize(
            response or {"summary": "done"},
            [{"round": 1}],
            state=engine_state or EngineState(),
            policy=finalization.Policy(
                query_contract="query-v1", route="route-a",
                evaluation_required=required, max_queries_per_round=4,
                configured_max_rounds=2, configured_max_queries=8,
                max_prompt_evidence_bytes=1000, max_prompt_evidence_rows=100,
            ),
            planning=finalization.Planning(
                retry_attempted=True, retry_produced_requests=True,
                deterministic_requests=({"query_id": "det-1"},),
                model_initial_requests=1,
            ),
            repair=finalization.Repair(
                produced_requests=True, admitted_requests=1,
                rejected_requests=0, candidates=({"query_id": "q-1"},),
                not_attempted_reason="",
            ),
            dependencies=self.dependencies(requirement),
            error_type=self.ContractError,
        )

    def test_full_audit_preserves_planning_repair_limits_and_bindings(self):
        result = self.invoke(engine_state=EngineState(repaired=True))
        audit = result.response["_investigation_query_audit"]
        self.assertEqual(audit["query_contract"], "query-v1")
        self.assertEqual(audit["model_route"], "route-a")
        self.assertEqual(audit["deterministic_protocol_plan"]["query_ids"], [
            "det-1"
        ])
        self.assertTrue(audit["query_planning_repair"]["attempted"])
        self.assertEqual(audit["limits"]["max_queries_total"], 8)
        self.assertEqual(audit["tool_call_bindings"], [{"query_id": "q-1"}])
        self.assertEqual(self.gaps, ["bounded gap"])

    def test_terminal_requests_are_removed_and_counted(self):
        result = self.invoke(response={
            "summary": "done",
            "investigation_query_requests": [{"query_id": "late"}],
        })
        self.assertNotIn("investigation_query_requests", result.response)
        self.assertEqual(result.state.terminal_requests_ignored, 1)
        self.assertEqual(
            result.response["_investigation_query_audit"][
                "terminal_requests_ignored"
            ], 1,
        )

    def test_required_evaluation_fails_closed_when_binding_gate_is_false(self):
        with self.assertRaisesRegex(self.ContractError, "successful read-only"):
            self.invoke(requirement=False, required=True)

    def test_no_rounds_or_ignored_requests_publish_no_synthetic_audit(self):
        result = finalization.finalize(
            {"summary": "done"}, [], state=EngineState(admitted=0),
            policy=finalization.Policy(
                "query-v1", "route-a", False, 4, 2, 8, 1000, 100
            ),
            planning=finalization.Planning(False, False, (), 0),
            repair=finalization.Repair(False, 0, 0, (), ""),
            dependencies=self.dependencies(), error_type=self.ContractError,
        )
        self.assertNotIn("_investigation_query_audit", result.response)
        self.assertIsNone(result.outcomes)


if __name__ == "__main__":
    unittest.main()
