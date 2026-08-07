from __future__ import annotations

import copy
import unittest

from n8n.onion_sentinel.analysis.query import coordinator, round_admission, state


class QueryCoordinatorPackageTests(unittest.TestCase):
    class ContractError(ValueError):
        pass

    def setUp(self):
        self.executed = []
        self.observed_rounds = []
        self.gaps = []

    def policy(self, *, evaluation=False):
        return coordinator.Policy(
            route="route-a",
            state_policy=state.Policy(1, 2, 2),
            rounds_override=None,
            queries_override=None,
            evaluation_required=evaluation,
            include_deterministic_requests=False,
            maximum_prompt_bytes=10_000,
            hosted_route=False,
            query_round_offset=0,
            model_call_id_prefix="primary-followup",
            model_call_purpose_prefix="evidence synthesis",
            model_call_independent_review=False,
            query_result_schema="query-results-v1",
            query_contract="query-contract-v1",
            max_discovered_observables=8,
            max_prompt_evidence_bytes=1000,
            max_prompt_evidence_rows=100,
        )

    def ports(self):
        def pop(response):
            return list(response.pop("investigation_query_requests", []))

        def execute(round_number, requests):
            self.executed.extend(copy.deepcopy(requests))
            return {
                "schema": "query-results-v1",
                "round": round_number,
                "requests": copy.deepcopy(requests),
                "results": [{
                    "query_id": item["query_id"],
                    "backend": item["backend"],
                    "status": "ok",
                    "read_only": True,
                } for item in requests],
                "audit": [],
            }

        return coordinator.Ports(
            pop_requests=pop,
            deterministic_requests=lambda _package: [],
            model_safe_copy=lambda value, _hosted: copy.deepcopy(value),
            planning_execute=lambda _package: self.fail("unexpected retry"),
            planning_phase=lambda _note: None,
            planning_preflight=lambda _package: None,
            planning_record=lambda _response, _duration, _status: None,
            normalize_request=lambda raw, **_kwargs: copy.deepcopy(raw),
            validate_repair=lambda _request, _scope: None,
            backend_available=lambda _backend: True,
            semantic_digest=lambda request: request["query_id"],
            authorize=lambda _round, _request: round_admission.Authorization(True),
            repair_scope=lambda _raw, **_kwargs: None,
            query_text=lambda value, limit: str(value or "")[:limit],
            valid_query_id=lambda value: bool(value),
            query_execute=execute,
            repair_failures=lambda _envelope: {},
            now=lambda: "2026-08-07T00:00:00Z",
            observe_round=lambda value: self.observed_rounds.append(value),
            validate_observables=lambda _sources, *, limit: [],
            canonical_digest=lambda _value: "d" * 64,
            error_digest=lambda _value: "e" * 64,
            repair_prompt_entry=lambda scope, **_kwargs: scope,
            request_from_scope=lambda scope: scope,
            admit_prompt=lambda _package, _rounds: None,
            build_model_input=lambda package, _number: package,
            synthesis_catalogue=lambda _value: None,
            synthesis_preflight=lambda _id, _value, _purpose: None,
            synthesis_execute=lambda _value: {
                "_analysis_model_route": "route-a", "summary": "done"
            },
            synthesis_record=lambda *_args: None,
            synthesis_phase=lambda _note: None,
            outcome_summary=lambda rounds, **_kwargs: {
                "round_count": len(rounds), "evidence_gaps": []
            },
            round_audit=lambda item: {
                "round": item["round"],
                "tool_call_bindings": [{
                    "query_id": item["requests"][0]["query_id"],
                    "read_only": True,
                }],
            },
            binding_summary=lambda _bindings, **_kwargs: {
                "read_only": True,
                "all_tool_call_bindings_read_only": True,
                "successful_read_only_queries": 1,
                "complete": True,
                "evaluation_requirement_satisfied": True,
            },
            append_gaps=lambda _response, gaps: self.gaps.extend(gaps),
            monotonic=iter((1.0, 1.1)).__next__,
        )

    def test_stable_interface_executes_one_bound_read_only_round(self):
        request = {"query_id": "q-1", "backend": "security_onion"}
        package = {"_local_investigation_query_context": {}}
        result = coordinator.run(
            package,
            {"investigation_query_requests": [request]},
            policy=self.policy(), ports=self.ports(), error_type=self.ContractError,
        )
        self.assertEqual(self.executed, [request])
        self.assertEqual(len(self.observed_rounds), 1)
        self.assertEqual(result["summary"], "done")
        audit = result["_investigation_query_audit"]
        self.assertEqual(audit["queries_admitted"], 1)
        self.assertTrue(audit["all_tool_call_bindings_read_only"])

    def test_empty_initial_plan_returns_without_query_or_synthetic_audit(self):
        result = coordinator.run(
            {}, {"summary": "no pivots"},
            policy=self.policy(), ports=self.ports(), error_type=self.ContractError,
        )
        self.assertEqual(result, {"summary": "no pivots"})
        self.assertEqual(self.executed, [])


if __name__ == "__main__":
    unittest.main()
