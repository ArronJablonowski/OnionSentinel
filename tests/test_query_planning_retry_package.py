from __future__ import annotations

import copy
import unittest

from n8n.onion_sentinel.analysis.query import planning_retry, state


class QueryPlanningRetryPackageTests(unittest.TestCase):
    class ContractError(ValueError):
        pass

    def setUp(self) -> None:
        self.limits = state.Limits(rounds=2, queries=8, queries_per_round=4)
        self.events = []
        self.response = {
            "_analysis_model_route": "route-a",
            "investigation_query_requests": [{"query_id": "q-1"}],
        }

    def dependencies(self, execute=None):
        clock = iter((10.0, 10.5))

        def pop_requests(response):
            return response.pop("investigation_query_requests", [])

        return planning_retry.Dependencies(
            model_safe_copy=lambda value, _hosted: copy.deepcopy(value),
            execute_model=execute or (lambda _package: copy.deepcopy(self.response)),
            pop_requests=pop_requests,
            phase=lambda: self.events.append(("phase",)),
            preflight=lambda package: self.events.append(("preflight", bool(package))),
            record=lambda response, duration, status: self.events.append(
                ("record", response.get("_analysis_model_route"), duration, status)
            ),
            monotonic=lambda: next(clock),
        )

    def invoke(self, package, dependencies=None, maximum=10_000):
        return planning_retry.run(
            package,
            route="route-a",
            limits=self.limits,
            maximum_prompt_bytes=maximum,
            hosted=False,
            policy=planning_retry.Policy(
                maximum_queries_per_round=4,
                instruction="request one bounded pivot",
            ),
            dependencies=dependencies or self.dependencies(),
            error_type=self.ContractError,
        )

    def test_success_preflights_records_and_removes_retry_instruction(self) -> None:
        package = {"case_id": "case-1"}
        result = self.invoke(package)
        self.assertEqual(result.response["_analysis_model_route"], "route-a")
        self.assertEqual(result.requests[0]["query_id"], "q-1")
        self.assertNotIn("investigation_query_planning_retry", package)
        self.assertEqual([event[0] for event in self.events], [
            "phase", "preflight", "record"
        ])

    def test_oversized_prompt_fails_before_phase_preflight_or_model(self) -> None:
        package = {"payload": "x" * 100}
        called = []
        with self.assertRaisesRegex(self.ContractError, "prompt exceeds"):
            self.invoke(
                package,
                dependencies=self.dependencies(lambda _package: called.append(True)),
                maximum=10,
            )
        self.assertEqual(called, [])
        self.assertEqual(self.events, [])

    def test_model_failure_and_invalid_response_are_recorded(self) -> None:
        def fail(_package):
            raise RuntimeError("synthetic")

        with self.assertRaisesRegex(RuntimeError, "synthetic"):
            self.invoke({}, dependencies=self.dependencies(fail))
        self.assertEqual(self.events[-1][-1], "failed:RuntimeError")

        self.events.clear()
        with self.assertRaisesRegex(self.ContractError, "non-object"):
            self.invoke({}, dependencies=self.dependencies(lambda _package: []))
        self.assertEqual(self.events[-1][-1], "failed:InvalidResponse")

    def test_route_drift_and_missing_requests_fail_closed(self) -> None:
        drift = copy.deepcopy(self.response)
        drift["_analysis_model_route"] = "route-b"
        with self.assertRaisesRegex(self.ContractError, "preserve the assigned"):
            self.invoke({}, dependencies=self.dependencies(lambda _package: drift))

        missing = {"_analysis_model_route": "route-a"}
        with self.assertRaisesRegex(self.ContractError, "produced no"):
            self.invoke({}, dependencies=self.dependencies(lambda _package: missing))


if __name__ == "__main__":
    unittest.main()
