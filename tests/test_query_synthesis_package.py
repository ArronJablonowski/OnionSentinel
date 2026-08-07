from __future__ import annotations

import unittest

from n8n.onion_sentinel.analysis.query import stopping, synthesis


class QuerySynthesisPackageTests(unittest.TestCase):
    class ContractError(ValueError):
        pass

    def setUp(self):
        self.events = []
        self.response = {"_analysis_model_route": "route-a", "summary": "done"}

    def dependencies(self, execute=None):
        clock = iter((10.0, 10.25))
        return synthesis.Dependencies(
            build_input=lambda package, number: {
                "package": package, "call_number": number
            },
            catalogue=lambda value: self.events.append(("catalogue", value)),
            preflight=lambda call_id, _value, purpose: self.events.append(
                ("preflight", call_id, purpose)
            ),
            execute=execute or (lambda _value: dict(self.response)),
            record=lambda call_id, purpose, response, _input, duration, status: (
                self.events.append(
                    ("record", call_id, purpose, response, duration, status)
                )
            ),
            phase=lambda note: self.events.append(("phase", note)),
            after_follow_up=stopping.after_follow_up,
            pop_requests=lambda response: response.pop(
                "investigation_query_requests", []
            ),
            ignore_terminal=lambda state, count: state + count,
            monotonic=lambda: next(clock),
        )

    def invoke(self, dependencies=None, **overrides):
        values = {
            "state": 10,
            "prior_call_number": 0,
            "remaining_rounds": 1,
            "remaining_queries": 2,
            "harness_round_number": 3,
            "policy": synthesis.Policy(
                route="route-a",
                call_id_prefix="primary-followup",
                call_purpose_prefix="primary evidence synthesis follow-up",
                independent_review=False,
                attest_route=True,
            ),
            "dependencies": dependencies or self.dependencies(),
            "error_type": self.ContractError,
        }
        values.update(overrides)
        return synthesis.run({"case_id": "case-1"}, **values)

    def test_follow_up_contract_is_bounded_and_explicit(self):
        value = synthesis.follow_up(
            round_number=2, remaining_rounds=1, remaining_queries=4
        )
        self.assertEqual(value["round"], 2)
        self.assertEqual(value["remaining_queries"], 4)
        self.assertIn("material discriminator", value["instruction"])

    def test_success_preserves_call_order_identity_and_state(self):
        result = self.invoke()
        self.assertEqual(result.call_id, "primary-followup-1")
        self.assertEqual(result.call_number, 1)
        self.assertFalse(result.stop)
        self.assertEqual(result.state, 10)
        self.assertEqual([event[0] for event in self.events], [
            "catalogue", "preflight", "record", "phase"
        ])

    def test_failure_is_recorded_and_reraised(self):
        def fail(_value):
            raise RuntimeError("synthetic")

        with self.assertRaisesRegex(RuntimeError, "synthetic"):
            self.invoke(dependencies=self.dependencies(fail))
        self.assertEqual(self.events[-1][-1], "failed:RuntimeError")

    def test_route_drift_and_non_object_response_fail_closed(self):
        self.response["_analysis_model_route"] = "route-b"
        with self.assertRaisesRegex(self.ContractError, "preserve the assigned"):
            self.invoke()
        self.events.clear()
        with self.assertRaisesRegex(self.ContractError, "non-object"):
            self.invoke(dependencies=self.dependencies(lambda _value: []))

    def test_terminal_budget_consumes_and_counts_unexecuted_requests(self):
        self.response["investigation_query_requests"] = [{"query_id": "late"}]
        result = self.invoke(remaining_rounds=0)
        self.assertTrue(result.stop)
        self.assertEqual(result.state, 11)
        self.assertNotIn("investigation_query_requests", result.response)


if __name__ == "__main__":
    unittest.main()
