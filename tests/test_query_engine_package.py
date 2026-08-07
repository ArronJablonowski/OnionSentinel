from __future__ import annotations

import unittest

from n8n.onion_sentinel.analysis.query import engine, state, stopping


class QueryEnginePackageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.limits = state.Limits(rounds=3, queries=3, queries_per_round=2)

    def test_admission_returns_immutable_transition_and_audit(self) -> None:
        initial = engine.begin(self.limits)
        transition = engine.admit_round(
            initial,
            [{"query_id": "q-1"}, {"query_id": "q-2"}, {"query_id": "q-3"}],
            round_number=1,
        )
        self.assertEqual(initial.queries_admitted, 0)
        self.assertEqual(transition.action, "admit")
        self.assertEqual(len(transition.admitted_requests), 2)
        self.assertEqual(transition.state.queries_admitted, 2)
        self.assertEqual(transition.state.requests_ignored, 1)
        self.assertEqual(transition.remaining.queries, 1)
        self.assertEqual(transition.audit["queries_admitted_before"], 0)
        self.assertEqual(transition.audit["queries_admitted_after"], 2)

    def test_empty_transition_preserves_state_and_stops(self) -> None:
        initial = engine.begin(self.limits)
        transition = engine.admit_round(initial, [], round_number=1)
        self.assertEqual(transition.action, "stop_empty")
        self.assertIs(transition.state, initial)
        self.assertEqual(transition.audit["raw_request_count"], 0)

    def test_ignore_is_monotonic_and_terminal_is_subset(self) -> None:
        initial = engine.begin(self.limits)
        ignored = engine.ignore(initial, 2)
        terminal = engine.ignore(ignored, 1, terminal=True)
        self.assertEqual(initial.requests_ignored, 0)
        self.assertEqual(terminal.requests_ignored, 3)
        self.assertEqual(terminal.terminal_requests_ignored, 1)

    def test_repair_transition_marks_single_attempt_without_widening_budget(self) -> None:
        admitted = engine.admit_round(
            engine.begin(self.limits), [{"query_id": "q"}], round_number=1
        ).state
        transition = engine.plan_repair(
            admitted,
            [{"scope": {"query_id": "q"}}],
            round_number=1,
            repair_round=False,
        )
        repeated = engine.plan_repair(
            transition.state,
            [{"scope": {"query_id": "q"}}],
            round_number=1,
            repair_round=False,
        )
        self.assertEqual(transition.action, "schedule_repair")
        self.assertTrue(transition.state.repair_attempted)
        self.assertEqual(transition.remaining.queries, 2)
        self.assertEqual(repeated.action, "no_repair")
        self.assertFalse(repeated.repair.scheduled)

    def test_repair_transition_preserves_explicit_exhaustion_reason(self) -> None:
        exhausted = engine.InvestigationState(
            limits=self.limits,
            queries_admitted=3,
        )
        transition = engine.plan_repair(
            exhausted,
            [{"scope": {"query_id": "q"}}],
            round_number=1,
            repair_round=False,
        )
        self.assertEqual(transition.action, "no_repair")
        self.assertEqual(
            transition.repair.not_attempted_reason,
            stopping.NO_QUERY_REASON,
        )


if __name__ == "__main__":
    unittest.main()
