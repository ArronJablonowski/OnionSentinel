from __future__ import annotations

import unittest

from n8n.onion_sentinel.analysis.query import stopping


class QueryStoppingPackageTests(unittest.TestCase):
    def test_round_entry_stops_only_without_requests(self) -> None:
        self.assertTrue(stopping.round_entry([]).stop)
        self.assertTrue(stopping.round_entry(None).stop)
        self.assertFalse(stopping.round_entry([{"query_id": "q"}]).stop)

    def test_repair_is_bounded_by_round_and_remaining_query_budget(self) -> None:
        scopes = [{"scope": index} for index in range(8)]
        decision = stopping.schedule_repair(
            scopes,
            already_attempted=False,
            remaining_rounds=1,
            remaining_queries=2,
            maximum_queries_per_round=4,
        )
        self.assertTrue(decision.scheduled)
        self.assertEqual(len(decision.considered), 4)
        self.assertEqual(len(decision.candidates), 2)
        self.assertEqual(decision.candidates, tuple(scopes[:2]))

    def test_repair_has_one_attempt_and_explicit_budget_failures(self) -> None:
        scope = [{"scope": 1}]
        repeated = stopping.schedule_repair(
            scope,
            already_attempted=True,
            remaining_rounds=1,
            remaining_queries=1,
            maximum_queries_per_round=4,
        )
        no_round = stopping.schedule_repair(
            scope,
            already_attempted=False,
            remaining_rounds=0,
            remaining_queries=1,
            maximum_queries_per_round=4,
        )
        no_query = stopping.schedule_repair(
            scope,
            already_attempted=False,
            remaining_rounds=1,
            remaining_queries=0,
            maximum_queries_per_round=4,
        )
        self.assertFalse(repeated.scheduled)
        self.assertEqual(repeated.not_attempted_reason, "")
        self.assertEqual(no_round.not_attempted_reason, stopping.NO_ROUND_REASON)
        self.assertEqual(no_query.not_attempted_reason, stopping.NO_QUERY_REASON)

    def test_follow_up_stops_when_either_budget_is_exhausted(self) -> None:
        self.assertFalse(stopping.after_follow_up(1, 1).stop)
        self.assertEqual(
            stopping.after_follow_up(0, 1).reason,
            stopping.NO_ROUND_REASON,
        )
        self.assertEqual(
            stopping.after_follow_up(1, 0).reason,
            stopping.NO_QUERY_REASON,
        )


if __name__ == "__main__":
    unittest.main()
