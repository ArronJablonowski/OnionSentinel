"""Direct contracts for bounded multi-round investigation query state."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.analysis.query import state  # noqa: E402


POLICY = state.Policy(
    maximum_rounds=3,
    maximum_queries=12,
    maximum_queries_per_round=4,
)


class QueryStatePackageTests(unittest.TestCase):
    def test_override_limits_are_clamped_to_positive_checked_in_bounds(self) -> None:
        self.assertEqual(
            state.resolve(POLICY, rounds_override=99, queries_override=99),
            state.Limits(rounds=3, queries=12, queries_per_round=4),
        )
        self.assertEqual(
            state.resolve(POLICY, rounds_override=-2, queries_override=0),
            state.Limits(rounds=1, queries=12, queries_per_round=4),
        )

    def test_evaluation_retry_reserves_one_round_and_reduces_query_budget(self) -> None:
        limits = state.resolve(POLICY).evaluation_retry(POLICY)
        self.assertEqual(
            limits, state.Limits(rounds=2, queries=8, queries_per_round=4)
        )

    def test_admission_is_capped_per_round_and_by_total_remaining_budget(self) -> None:
        budget = state.Budget(
            state.Limits(rounds=3, queries=6, queries_per_round=4)
        )
        first = budget.admit(list(range(6)))
        second = budget.admit(list(range(10, 14)))
        third = budget.admit([20])
        self.assertEqual(first, [0, 1, 2, 3])
        self.assertEqual(second, [10, 11])
        self.assertEqual(third, [])
        self.assertEqual(budget.admitted, 6)
        self.assertEqual(budget.ignored, 5)

    def test_remaining_capacity_and_repair_round_are_explicit(self) -> None:
        budget = state.Budget(state.resolve(POLICY))
        budget.admit([1, 2, 3])
        self.assertEqual(
            budget.remaining(1), state.Remaining(rounds=2, queries=9)
        )
        self.assertEqual(
            budget.remaining(1, repair_round=True),
            state.Remaining(rounds=0, queries=9),
        )

    def test_terminal_ignored_is_a_subset_of_total_ignored(self) -> None:
        budget = state.Budget(state.resolve(POLICY))
        budget.ignore(2)
        budget.ignore(3, terminal=True)
        budget.ignore(-10, terminal=True)
        self.assertEqual(budget.ignored, 5)
        self.assertEqual(budget.terminal_ignored, 3)


if __name__ == "__main__":
    unittest.main()
