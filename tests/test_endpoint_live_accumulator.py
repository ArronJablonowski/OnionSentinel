"""Characterize live-OSQuery accumulator provenance admission."""
from __future__ import annotations

from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.analysis.evidence import endpoint  # noqa: E402


class TracedDict(dict):
    def __init__(
        self,
        values: dict[str, object],
        *,
        label: str,
        calls: list[tuple[str, object]],
    ) -> None:
        super().__init__(values)
        self.label = label
        self.calls = calls

    def get(self, key: object, default: object = None) -> object:
        self.calls.append((f"{self.label}.get", key))
        return super().get(key, default)


class ExplodingDict(TracedDict):
    def get(self, key: object, default: object = None) -> object:
        super().get(key, default)
        raise RuntimeError(f"{self.label} cannot read {key}")


POLICY = endpoint.Policy("live-v1", "support-v1", frozenset({"ok"}))
DEPENDENCIES = endpoint.Dependencies(str, ValueError)


def accumulator(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "schema": "live-v1",
        "read_only": True,
        "complete": True,
        "batches": [{"validated": True}],
        "results": [{"result": 1}],
    }
    value.update(overrides)
    return value


class EndpointLiveAccumulatorCharacterizationTests(unittest.TestCase):
    def test_non_mapping_fails_without_result_evaluation(self) -> None:
        with mock.patch.object(endpoint, "_relevant_live_result") as relevant:
            for value in (None, [], "value", 0):
                with self.subTest(value=value):
                    self.assertFalse(endpoint._live_accumulator_has_evidence(
                        value, POLICY, DEPENDENCIES
                    ))
        relevant.assert_not_called()

    def test_provenance_field_and_batch_access_order_is_exact_and_lazy(self) -> None:
        calls: list[tuple[str, object]] = []
        first = TracedDict(
            {"validated": True}, label="batch-0", calls=calls
        )
        second = TracedDict(
            {"validated": False}, label="batch-1", calls=calls
        )
        third = ExplodingDict(
            {"validated": True}, label="batch-2", calls=calls
        )
        value = TracedDict(
            accumulator(batches=[first, second, third]),
            label="accumulator",
            calls=calls,
        )

        with mock.patch.object(endpoint, "_relevant_live_result") as relevant:
            self.assertFalse(endpoint._live_accumulator_has_evidence(
                value, POLICY, DEPENDENCIES
            ))

        self.assertEqual(calls, [
            ("accumulator.get", "batches"),
            ("accumulator.get", "results"),
            ("accumulator.get", "schema"),
            ("accumulator.get", "read_only"),
            ("batch-0.get", "validated"),
            ("batch-1.get", "validated"),
        ])
        relevant.assert_not_called()

    def test_each_provenance_gate_stops_before_complete_and_results(self) -> None:
        cases = (
            {"schema": "wrong"},
            {"read_only": 1},
            {"batches": None},
            {"batches": []},
            {"batches": ["not-a-batch"]},
            {"batches": [{"validated": 1}]},
        )
        for overrides in cases:
            calls: list[tuple[str, object]] = []
            value = TracedDict(
                accumulator(**overrides), label="accumulator", calls=calls
            )
            with self.subTest(overrides=overrides), mock.patch.object(
                endpoint, "_relevant_live_result"
            ) as relevant:
                self.assertFalse(endpoint._live_accumulator_has_evidence(
                    value, POLICY, DEPENDENCIES
                ))
                self.assertNotIn(("accumulator.get", "complete"), calls)
                relevant.assert_not_called()

    def test_complete_result_shape_and_relevance_are_ordered_and_lazy(self) -> None:
        results = [object(), object(), object()]
        calls: list[tuple[object, ...]] = []

        def relevant(value: object, policy: object, dependencies: object) -> bool:
            calls.append((value, policy, dependencies))
            if len(calls) == 3:
                raise AssertionError("relevance evaluated after first success")
            return len(calls) == 2

        value = accumulator(results=results)
        before_keys = tuple(value)
        before_batches = value["batches"]
        before_results = tuple(value["results"])
        with mock.patch.object(
            endpoint, "_relevant_live_result", side_effect=relevant
        ):
            self.assertTrue(endpoint._live_accumulator_has_evidence(
                value, POLICY, DEPENDENCIES
            ))

        self.assertEqual(len(calls), 2)
        for index, arguments in enumerate(calls):
            self.assertIs(arguments[0], results[index])
            self.assertIs(arguments[1], POLICY)
            self.assertIs(arguments[2], DEPENDENCIES)
        self.assertEqual(tuple(value), before_keys)
        self.assertIs(value["batches"], before_batches)
        self.assertEqual(len(value["results"]), len(before_results))
        self.assertTrue(all(
            current is original
            for current, original in zip(value["results"], before_results)
        ))

        for overrides in ({"complete": 1}, {"results": tuple(results)}):
            with self.subTest(overrides=overrides), mock.patch.object(
                endpoint, "_relevant_live_result"
            ) as matcher:
                self.assertFalse(endpoint._live_accumulator_has_evidence(
                    accumulator(**overrides), POLICY, DEPENDENCIES
                ))
                matcher.assert_not_called()

    def test_mapping_access_exceptions_propagate_at_the_current_boundary(self) -> None:
        calls: list[tuple[str, object]] = []
        value = ExplodingDict(
            accumulator(), label="accumulator", calls=calls
        )
        with self.assertRaisesRegex(RuntimeError, "cannot read batches"):
            endpoint._live_accumulator_has_evidence(
                value, POLICY, DEPENDENCIES
            )
        self.assertEqual(calls, [("accumulator.get", "batches")])


if __name__ == "__main__":
    unittest.main()
