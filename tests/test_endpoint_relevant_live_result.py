"""Characterize trusted live-result admission and query-table binding."""
from __future__ import annotations

import hashlib
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.analysis.evidence import endpoint  # noqa: E402


class NormalizationError(ValueError):
    pass


POLICY = endpoint.Policy(
    live_schema="live-v1",
    support_schema="support-v1",
    success_statuses=frozenset({"ok"}),
)


def result(query: str = "SELECT * FROM processes") -> dict[str, object]:
    return {
        "status": "ok",
        "rows": [{"pid": 1}],
        "query": query,
        "query_digest": hashlib.sha256(query.encode("utf-8")).hexdigest(),
        "support_bindings": [{"binding": 1}],
    }


class EndpointRelevantLiveResultCharacterizationTests(unittest.TestCase):
    def test_completed_shape_and_query_identity_gates_precede_normalization(self) -> None:
        calls: list[str] = []
        dependencies = endpoint.Dependencies(
            normalize_live_query=lambda _query: calls.append("normalize") or "unused",
            normalization_error=NormalizationError,
        )
        values = (
            None,
            {"status": "failed", "rows": [{}]},
            {"status": "ok", "rows": []},
            {"status": "ok", "rows": [{}], "query_digest": "a" * 63,
             "query": "SELECT 1"},
            {"status": "ok", "rows": [{}], "query_digest": "a" * 64,
             "query": ""},
        )
        for value in values:
            with self.subTest(value=value):
                self.assertFalse(endpoint._relevant_live_result(
                    value, POLICY, dependencies
                ))
        self.assertEqual(calls, [])

    def test_only_configured_normalization_error_is_converted_to_false(self) -> None:
        value = result()

        def configured(_query: str) -> str:
            raise NormalizationError("rejected")

        self.assertFalse(endpoint._relevant_live_result(
            value,
            POLICY,
            endpoint.Dependencies(configured, NormalizationError),
        ))

        def unexpected(_query: str) -> str:
            raise RuntimeError("normalizer defect")

        with self.assertRaisesRegex(RuntimeError, "normalizer defect"):
            endpoint._relevant_live_result(
                value,
                POLICY,
                endpoint.Dependencies(unexpected, NormalizationError),
            )

    def test_normalized_digest_mismatch_stops_before_support_admission(self) -> None:
        value = result("SELECT  *  FROM processes")
        calls: list[object] = []
        dependencies = endpoint.Dependencies(
            normalize_live_query=lambda query: calls.append(query)
            or "SELECT * FROM processes",
            normalization_error=NormalizationError,
        )
        with mock.patch.object(
            endpoint,
            "_support_matches",
            side_effect=lambda *_args: calls.append("support") or True,
        ):
            self.assertFalse(endpoint._relevant_live_result(
                value, POLICY, dependencies
            ))
        self.assertEqual(calls, ["SELECT  *  FROM processes"])

    def test_table_discovery_and_support_matching_are_exact_and_lazy(self) -> None:
        query = (
            "SELECT * FROM Processes p JOIN users u join SOCKET_events s "
            "JOIN users u2 JOIN 9invalid bad FROM _inventory"
        )
        value = result(query)
        supports = [object(), object(), object()]
        value["support_bindings"] = supports
        calls: list[tuple[object, ...]] = []

        def support(*args: object) -> bool:
            calls.append(args)
            if len(calls) == 3:
                raise AssertionError("lazy support matching evaluated past success")
            return len(calls) == 2

        dependencies = endpoint.Dependencies(lambda raw: raw, NormalizationError)
        with mock.patch.object(endpoint, "_support_matches", side_effect=support):
            self.assertTrue(endpoint._relevant_live_result(
                value, POLICY, dependencies
            ))

        self.assertEqual(len(calls), 2)
        expected_tables = {"processes", "users", "socket_events", "_inventory"}
        for index, args in enumerate(calls):
            self.assertIs(args[0], supports[index])
            self.assertIs(args[1], value)
            self.assertEqual(args[2], value["query_digest"])
            self.assertEqual(args[3], expected_tables)
            self.assertIs(args[4], POLICY)

        value["support_bindings"] = tuple(supports)
        with mock.patch.object(endpoint, "_support_matches") as matcher:
            self.assertFalse(endpoint._relevant_live_result(
                value, POLICY, dependencies
            ))
        matcher.assert_not_called()


if __name__ == "__main__":
    unittest.main()
