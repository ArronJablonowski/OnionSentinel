"""Characterize durable round-audit projection behavior."""
from __future__ import annotations

from copy import deepcopy
import unittest
from unittest import mock

from n8n.onion_sentinel.analysis.query import audit


class QueryRoundAuditCharacterizationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = audit.Policy(
            maximum_queries_per_round=3,
            success_statuses=frozenset({"ok", "partial"}),
            nonexecution_statuses=frozenset({"rejected"}),
        )

    def dependencies(self, calls: list[object] | None = None) -> audit.Dependencies:
        trace = calls if calls is not None else []

        def resolve(result: dict[str, object], query_id: str) -> tuple[str, object]:
            trace.append(("resolve", result, query_id))
            return str(result.get("status") or "unknown"), None

        def digest(value: object) -> str:
            trace.append(("digest", value))
            return f"digest-{len(trace)}"

        return audit.Dependencies(digest_json=digest, resolve_binding=resolve)

    def project(
        self,
        value: dict[str, object],
        *,
        calls: list[object] | None = None,
    ) -> dict[str, object]:
        return audit.round_audit(
            value,
            policy=self.policy,
            dependencies=self.dependencies(calls),
        )

    def test_malformed_results_and_legacy_request_count_are_preserved(self) -> None:
        broker_audit = ("legacy", "tuple")
        record = self.project(
            {
                "round": "round-one",
                "requests": "abc",
                "results": {"query_id": "ignored-non-list"},
                "audit": broker_audit,
            }
        )

        self.assertEqual(record["round"], "round-one")
        self.assertEqual(record["request_count"], 3)
        self.assertEqual(record["results"], [])
        self.assertEqual(record["trusted_queries"], [])
        self.assertEqual(record["tool_call_bindings"], [])
        self.assertIs(record["broker_audit"], broker_audit)
        self.assertEqual(record["request_normalizations"], [])

    def test_trusted_audits_flatten_cap_and_retain_entry_identity(self) -> None:
        first = {"query_id": "first"}
        second = {"query_id": "second"}
        third = {"query_id": "third"}
        fourth = {"query_id": "capped"}
        value = {
            "results": [
                {"trusted_query_audit": [first, "ignored", second]},
                {"trusted_query_audit": (third,)},
                {"trusted_query_audit": [third, fourth]},
                "ignored-result",
            ]
        }
        before = deepcopy(value)

        trusted = self.project(value)["trusted_queries"]

        self.assertEqual(trusted, [first, second, third])
        self.assertIs(trusted[0], first)
        self.assertIs(trusted[1], second)
        self.assertIs(trusted[2], third)
        self.assertEqual(value, before)

    def test_result_projection_preserves_order_bounds_and_query_ids_alias(self) -> None:
        query_ids = ["q-1", "q-2"]
        valid = {
            "query_id": " q-1 ",
            "query_ids": query_ids,
            "backend": " b " * 30,
            "status": " OK ",
            "error": "x" * 600,
            "evidence": {"query_digest": " d "},
        }
        record = self.project({"results": [None, valid, "ignored"]})

        self.assertEqual(len(record["results"]), 1)
        result = record["results"][0]
        self.assertEqual(list(result), [
            "query_id", "query_ids", "backend", "status", "query_digest", "error"
        ])
        self.assertEqual(result["query_id"], "q-1")
        self.assertEqual(len(result["backend"]), 40)
        self.assertEqual(result["status"], "OK")
        self.assertEqual(result["query_digest"], "d")
        self.assertEqual(len(result["error"]), 500)
        self.assertIs(result["query_ids"], query_ids)

    def test_binding_dependency_order_and_top_level_key_order_are_exact(self) -> None:
        calls: list[object] = []
        request = {"query_id": "q-1", "backend": "security_onion"}
        result = {
            "query_id": "q-1",
            "status": "ok",
            "read_only": True,
        }

        record = self.project(
            {"round": 2, "requests": [request], "results": [result]},
            calls=calls,
        )

        self.assertEqual(list(record), [
            "round",
            "request_count",
            "results",
            "trusted_queries",
            "tool_call_bindings",
            "broker_audit",
            "request_normalizations",
        ])
        self.assertEqual(calls, [
            ("resolve", result, "q-1"),
            ("digest", request),
            ("digest", result),
        ])

    def test_result_projection_failure_stops_before_binding_and_normalization(self) -> None:
        with mock.patch.object(
            audit, "_result_summary", side_effect=RuntimeError("summary failed")
        ) as summary, mock.patch.object(audit, "tool_call_bindings") as bindings, \
                mock.patch.object(audit, "_normalizations") as normalizations:
            with self.assertRaisesRegex(RuntimeError, "summary failed"):
                self.project({"results": [{"query_id": "q-1"}]})

        summary.assert_called_once_with({"query_id": "q-1"})
        bindings.assert_not_called()
        normalizations.assert_not_called()


if __name__ == "__main__":
    unittest.main()
