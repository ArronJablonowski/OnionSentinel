"""Characterize exact query-audit request/result indexing behavior."""
from __future__ import annotations

from copy import deepcopy
import unittest

from n8n.onion_sentinel.analysis.query import audit


class TraceDict(dict):
    def __init__(self, label: str, calls: list[object], **values: object) -> None:
        super().__init__(values)
        self.label = label
        self.calls = calls

    def get(self, key: str, default: object = None) -> object:
        self.calls.append((self.label, "get", key, default))
        return super().get(key, default)

    def __getitem__(self, key: str) -> object:
        self.calls.append((self.label, "getitem", key))
        return super().__getitem__(key)


class ExplodingQueryId:
    def __str__(self) -> str:
        raise RuntimeError("query identity exploded")


class QueryRequestResultMapCharacterizationTests(unittest.TestCase):
    def test_outer_containers_retain_exact_repeated_get_behavior(self) -> None:
        calls: list[object] = []
        value = TraceDict("round", calls, requests=[], results=[])

        self.assertEqual(audit._request_result_maps(value), ({}, {}))
        self.assertEqual(calls, [
            ("round", "get", "requests", None),
            ("round", "get", "requests", None),
            ("round", "get", "results", None),
            ("round", "get", "results", None),
        ])

        calls.clear()
        value = TraceDict("round", calls, requests="invalid", results={})
        self.assertEqual(audit._request_result_maps(value), ({}, {}))
        self.assertEqual(calls, [
            ("round", "get", "requests", None),
            ("round", "get", "results", None),
        ])

    def test_duplicate_requests_overwrite_without_changing_first_key_order(self) -> None:
        calls: list[object] = []
        first = TraceDict("first", calls, query_id="q-1", marker="first")
        second = TraceDict("second", calls, query_id="q-2", marker="second")
        replacement = TraceDict(
            "replacement", calls, query_id="q-1", marker="replacement"
        )

        requests, results = audit._request_result_maps(
            {"requests": [first, "ignored", second, replacement]}
        )

        self.assertEqual(list(requests), ["q-1", "q-2"])
        self.assertIs(requests["q-1"], replacement)
        self.assertIs(requests["q-2"], second)
        self.assertEqual(results, {})
        self.assertEqual(calls, [
            ("first", "get", "query_id", None),
            ("first", "get", "query_id", None),
            ("second", "get", "query_id", None),
            ("second", "get", "query_id", None),
            ("replacement", "get", "query_id", None),
            ("replacement", "get", "query_id", None),
        ])

    def test_grouped_results_stringify_ids_and_last_result_wins(self) -> None:
        calls: list[object] = []
        grouped = TraceDict("grouped", calls, query_ids=["q-1", None, 7])
        replacement = TraceDict("replacement", calls, query_id="q-1")

        _requests, results = audit._request_result_maps(
            {"results": [grouped, "ignored", replacement]}
        )

        self.assertEqual(list(results), ["q-1", "None", "7"])
        self.assertIs(results["q-1"], replacement)
        self.assertIs(results["None"], grouped)
        self.assertIs(results["7"], grouped)
        self.assertEqual(calls[:2], [
            ("grouped", "get", "query_ids", None),
            ("grouped", "getitem", "query_ids"),
        ])
        self.assertEqual(calls[2:], [
            ("replacement", "get", "query_ids", None),
            ("replacement", "get", "query_id", None),
            ("replacement", "getitem", "query_id"),
            ("replacement", "get", "backend", None),
            ("replacement", "get", "purpose", None),
            ("grouped", "get", "backend", None),
            ("grouped", "get", "purpose", None),
            ("grouped", "get", "backend", None),
            ("grouped", "get", "purpose", None),
        ])

    def test_missing_request_stubs_append_in_result_order_without_mutation(self) -> None:
        backend = {"owner": "osquery"}
        purpose = ["unsafe", "widening"]
        existing = {"query_id": "existing", "marker": True}
        first = {
            "query_id": "missing-1",
            "backend": backend,
            "purpose": "",
        }
        second = {
            "query_id": "missing-2",
            "purpose": purpose,
        }
        value = {"requests": [existing], "results": [first, second]}
        before = deepcopy(value)

        requests, results = audit._request_result_maps(value)

        self.assertEqual(list(requests), ["existing", "missing-1", "missing-2"])
        self.assertEqual(list(results), ["missing-1", "missing-2"])
        self.assertIs(requests["existing"], existing)
        self.assertIs(requests["missing-1"]["backend"], backend)
        self.assertEqual(
            requests["missing-1"]["purpose"],
            "proposal rejected before execution",
        )
        self.assertIs(requests["missing-2"]["purpose"], purpose)
        self.assertTrue(requests["missing-2"]["rejected_before_execution"])
        self.assertEqual(value, before)

    def test_query_id_stringification_exception_propagates(self) -> None:
        value = {
            "requests": [{"query_id": ExplodingQueryId()}],
            "results": [{"query_id": "unreached"}],
        }

        with self.assertRaisesRegex(RuntimeError, "query identity exploded"):
            audit._request_result_maps(value)


if __name__ == "__main__":
    unittest.main()
