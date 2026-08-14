"""Contracts for complete, content-bounded investigation query ledgers."""
from __future__ import annotations

import hashlib
import json
import unittest

from n8n.onion_sentinel.analysis.query import ledger


def digest_json(value: object) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def request(query_id: str = "query-1") -> dict[str, object]:
    return {
        "query_id": query_id,
        "backend": "elastic",
        "purpose": "validate_detection",
        "parameters": {
            "pack": "dns_activity",
            "window": {
                "start": "2026-08-14T10:00:00Z",
                "end": "2026-08-14T11:00:00Z",
            },
            "observables": {"ips": ["192.0.2.10"]},
            "size": 25,
            "aggregation": "events",
        },
    }


def trusted(
    query_id: str = "query-1",
    *,
    status: str = "ok",
    returned: int = 0,
    truncated: bool = False,
) -> dict[str, object]:
    return {
        "query_id": query_id,
        "execution_backend": "security-onion-elasticsearch",
        "status": status,
        "window": {
            "start": "2026-08-14T10:00:00Z",
            "end": "2026-08-14T11:00:00Z",
        },
        "returned_hits": returned,
        "truncated": truncated,
        "query_digest": "a" * 64,
        "result_digest": "b" * 64,
    }


class QueryLedgerPackageTests(unittest.TestCase):
    def entries(self, value: dict[str, object]) -> list[dict[str, object]]:
        return ledger.entries(
            value,
            digest_json=digest_json,
            maximum_entries=8,
        )

    def test_successful_empty_query_has_complete_explicit_identity(self) -> None:
        normalized = request()
        audit = trusted()
        result = {
            "backend": "security_onion",
            "query_ids": ["query-1"],
            "status": "ok",
            "read_only": True,
            "trusted_query_audit": [audit],
        }

        [entry] = self.entries({
            "round": 2,
            "requests": [normalized],
            "results": [result],
        })

        self.assertEqual(entry["schema"], "onion-sentinel-query-ledger-v1")
        self.assertEqual(entry["round"], 2)
        self.assertEqual(entry["query_id"], "query-1")
        self.assertEqual(entry["backend"], "elastic")
        self.assertEqual(entry["source"], "security-onion-elasticsearch")
        self.assertEqual(entry["normalized_query"], normalized)
        self.assertEqual(entry["normalized_query_digest"], digest_json(normalized))
        self.assertEqual(
            entry["requested_time_range"],
            normalized["parameters"]["window"],
        )
        self.assertEqual(entry["actual_time_range"], audit["window"])
        self.assertEqual(entry["result_count"], 0)
        self.assertFalse(entry["truncated"])
        self.assertEqual(entry["query_digest"], "a" * 64)
        self.assertEqual(entry["result_digest"], "b" * 64)
        self.assertEqual(entry["status"], "ok")
        self.assertEqual(entry["failure_class"], "empty_evidence")
        self.assertTrue(entry["read_only"])

    def test_adjusted_window_preserves_requested_and_actual_ranges(self) -> None:
        normalized = request()
        original = {
            "start": "2026-08-13T00:00:00Z",
            "end": "2026-08-15T00:00:00Z",
        }
        normalized["normalization"] = {
            "window_adjustment": {
                "adjusted": True,
                "requested_window": original,
                "executed_window": normalized["parameters"]["window"],
            }
        }
        audit = trusted(status="partial", returned=25, truncated=True)

        [entry] = self.entries({
            "round": 1,
            "requests": [normalized],
            "results": [{
                "backend": "security_onion",
                "query_ids": ["query-1"],
                "status": "partial",
                "read_only": True,
                "trusted_query_audit": [audit],
            }],
        })

        self.assertEqual(entry["requested_time_range"], original)
        self.assertEqual(
            entry["actual_time_range"], normalized["parameters"]["window"]
        )
        self.assertEqual(entry["result_count"], 25)
        self.assertTrue(entry["truncated"])
        self.assertEqual(entry["failure_class"], "partial_evidence")

    def test_failures_distinguish_authorization_transport_and_timeout(self) -> None:
        requests = [request("denied"), request("transport"), request("timeout")]
        results = [
            {
                "query_id": "denied", "backend": "elastic",
                "status": "rejected", "read_only": True,
                "error": "isolated local authorization rejected the proposal",
            },
            {
                "query_id": "transport", "backend": "elastic",
                "status": "error", "read_only": True,
                "error": "InvestigationPivotClientError",
            },
            {
                "query_id": "timeout", "backend": "elastic",
                "status": "timeout", "read_only": True,
            },
        ]

        entries = self.entries({"requests": requests, "results": results})

        self.assertEqual(
            [entry["failure_class"] for entry in entries],
            ["authorization_denied", "transport_or_broker_error", "timeout"],
        )
        self.assertEqual([entry["result_count"] for entry in entries], [None] * 3)
        self.assertEqual([entry["truncated"] for entry in entries], [None] * 3)
        self.assertIsNone(entries[0]["actual_time_range"])
        self.assertTrue(all(len(entry["query_digest"]) == 64 for entry in entries))
        self.assertTrue(all(len(entry["result_digest"]) == 64 for entry in entries))

    def test_grouped_result_binds_each_query_to_its_own_collector_audit(self) -> None:
        first = trusted("first", returned=1)
        second = trusted("second", returned=4)
        second["query_digest"] = "c" * 64
        second["result_digest"] = "d" * 64
        grouped = {
            "backend": "security_onion",
            "query_ids": ["first", "second"],
            "status": "ok",
            "read_only": True,
            "trusted_query_audit": [first, second],
        }

        entries = self.entries({
            "requests": [request("first"), request("second")],
            "results": [grouped],
        })

        self.assertEqual([entry["query_id"] for entry in entries], ["first", "second"])
        self.assertEqual([entry["result_count"] for entry in entries], [1, 4])
        self.assertEqual(
            [entry["result_digest"] for entry in entries],
            ["b" * 64, "d" * 64],
        )

    def test_projection_is_bounded_and_does_not_mutate_the_round(self) -> None:
        value = {
            "requests": [request(f"query-{index}") for index in range(5)],
            "results": [],
        }
        before = json.loads(json.dumps(value))

        projected = ledger.entries(
            value,
            digest_json=digest_json,
            maximum_entries=2,
        )

        self.assertEqual(len(projected), 2)
        self.assertEqual(value, before)


if __name__ == "__main__":
    unittest.main()
