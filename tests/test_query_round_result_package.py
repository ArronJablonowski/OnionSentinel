from __future__ import annotations

import copy
import unittest

from n8n.onion_sentinel.analysis.query import round_result


class QueryRoundResultPackageTests(unittest.TestCase):
    def dependencies(self, execute, failures=None):
        return round_result.Dependencies(
            execute=execute,
            repair_failures=failures or (lambda _envelope: {}),
            now=lambda: "2026-08-06T12:00:00Z",
        )

    def invoke(self, admitted, rejected=(), execute=None, failures=None):
        return round_result.run(
            admitted,
            rejected,
            round_number=3,
            policy=round_result.Policy(schema="query-results-v1"),
            dependencies=self.dependencies(
                execute or (lambda _requests: self.fail("unexpected execution")),
                failures,
            ),
        )

    def test_valid_broker_envelope_is_preserved_and_rejections_are_appended(self):
        envelope = {
            "schema": "query-results-v1",
            "round": 3,
            "requests": [{"query_id": "q-1", "backend": "security_onion"}],
            "results": [{"query_id": "q-1", "status": "ok"}],
            "audit": [{"query_id": "q-1"}],
        }
        rejected = [{"query_id": "q-2", "status": "rejected"}]
        result = self.invoke(
            envelope["requests"], rejected, execute=lambda _requests: envelope
        )
        self.assertIs(result.envelope, envelope)
        self.assertEqual([item["query_id"] for item in envelope["results"]], [
            "q-1", "q-2"
        ])

    def test_empty_admission_skips_execution_and_returns_canonical_envelope(self):
        result = self.invoke([])
        self.assertEqual(result.envelope, {
            "schema": "query-results-v1",
            "round": 3,
            "generated_at": "2026-08-06T12:00:00Z",
            "requests": [],
            "results": [],
            "audit": [],
        })

    def test_malformed_broker_response_fails_closed_per_admitted_request(self):
        admitted = [
            {"query_id": "q-1", "backend": "security_onion"},
            {"query_id": "q-2", "backend": "osquery"},
        ]
        snapshot = copy.deepcopy(admitted)
        result = self.invoke(admitted, execute=lambda _requests: {"results": {}})
        self.assertEqual(result.envelope["requests"], snapshot)
        self.assertEqual(admitted, snapshot)
        self.assertEqual(
            [item["status"] for item in result.envelope["results"]],
            ["invalid_response", "invalid_response"],
        )
        self.assertTrue(all(item["read_only"] for item in result.envelope["results"]))
        self.assertTrue(all(
            item["error"] == round_result.INVALID_ENVELOPE_ERROR
            for item in result.envelope["results"]
        ))

    def test_repair_failures_are_computed_before_local_rejections_are_merged(self):
        observed = []
        envelope = {"requests": [], "results": [], "audit": []}

        def failures(candidate):
            observed.extend(copy.deepcopy(candidate["results"]))
            return {"q-1": "bounded repair required"}

        result = self.invoke(
            [{"query_id": "q-1", "backend": "pcap_zeek"}],
            [{"query_id": "q-local", "status": "rejected"}],
            execute=lambda _requests: envelope,
            failures=failures,
        )
        self.assertEqual(observed, [])
        self.assertEqual(result.repair_failures, {
            "q-1": "bounded repair required"
        })
        self.assertEqual(result.envelope["results"][0]["query_id"], "q-local")


if __name__ == "__main__":
    unittest.main()
