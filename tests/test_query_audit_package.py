from __future__ import annotations

import hashlib
import json
import unittest

from n8n.onion_sentinel.analysis.query import audit


def digest_json(value):
    payload = json.dumps(
        value, sort_keys=True, separators=(",", ":"), default=str
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def resolve_binding(result, query_id):
    status = result.get("status", "unknown")
    observations = result.get("observations")
    if isinstance(observations, dict):
        return str(status), observations.get(query_id)
    return str(status), None


class QueryAuditPackageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = audit.Policy(
            maximum_queries_per_round=2,
            success_statuses=frozenset({"ok", "partial"}),
            nonexecution_statuses=frozenset(
                {"rejected", "denied", "blocked", "unauthorized", "forbidden"}
            ),
        )
        self.dependencies = audit.Dependencies(
            digest_json=digest_json,
            resolve_binding=resolve_binding,
        )

    def bindings(self, round_result):
        return audit.tool_call_bindings(
            round_result,
            policy=self.policy,
            dependencies=self.dependencies,
        )

    def test_binding_uses_exact_request_and_result_digests(self) -> None:
        request = {"query_id": "q-1", "backend": "security_onion", "limit": 10}
        result = {
            "query_id": "q-1",
            "backend": "security_onion",
            "status": "ok",
            "read_only": True,
        }
        [binding] = self.bindings(
            {"round": "3", "requests": [request], "results": [result]}
        )

        self.assertEqual(binding["call_id"], "round-3-q-1")
        self.assertEqual(binding["round_number"], 3)
        self.assertEqual(binding["request_digest"], digest_json(request))
        self.assertEqual(binding["result_digest"], digest_json(result))
        self.assertTrue(binding["read_only"])

    def test_grouped_result_creates_binding_for_each_query_id(self) -> None:
        requests = [
            {"query_id": "q-1", "backend": "security_onion"},
            {"query_id": "q-2", "backend": "security_onion"},
        ]
        result = {
            "query_ids": ["q-1", "q-2"],
            "backend": "security_onion",
            "status": "partial",
            "read_only": True,
        }

        bindings = self.bindings(
            {"round": 1, "requests": requests, "results": [result]}
        )

        self.assertEqual([item["query_id"] for item in bindings], ["q-1", "q-2"])
        self.assertEqual(
            {item["result_digest"] for item in bindings}, {digest_json(result)}
        )

    def test_rejected_result_reconstructs_stable_request_stub(self) -> None:
        result = {
            "query_id": "q-rejected",
            "backend": "osquery",
            "status": "rejected",
            "purpose": "unsafe widening",
            "read_only": False,
        }
        expected_stub = {
            "query_id": "q-rejected",
            "backend": "osquery",
            "purpose": "unsafe widening",
            "rejected_before_execution": True,
        }

        [binding] = self.bindings({"round": "invalid", "results": [result]})

        self.assertEqual(binding["round"], 0)
        self.assertEqual(binding["request_digest"], digest_json(expected_stub))
        self.assertEqual(binding["normalized_status"], "rejected")

    def test_bindings_are_capped_at_twice_the_round_query_budget(self) -> None:
        requests = [
            {"query_id": f"q-{index}", "backend": "security_onion"}
            for index in range(8)
        ]
        results = [
            {
                "query_id": request["query_id"],
                "status": "ok",
                "read_only": True,
            }
            for request in requests
        ]

        bindings = self.bindings({"requests": requests, "results": results})

        self.assertEqual(len(bindings), 4)

    def test_summary_accepts_successful_nonwidening_repair(self) -> None:
        bindings = [
            {"query_id": "q-1", "normalized_status": "rejected", "read_only": True},
            {"query_id": "q-1", "normalized_status": "ok", "read_only": True},
        ]

        summary = audit.binding_summary(
            bindings, queries_admitted=1, policy=self.policy
        )

        self.assertTrue(summary["complete"])
        self.assertTrue(summary["evaluation_requirement_satisfied"])
        self.assertEqual(summary["successful_read_only_queries"], 1)

    def test_summary_rejects_unrepaired_or_non_read_only_execution(self) -> None:
        unrepaired = audit.binding_summary(
            [
                {
                    "query_id": "q-1",
                    "normalized_status": "rejected",
                    "read_only": True,
                }
            ],
            queries_admitted=1,
            policy=self.policy,
        )
        mutable = audit.binding_summary(
            [
                {
                    "query_id": "q-1",
                    "normalized_status": "ok",
                    "read_only": False,
                }
            ],
            queries_admitted=1,
            policy=self.policy,
        )

        self.assertFalse(unrepaired["complete"])
        self.assertFalse(mutable["read_only"])
        self.assertFalse(mutable["all_tool_call_bindings_read_only"])
        self.assertFalse(mutable["evaluation_requirement_satisfied"])

    def test_round_audit_caps_trusted_queries_and_normalizations(self) -> None:
        requests = [
            {
                "query_id": f"q-{index}",
                "backend": "security_onion",
                "normalization": {"limit": index},
            }
            for index in range(4)
        ]
        results = [
            {
                "query_id": "q-0",
                "backend": "security_onion",
                "status": "ok",
                "read_only": True,
                "evidence": {"query_digest": "a" * 64},
                "trusted_query_audit": [
                    {"query_id": f"q-{index}"} for index in range(4)
                ],
            }
        ]

        record = audit.round_audit(
            {
                "round": 2,
                "requests": requests,
                "results": results,
                "audit": [{"event": "broker_admission"}],
            },
            policy=self.policy,
            dependencies=self.dependencies,
        )

        self.assertEqual(record["request_count"], 4)
        self.assertEqual(len(record["trusted_queries"]), 2)
        self.assertEqual(len(record["request_normalizations"]), 2)
        self.assertEqual(record["results"][0]["query_digest"], "a" * 64)
        self.assertEqual(record["broker_audit"], [{"event": "broker_admission"}])
        self.assertEqual(record["tool_call_bindings"][0]["query_id"], "q-0")
        self.assertEqual(record["query_ledger"][0]["query_id"], "q-0")


if __name__ == "__main__":
    unittest.main()
