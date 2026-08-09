from __future__ import annotations

import copy
import hashlib
import unittest

from n8n.onion_sentinel.analysis.evidence import endpoint


class NormalizationError(ValueError):
    pass


class EndpointEvidencePackageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = endpoint.Policy(
            live_schema="live-osquery-v1",
            support_schema="onion-sentinel-live-osquery-support-v1",
            success_statuses=frozenset({
                "ok", "success", "completed", "complete", "succeeded",
            }),
        )
        self.dependencies = endpoint.Dependencies(
            normalize_live_query=self._normalize,
            normalization_error=NormalizationError,
        )

    @staticmethod
    def _normalize(query: str) -> str:
        if not query.lstrip().lower().startswith("select "):
            raise NormalizationError("read-only SELECT required")
        return " ".join(query.split())

    def _live_package(self) -> dict:
        query = self._normalize(
            "SELECT pid, remote_address FROM process_open_sockets LIMIT 1"
        )
        query_digest = hashlib.sha256(query.encode()).hexdigest()
        address = "198.51.100.20"
        return {
            "_live_osquery_evidence_accumulator": {
                "schema": self.policy.live_schema,
                "read_only": True,
                "complete": True,
                "batches": [{"validated": True}],
                "results": [{
                    "status": "ok",
                    "target_alias": "endpoint-a",
                    "query": query,
                    "query_digest": query_digest,
                    "rows": [{"pid": "42", "remote_address": address}],
                    "support_bindings": [{
                        "schema": self.policy.support_schema,
                        "target_alias": "endpoint-a",
                        "query_digest": query_digest,
                        "table": "process_open_sockets",
                        "row_index": 0,
                        "column": "remote_address",
                        "observable_kind": "ip",
                        "observable_digest": hashlib.sha256(
                            f"ips\0{address}".encode()
                        ).hexdigest(),
                        "source": "trusted-investigation-context",
                        "temporal_scope": "collection_snapshot",
                    }],
                }],
            },
        }

    def test_live_evidence_requires_exact_query_row_and_support_binding(self) -> None:
        package = self._live_package()
        self.assertTrue(endpoint.has_trusted_evidence(
            package, policy=self.policy, dependencies=self.dependencies
        ))
        mutations = (
            lambda value: value["_live_osquery_evidence_accumulator"]
            ["batches"][0].update(validated=False),
            lambda value: value["_live_osquery_evidence_accumulator"]
            ["results"][0].update(query_digest="a" * 64),
            lambda value: value["_live_osquery_evidence_accumulator"]
            ["results"][0]["rows"][0].update(remote_address="203.0.113.9"),
            lambda value: value["_live_osquery_evidence_accumulator"]
            ["results"][0]["support_bindings"][0].update(target_alias="endpoint-b"),
        )
        for mutate in mutations:
            invalid = copy.deepcopy(package)
            mutate(invalid)
            with self.subTest(mutation=mutate):
                self.assertFalse(endpoint.has_trusted_evidence(
                    invalid, policy=self.policy, dependencies=self.dependencies
                ))

    def test_explicit_endpoint_collection_is_distinct_from_appliance_snapshot(self) -> None:
        explicit = {
            "incident_response_evidence": {
                "endpoint_evidence": {"status": "ok", "rows": [{"pid": "1"}]},
            }
        }
        appliance_only = {
            "incident_response_evidence": {
                "security_onion_response": {
                    "osquery_results": [{"status": "ok", "rows": [{"pid": "1"}]}],
                }
            }
        }

        self.assertTrue(endpoint.has_trusted_evidence(
            explicit, policy=self.policy, dependencies=self.dependencies
        ))
        self.assertFalse(endpoint.has_trusted_evidence(
            appliance_only, policy=self.policy, dependencies=self.dependencies
        ))

    def test_trusted_fields_require_complete_untruncated_read_only_rows(self) -> None:
        result = {
            "read_only": True,
            "status": "ok",
            "evidence": {
                "controls_valid": True,
                "complete": True,
                "partial": False,
                "results": [{
                    "status": "ok",
                    "semantic_valid": True,
                    "hits": [{"source": {"process": {"executable": "/bin/tool"}}}],
                    "rows": [{"process.executable": "/bin/other"}],
                }],
            },
        }
        package = {"investigation_query_results": {"rounds": [{"results": [result]}]}}

        self.assertEqual(
            endpoint.trusted_fields(package, policy=self.policy),
            {"process.executable"},
        )
        result["evidence"]["results"][0]["rows_prompt_truncated"] = True
        self.assertEqual(endpoint.trusted_fields(package, policy=self.policy), set())


if __name__ == "__main__":
    unittest.main()
