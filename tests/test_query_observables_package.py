from __future__ import annotations

import copy
import hashlib
import re
import unittest

from n8n.onion_sentinel.analysis.query import observables


class QueryObservablesPackageTests(unittest.TestCase):
    def setUp(self):
        self.policy = observables.ValidationPolicy(
            safe_domain_pattern=re.compile(
                r"(?i)(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
                r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
            ),
            safe_atom_pattern=re.compile(r"[A-Za-z0-9_.:@/-]+"),
            maximum_queries_per_round=12,
        )
        self.dependencies = observables.ValidationDependencies(
            text=lambda value, limit: str(value or "")[:limit],
            evidence_ref_component=lambda value, limit: (
                str(value)[:limit]
                if re.fullmatch(r"[A-Za-z0-9_.:@+=-]+", str(value))
                else "sha256-" + hashlib.sha256(str(value).encode()).hexdigest()[:20]
            ),
        )

    def test_only_successful_trusted_backends_reach_validator(self):
        rows = [
            {"backend": "security_onion", "status": "ok", "id": 1},
            {"backend": "pcap_zeek", "status": "partial", "id": 2},
            {"backend": "osquery", "status": "ok", "id": 3},
            {"backend": "security_onion", "status": "error", "id": 4},
            "malformed",
        ]
        observed = []

        def validate(sources, *, limit):
            observed.extend(copy.deepcopy(sources))
            self.assertEqual(limit, 3)
            return [{"kind": "ip", "value": "192.0.2.1"}]

        result = observables.promote([], rows, limit=3, validate=validate)
        self.assertEqual([item["id"] for item in observed], [1, 2])
        self.assertEqual(result.source_count, 2)
        self.assertEqual(result.promoted_count, 1)

    def test_existing_and_new_values_are_deduplicated_and_bounded(self):
        existing = [{"kind": "ip", "value": "192.0.2.1", "source": "old"}]
        snapshot = copy.deepcopy(existing)
        candidates = [
            {"kind": "ip", "value": "192.0.2.1", "source": "new"},
            {"kind": "domain", "value": "example.test"},
            {"kind": "ip", "value": "198.51.100.2"},
        ]
        result = observables.promote(
            existing,
            [{"backend": "security_onion", "status": "ok"}],
            limit=2,
            validate=lambda _sources, *, limit: candidates[:limit + 1],
        )
        self.assertEqual(existing, snapshot)
        self.assertEqual(len(result.observables), 2)
        self.assertEqual(result.observables[0]["source"], "old")
        self.assertEqual(result.observables[1]["value"], "example.test")

    def test_malformed_results_and_zero_capacity_promote_nothing(self):
        called = []
        result = observables.promote(
            "invalid", {"results": "invalid"}, limit=0,
            validate=lambda sources, *, limit: called.append((sources, limit)) or [],
        )
        self.assertEqual(result.observables, ())
        self.assertEqual(called, [([], 0)])

    def test_validation_promotes_only_digest_bound_positive_security_onion_hits(self):
        digest = "a" * 64
        result = {
            "backend": "security_onion",
            "status": "partial",
            "security_onion_response_digest": "b" * 64,
            "trusted_query_audit": [{
                "query_id": "q1", "query_digest": digest, "status": "ok",
            }],
            "evidence": {
                "controls_valid": True,
                "results": [{
                    "query_id": "q1", "query_digest": digest, "status": "ok",
                    "hits": [{
                        "index": "logs-test", "id": "hit-1",
                        "source": {
                            "source": {"ip": "192.0.2.10"},
                            "dns": {"question": {"name": "Example.COM."}},
                            "message": "198.51.100.99 must not become a pivot",
                        },
                    }],
                }],
            },
        }

        promoted = observables.validate(
            [result], limit=10, policy=self.policy, dependencies=self.dependencies
        )

        self.assertEqual(
            {(item["kind"], item["value"]) for item in promoted},
            {("ips", "192.0.2.10"), ("domains", "example.com")},
        )
        self.assertTrue(all("hit-1" in item["evidence_ref"] for item in promoted))

    def test_validation_rejects_forged_or_unbound_rows(self):
        forged_security_onion = {
            "backend": "security_onion",
            "status": "ok",
            "security_onion_response_digest": "b" * 64,
            "trusted_query_audit": [{
                "query_id": "q1", "query_digest": "a" * 64, "status": "ok",
            }],
            "evidence": {
                "controls_valid": True,
                "results": [{
                    "query_id": "q1", "query_digest": "c" * 64, "status": "ok",
                    "hits": [{"source": {"source": {"ip": "192.0.2.10"}}}],
                }],
            },
        }
        forged_pcap = {
            "backend": "pcap_zeek",
            "status": "ok",
            "query_id": "q2",
            "trusted_query_audit": [{
                "query_id": "q2", "query_digest": "d" * 64,
                "result_digest": "e" * 64, "evidence_ref": "bound", "status": "ok",
            }],
            "evidence": {
                "query_digest": "d" * 64, "result_digest": "e" * 64,
                "evidence_ref": "forged", "records": [{"source_ip": "192.0.2.11"}],
            },
        }

        self.assertEqual(observables.validate(
            [forged_security_onion, forged_pcap], limit=10,
            policy=self.policy, dependencies=self.dependencies,
        ), [])


if __name__ == "__main__":
    unittest.main()
