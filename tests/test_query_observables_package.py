from __future__ import annotations

import copy
import unittest

from n8n.onion_sentinel.analysis.query import observables


class QueryObservablesPackageTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
