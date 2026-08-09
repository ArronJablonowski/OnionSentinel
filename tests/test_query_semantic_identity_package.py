"""Direct contracts for investigation-request semantic identity."""
from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.analysis.query import semantic_identity  # noqa: E402


DEPENDENCIES = semantic_identity.Dependencies(
    normalize_live_query=lambda value: str(value or "").strip().rstrip(";"),
)


def request(backend: str, parameters: dict, **labels) -> dict:
    return {
        "query_id": labels.get("query_id", "query-1"),
        "purpose": labels.get("purpose", "Investigate one fact."),
        "backend": backend,
        "parameters": parameters,
        "normalization": labels.get("normalization", {}),
    }


class QuerySemanticIdentityPackageTests(unittest.TestCase):
    def digest(self, value: dict) -> str:
        return semantic_identity.digest(value, DEPENDENCIES)

    def test_labels_and_purpose_do_not_change_execution_identity(self) -> None:
        parameters = {"indicator_type": "DOMAIN", "indicator": "Example.TEST."}
        first = request("enrichment", parameters, query_id="first", purpose="one")
        second = request("enrichment", parameters, query_id="second", purpose="two")
        self.assertEqual(self.digest(first), self.digest(second))

    def test_security_onion_canonicalizes_observables_and_utc_window(self) -> None:
        first = request("elastic", {
            "observables": {
                "ips": ["2001:0db8::1", "192.0.2.1"],
                "domains": ["Example.TEST.", "example.test"],
            },
            "window": {
                "start": "2026-08-09T00:00:00Z",
                "end": "2026-08-09T01:00:00Z",
            },
        })
        second = request("elastic", {
            "observables": {
                "ips": ["192.0.2.1", "2001:db8:0:0:0:0:0:1"],
                "domains": ["example.test"],
            },
            "window": {
                "start": "2026-08-08T18:00:00-06:00",
                "end": "2026-08-08T19:00:00-06:00",
            },
        })
        self.assertEqual(self.digest(first), self.digest(second))

    def test_naive_time_is_not_assumed_to_be_utc(self) -> None:
        naive = request("oql", {"window": {
            "start": "2026-08-09T00:00:00", "end": "2026-08-09T01:00:00",
        }})
        aware = request("oql", {"window": {
            "start": "2026-08-09T00:00:00Z", "end": "2026-08-09T01:00:00Z",
        }})
        self.assertNotEqual(self.digest(naive), self.digest(aware))

    def test_missing_or_invalid_window_boundaries_are_not_synthesized(self) -> None:
        missing = request("elastic", {"window": {"start": "not-a-time"}})
        explicit_empty = request("elastic", {
            "window": {"start": "not-a-time", "end": ""},
        })
        self.assertNotEqual(self.digest(missing), self.digest(explicit_empty))

    def test_osquery_normalizes_sql_but_preserves_string_literal_case(self) -> None:
        first = request("osquery", {
            "target_alias": "host-a",
            "query": "SELECT  pid FROM processes WHERE name = 'Case Value';",
        })
        equivalent = request("osquery", {
            "target_alias": "host-a",
            "query": " select pid   from PROCESSES where NAME = 'Case Value' ",
        })
        different_literal = request("osquery", {
            "target_alias": "host-a",
            "query": "select pid from processes where name = 'case value'",
        })
        self.assertEqual(self.digest(first), self.digest(equivalent))
        self.assertNotEqual(self.digest(first), self.digest(different_literal))

    def test_derived_and_enrichment_text_are_case_canonical(self) -> None:
        pcap_first = request("pcap_zeek", {
            "indicator": "Example.TEST", "filters": {"protocol": "TCP"},
        })
        pcap_second = request("pcap_zeek", {
            "indicator": "example.test", "filters": {"protocol": "tcp"},
        })
        enrichment_first = request("enrichment", {
            "indicator_type": "DOMAIN", "indicator": " Example.TEST. ",
        })
        enrichment_second = request("enrichment", {
            "indicator_type": "domain", "indicator": "example.test",
        })
        self.assertEqual(self.digest(pcap_first), self.digest(pcap_second))
        self.assertEqual(self.digest(enrichment_first), self.digest(enrichment_second))

    def test_package_has_no_io_primitives(self) -> None:
        source = (ROOT / "n8n/onion_sentinel/analysis/query/semantic_identity.py").read_text()
        for primitive in (
            "import subprocess", "from subprocess", "urlopen(",
            "import requests", "requests.get(", "requests.post(", "open(",
        ):
            self.assertNotIn(primitive, source)


if __name__ == "__main__":
    unittest.main()
