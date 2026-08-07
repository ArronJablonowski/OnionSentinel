"""Direct authorization contracts for public enrichment queries."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.analysis.query import enrichment  # noqa: E402


class QueryContractError(ValueError):
    pass


class EnrichmentQueryPackageTests(unittest.TestCase):
    def normalize(self, kind: str, value: str, context):
        return enrichment.normalize(
            {"indicator_type": kind, "indicator": value},
            authorization_context=context,
            error_type=QueryContractError,
        )

    def test_admits_original_network_observables_by_exact_kind(self) -> None:
        context = {
            "permitted_observables": {
                "ips": ["192.0.2.10"],
                "domains": ["Example.COM."],
            }
        }
        self.assertEqual(
            self.normalize("ip", "192.0.2.10", context),
            {"indicator_type": "ip", "indicator": "192.0.2.10"},
        )
        self.assertEqual(
            self.normalize("domain", "example.com.", context),
            {"indicator_type": "domain", "indicator": "example.com"},
        )
        with self.assertRaisesRegex(QueryContractError, "not bound"):
            self.normalize("domain", "192.0.2.10", context)

    def test_admits_explicit_url_hash_and_cve_indicators(self) -> None:
        context = {
            "permitted_enrichment_indicators": {
                "url": ["https://example.test/path"],
                "hash": ["ABCDEF"],
                "cve": ["CVE-2026-1234"],
            }
        }
        for kind, value in (
            ("url", "https://example.test/path"),
            ("hash", "abcdef"),
            ("cve", "cve-2026-1234"),
        ):
            with self.subTest(kind=kind):
                result = self.normalize(kind, value, context)
                self.assertEqual(result["indicator_type"], kind)
                self.assertEqual(result["indicator"], value)

    def test_admits_only_supported_discovered_observable_kinds(self) -> None:
        context = {
            "discovered_observables": [
                {"kind": "ips", "value": "198.51.100.20"},
                {"kind": "domains", "value": "pivot.example."},
                {"kind": "users", "value": "not-an-enrichment-authority"},
                "malformed",
            ]
        }
        self.assertEqual(
            self.normalize("ip", "198.51.100.20", context)["indicator"],
            "198.51.100.20",
        )
        self.assertEqual(
            self.normalize("domain", "pivot.example", context)["indicator"],
            "pivot.example",
        )
        with self.assertRaisesRegex(QueryContractError, "not bound"):
            self.normalize("domain", "not-an-enrichment-authority", context)

    def test_fails_closed_without_authorization_or_supported_type(self) -> None:
        for context in (None, {}, [], {"permitted_observables": "invalid"}):
            with self.subTest(context=context), self.assertRaisesRegex(
                QueryContractError, "not bound"
            ):
                self.normalize("ip", "192.0.2.10", context)
        with self.assertRaisesRegex(QueryContractError, "unsupported"):
            self.normalize("command", "whoami", {})
        with self.assertRaisesRegex(QueryContractError, "one exact indicator"):
            self.normalize("ip", "", {})


if __name__ == "__main__":
    unittest.main()
