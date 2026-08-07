"""Direct contracts for SOC public-enrichment status projection."""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_soc_enrichment_status import compose_enrichment_status  # noqa: E402


class SocEnrichmentStatusTests(unittest.TestCase):
    def envelope(self, **external: object) -> str:
        return json.dumps({"external_intel": external})

    def test_status_precedence_is_records_errors_skips_indicators_none(self) -> None:
        cases = (
            (self.envelope(records=[{}], errors=[{}], skipped=[{}]), "enriched", (1, 1, 1)),
            (self.envelope(errors=[{}], skipped=[{}]), "error", (0, 1, 1)),
            (self.envelope(skipped=[{}]), "checked", (0, 1, 0)),
            (self.envelope(indicators={"public_ips": ["1"], "domains": ["a", "b"]}), "pending", (0, 0, 0)),
            (self.envelope(), "none", (0, 0, 0)),
        )
        for value, expected, counts in cases:
            with self.subTest(expected=expected):
                result = compose_enrichment_status(value)
                self.assertEqual(result["enrichment_status_key"], expected)
                self.assertEqual(
                    (result["enrichment_record_count"], result["enrichment_skip_count"], result["enrichment_error_count"]),
                    counts,
                )

    def test_indicator_count_admits_only_documented_list_categories(self) -> None:
        result = compose_enrichment_status({"external_intel": {"indicators": {
            "public_ips": ["1"], "domains": ["a"], "urls": ["u"],
            "hashes": ["h"], "cves": ["c"], "other": ["ignored"],
            "malformed": "ignored",
        }}})
        self.assertEqual(result["enrichment_status_key"], "pending")
        self.assertIn("5 public indicator(s)", result["enrichment_status_detail"])

    def test_malformed_or_missing_external_envelope_is_explicit_none(self) -> None:
        for value in ("{broken", [], None, {"external_intel": []}):
            with self.subTest(value=value):
                result = compose_enrichment_status(value)
                self.assertEqual(result["enrichment_status_key"], "none")
                self.assertEqual(result["enrichment_record_count"], 0)
                self.assertIn("No public enrichment data recorded", result["enrichment_status_detail"])


if __name__ == "__main__":
    unittest.main()
