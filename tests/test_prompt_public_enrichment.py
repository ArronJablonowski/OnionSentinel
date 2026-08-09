#!/usr/bin/env python3
"""Direct contracts for bounded public-enrichment prompt context."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))

from prompt_public_enrichment import (  # noqa: E402
    MAX_PROVIDER_PROMPT_BYTES,
    PublicEnrichmentRequest,
    PublicEnrichmentSources,
    build_public_enrichment_context,
    compact_public_enrichment_record,
)


def request(limit=5) -> PublicEnrichmentRequest:
    return PublicEnrichmentRequest(
        connection="connection",
        selected={"alert_id": "alert-1"},
        record_limit=limit,
        include_tests=False,
    )


def sources(rows) -> PublicEnrichmentSources:
    return PublicEnrichmentSources(
        row_value=lambda row, key: row.get(key),
        alert_group_rows=mock.Mock(return_value=rows),
        parse_json_object=lambda raw: json.loads(raw),
    )


def record(indicator="192.0.2.10", verdict="suspicious", raw=None):
    return {
        "source": "fixture-provider",
        "indicator": indicator,
        "indicator_type": "ip",
        "verdict": verdict,
        "confidence": "medium",
        "tags": ["fixture"],
        "raw_response": {"result": "fixture"} if raw is None else raw,
    }


class PromptPublicEnrichmentTests(unittest.TestCase):
    def test_small_provider_response_is_complete_and_digest_bound(self):
        raw = {"answer": ["benign", 1]}
        compact = compact_public_enrichment_record(record(raw=raw))
        serialized = json.dumps(raw, sort_keys=True, separators=(",", ":"))
        evidence = compact["provider_evidence"]

        self.assertIs(evidence["prompt_projection_complete"], True)
        self.assertEqual(evidence["response"], raw)
        self.assertEqual(
            evidence["response_sha256"],
            hashlib.sha256(serialized.encode()).hexdigest(),
        )
        self.assertNotIn("raw_response", compact)

    def test_large_provider_response_is_digest_plus_bounded_prefix(self):
        raw = {"payload": "x" * (MAX_PROVIDER_PROMPT_BYTES * 2)}
        compact = compact_public_enrichment_record(record(raw=raw))
        evidence = compact["provider_evidence"]

        self.assertIs(evidence["prompt_projection_complete"], False)
        self.assertNotIn("response", evidence)
        self.assertLessEqual(
            len(evidence["response_json_prefix"].encode()),
            MAX_PROVIDER_PROMPT_BYTES,
        )
        self.assertGreater(evidence["response_size_bytes"], MAX_PROVIDER_PROMPT_BYTES)

    def test_cached_digest_size_and_completeness_metadata_are_preserved(self):
        value = record(raw={"provider": "body"})
        value.update(
            {
                "raw_response_sha256": "a" * 64,
                "raw_response_size_bytes": 999,
                "raw_response_complete": False,
            }
        )

        evidence = compact_public_enrichment_record(value)["provider_evidence"]

        self.assertEqual(evidence["response_sha256"], "a" * 64)
        self.assertEqual(evidence["response_size_bytes"], 999)
        self.assertIs(evidence["cache_response_complete"], False)

    def test_group_context_deduplicates_bounds_and_normalizes_supporting_data(self):
        first = {
            "external_intel": {
                "records": [
                    record("192.0.2.10", "suspicious"),
                    record("198.51.100.20", "benign"),
                ],
                "skipped": [
                    {"source": "one", "reason": "unsupported", "secret": "drop"},
                    "plain reason",
                ],
                "errors": [{"source": "two", "reason": "timeout"}],
                "indicators": {"public_ips": ["192.0.2.10", "198.51.100.20"]},
            }
        }
        second = {
            "records": [
                record("192.0.2.10", "malicious"),
                record("203.0.113.30", "unknown"),
            ],
            "indicators": {"domains": ["one.test", "two.test", "three.test"]},
        }
        dependencies = sources(
            [
                {"enrichment_json": json.dumps(first)},
                {"enrichment_json": json.dumps(second)},
            ]
        )

        context = build_public_enrichment_context(dependencies, request(limit=3))

        dependencies.alert_group_rows.assert_called_once_with(
            "connection",
            {"alert_id": "alert-1"},
            include_tests=False,
            extra_columns=("enrichment_json",),
        )
        self.assertEqual(
            [item["indicator"] for item in context["records"]],
            ["192.0.2.10", "198.51.100.20", "203.0.113.30"],
        )
        self.assertEqual(
            context["verdict_counts"],
            {"suspicious": 1, "benign": 1, "unknown": 1},
        )
        self.assertEqual(
            context["skipped"],
            [
                {"source": "one", "reason": "unsupported"},
                {"reason": "plain reason"},
            ],
        )
        self.assertEqual(context["errors"], [{"source": "two", "reason": "timeout"}])
        self.assertEqual(
            context["indicators"]["domains"],
            ["one.test", "two.test", "three.test"],
        )
        self.assertIn("not as sole proof", context["usage_guidance"])

    def test_record_limit_stops_later_group_rows(self):
        parser = mock.Mock(side_effect=lambda raw: json.loads(raw))
        dependencies = PublicEnrichmentSources(
            row_value=lambda row, key: row.get(key),
            alert_group_rows=mock.Mock(
                return_value=[
                    {"enrichment_json": json.dumps({"records": [record()]})},
                    {"enrichment_json": json.dumps({"records": [record("198.51.100.2")]})},
                ]
            ),
            parse_json_object=parser,
        )

        context = build_public_enrichment_context(dependencies, request(limit=1))

        self.assertEqual(len(context["records"]), 1)
        self.assertEqual(parser.call_count, 1)


if __name__ == "__main__":
    unittest.main()
