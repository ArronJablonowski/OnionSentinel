"""Behavior contracts for interactive investigation pivot audit rendering."""
from __future__ import annotations

import html
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_investigation_audit_renderer import (  # noqa: E402
    InvestigationAuditRenderCallbacks,
    investigation_purpose_text,
    render_investigation_query_audit,
)


def html_text(value: object, fallback: str = "n/a") -> str:
    return html.escape(str(value or "").strip() or fallback)


def nonnegative_int(value: object) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError, OverflowError):
        return 0


def linked_finding(report: dict, digest: object) -> str:
    return f"linked <finding> for {digest}" if digest else ""


class InvestigationAuditRendererTests(unittest.TestCase):
    def setUp(self) -> None:
        self.callbacks = InvestigationAuditRenderCallbacks(
            html_text=html_text,
            nonnegative_int=nonnegative_int,
            linked_finding=linked_finding,
        )

    def test_missing_audit_renders_nothing(self) -> None:
        rendered, query_count = render_investigation_query_audit(
            {}, {}, self.callbacks
        )

        self.assertEqual((rendered, query_count), ("", 0))

    def test_empty_audit_preserves_summary_and_empty_state(self) -> None:
        response = {
            "_investigation_query_audit": {
                "query_contract": "broker-v1",
                "provider_neutral": True,
                "model_route": "primary <route>",
                "rounds_completed": "invalid",
                "queries_admitted": -4,
                "requests_ignored_or_over_budget": 2,
                "rounds": "invalid",
            }
        }

        rendered, query_count = render_investigation_query_audit(
            response, {}, self.callbacks
        )

        self.assertEqual(query_count, 0)
        self.assertIn("Interactive Investigation Pivot Audit", rendered)
        self.assertIn("primary &lt;route&gt;", rendered)
        self.assertIn("<b>Rounds:</b> 0", rendered)
        self.assertIn("<b>Admitted:</b> 0", rendered)
        self.assertIn("<b>Rejected/over budget:</b> 2", rendered)
        self.assertIn("No broker-authorized pivot", rendered)

    def test_backend_specific_records_escape_and_preserve_execution_details(self) -> None:
        queries = [
            {
                "backend": "elasticsearch",
                "pack": "network <flow>",
                "purpose": "validate_detection",
                "status": "ok",
                "query_digest": "digest-elastic",
                "window": {"start": "start", "end": "end"},
                "total_hits": 8,
                "returned_hits": 3,
                "semantics": "exact",
                "execution_backend": "relay",
                "index_scan_truncated": True,
                "oql_equivalent": 'source.ip == "192.0.2.1"',
                "kql_equivalent": 'source.ip: "192.0.2.1"',
                "query_dsl": {"query": {"term": {"tag": "<unsafe>"}}},
            },
            {
                "backend": "osquery",
                "target_alias": "host-1",
                "purpose": "custom <purpose>",
                "execution_digest": "digest-osquery",
                "total_rows": 4,
                "returned_rows": 2,
                "query": "SELECT '<process>' FROM processes;",
                "error": "partial <error>",
            },
            {
                "backend": "pcap",
                "operation": "flow",
                "request_digest": "digest-pcap",
                "candidate_records_scanned": 10,
                "records_returned": 1,
                "filters": {"source_ip": "192.0.2.1"},
                "indicator": "198.51.100.2",
                "limit": 5,
            },
            {
                "backend": "zeek",
                "query_id": "dns-pivot",
                "query_digest": "digest-zeek",
                "operation": "dns",
                "filters": {"query": "example.test"},
            },
        ]
        response = {
            "_investigation_query_audit": {
                "rounds": [{"round": 2, "trusted_queries": queries}],
            }
        }

        rendered, query_count = render_investigation_query_audit(
            response, {}, self.callbacks
        )

        self.assertEqual(query_count, 4)
        self.assertIn("Pivot 1 (round 2): ELASTICSEARCH · network &lt;flow&gt;", rendered)
        self.assertIn(
            "Validate whether the observed event matches the triggering detection.",
            rendered,
        )
        self.assertIn('data-query-purpose="custom &lt;purpose&gt;"', rendered)
        self.assertIn('data-query-finding="linked &lt;finding&gt; for digest-elastic"', rendered)
        self.assertIn("8 total / 3 returned", rendered)
        self.assertIn("4 total / 2 returned", rendered)
        self.assertIn("10 scanned / 1 returned", rendered)
        self.assertIn("<b>Truncated:</b> true", rendered)
        self.assertIn("OQL (analyst-readable equivalent)", rendered)
        self.assertIn("KQL (analyst-readable equivalent)", rendered)
        self.assertIn("Elasticsearch Query DSL (exact executed request)", rendered)
        self.assertIn("&lt;unsafe&gt;", rendered)
        self.assertIn("OSquery SQL (exact executed live query)", rendered)
        self.assertIn("SELECT &#x27;&lt;process&gt;&#x27; FROM processes;", rendered)
        self.assertIn("Structured PCAP/Zeek request (exact broker input)", rendered)
        self.assertIn("partial &lt;error&gt;", rendered)

    def test_renderer_bounds_rounds_and_queries_and_skips_malformed_records(self) -> None:
        rounds = []
        for round_index in range(13):
            queries = [{"query_id": f"q-{round_index}-{index}"} for index in range(13)]
            queries.insert(0, "malformed")
            rounds.append({"round": round_index + 1, "trusted_queries": queries})
        rounds.insert(0, "malformed")
        response = {"_investigation_query_audit": {"rounds": rounds}}

        rendered, query_count = render_investigation_query_audit(
            response, {}, self.callbacks
        )

        self.assertEqual(query_count, 121)
        self.assertIn("Pivot 121", rendered)
        self.assertNotIn("Pivot 122", rendered)
        self.assertNotIn("q-11-", rendered)

    def test_stable_purpose_labels_and_free_form_fallback(self) -> None:
        self.assertEqual(
            investigation_purpose_text("measure_prevalence"),
            "Measure how often the exact activity appears in the authorized window.",
        )
        self.assertEqual(
            investigation_purpose_text("Confirm custom hypothesis."),
            "Confirm custom hypothesis.",
        )


if __name__ == "__main__":
    unittest.main()
