"""Behavior contracts for the extracted Incident Response report renderer."""
from __future__ import annotations

import html
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_incident_report_renderer import (  # noqa: E402
    IncidentReportRenderCallbacks,
    render_incident_response_report,
)


def html_text(value: object, fallback: str = "n/a") -> str:
    rendered = str(value or "").strip() or fallback
    return html.escape(rendered)


def nonnegative_int(value: object) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def linked_finding(report: dict, digest: object) -> str:
    return f"finding for {digest}" if digest else ""


def html_list(value: object, empty_message: str = "No findings were recorded.") -> str:
    values = value if isinstance(value, list) else []
    items = "".join(f"<li>{html_text(item)}</li>" for item in values)
    return f"<ul>{items}</ul>" if items else f"<p>{html.escape(empty_message)}</p>"


def report_section(title: str, body: str) -> str:
    return f"<section><h4>{html.escape(title)}</h4>{body}</section>"


class IncidentReportRendererTests(unittest.TestCase):
    def setUp(self) -> None:
        self.callbacks = IncidentReportRenderCallbacks(
            html_text=html_text,
            nonnegative_int=nonnegative_int,
            linked_finding=linked_finding,
            html_list=html_list,
            report_section=report_section,
            investigation_audit=lambda response, report: (
                '<section id="investigation-audit"></section>',
                2,
            ),
            review_panel=lambda review, **kwargs: '<section id="review-panel"></section>',
        )

    def test_empty_report_escapes_failure_and_has_no_query_or_review_panel(self) -> None:
        rendered, query_count = render_incident_response_report(
            {
                "case_id": "ir-1",
                "agent_status": "analysis_failed",
                "latest_error": '<script>alert("bad")</script>',
            },
            {},
            {"model": "gpt-test"},
            {"status": "completed"},
            self.callbacks,
        )

        self.assertEqual(query_count, 0)
        self.assertIn("Incident Response Investigation", rendered)
        self.assertIn("&lt;script&gt;", rendered)
        self.assertNotIn("<script>", rendered)
        self.assertNotIn("review-panel", rendered)

    def test_complete_report_preserves_order_escaping_and_query_counts(self) -> None:
        response = {
            "incident_response_report": {
                "executive_bluf": "Observed <payload>",
                "factual_timeline": [
                    {
                        "timestamp": "2026-08-07T12:00:00Z",
                        "event": "Connection <opened>",
                        "query_digest": "digest-1",
                    }
                ],
                "security_onion_findings": ["Finding <one>"],
                "confidence": "medium",
            },
            "_incident_query_audit": {
                "trusted_source": "relay",
                "queries": [
                    {
                        "pack": "network_flow",
                        "query_digest": "digest-1",
                        "query_dsl": {"query": {"term": {"tag": "<unsafe>"}}},
                    },
                    "malformed",
                ],
            },
            "_incident_osquery_audit": {
                "queries": [{"pack": "appliance", "query": "select '<x>';"}],
            },
            "_incident_live_osquery_audit": {
                "queries": [{"target_alias": "host-1", "query": "select * from processes;"}],
            },
        }

        rendered, query_count = render_incident_response_report(
            {"case_id": "ir-2", "dashboard_group_id": "group-2"},
            response,
            {"generated_at": "now", "model": "gpt-test"},
            {"status": "completed"},
            self.callbacks,
        )

        self.assertEqual(query_count, 5)
        self.assertNotIn("<payload>", rendered)
        self.assertIn("Observed &lt;payload&gt;", rendered)
        self.assertIn("&lt;unsafe&gt;", rendered)
        self.assertIn("data-query-finding=\"finding for digest-1\"", rendered)
        expected_order = (
            "review-panel",
            "Incident Response Investigation",
            "Security Onion Query Audit",
            "Security Onion Appliance OSQuery Snapshot Audit",
            "Endpoint Live OSQuery Audit",
            "investigation-audit",
        )
        positions = [rendered.index(marker) for marker in expected_order]
        self.assertEqual(positions, sorted(positions))

    def test_audits_enforce_bounded_presentation_counts(self) -> None:
        report = {"executive_bluf": "bounded", "confidence": "low"}
        response = {
            "incident_response_report": report,
            "_incident_query_audit": {
                "queries": [{"query_digest": str(index)} for index in range(105)]
            },
            "_incident_osquery_audit": {
                "queries": [{"query": "select 1;"} for _ in range(40)]
            },
            "_incident_live_osquery_audit": {
                "queries": [{"query": "select 1;"} for _ in range(40)]
            },
        }

        rendered, query_count = render_incident_response_report(
            {"case_id": "ir-3"}, response, {}, None, self.callbacks
        )

        self.assertEqual(query_count, 166)
        self.assertIn("Query 100:", rendered)
        self.assertNotIn("Query 101:", rendered)
        self.assertIn("OSquery 32:", rendered)
        self.assertNotIn("OSquery 33:", rendered)
        self.assertIn("Endpoint Query 32:", rendered)
        self.assertNotIn("Endpoint Query 33:", rendered)

    def test_non_mapping_report_uses_empty_state(self) -> None:
        rendered, query_count = render_incident_response_report(
            {"case_id": "ir-4", "agent_status": "queued"},
            {"incident_response_report": ["invalid"]},
            {},
            None,
            self.callbacks,
        )

        self.assertEqual(query_count, 0)
        self.assertIn("Incident Responder analysis is queued.", rendered)


if __name__ == "__main__":
    unittest.main()
