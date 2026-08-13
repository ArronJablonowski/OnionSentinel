#!/usr/bin/env python3
"""Parity and purity contracts for extracted analysis report rendering."""
from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
N8N_ROOT = ROOT / "n8n"
if str(N8N_ROOT) not in sys.path:
    sys.path.insert(0, str(N8N_ROOT))

from onion_sentinel.analysis.reporting import incident, markdown


RUNNER_PATH = ROOT / "n8n" / "bin" / "run-local-ai-analysis.py"
SPEC = importlib.util.spec_from_file_location("reporting_parity_runner", RUNNER_PATH)
RUNNER = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(RUNNER)


class ReportingMarkdownPackageTests(unittest.TestCase):
    def normalized_response(self):
        return RUNNER.validate_response(
            {
                "detection_outcome": "true_positive_suspicious",
                "bluf": (
                    "True Positive - Suspicious: The synthetic DNS evidence "
                    "is real but not confirmed malicious."
                ),
                "summary": "Synthetic alert summary.",
                "likely_meaning": "Synthetic meaning.",
                "severity_reasoning": "Synthetic severity.",
                "alert_frequency_assessment": "Synthetic frequency.",
                "public_enrichment_findings": [
                    "OTX marked 198.51.100.10 suspicious with medium confidence."
                ],
                "pcap_analysis_findings": [
                    "Zeek saw one DNS query for example.test."
                ],
                "false_positive_possibilities": [],
                "recommended_next_steps": ["Pivot in Security Onion."],
                "evidence_used": ["Synthetic evidence."],
                "evidence_gaps": [],
                "confidence": "medium",
                "escalation_needed": False,
                "hosted_second_opinion_recommended": False,
                "tuning_recommendation": "none",
                "tuning_reason": "No tuning needed.",
                "recommended_tuning_actions": [],
            }
        )

    def test_frozen_report_is_byte_identical_to_pre_extraction_baseline(self) -> None:
        rendered = markdown.render(
            {
                "alert": {
                    "alert_id": "alert-1",
                    "rule_name": "Unit Test",
                    "triage_level": "low",
                },
                "analysis_policy": {},
            },
            self.normalized_response(),
            "2026-07-07  10:00:00-06:00",
            Path("/synthetic/analysis.json"),
            normalize_correlation=RUNNER.normalize_correlation_assessment,
            safe_filename=RUNNER.safe_filename,
            bounded_text_list=RUNNER.bounded_text_list,
        )
        self.assertEqual(len(rendered.encode("utf-8")), 2578)
        self.assertEqual(
            hashlib.sha256(rendered.encode("utf-8")).hexdigest(),
            "7a7b5ab81b8aa3598bfe7fdd14dfc0920dac06dd26122877297e7aea0f868aff",
        )

    def test_query_audits_preserve_exact_copyable_query_blocks(self) -> None:
        response = {
            "_incident_query_audit": {
                "trusted_source": "relay",
                "read_only": True,
                "complete": True,
                "partial": False,
                "queries": [
                    {
                        "pack": "alert_context",
                        "status": "ok",
                        "query_digest": "digest-1",
                        "window": {"start": "a", "end": "b"},
                        "total_hits": 1,
                        "returned_hits": 1,
                        "kql_equivalent": "event.id:*",
                        "query_dsl": {"query": {"match_all": {}}},
                    }
                ],
            },
            "_incident_osquery_audit": {
                "queries": [
                    {
                        "pack": "processes",
                        "query": "select * from processes;",
                        "rows_preview": [{"pid": "1"}],
                    }
                ]
            },
            "_incident_live_osquery_audit": {
                "queries": [
                    {
                        "target_alias": "host-a",
                        "query": "select * from listening_ports;",
                    }
                ]
            },
        }
        query = "\n".join(incident.render_security_onion_query_audit(response))
        appliance = "\n".join(incident.render_appliance_osquery_audit(response))
        live = "\n".join(incident.render_live_osquery_audit(response))
        self.assertIn("```kql\nevent.id:*\n```", query)
        self.assertIn('"match_all": {}', query)
        self.assertIn("```sql\nselect * from processes;\n```", appliance)
        self.assertIn('"pid": "1"', appliance)
        self.assertIn("```sql\nselect * from listening_ports;\n```", live)

    def test_security_onion_audit_preserves_defaults_numbering_and_exact_lines(self) -> None:
        response = {
            "_incident_query_audit": {
                "queries": [
                    "ignored",
                    {
                        "window": {"start": "first", "end": "last"},
                        "query_dsl": {"z": 1, "a": {"b": 2}},
                    },
                ]
            }
        }
        snapshot = {
            "_incident_query_audit": {
                "queries": [
                    "ignored",
                    {
                        "window": {"start": "first", "end": "last"},
                        "query_dsl": {"z": 1, "a": {"b": 2}},
                    },
                ]
            }
        }

        self.assertEqual(incident.render_security_onion_query_audit(response), [
            "## Security Onion Query Audit",
            "",
            "- **Trusted source:** n/a",
            "- **Read only:** True",
            "- **Complete:** False",
            "- **Partial:** True",
            "",
            "### Query 2: evidence pack",
            "",
            "- **Status:** unknown",
            "- **Digest:** `n/a`",
            "- **Window:** first to last",
            "- **Hits:** 0 total; 0 returned",
            "",
            "#### KQL (analyst-readable equivalent)",
            "",
            "```kql",
            "n/a",
            "```",
            "",
            "#### Elasticsearch Query DSL (exact executed request)",
            "",
            "```json",
            '{\n  "a": {\n    "b": 2\n  },\n  "z": 1\n}',
            "```",
            "",
        ])
        self.assertEqual(response, snapshot)

    def test_security_onion_audit_empty_and_invalid_window_boundaries(self) -> None:
        self.assertEqual(incident.render_security_onion_query_audit({}), [])
        self.assertEqual(
            incident.render_security_onion_query_audit({
                "_incident_query_audit": {"queries": "not-a-list"}
            })[-1],
            "No restricted Security Onion queries were recorded.",
        )
        with self.assertRaises(AttributeError):
            incident.render_security_onion_query_audit({
                "_incident_query_audit": {"queries": [{"window": None}]}
            })

    def test_appliance_osquery_audit_preserves_numbering_preview_error_order(self) -> None:
        response = {
            "_incident_osquery_audit": {
                "trusted_source": "relay",
                "read_only": False,
                "queries": [
                    "ignored",
                    {
                        "pack": "process review",
                        "target": "appliance-a",
                        "status": "partial",
                        "query_digest": "digest",
                        "total_rows": 3,
                        "returned_rows": 1,
                        "support_binding_count": 2,
                        "duration_ms": 17,
                        "query": "select pid from processes;",
                        "rows_preview": [{"z": 1, "a": 2}],
                        "error": "bounded failure",
                    },
                ],
            }
        }
        snapshot = __import__("copy").deepcopy(response)
        lines = incident.render_appliance_osquery_audit(response)

        self.assertEqual(lines[:6], [
            "## Security Onion Appliance OSQuery Snapshot Audit", "",
            "- **Trusted source:** relay", "- **Read only:** False", "",
            "### OSquery 2: process review",
        ])
        self.assertEqual(lines[-8:], [
            "#### Bounded Result Preview", "", "```json",
            '[\n  {\n    "a": 2,\n    "z": 1\n  }\n]', "```", "",
            "- **Error:** bounded failure", "",
        ])
        self.assertLess(lines.index("```sql"), lines.index("#### Bounded Result Preview"))
        self.assertEqual(response, snapshot)

    def test_appliance_osquery_audit_empty_defaults_and_preview_boundaries(self) -> None:
        self.assertEqual(incident.render_appliance_osquery_audit({}), [])
        empty = incident.render_appliance_osquery_audit({
            "_incident_osquery_audit": {"queries": "not-a-list"}
        })
        self.assertEqual(empty[-1], (
            "No validated Security Onion appliance OSQuery snapshots were recorded."
        ))
        defaults = incident.render_appliance_osquery_audit({
            "_incident_osquery_audit": {"queries": [{}]}
        })
        self.assertIn("### OSquery 1: reviewed pack", defaults)
        self.assertIn("- **Rows:** 0 total; 0 returned", defaults)
        self.assertNotIn("#### Bounded Result Preview", defaults)
        self.assertNotIn("- **Error:**", "\n".join(defaults))

    def test_reporting_modules_do_not_perform_io(self) -> None:
        for path in (
            N8N_ROOT / "onion_sentinel" / "analysis" / "reporting" / "incident.py",
            N8N_ROOT / "onion_sentinel" / "analysis" / "reporting" / "markdown.py",
        ):
            source = path.read_text(encoding="utf-8")
            for forbidden in (
                ".write_text(",
                ".write_bytes(",
                "urlopen(",
                "subprocess.",
                "sqlite3.",
            ):
                self.assertNotIn(forbidden, source, (path.name, forbidden))


if __name__ == "__main__":
    unittest.main()
