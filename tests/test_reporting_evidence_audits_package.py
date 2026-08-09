"""Direct contracts for restricted collector audit projections."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
N8N_ROOT = ROOT / "n8n"
sys.path.insert(0, str(N8N_ROOT))
from onion_sentinel.analysis.reporting import evidence_audits  # noqa: E402


DEPENDENCIES = evidence_audits.Dependencies(
    bounded_text=lambda value, limit: str(value or "")[:limit],
    safe_nonnegative_int=lambda value: max(0, int(value or 0)),
)


def package(response: dict) -> dict:
    return {
        "incident_response_evidence": {
            "generated_at": "2026-08-09T12:00:00Z",
            "security_onion_response": response,
        },
    }


class EvidenceAuditPackageTests(unittest.TestCase):
    def test_missing_collector_has_stable_fail_closed_audits(self) -> None:
        security_onion = evidence_audits.security_onion(
            {}, policy=evidence_audits.Policy(), dependencies=DEPENDENCIES,
        )
        osquery = evidence_audits.appliance_osquery(
            {}, policy=evidence_audits.Policy(), dependencies=DEPENDENCIES,
        )
        self.assertEqual(security_onion["queries"], [])
        self.assertFalse(security_onion["complete"])
        self.assertTrue(security_onion["partial"])
        self.assertTrue(security_onion["read_only"])
        self.assertIn("unavailable", security_onion["error"])
        self.assertEqual(osquery["queries"], [])
        self.assertTrue(osquery["read_only"])
        self.assertIn("unavailable", osquery["error"])

    def test_security_onion_projects_query_provenance_without_hits(self) -> None:
        query_dsl = {"query": {"term": {"event.id": "alert-1"}}}
        audit = evidence_audits.security_onion(
            package({
                "complete": True,
                "partial": False,
                "read_only": True,
                "query_contract": "query-v1",
                "results": [{
                    "pack": "alert_context",
                    "status": "ok",
                    "query_digest": "digest-1",
                    "kql_equivalent": "event.id:alert-1",
                    "query_dsl": query_dsl,
                    "window_index": 2,
                    "window": {"start": "start", "end": "end"},
                    "total_hits": 9,
                    "returned_hits": 3,
                    "prompt_projection": {"source_returned_hits": 7},
                    "truncated": True,
                    "duration_ms": 12,
                    "hits": [{"secret": "must-not-project"}],
                }, "malformed"],
            }),
            policy=evidence_audits.Policy(maximum_security_onion_queries=2),
            dependencies=DEPENDENCIES,
        )
        self.assertTrue(audit["complete"])
        self.assertFalse(audit["partial"])
        self.assertEqual(audit["query_contract"], "query-v1")
        self.assertEqual(len(audit["queries"]), 1)
        query = audit["queries"][0]
        self.assertIs(query["query_dsl"], query_dsl)
        self.assertEqual(query["window"], {"start": "start", "end": "end"})
        self.assertEqual(query["source_returned_hits"], 7)
        self.assertTrue(query["prompt_projection_applied"])
        self.assertNotIn("hits", query)
        self.assertNotIn("secret", repr(audit))

    def test_appliance_osquery_enforces_query_row_and_column_caps(self) -> None:
        audit = evidence_audits.appliance_osquery(
            package({
                "read_only": True,
                "query_contract": "osquery-v1",
                "osquery_results": [{
                    "pack": "processes",
                    "target": "security-onion",
                    "status": "ok",
                    "query_digest": "digest-2",
                    "query": "SELECT * FROM processes;",
                    "total_rows": 20,
                    "returned_rows": 5,
                    "truncated": True,
                    "duration_ms": 3,
                    "rows": [
                        {"pid": 0, "name": "init", "path": "/sbin/init"},
                        {"pid": 1, "name": "agent", "path": "/bin/agent"},
                    ],
                }, {"pack": "ignored"}],
            }),
            policy=evidence_audits.Policy(
                maximum_osquery_queries=1,
                maximum_osquery_rows=1,
                maximum_osquery_columns=2,
            ),
            dependencies=DEPENDENCIES,
        )
        self.assertEqual(len(audit["queries"]), 1)
        query = audit["queries"][0]
        self.assertEqual(query["query"], "SELECT * FROM processes;")
        self.assertEqual(query["total_rows"], 20)
        self.assertEqual(query["rows_preview"], [{"pid": "", "name": "init"}])
        self.assertNotIn("path", query["rows_preview"][0])

    def test_reporting_projection_has_no_io_primitives(self) -> None:
        source = (
            N8N_ROOT / "onion_sentinel" / "analysis" / "reporting"
            / "evidence_audits.py"
        ).read_text(encoding="utf-8")
        for forbidden in (
            ".write_text(", ".write_bytes(", "urlopen(", "subprocess.",
            "sqlite3.",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
