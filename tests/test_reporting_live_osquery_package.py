"""Direct contracts for bounded live endpoint audit projection."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.analysis.reporting import live_osquery  # noqa: E402


DEPENDENCIES = live_osquery.Dependencies(
    bounded_text=lambda value, limit: str(value or "")[:limit],
    safe_nonnegative_int=lambda value: max(0, int(value or 0)),
)


class LiveOsqueryReportingTests(unittest.TestCase):
    def test_absent_evidence_has_stable_empty_audit(self) -> None:
        result = live_osquery.audit(
            {},
            policy=live_osquery.Policy(support_schema="support-v1"),
            dependencies=DEPENDENCIES,
        )
        self.assertEqual(result["queries"], [])
        self.assertTrue(result["read_only"])
        self.assertFalse(result["complete"])
        self.assertIn("No endpoint", result["error"])

    def test_projection_enforces_shared_preview_and_support_bounds(self) -> None:
        evidence = {
            "schema": "live-v1",
            "generated_at": "now",
            "read_only": True,
            "complete": False,
            "control_plane_writes": True,
            "control_plane_write_status": "confirmed",
            "collection_error": "partial",
            "batches": [
                {"validated": True}, {"validated": False}, "malformed",
            ],
            "results": [{
                "target_alias": "endpoint-a",
                "status": "ok",
                "purpose": "inspect sockets",
                "query_digest": "digest",
                "query": "SELECT * FROM process_open_sockets;",
                "rows": [{"pid": index, "extra": "x"} for index in range(5)],
                "total_rows": 8,
                "truncated": True,
                "duration_ms": 4,
                "support_bindings": [
                    {"schema": "support-v1"},
                    {"schema": "other"},
                ],
            }],
        }
        result = live_osquery.audit(
            {"_live_osquery_evidence_accumulator": evidence},
            policy=live_osquery.Policy(
                support_schema="support-v1",
                maximum_preview_rows=2,
                maximum_preview_bytes=10_000,
                maximum_rows_per_query=5,
                maximum_columns_per_row=1,
            ),
            dependencies=DEPENDENCIES,
        )
        self.assertEqual(result["batches"], 3)
        self.assertEqual(result["validated_batches"], 1)
        self.assertEqual(result["failed_batches"], 1)
        self.assertTrue(result["preview_truncated"])
        query = result["queries"][0]
        self.assertEqual(query["returned_rows"], 5)
        self.assertEqual(len(query["rows_preview"]), 2)
        self.assertEqual(query["rows_preview"], [{"pid": ""}, {"pid": "1"}])
        self.assertTrue(query["rows_preview_truncated"])
        self.assertEqual(query["support_binding_count"], 1)
        self.assertEqual(result["control_plane_write_status"], "confirmed")
        self.assertEqual(result["error"], "partial")


if __name__ == "__main__":
    unittest.main()
