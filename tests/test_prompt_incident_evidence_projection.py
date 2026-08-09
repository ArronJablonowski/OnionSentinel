#!/usr/bin/env python3
"""Direct contracts for incident-evidence prompt projection."""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))

from prompt_incident_evidence_projection import (  # noqa: E402
    project_incident_evidence_hits,
    project_incident_evidence_osquery_rows,
    reject_preprojected_incident_evidence_source,
)


class PromptIncidentEvidenceProjectionTests(unittest.TestCase):
    def test_elastic_projection_is_prefix_bounded_and_auditable(self) -> None:
        result = {
            "hits": [{"id": index} for index in range(4)],
            "returned_hits": 4,
            "total_hits": 4,
            "total_hits_relation": "eq",
            "truncated": False,
        }
        artifact = {"security_onion_response": {"results": [result]}}

        self.assertEqual(
            project_incident_evidence_hits(
                artifact,
                limit=2,
                reason="direct_test",
            ),
            1,
        )
        self.assertEqual(result["hits"], [{"id": 0}, {"id": 1}])
        self.assertTrue(result["truncated"])
        self.assertEqual(result["prompt_projection"]["source_returned_hits"], 4)
        self.assertEqual(result["prompt_projection"]["retained_hits"], 2)

    def test_reprojection_preserves_source_and_accumulates_reasons(self) -> None:
        result = {"hits": [1, 2, 3], "returned_hits": 3, "total_hits": 3}
        artifact = {"security_onion_response": {"results": [result]}}
        project_incident_evidence_hits(artifact, limit=2, reason="first")
        source = copy.deepcopy(result["prompt_projection"])

        project_incident_evidence_hits(artifact, limit=1, reason="second")

        projection = result["prompt_projection"]
        self.assertEqual(projection["source_hits_sha256"], source["source_hits_sha256"])
        self.assertEqual(projection["reasons"], ["first", "second"])

    def test_osquery_projection_stops_before_oversized_first_row(self) -> None:
        result = {
            "rows": [{"value": "x" * 100}, {"value": "small"}],
            "returned_rows": 2,
            "total_rows": 2,
            "truncated": False,
        }
        artifact = {"security_onion_response": {"osquery_results": [result]}}

        projected = project_incident_evidence_osquery_rows(
            artifact,
            limit=5,
            max_retained_bytes=1000,
            max_row_bytes=20,
            reason="oversized_row",
        )

        self.assertEqual(projected, 1)
        self.assertEqual(result["rows"], [])
        self.assertEqual(result["prompt_projection"]["source_returned_rows"], 2)

    def test_invalid_limits_and_reason_fail_closed(self) -> None:
        artifact = {"security_onion_response": {"osquery_results": []}}
        for options in (
            {"limit": True, "max_retained_bytes": 1, "max_row_bytes": 1, "reason": "x"},
            {"limit": 1, "max_retained_bytes": -1, "max_row_bytes": 1, "reason": "x"},
            {"limit": 1, "max_retained_bytes": 1, "max_row_bytes": 1, "reason": ""},
        ):
            with self.subTest(options=options), self.assertRaises(ValueError):
                project_incident_evidence_osquery_rows(artifact, **options)

    def test_preprojected_collector_input_is_rejected(self) -> None:
        artifact = {
            "security_onion_response": {
                "results": [{"prompt_projection": {"version": 1}}]
            }
        }
        with self.assertRaisesRegex(ValueError, "must not contain"):
            reject_preprojected_incident_evidence_source(artifact)


if __name__ == "__main__":
    unittest.main()
