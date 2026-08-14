"""Contracts for material claim-to-evidence validation."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.analysis.conclusions import claim_evidence  # noqa: E402


class ClaimEvidenceError(ValueError):
    pass


DEPS = claim_evidence.Dependencies(
    error_type=ClaimEvidenceError,
    bounded_reference=lambda value: " ".join(str(value or "").split())[:512],
)


def package() -> dict:
    return {
        "evidence_reference_contract": {
            "references": [
                {
                    "ref": "alert:current",
                    "corroborating": True,
                    "source_class": "security_onion_detection",
                    "returned": 1,
                    "status": "ok",
                },
                {
                    "ref": "query:empty",
                    "corroborating": False,
                    "source_class": "security_onion_investigation_query",
                    "returned": 0,
                    "status": "ok",
                    "scope_exact": True,
                },
                {
                    "ref": "query:failed",
                    "corroborating": False,
                    "source_class": "live_endpoint_osquery",
                    "status": "failed",
                },
                {
                    "ref": "score:behavioral",
                    "corroborating": True,
                    "source_class": "ac_hunter_behavioral_score",
                    "returned": 1,
                    "status": "ok",
                },
            ]
        }
    }


def claim(
    identifier: str,
    kind: str,
    *,
    fields: list[str] | None = None,
    supports: list[str] | None = None,
    contradicts: list[str] | None = None,
    missing: list[str] | None = None,
    certainty: str = "supported",
    scope: str = "event_occurrence",
    supersedes: str | None = None,
    correction_reason: str = "",
) -> dict:
    return {
        "id": identifier,
        "kind": kind,
        "statement": f"Statement for {identifier}.",
        "material": True,
        "claim_scope": scope,
        "report_fields": fields or [],
        "certainty": certainty,
        "supporting_evidence_refs": supports or [],
        "contradicting_evidence_refs": contradicts or [],
        "decisive_missing_evidence": missing or [],
        "supersedes_claim_id": supersedes,
        "correction_reason": correction_reason,
    }


def valid_graph() -> dict:
    return {
        "schema": "onion-sentinel-claim-evidence-graph-v1",
        "claims": [
            claim(
                "observed-event", "observation",
                fields=["event_status"], supports=["alert:current"],
            ),
            claim(
                "bounded-absence", "negative_evidence",
                supports=["query:empty"], certainty="supported",
            ),
            claim(
                "endpoint-gap", "unavailable_telemetry",
                supports=["query:failed"], certainty="unavailable",
                missing=["A successful endpoint process query."],
            ),
            claim(
                "alternative", "hypothesis",
                supports=["alert:current"], contradicts=["query:empty"],
                missing=["A process-to-flow join."], certainty="tentative",
            ),
            claim(
                "final", "final_determination",
                fields=[
                    "detection_outcome", "activity_disposition", "handling",
                    "confidence",
                ],
                supports=["alert:current"], contradicts=["query:empty"],
                missing=["Endpoint attribution remains unavailable."],
                scope="activity_disposition",
            ),
        ],
    }


class ClaimEvidencePackageTests(unittest.TestCase):
    def test_valid_graph_preserves_all_claim_classes_and_edges(self) -> None:
        result = claim_evidence.validate(
            valid_graph(),
            {
                "event_status": "observed",
                "detection_outcome": "inconclusive",
                "activity_disposition": "unknown",
                "handling": "investigate",
                "confidence": "medium",
            },
            package(),
            DEPS,
        )

        self.assertEqual(
            {item["kind"] for item in result["claims"]},
            {
                "observation", "negative_evidence", "unavailable_telemetry",
                "hypothesis", "final_determination",
            },
        )
        self.assertEqual(
            result["validation"]["covered_report_fields"],
            [
                "activity_disposition", "confidence", "detection_outcome",
                "event_status", "handling",
            ],
        )

    def test_material_claim_without_an_evidence_edge_fails_closed(self) -> None:
        graph = valid_graph()
        graph["claims"][0]["supporting_evidence_refs"] = []
        with self.assertRaisesRegex(
            ClaimEvidenceError, "material claim observed-event has no evidence edge",
        ):
            claim_evidence.validate(graph, {}, package(), DEPS)

    def test_foreign_reference_and_result_semantic_mismatch_fail(self) -> None:
        foreign = valid_graph()
        foreign["claims"][0]["supporting_evidence_refs"] = ["model:invented"]
        with self.assertRaisesRegex(ClaimEvidenceError, "outside the evidence contract"):
            claim_evidence.validate(foreign, {}, package(), DEPS)

        mismatch = valid_graph()
        mismatch["claims"][0]["supporting_evidence_refs"] = ["query:empty"]
        with self.assertRaisesRegex(ClaimEvidenceError, "zero-row evidence"):
            claim_evidence.validate(mismatch, {}, package(), DEPS)

    def test_behavioral_score_alone_cannot_support_malware_attribution(self) -> None:
        graph = valid_graph()
        final = graph["claims"][-1]
        final["claim_scope"] = "malware_attribution"
        final["certainty"] = "confirmed"
        final["supporting_evidence_refs"] = ["score:behavioral"]
        final["contradicting_evidence_refs"] = []
        with self.assertRaisesRegex(
            ClaimEvidenceError, "behavioral scores alone cannot support malware attribution",
        ):
            claim_evidence.validate(graph, {}, package(), DEPS)

    def test_reviewer_correction_retains_original_and_reason(self) -> None:
        missing_original = valid_graph()
        missing_original["claims"].append(claim(
            "reviewed-final", "final_determination",
            supports=["alert:current"], supersedes="primary-final",
            correction_reason="The bounded absence contradicts the original certainty.",
            scope="activity_disposition",
        ))
        with self.assertRaisesRegex(ClaimEvidenceError, "superseded claim is absent"):
            claim_evidence.validate(missing_original, {}, package(), DEPS)

        retained = valid_graph()
        retained["claims"].append(claim(
            "reviewed-final", "final_determination",
            supports=["alert:current"], contradicts=["query:empty"],
            supersedes="final",
            correction_reason="The exact bounded absence reduces certainty.",
            scope="activity_disposition",
        ))
        result = claim_evidence.validate(retained, {}, package(), DEPS)
        reviewed = result["claims"][-1]
        self.assertEqual(reviewed["supersedes_claim_id"], "final")
        self.assertIn("reduces certainty", reviewed["correction_reason"])


if __name__ == "__main__":
    unittest.main()
