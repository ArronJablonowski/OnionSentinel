"""End-to-end compatibility contracts for claim-evidence response admission."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
sys.path.insert(0, str(BIN))
from prompt_response_contract import (  # noqa: E402
    PromptContractRequest,
    build_prompt_contract,
)


def load_runner():
    spec = importlib.util.spec_from_file_location(
        "claim_evidence_runtime_runner", BIN / "run-local-ai-analysis.py",
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class ClaimEvidenceRuntimeIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.runner = load_runner()

    def prompt(self) -> dict:
        prompt = build_prompt_contract(PromptContractRequest(
            agent_role="soc-analyst", blind_reanalysis=False,
            role_prompt="Fixture role", task="Fixture task",
            query_packs=("alert_context",), query_v2=False,
        ))
        prompt["evidence_reference_contract"] = {"references": [{
            "ref": "alert:one", "corroborating": True,
            "source_class": "security_onion_detection",
            "status": "ok", "returned": 1,
        }]}
        return prompt

    def response(self) -> dict:
        return {
            **self.runner.DEFAULT_RESPONSE_VALUES,
            **self.runner.STRICT_RESPONSE_VALUES,
            "bluf": "Inconclusive: bounded evidence.",
            "summary": "Bounded evidence.",
            "likely_meaning": "Unknown.",
            "severity_reasoning": "Unknown.",
            "alert_frequency_assessment": "One observation.",
            "detection_outcome": "inconclusive",
            "event_status": "observed",
            "detection_validity": "unknown",
            "activity_disposition": "unknown",
            "handling": "investigate",
            "duplicate_of": None,
            "confidence": "medium",
            "confidence_score": 0.65,
            "evidence_used": ["alert:one"],
            "evidence_gaps": [],
            "hypotheses": [],
            "claim_evidence_graph": {
                "schema": "onion-sentinel-claim-evidence-graph-v1",
                "claims": [{
                    "id": "final", "claim_kind": "final_determination",
                    "statement": "The supplied evidence is inconclusive.",
                    "material": True, "claim_scope": "activity_disposition",
                    "report_fields": [
                        "event_status", "detection_validity",
                        "activity_disposition", "handling", "duplicate_of",
                        "detection_outcome", "confidence", "confidence_score",
                        "escalation_needed", "tuning_recommendation",
                    ],
                    "certainty": "supported",
                    "supporting_evidence_refs": ["alert:one"],
                    "contradicting_evidence_refs": [],
                    "decisive_missing_evidence": ["Endpoint attribution."],
                    "supersedes_claim_id": None, "correction_reason": "",
                }],
            },
        }

    def test_valid_graph_survives_full_response_guard_and_confidence_pipeline(self) -> None:
        result = self.runner.validate_response(self.response(), self.prompt())

        self.assertTrue(result["_claim_evidence_validation"]["valid"])
        self.assertEqual(result["claim_evidence_graph"]["claims"][0]["id"], "final")
        self.assertNotIn(
            "material conclusions lack valid claim-to-evidence bindings",
            result["_verdict_validation"].get("contradictions", []),
        )

    def test_missing_advertised_graph_caps_certainty_and_blocks_automation(self) -> None:
        response = self.response()
        response.pop("claim_evidence_graph")

        result = self.runner.validate_response(response, self.prompt())

        self.assertFalse(result["_claim_evidence_validation"]["valid"])
        self.assertEqual(result["confidence"], "low")
        self.assertLessEqual(result["confidence_score"], 0.39)
        self.assertTrue(result["_verdict_validation"]["material_contradiction"])
        self.assertTrue(result["_automation_controls"]["requires_human_review"])


if __name__ == "__main__":
    unittest.main()
