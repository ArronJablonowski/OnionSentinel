#!/usr/bin/env python3
"""End-to-end source contracts for AC Hunter selection and citation."""
from __future__ import annotations

import json
import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))

from investigation_skills import (  # noqa: E402
    load_investigation_skills,
    resolve_investigation_skills,
)
from prompt_package_view_model import (  # noqa: E402
    PreparedPromptPackageView,
    assemble_prepared_prompt_package,
)
from prompt_response_contract import GROUNDING_BEFORE_CONTEXT  # noqa: E402


DIGEST = "b" * 64


def load_runner():
    path = BIN / "run-local-ai-analysis.py"
    spec = importlib.util.spec_from_file_location(
        "ac_hunter_harness_evidence_runner", path
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class AcHunterHarnessEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.runner = load_runner()

    def test_registry_selects_approved_guidance_only_when_evidence_is_available(self):
        registry = load_investigation_skills(
            ROOT / "n8n" / "config" / "investigation_skills.json"
        )
        ac_skill = next(
            skill for skill in registry["skills"]
            if skill["id"] == "ac-hunter-behavioral-review"
        )
        self.assertEqual(ac_skill["status"], "active")
        self.assertIn("ac_hunter_behavioral_context", ac_skill["required_evidence"])

        base = {
            "event_dataset": "suricata.alert",
            "transport_protocol": "tcp",
            "destination_port": 443,
            "rule_name": "Fixture",
        }
        absent = resolve_investigation_skills(registry, base, "soc-analyst")
        present = resolve_investigation_skills(
            registry,
            {**base, "evidence_sources": ["ac_hunter_behavioral_context"]},
            "soc-analyst",
        )

        self.assertNotIn(
            "ac-hunter-behavioral-review",
            [item["id"] for item in absent["selected"]],
        )
        self.assertIn(
            "ac-hunter-behavioral-review",
            [item["id"] for item in present["selected"]],
        )

    def test_package_exposes_context_and_digest_bound_citation(self):
        ac_context = {
            "schema": "onion-sentinel-ac-hunter-evidence-context-v1",
            "status": "fresh",
            "available": True,
            "complete": True,
            "stale": False,
            "evidence_ref": f"ac-hunter:{DIGEST}",
            "evidence_digest": DIGEST,
            "returned": 1,
            "findings": [{"id": "finding-1"}],
        }
        snapshot = SimpleNamespace(
            alert={"alert_id": "alert-1"},
            grouped_alert_context={},
            public_enrichment={},
            pcap_evidence={},
            ac_hunter_evidence=ac_context,
            authorization_evidence={},
            analyst_state={},
            latest_daily_rollup={},
        )
        detection = SimpleNamespace(
            investigation_skills={"selected": []},
            detection_validation={},
            asset_context={},
        )
        admitted = SimpleNamespace(
            investigation_capability={},
            local_investigation_query_context={},
            correlation_context={},
            memory_context={},
            incident_evidence=None,
        )
        history = SimpleNamespace(
            prior_analyses=[], related_alerts=[], recent_notifications=[]
        )
        package = assemble_prepared_prompt_package(
            PreparedPromptPackageView(
                agent_role="soc-analyst",
                blind_reanalysis=False,
                lineage={},
                generated_at="2026-08-14T20:00:00Z",
                analysis_policy={},
                runtime_files={},
                prompt_contract={},
                core_snapshot=snapshot,
                detection_context=detection,
                admitted_evidence=admitted,
                history=history,
            )
        )
        contract = self.runner.evidence_reference_contract(package)

        self.assertIs(package["ac_hunter_evidence"], ac_context)
        reference = next(
            item for item in contract["references"]
            if item["ref"] == f"ac-hunter:{DIGEST}"
        )
        self.assertEqual(reference["source"], "ac_hunter_evidence")
        self.assertEqual(reference["source_class"], "behavioral_context")
        self.assertEqual(reference["evidence_digest"], DIGEST)
        self.assertTrue(reference["corroborating"])
        package["evidence_reference_contract"] = contract
        validated = self.runner.validate_evidence_references(
            {"evidence_used": [f"ac-hunter:{DIGEST}"]}, package
        )
        self.assertEqual(validated["evidence_used"], [f"ac-hunter:{DIGEST}"])
        self.assertEqual(
            validated["_evidence_reference_validation"][
                "corroborating_source_classes"
            ],
            ["behavioral_context"],
        )

    def test_prompt_contract_keeps_behavioral_context_non_authoritative(self):
        instructions = "\n".join(GROUNDING_BEFORE_CONTEXT)
        self.assertIn("AC Hunter", instructions)
        self.assertIn("untrusted behavioral context", instructions)
        self.assertIn("never", instructions.lower())
        self.assertIn("malware", instructions.lower())

    def test_candidate_remains_honest_until_governed_promotion(self):
        candidate = json.loads((
            ROOT / "n8n" / "config" / "investigation-skills-v2-candidates"
            / "ac-hunter-behavioral-review-v2.candidate.json"
        ).read_text(encoding="utf-8"))
        self.assertEqual(candidate["maintainer"]["reviewer"], "pending")
        self.assertFalse(candidate["verification"]["human_approved"])


if __name__ == "__main__":
    unittest.main()
