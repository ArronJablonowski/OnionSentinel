#!/usr/bin/env python3
"""Direct contracts for final prompt-package assembly."""
from __future__ import annotations

from pathlib import Path
import sys
from types import SimpleNamespace
import unittest


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))

from prompt_package_view_model import (  # noqa: E402
    BLIND_EXCLUDED_CONTEXT,
    PreparedPromptPackageView,
    PromptPackageView,
    assemble_prepared_prompt_package,
    assemble_prompt_package,
)


def view(**changes) -> PromptPackageView:
    values = {
        "agent_role": "soc-analyst",
        "blind_reanalysis": False,
        "lineage": {"analysis_id": "analysis-1"},
        "generated_at": "2026-08-08T12:00:00Z",
        "analysis_policy": {"primary": "gpt-5.5"},
        "runtime_files": {"system_prompt_file": "/fixture/prompt.md"},
        "prompt_contract": {"instructions": {"task": "Investigate"}},
        "evidence_sections": {"alert": {"alert_id": "alert-1"}},
        "incident_evidence": None,
    }
    values.update(changes)
    return PromptPackageView(**values)


class PromptPackageViewModelTests(unittest.TestCase):
    def test_prepared_subsystems_map_to_their_exact_evidence_sections(self):
        snapshot = SimpleNamespace(
            alert={"alert_id": "alert-1"},
            grouped_alert_context={"group": 1},
            public_enrichment={"intel": 1},
            pcap_evidence={"pcap": 1},
            ac_hunter_evidence={"ac_hunter": 1},
            authorization_evidence={"authorization": 1},
            analyst_state={"state": 1},
            latest_daily_rollup={"rollup": 1},
        )
        detection = SimpleNamespace(
            investigation_skills={"skills": 1},
            detection_validation={"validation": 1},
            asset_context={"assets": 1},
        )
        admitted = SimpleNamespace(
            investigation_capability={"capability": 1},
            local_investigation_query_context={"local": 1},
            correlation_context={"correlation": 1},
            memory_context={"memory": 1},
            incident_evidence=None,
        )
        history = SimpleNamespace(
            prior_analyses=[{"prior": 1}],
            related_alerts=[{"related": 1}],
            recent_notifications=[{"notification": 1}],
        )

        package = assemble_prepared_prompt_package(
            PreparedPromptPackageView(
                agent_role="soc-analyst",
                blind_reanalysis=False,
                lineage={"analysis_id": "analysis-1"},
                generated_at="2026-08-08T12:00:00Z",
                analysis_policy={},
                runtime_files={},
                prompt_contract={},
                core_snapshot=snapshot,
                detection_context=detection,
                admitted_evidence=admitted,
                history=history,
            )
        )

        self.assertIs(package["alert"], snapshot.alert)
        self.assertIs(package["detection_validation"], detection.detection_validation)
        self.assertIs(package["ac_hunter_evidence"], snapshot.ac_hunter_evidence)
        self.assertIs(package["investigation_query_capability"], admitted.investigation_capability)
        self.assertIs(package["prior_analyses"], history.prior_analyses)
        self.assertIs(package["recent_notifications"], history.recent_notifications)

    def test_soc_package_assembles_prepared_sections_without_ir_evidence(self):
        package = assemble_prompt_package(view())

        self.assertEqual(package["package_type"], "soc-ai-investigation-prompt")
        self.assertEqual(package["analysis_id"], "analysis-1")
        self.assertEqual(package["alert"]["alert_id"], "alert-1")
        self.assertEqual(package["instructions"]["task"], "Investigate")
        self.assertNotIn("incident_response_evidence", package)
        self.assertEqual(
            package["reanalysis_context"],
            {"blind": False, "excluded_context": []},
        )

    def test_blind_reanalysis_declares_exact_excluded_context(self):
        package = assemble_prompt_package(view(blind_reanalysis=True))

        self.assertEqual(
            package["reanalysis_context"],
            {"blind": True, "excluded_context": list(BLIND_EXCLUDED_CONTEXT)},
        )

    def test_incident_responder_fails_closed_without_restricted_evidence(self):
        with self.assertRaisesRegex(
            RuntimeError,
            "requires validated restricted Security Onion evidence",
        ):
            assemble_prompt_package(view(agent_role="incident-responder"))

    def test_incident_responder_attaches_validated_evidence_projection(self):
        evidence = {"schema": "fixture", "security_onion_response": {}}

        package = assemble_prompt_package(
            view(agent_role="incident-responder", incident_evidence=evidence)
        )

        self.assertIs(package["incident_response_evidence"], evidence)


if __name__ == "__main__":
    unittest.main()
