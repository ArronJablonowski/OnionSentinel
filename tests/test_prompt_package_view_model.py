#!/usr/bin/env python3
"""Direct contracts for final prompt-package assembly."""
from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))

from prompt_package_view_model import (  # noqa: E402
    BLIND_EXCLUDED_CONTEXT,
    PromptPackageView,
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
