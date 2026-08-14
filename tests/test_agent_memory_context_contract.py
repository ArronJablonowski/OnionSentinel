#!/usr/bin/env python3
"""Contracts for versioned, case-isolated agent-memory manifests."""
from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))

from agent_memory_context_contract import (  # noqa: E402
    MEMORY_CONTEXT_CONTRACT_SCHEMA,
    attach_agent_memory_context_contract,
)


def package(case_id: str = "investigation-case-a") -> dict:
    return {
        "package_type": "soc-ai-investigation-prompt",
        "agent_role": "soc-analyst",
        "group_id": "group-a",
        "alert": {"alert_id": "alert-a", "message": "bounded fixture"},
        "grouped_alert_context": {"group_id": "group-a", "raw_alert_rows": 1},
        "analyst_state": {"group_id": "group-a", "status": "open"},
        "prior_analyses": [{
            "analysis_id": "analysis-prior-a",
            "summary": "Prior bounded conclusion.",
            "evidence_used": ["alert:alert-a"],
            "evidence_gaps": ["Endpoint process lineage unavailable."],
            "confidence": "medium",
            "confidence_score": 0.61,
            "hypotheses": [{
                "id": "hypothesis-a",
                "status": "unresolved",
                "supporting_evidence": ["alert:alert-a"],
                "contradicting_evidence": ["query:absence-a"],
                "next_discriminator": "Collect endpoint process lineage.",
            }],
        }],
        "correlated_alert_context": {"candidates": []},
        "_local_investigation_query_context": {"case_id": case_id},
        "evidence_reference_contract": {
            "schema": "onion-sentinel-evidence-reference-contract-v1",
            "refs": ["alert:alert-a", "query:absence-a"],
        },
        "agent_memory": {
            "role_memory": {
                "agent_role": "soc-analyst",
                "records": [{"id": "role-a", "version": 2}],
                "snapshot": {
                    "schema": "onion-sentinel-agent-memory-snapshot-v1",
                    "source_digest": "a" * 64,
                    "selected_records_digest": "b" * 64,
                    "selected_record_versions": [{"id": "role-a", "version": 2}],
                    "source_bytes": 410,
                    "selected_records_bytes": 120,
                    "manual_notes_bytes": 20,
                },
            },
            "shared_memory": {
                "agent_role": "shared",
                "records": [{"id": "shared-a", "version": 4}],
                "snapshot": {
                    "schema": "onion-sentinel-agent-memory-snapshot-v1",
                    "source_digest": "c" * 64,
                    "selected_records_digest": "d" * 64,
                    "selected_record_versions": [{"id": "shared-a", "version": 4}],
                    "source_bytes": 520,
                    "selected_records_bytes": 130,
                    "manual_notes_bytes": 0,
                },
            },
        },
    }


class AgentMemoryContextContractTests(unittest.TestCase):
    def test_contract_separates_and_digests_all_four_memory_layers(self) -> None:
        prompt = package()

        result = attach_agent_memory_context_contract(
            prompt,
            evaluation_frozen=True,
        )

        self.assertIs(result, prompt)
        contract = prompt["memory_context_contract"]
        self.assertEqual(contract["schema"], MEMORY_CONTEXT_CONTRACT_SCHEMA)
        self.assertEqual(contract["case_id"], "investigation-case-a")
        self.assertEqual(contract["agent_role"], "soc-analyst")
        self.assertTrue(contract["evaluation_frozen"])
        self.assertEqual(
            list(contract["layers"]),
            [
                "immutable_evidence",
                "case_local_working_memory",
                "durable_analyst_memory",
                "shared_cross_agent_knowledge",
            ],
        )
        self.assertEqual(
            contract["layers"]["durable_analyst_memory"]["source_digest"],
            "a" * 64,
        )
        self.assertEqual(
            contract["layers"]["shared_cross_agent_knowledge"]["source_digest"],
            "c" * 64,
        )
        self.assertEqual(len(contract["contract_digest"]), 64)
        self.assertEqual(
            contract["summary_requirements"],
            ["citations", "uncertainty", "contradictions", "telemetry_gaps"],
        )

    def test_contract_is_idempotent_and_case_identity_changes_its_digest(self) -> None:
        first = package("investigation-case-a")
        second = package("investigation-case-b")

        attach_agent_memory_context_contract(first, evaluation_frozen=False)
        original = copy.deepcopy(first["memory_context_contract"])
        attach_agent_memory_context_contract(first, evaluation_frozen=False)
        attach_agent_memory_context_contract(second, evaluation_frozen=False)

        self.assertEqual(first["memory_context_contract"], original)
        self.assertNotEqual(
            first["memory_context_contract"]["contract_digest"],
            second["memory_context_contract"]["contract_digest"],
        )
        self.assertNotEqual(
            first["memory_context_contract"]["layers"]["case_local_working_memory"]["manifest_digest"],
            second["memory_context_contract"]["layers"]["case_local_working_memory"]["manifest_digest"],
        )

    def test_contract_is_provider_neutral_and_contains_no_memory_content(self) -> None:
        prompt = package()
        attach_agent_memory_context_contract(prompt, evaluation_frozen=True)
        contract = prompt["memory_context_contract"]

        self.assertEqual(contract["provider_contract"], "provider-neutral")
        encoded = str(contract)
        self.assertNotIn("Prior bounded conclusion", encoded)
        self.assertNotIn("Endpoint process lineage unavailable", encoded)
        self.assertNotIn("bounded fixture", encoded)
        self.assertNotIn("path", encoded.lower())

    def test_missing_case_or_snapshot_identity_fails_closed(self) -> None:
        missing_case = package()
        missing_case["_local_investigation_query_context"].pop("case_id")
        with self.assertRaisesRegex(ValueError, "case identity"):
            attach_agent_memory_context_contract(
                missing_case,
                evaluation_frozen=False,
            )

        missing_snapshot = package()
        missing_snapshot["agent_memory"]["shared_memory"].pop("snapshot")
        with self.assertRaisesRegex(ValueError, "shared.*snapshot"):
            attach_agent_memory_context_contract(
                missing_snapshot,
                evaluation_frozen=False,
            )

        unsupported_snapshot = package()
        unsupported_snapshot["agent_memory"]["role_memory"]["snapshot"][
            "schema"
        ] = "onion-sentinel-agent-memory-snapshot-v0"
        with self.assertRaisesRegex(ValueError, "snapshot schema is unsupported"):
            attach_agent_memory_context_contract(
                unsupported_snapshot,
                evaluation_frozen=False,
            )


if __name__ == "__main__":
    unittest.main()
