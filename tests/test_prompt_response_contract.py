#!/usr/bin/env python3
"""Direct contracts for model-visible instructions and response schema."""
from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))

from prompt_response_contract import (  # noqa: E402
    INCIDENT_GROUNDING,
    PromptContractRequest,
    build_prompt_contract,
)


def request(**changes):
    values = {
        "agent_role": "soc-analyst",
        "blind_reanalysis": False,
        "role_prompt": "Fixture analyst role",
        "task": "Fixture investigation task",
        "query_packs": ("alert_context", "network_flow"),
        "query_v2": False,
    }
    values.update(changes)
    return PromptContractRequest(**values)


class PromptResponseContractTests(unittest.TestCase):
    def test_contract_binds_role_task_and_query_capability_schema(self):
        contract = build_prompt_contract(request())

        self.assertEqual(contract["instructions"]["role"], "Fixture analyst role")
        self.assertEqual(contract["instructions"]["task"], "Fixture investigation task")
        parameters = contract["response_schema"]["investigation_query_requests"][0][
            "parameters"
        ]
        self.assertEqual(
            parameters["pack"],
            "for elastic/oql: alert_context|network_flow",
        )
        self.assertNotIn("|anchor_nearest", parameters["aggregation"])

    def test_v2_schema_advertises_anchor_nearest_without_other_drift(self):
        v1 = build_prompt_contract(request())
        v2 = build_prompt_contract(request(query_v2=True))
        v1_parameters = v1["response_schema"]["investigation_query_requests"][0][
            "parameters"
        ]
        v2_parameters = v2["response_schema"]["investigation_query_requests"][0][
            "parameters"
        ]

        self.assertIn("|anchor_nearest", v2_parameters["aggregation"])
        v1_parameters["aggregation"] = v2_parameters["aggregation"]
        self.assertEqual(v1, v2)

    def test_blind_reanalysis_replaces_only_prior_model_context_guidance(self):
        normal = build_prompt_contract(request())
        blind = build_prompt_contract(request(blind_reanalysis=True))
        differences = [
            (left, right)
            for left, right in zip(
                normal["instructions"]["grounding"],
                blind["instructions"]["grounding"],
            )
            if left != right
        ]

        self.assertEqual(len(differences), 1)
        self.assertIn("prior_analyses", differences[0][0])
        self.assertIn("blind reanalysis", differences[0][1].lower())

    def test_incident_responder_adds_restricted_evidence_contract(self):
        contract = build_prompt_contract(request(agent_role="incident-responder"))

        self.assertEqual(
            contract["instructions"]["grounding"][-len(INCIDENT_GROUNDING):],
            INCIDENT_GROUNDING,
        )
        report = contract["response_schema"]["incident_response_report"]
        self.assertIn("factual_timeline", report)
        self.assertIn("security_onion_findings", report)
        self.assertIn("osquery_findings", report)
        self.assertIn("evidence_gaps", report)

    def test_contract_instances_do_not_share_mutable_state(self):
        first = build_prompt_contract(request(agent_role="incident-responder"))
        second = build_prompt_contract(request(agent_role="incident-responder"))
        first["instructions"]["grounding"].append("mutation")
        first["response_schema"]["incident_response_report"]["scope"] = "mutation"

        self.assertNotIn("mutation", second["instructions"]["grounding"])
        self.assertNotEqual(
            second["response_schema"]["incident_response_report"]["scope"],
            "mutation",
        )


if __name__ == "__main__":
    unittest.main()
