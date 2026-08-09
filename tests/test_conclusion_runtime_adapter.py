#!/usr/bin/env python3
"""Characterization tests for conclusion runtime binding."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
N8N_ROOT = ROOT / "n8n"
if str(N8N_ROOT) not in sys.path:
    sys.path.insert(0, str(N8N_ROOT))

from onion_sentinel.analysis.conclusions import runtime_adapter


class ConclusionRuntimeAdapterTests(unittest.TestCase):
    def test_hypotheses_remain_structured_bounded_and_closed_vocab(self) -> None:
        values = [{
            "id": "candidate with spaces",
            "statement": "s" * 2500,
            "status": "invented",
            "supporting_evidence": ["e" * 600] * 25,
            "contradicting_evidence": ["c"],
            "next_discriminator": "n" * 1200,
        }] + [{
            "id": f"h-{index}", "statement": "bounded", "status": "supported",
        } for index in range(25)]
        result = runtime_adapter.normalize_hypotheses(values)
        self.assertEqual(len(result), 20)
        self.assertEqual(result[0]["id"], "candidate-with-spaces")
        self.assertEqual(result[0]["status"], "unresolved")
        self.assertEqual(len(result[0]["statement"]), 2000)
        self.assertEqual(len(result[0]["supporting_evidence"]), 20)
        self.assertEqual(len(result[0]["supporting_evidence"][0]), 500)
        self.assertEqual(len(result[0]["next_discriminator"]), 1000)

    def test_endpoint_gap_reconciliation_is_narrow_and_audited(self) -> None:
        bindings = {
            "_trusted_endpoint_evidence_fields": lambda _package: {
                "process.executable"
            },
            "_remove_supplied_executable_path_gap": (
                runtime_adapter.remove_supplied_executable_path_gap
            ),
        }
        response = {
            "evidence_gaps": [
                "process.executable path missing",
                "process.executable paths, parent process is unknown",
                "unrelated network gap",
                {"structured": "preserved"},
            ],
            "incident_response_report": {
                "constraints": ["Executable path not provided"]
            },
        }
        result = runtime_adapter.reconcile_endpoint_gaps(
            bindings, response, {"case": "one"}
        )
        self.assertEqual(result["evidence_gaps"], [
            "parent process is unknown",
            "unrelated network gap",
            {"structured": "preserved"},
        ])
        self.assertEqual(result["incident_response_report"]["constraints"], [])
        self.assertEqual(
            result["_endpoint_evidence_gap_reconciliation"],
            {
                "schema": "onion-sentinel-endpoint-evidence-gap-reconciliation-v1",
                "executable_path_supplied": True,
                "rewritten_gap_count": 1,
                "removed_gap_count": 2,
            },
        )

    def test_factored_verdict_uses_live_closed_vocab_and_boolean_port(self) -> None:
        verdict = mock.Mock()
        verdict.normalize.side_effect = lambda response, **kwargs: kwargs
        boolean = mock.Mock()
        bindings = {
            "_conclusion_verdict": lambda: verdict,
            "DETECTION_OUTCOME_VALUES": {"true_positive_malicious"},
            "EVENT_STATUS_VALUES": {"observed"},
            "DETECTION_VALIDITY_VALUES": {"valid"},
            "ACTIVITY_DISPOSITION_VALUES": {"malicious"},
            "HANDLING_VALUES": {"escalate"},
            "FACTORED_VERDICT_KEYS": ("event_status", "handling"),
            "boolean_setting": boolean,
        }
        ports = runtime_adapter.normalize_verdict(bindings, {"case": "one"})
        self.assertEqual(ports["outcome_values"], {"true_positive_malicious"})
        self.assertEqual(ports["handling_values"], {"escalate"})
        self.assertEqual(ports["factored_keys"], ("event_status", "handling"))
        self.assertIs(ports["boolean_setting"], boolean)

    def test_confidence_and_authorization_guards_resolve_live_dependencies(
        self,
    ) -> None:
        confidence = mock.Mock()
        confidence.calibrate.side_effect = lambda _response, **kwargs: kwargs
        normalize_outcome = mock.Mock()
        label = mock.Mock()
        bindings = {
            "_conclusion_confidence": lambda: confidence,
            "CONFIDENCE_VALUES": {"low", "medium", "high"},
            "CONFIDENCE_SCORE_BY_LABEL": {"low": 0.2, "high": 0.9},
            "CONFIDENCE_CALIBRATION_VERSION": "v1",
            "DECISION_CRITICAL_KEYS": {"handling"},
            "CONSEQUENTIAL_CLOSURE_OUTCOMES": {"authorized_benign"},
            "normalized_detection_outcome": normalize_outcome,
            "confidence_label_for_score": label,
        }
        ports = runtime_adapter.calibrate_confidence(bindings, {})
        self.assertIs(ports["outcome_normalizer"], normalize_outcome)
        self.assertIs(ports["label_for_score"], label)

        authorization = mock.Mock()
        dependencies = object()
        authorization.apply_policy_sensitive.return_value = {"guard": "policy"}
        bindings = {
            "_conclusion_authorization": lambda: authorization,
            "_authorization_guard_dependencies": lambda: dependencies,
        }
        result = runtime_adapter.authorization_guard(
            bindings, {}, {}, policy_sensitive=True
        )
        self.assertEqual(result, {"guard": "policy"})
        authorization.apply_policy_sensitive.assert_called_once_with(
            {}, {}, dependencies
        )
        authorization.apply_authorized_benign.assert_not_called()


if __name__ == "__main__":
    unittest.main()
