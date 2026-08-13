"""Characterize advisory tuning evidence-gap signal collection."""
from __future__ import annotations

import copy
import unittest

from n8n.onion_sentinel.analysis.conclusions import tuning


class TrackingDict(dict):
    def __init__(self, *args: object, trace: list[object], label: str, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self.trace = trace
        self.label = label

    def get(self, key: object, default: object = None) -> object:
        self.trace.append(("get", self.label, key, default))
        return super().get(key, default)


def dependencies(trace: list[object], truthy: set[object] | None = None) -> tuning.Dependencies:
    truthy = truthy or set()

    def bounded(value: object, **kwargs: object) -> list[str]:
        trace.append(("bounded", value, kwargs))
        return ["present"] if any(value == item for item in truthy) else []

    return tuning.Dependencies(
        bounded_text_list=bounded,
        has_authorization_evidence=lambda _package: False,
        control_tuning_values=frozenset({"suppress", "drop"}),
    )


class TuningEvidenceGapSignalTests(unittest.TestCase):
    def test_signal_and_access_order_with_report_short_circuit_are_exact(self) -> None:
        trace: list[object] = []
        response = TrackingDict(
            {
                "evidence_gaps": "top-gap",
                "incident_response_report": TrackingDict(
                    {
                        "evidence_gaps": "report-gap",
                        "constraints": "unreached-constraints",
                    },
                    trace=trace,
                    label="report",
                ),
                "_incident_evidence_completeness": TrackingDict(
                    {"complete_for_high_confidence": False, "limiters": "unreached"},
                    trace=trace,
                    label="completeness",
                ),
                "_evidence_reference_validation": TrackingDict(
                    {"invalid_refs": ["bad"]}, trace=trace, label="references"
                ),
                "_verdict_validation": TrackingDict(
                    {"material_contradiction": "yes"}, trace=trace, label="verdict"
                ),
            },
            trace=trace,
            label="response",
        )

        result = tuning.material_evidence_gap_signals(
            response,
            dependencies(trace, {"top-gap", "report-gap"}),
        )

        self.assertEqual(result, [
            "reported_evidence_gaps",
            "incident_report_evidence_gaps",
            "incident_evidence_incomplete",
            "invalid_evidence_references",
            "material_evidence_contradiction",
        ])
        self.assertEqual(trace, [
            ("get", "response", "evidence_gaps", None),
            ("bounded", "top-gap", {"limit": 1}),
            ("get", "response", "incident_response_report", None),
            ("get", "report", "evidence_gaps", None),
            ("bounded", "report-gap", {"limit": 1}),
            ("get", "response", "_incident_evidence_completeness", None),
            ("get", "completeness", "complete_for_high_confidence", None),
            ("get", "response", "_evidence_reference_validation", None),
            ("get", "references", "invalid_refs", None),
            ("get", "response", "_verdict_validation", None),
            ("get", "verdict", "material_contradiction", None),
        ])

    def test_false_identity_and_fallback_branches_are_preserved(self) -> None:
        trace: list[object] = []
        report = TrackingDict(
            {"evidence_gaps": "", "constraints": "constraint"},
            trace=trace,
            label="report",
        )
        completeness = TrackingDict(
            {"complete_for_high_confidence": 0, "limiters": ["limited"]},
            trace=trace,
            label="completeness",
        )
        response = TrackingDict(
            {
                "incident_response_report": report,
                "_incident_evidence_completeness": completeness,
                "_evidence_reference_validation": [],
                "_verdict_validation": "invalid",
            },
            trace=trace,
            label="response",
        )
        self.assertEqual(
            tuning.material_evidence_gap_signals(
                response, dependencies(trace, {"constraint"})
            ),
            ["incident_report_evidence_gaps", "incident_evidence_incomplete"],
        )
        self.assertIn(("get", "completeness", "limiters", None), trace)

    def test_callback_and_mapping_exceptions_propagate(self) -> None:
        def explode(_value: object, **_kwargs: object) -> list[str]:
            raise LookupError("bounded evidence failed")

        deps = tuning.Dependencies(
            bounded_text_list=explode,
            has_authorization_evidence=lambda _package: False,
            control_tuning_values=frozenset(),
        )
        with self.assertRaisesRegex(LookupError, "bounded evidence failed"):
            tuning.material_evidence_gap_signals({"evidence_gaps": []}, deps)

        class ExplodingResponse(dict):
            def get(self, key: object, default: object = None) -> object:
                raise RuntimeError("response get failed")

        with self.assertRaisesRegex(RuntimeError, "response get failed"):
            tuning.material_evidence_gap_signals(ExplodingResponse(), deps)

    def test_input_is_not_mutated(self) -> None:
        response = {
            "evidence_gaps": ["gap"],
            "incident_response_report": {"constraints": ["constraint"]},
            "_incident_evidence_completeness": {"limiters": ["limit"]},
            "_evidence_reference_validation": {"invalid_refs": ["ref"]},
            "_verdict_validation": {"material_contradiction": True},
        }
        snapshot = copy.deepcopy(response)
        tuning.material_evidence_gap_signals(
            response, dependencies([], {tuple(response["evidence_gaps"])})
        )
        self.assertEqual(response, snapshot)


if __name__ == "__main__":
    unittest.main()
