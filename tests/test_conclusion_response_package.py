from __future__ import annotations

import unittest

from n8n.onion_sentinel.analysis.conclusions import response


class ConclusionResponsePackageTests(unittest.TestCase):
    def setUp(self) -> None:
        required = frozenset({
            "detection_outcome", "bluf", "summary", "likely_meaning",
            "severity_reasoning", "alert_frequency_assessment", "tuning_reason",
            "confidence", "tuning_recommendation", "escalation_needed",
            "hosted_second_opinion_recommended", "correlation_assessment",
            "memory_candidates", "evidence_gaps",
        })
        self.policy = response.Policy(
            required_keys=required,
            strict_required_keys=frozenset({"event_status", "hypotheses"}),
            default_values={
                **{key: "default" for key in required},
                "detection_outcome": "invented outcome",
                "confidence": "invented confidence",
                "tuning_recommendation": "invented tuning",
                "escalation_needed": False,
                "hosted_second_opinion_recommended": False,
                "correlation_assessment": {},
                "memory_candidates": [],
                "evidence_gaps": [],
            },
            strict_default_values={"event_status": "unknown", "hypotheses": []},
            list_keys=frozenset({"evidence_gaps"}),
            confidence_values=frozenset({"low", "medium", "high"}),
            tuning_values=frozenset({"none", "needs_more_data"}),
            detection_outcome_values=frozenset({"inconclusive"}),
            legacy_detection_outcomes=frozenset({"authorized_benign"}),
        )
        self.order = []
        guards = tuple(self._stage(name) for name in ("guard-a", "guard-b"))
        self.dependencies = response.Dependencies(
            boolean_setting=lambda value: bool(value),
            coerce_list=lambda value: list(value) if isinstance(value, list) else [],
            normalize_correlation=lambda value: dict(value or {}),
            normalize_memory=lambda value: list(value or []),
            normalize_hypotheses=lambda value: list(value or []),
            is_incident_responder=lambda package: bool(
                isinstance(package, dict) and package.get("agent_role") == "incident-responder"
            ),
            validate_report_shape=lambda value: {
                "valid": isinstance(value, dict) and bool(value),
                "missing_fields": [] if value else ["timeline"],
                "model_report_present": isinstance(value, dict),
            },
            normalize_report=lambda value: {
                **dict(value or {}), "confidence_score": 0.9,
            },
            normalize_factored=self._stage("factored"),
            guards=guards,
            normalize_scope=self._stage("scope"),
            calibrate_confidence=lambda value: self._record("confidence", value),
            reconcile_report=self._stage("report"),
        )

    def _stage(self, name):
        def apply(value, _package=None):
            self.order.append(name)
            return value
        return apply

    def _record(self, name, value):
        self.order.append(name)
        return value

    def test_safe_repair_strips_tool_protocol_and_preserves_guard_order(self) -> None:
        result = response.normalize(
            {
                "investigation_query_requests": [{"query": "must disappear"}],
                "pcap_query_requests": [{}],
                "live_osquery_requests": [{}],
            },
            None,
            policy=self.policy,
            dependencies=self.dependencies,
        )

        self.assertNotIn("investigation_query_requests", result)
        self.assertNotIn("pcap_query_requests", result)
        self.assertNotIn("live_osquery_requests", result)
        self.assertEqual(result["confidence"], "low")
        self.assertEqual(result["tuning_recommendation"], "needs_more_data")
        self.assertEqual(result["_invalid_detection_outcome"], "invented outcome")
        self.assertIn("bluf", result["_schema_repair"]["missing_keys"])
        self.assertEqual(
            self.order,
            ["factored", "guard-a", "guard-b", "scope", "confidence", "report"],
        )
        self.assertEqual(result["final_disposition_status"], "primary_unreviewed")

    def test_incident_report_repair_and_soc_projection_remain_distinct(self) -> None:
        incident = response.normalize(
            {},
            {"agent_role": "incident-responder"},
            policy=self.policy,
            dependencies=self.dependencies,
        )
        self.assertFalse(incident["_incident_response_report_validation"]["valid"])
        self.assertIn(
            "incident_response_report.timeline",
            incident["_schema_repair"]["missing_keys"],
        )
        self.assertIn(
            "incident_response_report", incident["_schema_repair"]["missing_keys"]
        )

        self.order.clear()
        soc = response.normalize(
            {"incident_response_report": {"summary": "unsolicited"}},
            {"agent_role": "soc-analyst"},
            policy=self.policy,
            dependencies=self.dependencies,
        )
        self.assertNotIn("confidence_score", soc["incident_response_report"])


if __name__ == "__main__":
    unittest.main()
