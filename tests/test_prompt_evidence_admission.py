#!/usr/bin/env python3
"""Direct contracts for governed prompt evidence admission."""
from __future__ import annotations

from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))

from prompt_evidence_admission import (  # noqa: E402
    PromptEvidenceAdmissionRequest,
    PromptEvidenceAdmissionSources,
    blind_model_authored_context,
    permitted_enrichment_indicators,
    prepare_prompt_evidence_admission,
)


def request(**changes) -> PromptEvidenceAdmissionRequest:
    values = {
        "selected": {"alert_id": "alert-1"},
        "agent_role": "incident-responder",
        "group_id": "group-1",
        "exact_validation_rows": [{"exact": 1}],
        "pcap_context": {"parsed_evidence": [{"packet": 1}]},
        "enrichment_context": {
            "indicators": {
                "public_ips": ["192.0.2.10"],
                "domains": ["example.test"],
                "urls": ["https://example.test/path"],
                "hashes": [{"value": "abc"}, "def"],
                "cves": ["CVE-2026-1000"],
            }
        },
        "ac_hunter_context": {"status": "fresh"},
        "compact_alert": {"compact": 1},
        "grouped_alert_context": {"group": 1},
        "detection_validation": {"intent": "match"},
        "asset_context": {"asset": 1},
        "authorization_evidence": {"authorized": False},
        "analyst_state": {"state": 1},
        "correlation_context": {"candidates": []},
        "role_memory_file": Path("/fixture/role-memory.md"),
        "shared_memory_file": Path("/fixture/shared-memory.md"),
        "memory_bytes": 4096,
        "blind_reanalysis": False,
        "incident_evidence_file": None,
        "maximum_incident_evidence_bytes": 8192,
    }
    values.update(changes)
    return PromptEvidenceAdmissionRequest(**values)


def sources(**changes) -> PromptEvidenceAdmissionSources:
    values = {
        "investigation_query_context": mock.Mock(
            return_value=({"capability": 1}, {"context_id": "context-1"})
        ),
        "build_agent_memory_context": mock.Mock(return_value={"memory": 1}),
        "blind_model_authored_context": mock.Mock(
            return_value=({"blind_memory": 1}, {"blind_correlation": 1})
        ),
        "load_json_bounded": mock.Mock(return_value={"incident": 1}),
        "validate_incident_evidence": mock.Mock(),
        "reject_preprojected_incident_evidence": mock.Mock(),
        "project_incident_evidence_hits": mock.Mock(),
    }
    values.update(changes)
    return PromptEvidenceAdmissionSources(**values)


class PromptEvidenceAdmissionTests(unittest.TestCase):
    def test_admits_exact_query_context_enrichment_and_memory_evidence(self):
        dependencies = sources()
        prepared = prepare_prompt_evidence_admission(dependencies, request())

        dependencies.investigation_query_context.assert_called_once_with(
            {"alert_id": "alert-1"},
            [{"exact": 1}],
            "group-1",
            "incident-responder",
            True,
        )
        self.assertEqual(
            prepared.local_investigation_query_context[
                "permitted_enrichment_indicators"
            ],
            {
                "ip": ["192.0.2.10"],
                "domain": ["example.test"],
                "url": ["https://example.test/path"],
                "hash": ["abc", "def"],
                "cve": ["CVE-2026-1000"],
            },
        )
        memory_call = dependencies.build_agent_memory_context.call_args
        self.assertEqual(memory_call.kwargs["agent_role"], "incident-responder")
        self.assertEqual(memory_call.kwargs["limit_bytes"], 4096)
        self.assertEqual(
            memory_call.kwargs["evidence"]["detection_validation"],
            {"intent": "match"},
        )
        self.assertEqual(prepared.memory_context, {"memory": 1})
        self.assertEqual(prepared.correlation_context, {"candidates": []})
        self.assertIsNone(prepared.incident_evidence)
        dependencies.blind_model_authored_context.assert_not_called()

    def test_blind_reanalysis_filters_memory_and_correlation_after_loading(self):
        dependencies = sources()

        prepared = prepare_prompt_evidence_admission(
            dependencies,
            request(blind_reanalysis=True),
        )

        dependencies.blind_model_authored_context.assert_called_once_with(
            {"memory": 1},
            {"candidates": []},
        )
        self.assertEqual(prepared.memory_context, {"blind_memory": 1})
        self.assertEqual(prepared.correlation_context, {"blind_correlation": 1})

    def test_incident_evidence_is_validated_before_and_after_projection(self):
        events: list[str] = []
        evidence = {"incident": 1}
        dependencies = sources(
            load_json_bounded=mock.Mock(
                side_effect=lambda path, limit: events.append("load") or evidence
            ),
            validate_incident_evidence=mock.Mock(
                side_effect=lambda value: events.append("validate")
            ),
            reject_preprojected_incident_evidence=mock.Mock(
                side_effect=lambda value: events.append("reject")
            ),
            project_incident_evidence_hits=mock.Mock(
                side_effect=lambda value, **kwargs: events.append("project")
            ),
        )

        prepared = prepare_prompt_evidence_admission(
            dependencies,
            request(incident_evidence_file=Path("/fixture/incident.json")),
        )

        self.assertEqual(events, ["load", "validate", "reject", "project", "validate"])
        dependencies.load_json_bounded.assert_called_once_with(
            Path("/fixture/incident.json"),
            8192,
        )
        dependencies.project_incident_evidence_hits.assert_called_once_with(
            evidence,
            limit=20,
            reason="initial_prompt_projection",
        )
        self.assertIs(prepared.incident_evidence, evidence)

    def test_blind_filter_keeps_only_operator_confirmed_model_memory(self):
        memory = {
            "role_memory": {
                "records": [
                    {"status": "operator-confirmed", "value": "keep"},
                    {"status": "model-observed", "value": "remove"},
                ]
            },
            "shared_memory": {"records": ["malformed"]},
        }
        correlation = {
            "candidates": [
                {
                    "prior_analysis": {"verdict": "malicious"},
                    "previous_correlation": {"score": 1},
                    "correlation_reasons": [
                        "same source",
                        "previous correlation record exists",
                    ],
                }
            ]
        }

        filtered_memory, filtered_correlation = blind_model_authored_context(
            memory,
            correlation,
        )

        self.assertEqual(
            filtered_memory["role_memory"]["records"],
            [{"status": "operator-confirmed", "value": "keep"}],
        )
        self.assertEqual(filtered_memory["shared_memory"]["records"], [])
        candidate = filtered_correlation["candidates"][0]
        self.assertNotIn("prior_analysis", candidate)
        self.assertNotIn("previous_correlation", candidate)
        self.assertEqual(candidate["correlation_reasons"], ["same source"])
        self.assertEqual(len(memory["role_memory"]["records"]), 2)
        self.assertIn("prior_analysis", correlation["candidates"][0])

    def test_blind_filter_rebinds_the_exact_selected_memory_snapshot(self):
        memory = {
            "role_memory": {
                "records": [
                    {"id": "keep", "version": 3, "status": "operator-confirmed"},
                    {"id": "remove", "version": 7, "status": "model-observed"},
                ],
                "snapshot": {
                    "source_digest": "a" * 64,
                    "selected_records_digest": "b" * 64,
                    "selected_record_versions": [
                        {"id": "keep", "version": 3},
                        {"id": "remove", "version": 7},
                    ],
                },
            },
            "shared_memory": {"records": []},
        }

        filtered, _ = blind_model_authored_context(memory, {})

        snapshot = filtered["role_memory"]["snapshot"]
        self.assertEqual(
            snapshot["selected_record_versions"],
            [{"id": "keep", "version": 3}],
        )
        self.assertNotEqual(snapshot["selected_records_digest"], "b" * 64)
        self.assertTrue(snapshot["selection_filtered"])
        self.assertEqual(
            memory["role_memory"]["snapshot"]["selected_record_versions"],
            [
                {"id": "keep", "version": 3},
                {"id": "remove", "version": 7},
            ],
        )

    def test_malformed_indicator_container_fails_closed(self):
        with self.assertRaises(AttributeError):
            permitted_enrichment_indicators({"indicators": None})


if __name__ == "__main__":
    unittest.main()
