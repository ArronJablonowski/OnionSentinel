#!/usr/bin/env python3
"""Regression coverage for query transport isolation and durable audit notes."""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
BIN_DIR = REPO_ROOT / "n8n" / "bin"


def load_module(name: str, path: Path):
    if str(BIN_DIR) not in sys.path:
        sys.path.insert(0, str(BIN_DIR))
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class InvestigationQueryTransportAndMarkdownTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.runner = load_module(
            "investigation_query_transport_markdown_runner",
            BIN_DIR / "run-local-ai-analysis.py",
        )
        cls.builder = load_module(
            "investigation_query_transport_markdown_builder",
            BIN_DIR / "build-ai-investigation-prompt.py",
        )
        cls.contract = sys.modules["investigation_query_contract"]

    @staticmethod
    def authorization_context() -> dict:
        return {
            "context_id": "context-transport-test",
            "case_id": "case-transport-test",
            "group_id": "group-transport-test",
            "actor_role": "incident_responder",
            "anchor": {
                "index": ".ds-logs-suricata.alerts-so-2026.07.24-000001",
                "id": "alert-transport-test",
            },
            "anchor_time": "2026-07-24T18:30:00.000Z",
            "time_envelope": {
                "start": "2026-07-24T17:00:00.000Z",
                "end": "2026-07-24T20:00:00.000Z",
            },
            "permitted_observables": {
                "ips": ["192.0.2.10"],
                "domains": [],
                "hosts": [],
                "users": [],
            },
            "discovered_observables": [],
            "permitted_event_tuples": [],
            "permitted_enrichment_indicators": {
                "hash": ["deadbeef"],
            },
            "local_private_runtime_state": "must-not-cross-broker-boundary",
        }

    @staticmethod
    def elastic_request() -> dict:
        return {
            "query_id": "transport-pivot",
            "backend": "elastic",
            "purpose": "correlate_observable",
            "parameters": {
                "pack": "network_flow",
                "window": {
                    "start": "2026-07-24T18:00:00Z",
                    "end": "2026-07-24T19:00:00Z",
                },
                "observables": {
                    "ips": ["192.0.2.10"],
                    "domains": [],
                    "hosts": [],
                    "users": [],
                },
                "size": 25,
                "aggregation": "events",
            },
        }

    def normalized_elastic_request(self) -> dict:
        context = self.authorization_context()
        return self.runner.normalize_investigation_query_request(
            self.elastic_request(),
            round_number=1,
            position=1,
            time_envelope=context["time_envelope"],
            authorization_context=context,
        )

    def test_security_onion_receives_only_exact_contract_context(self) -> None:
        context = self.authorization_context()
        security = mock.Mock(return_value={
            "complete": True,
            "partial": False,
            "model_evidence": {},
            "query_audit": [],
            "audit": {},
        })

        result = self.runner.execute_investigation_query_batch(
            {"_local_investigation_query_context": context},
            [self.normalized_elastic_request()],
            round_number=1,
            security_onion_executor=security,
        )

        self.assertEqual(result["results"][0]["status"], "ok")
        security.assert_called_once()
        transported = security.call_args.args[1]
        self.assertEqual(
            set(transported),
            set(self.contract.AUTHORIZATION_CONTEXT_ALLOWED_KEYS),
        )
        self.assertNotIn("permitted_enrichment_indicators", transported)
        self.assertNotIn("local_private_runtime_state", transported)
        self.assertEqual(
            context["permitted_enrichment_indicators"],
            {"hash": ["deadbeef"]},
        )

    def test_missing_required_security_context_rejects_without_dispatch(self) -> None:
        context = self.authorization_context()
        context.pop("anchor_time")
        security = mock.Mock()

        result = self.runner.execute_investigation_query_batch(
            {"_local_investigation_query_context": context},
            [self.normalized_elastic_request()],
            round_number=1,
            security_onion_executor=security,
        )

        security.assert_not_called()
        self.assertEqual(result["results"][0]["status"], "rejected")
        self.assertIn(
            "authorization context is invalid",
            result["results"][0]["error"],
        )
        self.assertIn("anchor_time", result["results"][0]["error"])

    def test_enrichment_keeps_local_only_indicator_authorization(self) -> None:
        context = self.authorization_context()
        request = self.runner.normalize_investigation_query_request(
            {
                "query_id": "hash-enrichment",
                "backend": "enrichment",
                "purpose": "Check a supplied file hash.",
                "parameters": {
                    "indicator_type": "hash",
                    "indicator": "deadbeef",
                },
            },
            round_number=1,
            position=1,
            authorization_context=context,
        )
        enrichment = mock.Mock(return_value={
            "schema": "onion-sentinel-investigation-enrichment-evidence-v1",
            "status": "ok",
            "indicator_type": "hash",
            "indicator": "deadbeef",
            "query_digest": "1" * 64,
            "result_digest": "2" * 64,
            "evidence_ref": "enrichment:test",
        })

        result = self.runner.execute_investigation_query_batch(
            {"_local_investigation_query_context": context},
            [request],
            round_number=1,
            enrichment_executor=enrichment,
            enrichment_config={"enabled": True},
        )

        enrichment.assert_called_once()
        self.assertEqual(result["results"][0]["status"], "ok")

    def test_pcap_relevance_scope_is_local_only_and_exact_record_survives(self) -> None:
        request_epoch = 1785627574.978117
        exact = {
            "timestamp_epoch": request_epoch,
            "source_ip": "10.77.7.222",
            "source_port": 58567,
            "destination_ip": "10.77.7.1",
            "destination_port": 53,
            "transport": "udp",
            "query": "exact.example",
        }
        decoys = [
            {
                **exact,
                "source_port": 40000 + index,
                "query": f"decoy-{index}.example",
            }
            for index in range(40)
        ]
        compact = self.builder.compact_pcap_analysis({
            "request": {
                "first_seen": request_epoch,
                "last_seen": request_epoch,
                "source_ip": "10.77.7.222",
                "source_port": 58567,
                "destination_ip": "10.77.7.1",
                "destination_port": 53,
                "transport_protocol": "udp",
                "max_window_seconds": 120,
            },
            "zeek": {"_local_query_index": {"dns": [*decoys, exact]}},
        })
        package = {
            "pcap_evidence": {"parsed_evidence": [compact]},
            "prior_analyses": [
                {"id": index, "content": "x" * 1000}
                for index in range(100)
            ],
        }

        compacted, _encoded = self.builder.compact_package_to_budget(
            package,
            50_000,
        )
        retained = compacted["pcap_evidence"]["parsed_evidence"][0]
        self.assertEqual(retained["_local_query_index"]["dns"][0], exact)
        self.assertIn("_local_request_scope", retained)

        transported = self.runner.model_safe_copy(compacted)
        transported_evidence = transported["pcap_evidence"][
            "parsed_evidence"
        ][0]
        self.assertNotIn("_local_request_scope", transported_evidence)
        self.assertNotIn("_local_query_index", transported_evidence)

    @staticmethod
    def query_audit() -> dict:
        return {
            "query_contract": "onion-sentinel-investigation-pivots-v2",
            "provider_neutral": True,
            "model_route": "codex-cli:gpt-5.5:high",
            "rounds_completed": 1,
            "queries_admitted": 3,
            "requests_ignored_or_over_budget": 0,
            "read_only": True,
            "all_tool_call_bindings_read_only": True,
            "complete": True,
            "rounds": [{
                "round": 1,
                "requests": [{
                    "purpose": "UNTRUSTED_MODEL_REQUEST_MUST_NOT_RENDER",
                }],
                "results": [{
                    "error": "UNTRUSTED_RESULT_MUST_NOT_RENDER",
                }],
                "trusted_queries": [
                    {
                        "query_id": "elastic-1",
                        "backend": "elastic",
                        "pack": "network_flow",
                        "purpose": "Establish the trusted flow timeline.",
                        "status": "ok",
                        "window": {
                            "start": "2026-07-24T18:00:00Z",
                            "end": "2026-07-24T19:00:00Z",
                        },
                        "query_digest": "a" * 64,
                        "result_digest": "b" * 64,
                        "evidence_ref": "security-onion:elastic-1",
                        "total_hits": 4,
                        "returned_hits": 4,
                        "oql_equivalent": "source.ip:192.0.2.10",
                        "kql_equivalent": "source.ip : 192.0.2.10",
                        "query_dsl": {
                            "query": {"term": {"source.ip": "192.0.2.10"}},
                        },
                    },
                    {
                        "query_id": "osquery-1",
                        "backend": "osquery",
                        "target_alias": "endpoint-a",
                        "purpose": (
                            "Inspect the trusted endpoint.\n"
                            "## FORGED_HEADING [click](https://evil.example) "
                            "<script>alert(1)</script>"
                        ),
                        "status": "ok",
                        "query_digest": "c" * 64,
                        "result_digest": "d" * 64,
                        "total_rows": 1,
                        "returned_rows": 1,
                        "query": (
                            "SELECT hostname FROM system_info "
                            "WHERE hostname = '```' LIMIT 1;"
                        ),
                    },
                    {
                        "query_id": "pcap-1",
                        "backend": "pcap_zeek",
                        "operation": "dns",
                        "purpose": "Inspect derived DNS evidence.",
                        "status": "ok",
                        "query_digest": "e" * 64,
                        "result_digest": "f" * 64,
                        "candidate_records_scanned": 8,
                        "records_returned": 2,
                        "filters": {"query": "example.test"},
                        "indicator": "example.test",
                        "limit": 10,
                    },
                ],
            }],
        }

    def test_markdown_renders_only_trusted_iterative_query_records(self) -> None:
        markdown = "\n".join(
            self.runner.render_investigation_query_audit_markdown({
                "_investigation_query_audit": self.query_audit(),
            })
        )

        self.assertIn("## Interactive Investigation Query Audit", markdown)
        self.assertIn("source.ip:192.0.2.10", markdown)
        self.assertIn("source.ip : 192.0.2.10", markdown)
        self.assertIn('"term": {', markdown)
        self.assertIn("````sql", markdown)
        self.assertIn("WHERE hostname = '```' LIMIT 1;", markdown)
        self.assertNotIn("\n## FORGED_HEADING", markdown)
        self.assertNotIn("[click](https://evil.example)", markdown)
        self.assertNotIn("<script>", markdown)
        self.assertIn("&lt;script&gt;alert\\(1\\)&lt;/script&gt;", markdown)
        self.assertIn("PCAP/Zeek request (exact structured request)", markdown)
        self.assertIn('"operation": "dns"', markdown)
        self.assertIn("total hits=4; returned hits=4", markdown)
        self.assertNotIn("UNTRUSTED_MODEL_REQUEST_MUST_NOT_RENDER", markdown)
        self.assertNotIn("UNTRUSTED_RESULT_MUST_NOT_RENDER", markdown)

    def test_render_markdown_includes_iterative_query_audit(self) -> None:
        response = self.runner.validate_response({
            "detection_outcome": "inconclusive",
            "bluf": "Inconclusive - Needs More Data: Synthetic fixture.",
            "summary": "Synthetic fixture.",
            "likely_meaning": "Synthetic fixture.",
            "severity_reasoning": "Synthetic fixture.",
            "alert_frequency_assessment": "Synthetic fixture.",
            "public_enrichment_findings": [],
            "pcap_analysis_findings": [],
            "false_positive_possibilities": [],
            "recommended_next_steps": [],
            "evidence_used": [],
            "evidence_gaps": [],
            "confidence": "low",
            "escalation_needed": False,
            "hosted_second_opinion_recommended": False,
            "tuning_recommendation": "needs_more_data",
            "tuning_reason": "Synthetic fixture.",
            "recommended_tuning_actions": [],
        })
        response["_investigation_query_audit"] = self.query_audit()

        markdown = self.runner.render_markdown(
            {
                "alert": {
                    "alert_id": "alert-transport-test",
                    "rule_name": "Synthetic alert",
                    "triage_level": "medium",
                },
                "analysis_policy": {},
            },
            response,
            "2026-07-24T20:00:00Z",
            Path("analysis.json"),
        )

        self.assertIn("## Interactive Investigation Query Audit", markdown)
        self.assertIn("````sql", markdown)
        self.assertIn("WHERE hostname = '```' LIMIT 1;", markdown)
        self.assertNotIn("UNTRUSTED_MODEL_REQUEST_MUST_NOT_RENDER", markdown)

    def test_existing_live_osquery_audit_uses_safe_fence_and_metadata(self) -> None:
        markdown = "\n".join(
            self.runner.render_incident_live_osquery_audit_markdown({
                "_incident_live_osquery_audit": {
                    "trusted_source": "collector\n## FORGED_SOURCE",
                    "queries": [{
                        "target_alias": "endpoint-a",
                        "purpose": "Review\n## FORGED_PURPOSE [x](https://evil.example)",
                        "status": "error",
                        "query_digest": "a" * 64,
                        "query": (
                            "SELECT hostname FROM system_info "
                            "WHERE hostname = '```' LIMIT 1;"
                        ),
                        "error": "failed\n<div>FORGED_HTML</div>",
                    }],
                },
            })
        )

        self.assertIn("````sql", markdown)
        self.assertIn("WHERE hostname = '```' LIMIT 1;", markdown)
        self.assertNotIn("\n## FORGED_SOURCE", markdown)
        self.assertNotIn("\n## FORGED_PURPOSE", markdown)
        self.assertNotIn("[x](https://evil.example)", markdown)
        self.assertNotIn("<div>", markdown)
        self.assertIn("&lt;div&gt;FORGED\\_HTML&lt;/div&gt;", markdown)


if __name__ == "__main__":
    unittest.main()
