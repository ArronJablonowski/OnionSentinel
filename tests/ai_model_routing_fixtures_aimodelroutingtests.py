from __future__ import annotations

from ai_model_routing_fixtures import (
    BIN_DIR,
    ExitStack,
    PIPELINE_ADAPTERS,
    Path,
    REPO_ROOT,
    RUNNER_PATH,
    ThreadPoolExecutor,
    build_agent_memory_context_contract,
    copy,
    hashlib,
    importlib,
    io,
    json,
    load_runner,
    mock,
    sys,
    tempfile,
    unittest,
)

class AiModelRoutingTestsFixtures(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.runner = load_runner()


    def complete_response(self, **overrides):
        response = {
            **self.runner.DEFAULT_RESPONSE_VALUES,
            "bluf": "Inconclusive: synthetic evidence requires review.",
            "summary": "Synthetic complete response.",
            "likely_meaning": "Synthetic activity.",
            "severity_reasoning": "Synthetic severity rationale.",
            "alert_frequency_assessment": "One synthetic observation.",
            "evidence_used": ["alert.synthetic:E1", "alert.synthetic:E2"],
            "evidence_gaps": [],
            "confidence": "medium",
            "confidence_score": 0.65,
            "detection_outcome": "inconclusive",
            "escalation_needed": False,
            "tuning_recommendation": "needs_more_data",
            "tuning_reason": "Synthetic fixture requires more data.",
        }
        response.update(overrides)
        return response


    def complete_incident_report(self, **overrides):
        report = {
            "executive_bluf": "Synthetic fact-grounded incident bottom line.",
            "detection_outcome_reasoning": "Synthetic factored-verdict reasoning.",
            "scope": "Synthetic bounded incident scope.",
            "affected_systems": ["host-a supported by synthetic evidence"],
            "constraints": [],
            "methodology": ["Reviewed the supplied synthetic evidence."],
            "factual_timeline": [
                {
                    "timestamp": "2026-07-24T12:00:00-06:00",
                    "event": "Synthetic event observed.",
                    "source_pack": "alert_context",
                    "query_digest": "a" * 64,
                    "confidence": "high",
                },
            ],
            "security_onion_findings": ["Synthetic Security Onion finding."],
            "osquery_findings": ["No endpoint OSQuery evidence supplied."],
            "pcap_findings": ["Synthetic PCAP finding."],
            "host_findings": ["No host telemetry supplied."],
            "correlation_findings": ["No supported correlation."],
            "containment_recommendations": ["Preserve evidence."],
            "eradication_recommendations": ["Defer pending confirmation."],
            "recovery_recommendations": ["Defer pending confirmation."],
            "follow_up_queries": ["Collect the missing discriminator."],
            "evidence_gaps": ["No endpoint telemetry supplied."],
            "conclusion": "Synthetic fact-grounded conclusion.",
            "confidence": "high",
            "confidence_score": 0.9,
        }
        report.update(overrides)
        return report


    def complete_incident_prompt(self, **overrides):
        prompt = {
            "agent_role": "incident-responder",
            "incident_response_evidence": {
                "coverage_note": "Complete synthetic alert firing window.",
                "security_onion_response": {
                    "complete": True,
                    "partial": False,
                    "semantic_validity": {
                        "controls_valid": True,
                        "semantic_valid": True,
                    },
                    "results": [],
                },
            },
        }
        prompt.update(overrides)
        return prompt


    def trusted_endpoint_executable_prompt(self):
        return {
            "investigation_query_results": {
                "rounds": [
                    {
                        "results": [
                            {
                                "backend": "security_onion",
                                "status": "ok",
                                "read_only": True,
                                "evidence": {
                                    "controls_valid": True,
                                    "complete": True,
                                    "partial": False,
                                    "results": [
                                        {
                                            "query_id": (
                                                "deterministic-osquery-history-attribution"
                                            ),
                                            "pack": "osquery_history",
                                            "status": "ok",
                                            "semantic_valid": True,
                                            "truncated": False,
                                            "hits": [
                                                {
                                                    "_source": {
                                                        "process": {
                                                            "name": (
                                                                "Microsoft Update Assistant"
                                                            ),
                                                            "executable": (
                                                                "/Applications/Microsoft "
                                                                "Update Assistant"
                                                            ),
                                                        }
                                                    }
                                                }
                                            ],
                                        }
                                    ],
                                },
                            }
                        ]
                    }
                ]
            }
        }


    def canonical_authorization_prompt(self, **overrides):
        alert = {
            "alert_id": "synthetic-authorized-alert",
            "timestamp": "2026-07-24T18:30:00Z",
            "first_seen": "2026-07-24T18:30:00Z",
            "last_seen": "2026-07-24T18:30:00Z",
            "source_ip": "192.0.2.10",
            "source_port": 49152,
            "destination_ip": "198.51.100.20",
            "destination_port": 443,
            "rule_id": "2100001",
            "transport_protocol": "tcp",
        }
        alert.update(overrides.pop("alert", {}))
        coverage = {
            "source_ips": [alert["source_ip"]],
            "destination_ips": [alert["destination_ip"]],
            "rule_ids": [alert["rule_id"]],
            "source_ports": [alert["source_port"]],
            "destination_ports": [alert["destination_port"]],
            "destination_port_ranges": [],
            "transport_protocols": [alert["transport_protocol"]],
            "authorization_start": "2026-07-24T18:00:00Z",
            "authorization_end": "2026-07-24T19:00:00Z",
        }
        coverage.update(overrides.pop("coverage", {}))
        digest = hashlib.sha256(
            json.dumps(
                {"coverage": coverage},
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        entry = {
            "authorized": True,
            "source": "operator_assertion",
            "evidence_ref": f"authorized-activity:sha256:{digest}",
            "coverage": coverage,
        }
        entry.update(overrides.pop("entry", {}))
        prompt = {
            "alert": alert,
            "authorization_evidence": {
                "status": "operator_authorized",
                "entries": [entry],
            },
        }
        prompt.update(overrides)
        return prompt
