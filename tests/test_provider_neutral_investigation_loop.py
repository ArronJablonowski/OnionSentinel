#!/usr/bin/env python3
"""Focused contracts for the provider-neutral investigation pivot loop."""
from __future__ import annotations

import copy
import importlib.util
import json
import sys
import tempfile
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


class RecordingHarness:
    """Minimal harness double that makes call ordering observable."""

    class _Policy:
        def __init__(self, mode: str) -> None:
            self.mode = mode

    class _Decision:
        def __init__(self, allowed: bool, backend: str) -> None:
            self.allowed = allowed
            self.capability = f"query.{backend}"
            self.reason = "test policy decision"

    def __init__(
        self,
        events: list[tuple],
        *,
        mode: str = "enforce",
        tool_allowed: bool = True,
        fail_authorization: bool = False,
    ) -> None:
        self.events = events
        self.policy = self._Policy(mode)
        self.tool_allowed = tool_allowed
        self.fail_authorization = fail_authorization

    def phase(self, phase: str, route: str = "", reason: str = "") -> None:
        self.events.append(("phase", phase, route, reason))

    def authorize_tool(
        self,
        *,
        round_number: int,
        query_id: str,
        backend: str,
    ) -> _Decision:
        self.events.append(
            ("authorize_tool", round_number, query_id, backend)
        )
        if self.fail_authorization:
            raise RuntimeError("synthetic shadow observation failure")
        return self._Decision(self.tool_allowed, backend)

    def preflight_query_batch(
        self,
        *,
        round_number: int,
        request_count: int,
    ) -> None:
        self.events.append(
            ("preflight_query_batch", round_number, request_count)
        )

    def query_round(self, round_result: dict) -> None:
        self.events.append(("query_round", round_result.get("round")))

    def catalogue_prompt_evidence(self, _prompt_package: dict) -> None:
        self.events.append(("catalogue_prompt_evidence",))

    def preflight_model_call(
        self,
        *,
        call_id: str,
        input_value: object,
        requested_route: str,
        purpose: str,
        independent_review: bool = False,
    ) -> None:
        self.events.append(
            (
                "preflight_model_call",
                call_id,
                independent_review,
                bool(input_value),
                requested_route,
                purpose,
            )
        )

    def model_call(
        self,
        *,
        call_id: str,
        independent_review: bool = False,
        **_kwargs,
    ) -> None:
        self.events.append(
            ("model_call", call_id, independent_review)
        )


class ProviderNeutralInvestigationLoopTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.runner = load_module(
            "provider_neutral_investigation_runner",
            BIN_DIR / "run-local-ai-analysis.py",
        )
        cls.builder = load_module(
            "provider_neutral_investigation_builder",
            BIN_DIR / "build-ai-investigation-prompt.py",
        )
        cls.contract = load_module(
            "provider_neutral_investigation_contract",
            BIN_DIR / "investigation_query_contract.py",
        )
        cls.harness = sys.modules["onion_sentinel_harness"]

    @staticmethod
    def elastic_request(query_id: str = "pivot-1") -> dict:
        return {
            "query_id": query_id,
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

    @staticmethod
    def successful_security_onion_round(
        requests: list[dict],
        *,
        round_number: int,
    ) -> dict:
        query_digest = "a" * 64
        result_digest = "b" * 64
        query_ids = [item["query_id"] for item in requests]
        return {
            "schema": "onion-sentinel-investigation-query-results-v1",
            "round": round_number,
            "requests": copy.deepcopy(requests),
            "results": [
                {
                    "backend": "security_onion",
                    "query_ids": query_ids,
                    "status": "ok",
                    "read_only": True,
                    "evidence": {
                        "controls_valid": True,
                        "results": [
                            {
                                "query_id": query_id,
                                "status": "ok",
                                "returned_hits": 1,
                            }
                            for query_id in query_ids
                        ],
                    },
                    "trusted_query_audit": [
                        {
                            "query_id": query_id,
                            "status": "ok",
                            "query_digest": query_digest,
                            "result_digest": result_digest,
                            "evidence_ref": f"query:{query_digest}",
                            "returned_hits": 1,
                        }
                        for query_id in query_ids
                    ],
                }
            ],
            "audit": [
                {
                    "backend": "security_onion",
                    "complete": True,
                    "partial": False,
                    "read_only": True,
                }
            ],
        }

    def test_hosted_transport_keeps_safe_query_protocol_and_strips_raw_packet_fields(self) -> None:
        package = {
            "response_schema": {
                "investigation_query_requests": [
                    {
                        "backend": "elastic|oql|osquery|pcap_zeek",
                        "parameters": {},
                    }
                ]
            },
            "investigation_query_results": {
                "rounds": [
                    {
                        "results": [
                            {
                                "backend": "pcap_zeek",
                                "evidence": {
                                    "connection_count": 2,
                                    "packet_samples": [{"raw_payload": "secret"}],
                                    "payload": "secret",
                                    "event": {
                                        "dataset": "zeek.conn",
                                        "original": "raw event",
                                    },
                                    "process": {
                                        "name": "safe-process",
                                        "command_line": "secret --token value",
                                        "args": ["secret"],
                                    },
                                    "url": {
                                        "domain": "safe.example",
                                        "query": "authorization=secret",
                                    },
                                    "uri": "/login?token=TOPSECRET",
                                    "referrer": "https://safe.example/?session=ABC",
                                    "user_agent": "secret-UA",
                                    "file": {
                                        "path": "/Users/alice/private/customer-list.csv"
                                    },
                                    "rows": [{
                                        "path": "/Users/alice/.ssh/id_rsa",
                                        "key": "PRIVATESECRET",
                                    }],
                                    "dns": {
                                        "question": {"name": "safe.example"}
                                    },
                                    "message": "raw message",
                                    "authorization": "Bearer secret",
                                    "cookie": "session=secret",
                                    "api_token": "secret",
                                    "cmdline": "secret command",
                                    "environment": "SECRET=value",
                                    "content": "secret content",
                                    "data": "secret data",
                                },
                            }
                        ]
                    }
                ]
            },
            "_local_investigation_query_context": {
                "anchor": {"index": "private", "id": "private"}
            },
        }

        hosted = self.runner.model_safe_copy(package, hosted=True)
        encoded = json.dumps(hosted)

        self.assertIn("investigation_query_requests", encoded)
        self.assertIn("investigation_query_results", encoded)
        self.assertIn("connection_count", encoded)
        self.assertNotIn("packet_samples", encoded)
        self.assertNotIn("raw_payload", encoded)
        self.assertNotIn('"payload"', encoded)
        self.assertNotIn("raw event", encoded)
        self.assertNotIn("secret --token", encoded)
        self.assertNotIn("authorization=secret", encoded)
        self.assertNotIn("raw message", encoded)
        self.assertNotIn("Bearer secret", encoded)
        self.assertNotIn("session=secret", encoded)
        self.assertNotIn("secret command", encoded)
        self.assertNotIn("SECRET=value", encoded)
        self.assertNotIn("TOPSECRET", encoded)
        self.assertNotIn("session=ABC", encoded)
        self.assertNotIn("secret-UA", encoded)
        self.assertNotIn("customer-list.csv", encoded)
        self.assertNotIn("PRIVATESECRET", encoded)
        self.assertIn("zeek.conn", encoded)
        self.assertIn("safe-process", encoded)
        self.assertIn("safe.example", encoded)
        self.assertNotIn("_local_investigation_query_context", encoded)

    def test_hosted_query_records_use_positive_projection_and_content_redaction(self) -> None:
        package = {
            "investigation_query_results": {
                "rounds": [{
                    "results": [
                        {
                            "backend": "pcap_zeek",
                            "evidence": {
                                "records": [{
                                    "source_ip": "192.0.2.10",
                                    "sni": "safe.example",
                                    "status_message": "Authorization: Bearer TOPSECRET",
                                    "additional": "password=TOPSECRET",
                                    "notice": "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
                                }]
                            },
                        },
                        {
                            "backend": "osquery",
                            "evidence": {
                                "rows": [{
                                    "pid": "42",
                                    "name": "safe-process",
                                    "username": "alice",
                                    "directory": "/Users/alice/private",
                                    "cwd": r"C:\Users\alice\private",
                                    "status": "token=TOPSECRET",
                                }]
                            },
                        },
                        {
                            "backend": "security_onion",
                            "evidence": {
                                "results": [{
                                    "hits": [{
                                        "id": "auth-hit",
                                        "index": "logs-system.auth-default",
                                        "source": {
                                            "@timestamp": "2026-07-24T18:30:00Z",
                                            "event": {
                                                "dataset": "system.auth",
                                                "outcome": "failure",
                                            },
                                            "source": {"ip": "192.0.2.55"},
                                            "user": {"name": "invalid-user"},
                                            "ssl": {
                                                "server_name": "safe-tls.example",
                                            },
                                            "message": "password=TOPSECRET",
                                        },
                                    }]
                                }]
                            },
                        },
                    ]
                }]
            }
        }

        encoded = json.dumps(
            self.runner.model_safe_copy(package, hosted=True)
        )

        self.assertIn("192.0.2.10", encoded)
        self.assertIn("safe.example", encoded)
        self.assertIn("safe-process", encoded)
        self.assertIn("system.auth", encoded)
        self.assertIn("192.0.2.55", encoded)
        self.assertIn("invalid-user", encoded)
        self.assertIn("safe-tls.example", encoded)
        self.assertNotIn("TOPSECRET", encoded)
        self.assertNotIn("QWxhZGRpb", encoded)
        self.assertNotIn("status_message", encoded)
        self.assertNotIn("additional", encoded)
        self.assertNotIn("notice", encoded)
        self.assertNotIn("username", encoded)
        self.assertNotIn("directory", encoded)
        self.assertNotIn('"cwd"', encoded)
        self.assertNotIn("/Users/alice", encoded)
        self.assertNotIn(r"C:\\Users\\alice", encoded)

    def test_normalizer_rejects_arbitrary_query_syntax_and_raw_packet_operation(self) -> None:
        with self.assertRaisesRegex(
            self.runner.InvestigationQueryError,
            "unsupported elastic parameters",
        ):
            self.runner.normalize_investigation_query_request(
                {
                    **self.elastic_request(),
                    "parameters": {
                        **self.elastic_request()["parameters"],
                        "query_dsl": {"match_all": {}},
                    },
                },
                round_number=1,
                position=1,
            )

        with self.assertRaisesRegex(
            self.runner.InvestigationQueryError,
            "unsupported derived-evidence operation",
        ):
            self.runner.normalize_investigation_query_request(
                {
                    "query_id": "raw-packet",
                    "backend": "pcap_zeek",
                    "purpose": "Retrieve packet bytes.",
                    "parameters": {"operation": "raw_packets", "limit": 1},
                },
                round_number=1,
                position=1,
            )

    def test_normalizer_preserves_bounded_role_aware_event_tuple(self) -> None:
        request = self.elastic_request("role-aware")
        request["parameters"]["observables"]["ips"].append("198.51.100.20")
        request["parameters"]["event_tuple"] = {
            "source_ip": "192.0.2.10",
            "destination_ip": "198.51.100.20",
            "source_port": "49152",
            "destination_port": 443,
            "transport": "TCP",
            "protocol": "TLS",
            "community_id": "1:trusted-flow=",
            "rule_id": "2016150",
        }

        normalized = self.runner.normalize_investigation_query_request(
            request,
            round_number=1,
            position=1,
        )

        self.assertEqual(normalized["parameters"]["event_tuple"], {
            "source_ip": "192.0.2.10",
            "destination_ip": "198.51.100.20",
            "source_port": 49152,
            "destination_port": 443,
            "transport": "tcp",
            "protocol": "tls",
            "community_id": "1:trusted-flow=",
            "rule_id": "2016150",
        })

        request["parameters"]["event_tuple"]["destination_port"] = 70000
        with self.assertRaisesRegex(
            self.runner.InvestigationQueryError,
            "port range",
        ):
            self.runner.normalize_investigation_query_request(
                request,
                round_number=1,
                position=1,
            )

    def test_normalizer_projects_union_parameters_to_selected_backend(self) -> None:
        request = self.elastic_request("project-union")
        request["parameters"].update(
            {
                "operation": "dns",
                "filters": {"query": "example.test"},
                "indicator": "example.test",
                "limit": 5,
                "target_alias": "endpoint-a",
                "query": "SELECT pid FROM processes LIMIT 1",
            }
        )

        normalized = self.runner.normalize_investigation_query_request(
            request,
            round_number=1,
            position=1,
        )

        self.assertEqual(
            set(normalized["parameters"]),
            {"pack", "window", "observables", "size", "aggregation"},
        )
        self.assertEqual(
            normalized["normalization"]["dropped_cross_backend_parameters"],
            [
                "filters",
                "indicator",
                "limit",
                "operation",
                "query",
                "target_alias",
            ],
        )

    def test_normalizer_projects_union_parameters_to_derived_backend(self) -> None:
        request = {
            "query_id": "project-derived-union",
            "backend": "pcap_zeek",
            "purpose": "Confirm the capture-derived DNS records for the host.",
            "parameters": {
                "operation": "dns",
                "filters": {"query": "example.test"},
                "indicator": "example.test",
                "limit": 5,
                "pack": "dns_activity",
                "window": {
                    "start": "2026-07-24T18:00:00Z",
                    "end": "2026-07-24T19:00:00Z",
                },
                "observables": {
                    "ips": ["192.0.2.10"],
                    "domains": ["example.test"],
                    "hosts": [],
                    "users": [],
                },
                "size": 25,
                "aggregation": "events",
                "target_alias": "endpoint-a",
                "query": "SELECT pid FROM processes LIMIT 1",
            },
        }

        normalized = self.runner.normalize_investigation_query_request(
            request,
            round_number=1,
            position=1,
        )

        self.assertEqual(
            normalized["parameters"],
            {
                "operation": "dns",
                "filters": {"query": "example.test"},
                "indicator": "example.test",
                "limit": 5,
            },
        )
        self.assertEqual(
            normalized["normalization"]["dropped_cross_backend_parameters"],
            [
                "aggregation",
                "observables",
                "pack",
                "query",
                "size",
                "target_alias",
                "window",
            ],
        )

    def test_historical_malformed_shapes_recover_safe_intent(self) -> None:
        """Three common malformed requests normalize; one unsafe request rejects."""
        elastic_union = self.elastic_request("elastic-union")
        elastic_union["parameters"].update(
            {
                "operation": "connections",
                "filters": {"source_ip": "192.0.2.10"},
                "indicator": "192.0.2.10",
                "limit": 10,
                "target_alias": "endpoint-a",
                "query": "SELECT pid FROM processes LIMIT 1",
            }
        )
        pcap_union = {
            "query_id": "pcap-union",
            "backend": "pcap_zeek",
            "purpose": "Inspect capture-derived connection evidence.",
            "parameters": {
                "operation": "connections",
                "filters": {"source_ip": "192.0.2.10"},
                "indicator": "192.0.2.10",
                "limit": 10,
                **self.elastic_request()["parameters"],
            },
        }
        long_window = self.elastic_request("long-window")
        long_window["parameters"]["window"] = {
            "start": "2026-07-23T18:30:00Z",
            "end": "2026-07-25T18:30:00Z",
        }
        no_observable = self.elastic_request("no-observable")
        no_observable["parameters"]["observables"] = {
            "ips": [],
            "domains": [],
            "hosts": [],
            "users": [],
        }
        envelope = {
            "start": "2026-07-23T18:30:00Z",
            "end": "2026-07-25T18:30:00Z",
        }

        recovered = []
        rejected = []
        for position, request in enumerate(
            [elastic_union, pcap_union, long_window, no_observable],
            1,
        ):
            try:
                recovered.append(
                    self.runner.normalize_investigation_query_request(
                        request,
                        round_number=1,
                        position=position,
                        time_envelope=envelope,
                    )
                )
            except self.runner.InvestigationQueryError as exc:
                rejected.append(str(exc))

        self.assertEqual(len(recovered), 3)
        self.assertEqual(len(rejected), 1)
        self.assertIn("at least one exact observable", rejected[0])

    def test_normalizer_clamps_long_window_nearest_alert_and_audits_gap(self) -> None:
        request = self.elastic_request("long-window")
        request["parameters"]["window"] = {
            "start": "2026-07-23T18:30:00Z",
            "end": "2026-07-25T18:30:00Z",
        }

        normalized = self.runner.normalize_investigation_query_request(
            request,
            round_number=1,
            position=1,
            time_envelope={
                "start": "2026-07-23T18:30:00Z",
                "end": "2026-07-25T18:30:00Z",
            },
        )

        self.assertEqual(
            normalized["parameters"]["window"],
            {
                "start": "2026-07-24T06:30:00.000Z",
                "end": "2026-07-25T06:30:00.000Z",
            },
        )
        adjustment = normalized["normalization"]["window_adjustment"]
        self.assertTrue(adjustment["adjusted"])
        self.assertIn("clamped_to_24_hours_nearest_alert", adjustment["reasons"])

    def test_security_preflight_isolates_one_invalid_observable(self) -> None:
        context = {
            "context_id": "context-test",
            "case_id": "investigation-test",
            "group_id": "group-test",
            "actor_role": "incident_responder",
            "anchor": {
                "index": ".ds-logs-suricata.alerts-so-2026.07.24-000001",
                "id": "alert-1",
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
        }
        valid = self.runner.normalize_investigation_query_request(
            self.elastic_request("valid"),
            round_number=1,
            position=1,
            time_envelope=context["time_envelope"],
        )
        invalid_raw = self.elastic_request("invalid")
        invalid_raw["parameters"]["observables"]["ips"] = ["203.0.113.99"]
        invalid = self.runner.normalize_investigation_query_request(
            invalid_raw,
            round_number=1,
            position=2,
            time_envelope=context["time_envelope"],
        )
        security = mock.Mock(
            return_value={
                "complete": True,
                "partial": False,
                "model_evidence": {
                    "results": [{"query_id": "valid", "status": "ok"}]
                },
                "query_audit": [
                    {
                        "query_id": "valid",
                        "dialect": "elastic",
                        "status": "ok",
                        "query_digest": "a" * 64,
                    }
                ],
                "audit": {},
            }
        )

        result = self.runner.execute_investigation_query_batch(
            {"_local_investigation_query_context": context},
            [valid, invalid],
            round_number=1,
            security_onion_executor=security,
        )

        security.assert_called_once()
        proposal = security.call_args.args[0]
        self.assertEqual(
            [item["query_id"] for item in proposal["queries"]],
            ["valid"],
        )
        rejected = next(
            item for item in result["results"]
            if item.get("query_id") == "invalid"
        )
        self.assertEqual(rejected["status"], "rejected")
        self.assertIn("isolated local authorization", rejected["error"])

    def test_security_batch_forwards_only_authorized_event_tuple(self) -> None:
        context = {
            "context_id": "context-role-aware",
            "case_id": "investigation-role-aware",
            "group_id": "group-role-aware",
            "actor_role": "incident_responder",
            "anchor": {
                "index": ".ds-logs-suricata.alerts-so-2026.07.24-000001",
                "id": "alert-1",
            },
            "anchor_time": "2026-07-24T18:30:00.000Z",
            "time_envelope": {
                "start": "2026-07-24T17:00:00.000Z",
                "end": "2026-07-24T20:00:00.000Z",
            },
            "permitted_observables": {
                "ips": ["192.0.2.10", "198.51.100.20"],
                "domains": [],
                "hosts": [],
                "users": [],
            },
            "discovered_observables": [],
            "permitted_event_tuples": [{
                "event_tuple": {
                    "source_ip": "192.0.2.10",
                    "destination_ip": "198.51.100.20",
                    "destination_port": 443,
                    "transport": "tcp",
                    "protocol": "tls",
                },
                "role_semantics": "packet_direction",
                "source": "trusted_context",
                "evidence_ref": "context:event-tuple:flow-1",
            }],
        }
        raw = self.elastic_request("role-aware")
        raw["parameters"]["pack"] = "alert_context"
        raw["parameters"]["observables"]["ips"].append("198.51.100.20")
        raw["parameters"]["event_tuple"] = {
            "source_ip": "192.0.2.10",
            "destination_ip": "198.51.100.20",
            "destination_port": 443,
            "transport": "tcp",
            "protocol": "tls",
        }
        request = self.runner.normalize_investigation_query_request(
            raw,
            round_number=1,
            position=1,
            time_envelope=context["time_envelope"],
        )
        security = mock.Mock(return_value={
            "complete": False,
            "partial": False,
            "model_evidence": {"results": []},
            "query_audit": [],
            "audit": {},
        })

        self.runner.execute_investigation_query_batch(
            {"_local_investigation_query_context": context},
            [request],
            round_number=1,
            security_onion_executor=security,
        )

        security.assert_called_once()
        self.assertEqual(
            security.call_args.args[0]["queries"][0]["event_tuple"],
            raw["parameters"]["event_tuple"],
        )

    def test_outcome_summary_counts_logical_queries_and_zero_success_gap(self) -> None:
        summary = self.runner.investigation_query_outcome_summary(
            [
                {
                    "requests": [],
                    "results": [
                        {
                            "backend": "security_onion",
                            "status": "ok",
                            "query_ids": ["a", "b"],
                        },
                        {"backend": "contract", "status": "rejected"},
                        {"backend": "elastic", "status": "error"},
                        {"backend": "pcap_zeek", "status": "partial"},
                    ],
                }
            ],
            queries_admitted=5,
        )
        self.assertEqual(summary["successful_queries"], 2)
        self.assertEqual(summary["rejected_queries"], 1)
        self.assertEqual(summary["error_queries"], 1)
        self.assertEqual(summary["partial_queries"], 1)
        self.assertFalse(summary["zero_success"])

        zero = self.runner.investigation_query_outcome_summary(
            [{"requests": [], "results": [{"status": "rejected"}]}],
            queries_admitted=1,
        )
        self.assertTrue(zero["zero_success"])
        response = {"incident_response_report": {"evidence_gaps": []}}
        self.runner._append_investigation_evidence_gaps(
            response,
            zero["evidence_gaps"],
        )
        self.assertIn(
            "no follow-up query evidence was collected",
            response["incident_response_report"]["evidence_gaps"][0],
        )

    def test_outcome_summary_counts_nested_partial_security_onion_batch(self) -> None:
        summary = self.runner.investigation_query_outcome_summary(
            [
                {
                    "requests": [],
                    "results": [
                        {
                            "backend": "security_onion",
                            "query_ids": ["successful-pivot", "failed-pivot"],
                            "status": "partial",
                            "evidence": {
                                "controls_valid": True,
                                "results": [
                                    {
                                        "query_id": "successful-pivot",
                                        "status": "ok",
                                        "semantic_valid": True,
                                    },
                                    {
                                        "query_id": "failed-pivot",
                                        "status": "error",
                                        "semantic_valid": False,
                                    },
                                ],
                            },
                        },
                    ],
                },
            ],
            queries_admitted=2,
        )

        self.assertEqual(summary["successful_queries"], 1)
        self.assertEqual(summary["error_queries"], 1)
        self.assertEqual(summary["partial_queries"], 0)
        self.assertFalse(summary["zero_success"])
        self.assertIn(
            "did not return complete successful evidence",
            summary["evidence_gaps"][0],
        )

    def test_mixed_batch_uses_injected_read_only_brokers(self) -> None:
        prompt_package = {
            "_local_investigation_query_context": {
                "case_id": "investigation-test",
                "anchor": {
                    "index": ".ds-logs-suricata.alerts-so-2026.07.24-000001",
                    "id": "alert-1",
                },
            },
            "pcap_evidence": {
                "parsed_evidence": [
                    {
                        "request_id": "pcap-test",
                        "group_id": "group-test",
                        "generated_at": "2026-07-24T18:30:00Z",
                        "pcap_files": [
                            {
                                "name": "synthetic.pcap",
                                "size_bytes": 64,
                                "sha256": "f" * 64,
                            }
                        ],
                    }
                ]
            },
            "alert": {"alert_id": "synthetic"},
        }
        requests = [
            self.runner.normalize_investigation_query_request(
                self.elastic_request(),
                round_number=1,
                position=1,
            ),
            self.runner.normalize_investigation_query_request(
                {
                    "query_id": "host-1",
                    "backend": "osquery",
                    "purpose": "Check the endpoint process inventory for the suspected binary.",
                    "parameters": {
                        "target_alias": "endpoint-a",
                        "query": "SELECT name, path FROM processes LIMIT 20",
                    },
                },
                round_number=1,
                position=2,
            ),
            self.runner.normalize_investigation_query_request(
                {
                    "query_id": "zeek-1",
                    "backend": "pcap_zeek",
                    "purpose": "Confirm the exact DNS answer associated with the connection.",
                    "parameters": {
                        "operation": "dns",
                        "filters": {"query": "example.test"},
                        "limit": 5,
                    },
                },
                round_number=1,
                position=3,
            ),
        ]
        security = mock.Mock(
            return_value={
                "complete": True,
                "partial": False,
                "model_evidence": {"results": [{"query_id": "pivot-1", "status": "ok"}]},
                "query_audit": [
                    {
                        "query_id": "pivot-1",
                        "dialect": "elastic",
                        "status": "ok",
                        "query_dsl": {"query": {"term": {"source.ip": "192.0.2.10"}}},
                        "query_digest": "b" * 64,
                        "returned_hits": 1,
                    }
                ],
                "audit": {
                    "query_contract": self.runner.INVESTIGATION_QUERY_CONTRACT,
                    "authorized_request_digest": "c" * 64,
                    "authorization_context_digest": "d" * 64,
                    "security_onion_response_digest": "e" * 64,
                },
            }
        )
        osquery = mock.Mock(
            return_value={
                "complete": True,
                "results": [
                    {
                        "status": "ok",
                        "target_alias": "endpoint-a",
                        "query_digest": "a" * 64,
                        "rows": [],
                    }
                ],
            }
        )
        derived_query = {
            "operation": "dns",
            "filters": {"query": "example.test"},
            "indicator": "",
            "limit": 5,
        }
        derived_query_digest = self.runner.hashlib.sha256(
            json.dumps(
                {
                    "contract": self.runner.PCAP_QUERY_CONTRACT,
                    "request": derived_query,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        empty_result_digest = self.runner.hashlib.sha256(b"[]").hexdigest()
        derived = mock.Mock(
            return_value={
                "schema": self.runner.PCAP_QUERY_CONTRACT,
                "executed": [derived_query],
                "results": [
                    {
                        "query": derived_query,
                        "query_digest": derived_query_digest,
                        "result_digest": empty_result_digest,
                        "evidence_ref": "legacy-ref",
                        "records": [],
                        "audit": {
                            "candidate_records_scanned": 0,
                            "unique_records_matched": 0,
                            "records_returned": 0,
                            "derived_views_considered": ["zeek.dns"],
                        },
                    }
                ],
            }
        )

        result = self.runner.execute_investigation_query_batch(
            prompt_package,
            requests,
            round_number=1,
            live_osquery_config={"enabled": True},
            security_onion_executor=security,
            osquery_executor=osquery,
            derived_executor=derived,
        )

        self.assertEqual(result["schema"], self.runner.INVESTIGATION_QUERY_RESULT_SCHEMA)
        self.assertEqual({item["backend"] for item in result["results"]}, {
            "security_onion",
            "osquery",
            "pcap_zeek",
        })
        security.assert_called_once()
        osquery.assert_called_once()
        derived.assert_called_once()
        self.assertEqual(
            derived.call_args.args[1][0]["filters"],
            {"query": "example.test"},
        )
        security_result = next(
            item for item in result["results"] if item["backend"] == "security_onion"
        )
        self.assertEqual(
            security_result["trusted_query_audit"][0]["query_digest"],
            "b" * 64,
        )
        self.assertEqual(security_result["status"], "ok")
        security_audit = next(
            item for item in result["audit"] if item["backend"] == "security_onion"
        )
        self.assertEqual(security_audit["authorized_request_digest"], "c" * 64)
        derived_result = next(
            item for item in result["results"] if item["backend"] == "pcap_zeek"
        )
        self.assertTrue(
            derived_result["evidence"]["evidence_ref"].startswith(
                "derived-pcap-zeek:"
            )
        )
        self.assertEqual(
            derived_result["trusted_query_audit"][0]["evidence_ref"],
            derived_result["evidence"]["evidence_ref"],
        )

    def test_derived_evidence_reference_is_bound_to_capture_identity(self) -> None:
        def context(digest: str) -> dict:
            return {
                "parsed_evidence": [
                    {
                        "request_id": "same-request",
                        "group_id": "same-group",
                        "generated_at": "2026-07-24T18:30:00Z",
                        "pcap_files": [
                            {
                                "name": "capture.pcap",
                                "size_bytes": 42,
                                "sha256": digest,
                            }
                        ],
                    }
                ]
            }

        first = self.runner._derived_evidence_source_digest(context("a" * 64))
        second = self.runner._derived_evidence_source_digest(context("b" * 64))

        self.assertNotEqual(first, second)

    def test_initial_model_preflight_precedes_model_execution(self) -> None:
        events: list[tuple] = []
        harness = RecordingHarness(events)

        def model_executor(*_args, **_kwargs):
            events.append(("initial_model_executor",))
            return {"summary": "Initial analysis completed."}

        settings = {
            "agent_models": {
                "soc-analyst": "codex-cli:gpt-5.6-sol:high",
            }
        }
        with mock.patch.object(
            self.runner,
            "analyze_model_route",
            side_effect=model_executor,
        ):
            response = self.runner.analyze_with_config(
                {"case_id": "case-preflight-order"},
                object(),
                settings=settings,
                harness_runtime=harness,
            )

        self.assertEqual(response["summary"], "Initial analysis completed.")
        preflight_position = next(
            index
            for index, event in enumerate(events)
            if event[:2] == ("preflight_model_call", "primary-initial")
        )
        execution_position = events.index(("initial_model_executor",))
        self.assertLess(preflight_position, execution_position)

    def test_evaluation_retry_collects_successful_read_only_pivot_and_binds_audit(
        self,
    ) -> None:
        events: list[tuple] = []
        harness = RecordingHarness(events, mode="shadow")
        route = "codex-cli:gpt-5.6-sol:high"
        prompt_package = {
            "case_id": "case-evaluation-retry",
            "investigation_query_capability": {
                "enabled": True,
                "backends": {"elastic": {"enabled": True}},
            },
            "_local_investigation_query_context": {
                "anchor": {
                    "index": ".ds-logs-suricata.alerts-so-2026.07.24-000001",
                    "id": "alert-evaluation-retry",
                },
            },
        }
        settings = {"agent_models": {"soc-analyst": route}}
        executed_round: dict[str, dict] = {}

        def model_executor(
            observed_route,
            package,
            _args,
            _settings,
        ):
            self.assertEqual(observed_route, route)
            if "investigation_follow_up" not in package:
                events.append(("model_executor", "query-planning", observed_route))
                retry = package["investigation_query_planning_retry"]
                self.assertEqual(retry["attempt"], 1)
                self.assertEqual(retry["maximum_attempts"], 1)
                return {
                    "investigation_query_requests": [self.elastic_request()],
                    "_analysis_model_route": route,
                }
            events.append(("model_executor", "evidence-synthesis", observed_route))
            return {
                "summary": "Final response after a dynamic pivot.",
                "_analysis_model_route": route,
            }

        def query_executor(
            _package,
            requests,
            *,
            round_number,
            live_osquery_config,
        ):
            self.assertIsNone(live_osquery_config)
            result = self.successful_security_onion_round(
                requests,
                round_number=round_number,
            )
            executed_round["value"] = result
            return result

        with mock.patch.dict(
            self.runner.os.environ,
            {self.runner.EVALUATION_FREEZE_MEMORY_ENV: "1"},
        ):
            response = self.runner.apply_investigation_query_loop(
                prompt_package,
                {
                    "summary": "Initial response omitted a pivot.",
                    "_analysis_model_route": route,
                },
                self.runner.argparse.Namespace(
                    max_prompt_bytes=self.runner.DEFAULT_MAX_PROMPT_BYTES,
                ),
                settings,
                "soc-analyst",
                harness_runtime=harness,
                model_executor=model_executor,
                query_executor=query_executor,
            )

        audit = response["_investigation_query_audit"]
        self.assertTrue(audit["planning_retry_attempted"])
        self.assertTrue(audit["planning_retry_produced_requests"])
        self.assertTrue(audit["query_planning_retry"]["attempted"])
        self.assertTrue(audit["read_only"])
        self.assertTrue(audit["all_tool_call_bindings_read_only"])
        self.assertTrue(audit["complete"])
        self.assertEqual(audit["successful_read_only_queries"], 1)
        self.assertTrue(audit["evaluation_requirement_satisfied"])
        self.assertTrue(
            audit["evaluation_query_guarantee"][
                "evaluation_requirement_satisfied"
            ]
        )
        self.assertEqual(len(audit["tool_call_bindings"]), 1)
        binding = audit["tool_call_bindings"][0]
        exact_round = executed_round["value"]
        self.assertEqual(
            binding["request_digest"],
            self.harness.digest_json(exact_round["requests"][0]),
        )
        self.assertEqual(
            binding["result_digest"],
            self.harness.digest_json(exact_round["results"][0]),
        )
        self.assertEqual(binding["call_id"], "round-1-pivot-1")
        self.assertEqual(binding["backend"], "elastic")
        self.assertEqual(binding["status"], "ok")
        self.assertIs(binding["read_only"], True)
        planning_preflight = next(
            index
            for index, event in enumerate(events)
            if event[:2]
            == ("preflight_model_call", "primary-query-planning-retry-1")
        )
        planning_execution = events.index(
            ("model_executor", "query-planning", route)
        )
        self.assertLess(planning_preflight, planning_execution)
        self.assertIn(
            ("model_call", "primary-query-planning-retry-1", False),
            events,
        )
        self.assertIn(("model_call", "primary-followup-1", False), events)

    def test_evaluation_retry_without_query_fails_before_pivot_or_persistence(
        self,
    ) -> None:
        events: list[tuple] = []
        harness = RecordingHarness(events, mode="shadow")
        route = "codex-cli:gpt-5.5:high"
        model_executor = mock.Mock(
            return_value={
                "summary": "Still no query request.",
                "_analysis_model_route": route,
            }
        )
        query_executor = mock.Mock()

        with (
            mock.patch.dict(
                self.runner.os.environ,
                {self.runner.EVALUATION_FREEZE_MEMORY_ENV: "1"},
            ),
            self.assertRaisesRegex(
                self.runner.InvestigationQueryError,
                "produced no investigation_query_requests",
            ),
        ):
            self.runner.apply_investigation_query_loop(
                {},
                {
                    "summary": "Initial response omitted a pivot.",
                    "_analysis_model_route": route,
                },
                self.runner.argparse.Namespace(
                    max_prompt_bytes=self.runner.DEFAULT_MAX_PROMPT_BYTES,
                ),
                {"agent_models": {"soc-analyst": route}},
                "soc-analyst",
                harness_runtime=harness,
                model_executor=model_executor,
                query_executor=query_executor,
            )

        model_executor.assert_called_once()
        query_executor.assert_not_called()
        self.assertIn(
            ("model_call", "primary-query-planning-retry-1", False),
            events,
        )

    def test_evaluation_fails_when_dynamic_pivot_is_not_successful_read_only(
        self,
    ) -> None:
        events: list[tuple] = []
        harness = RecordingHarness(events, mode="shadow")
        route = "codex-cli:gpt-5.5:high"

        def failed_query_round(
            _package,
            requests,
            *,
            round_number,
            live_osquery_config,
        ):
            self.assertIsNone(live_osquery_config)
            return {
                "schema": self.runner.INVESTIGATION_QUERY_RESULT_SCHEMA,
                "round": round_number,
                "requests": copy.deepcopy(requests),
                "results": [
                    {
                        "query_id": requests[0]["query_id"],
                        "backend": "elastic",
                        "status": "error",
                        "read_only": True,
                        "error": "synthetic broker failure",
                    }
                ],
                "audit": [],
            }

        with (
            mock.patch.dict(
                self.runner.os.environ,
                {self.runner.EVALUATION_FREEZE_MEMORY_ENV: "1"},
            ),
            self.assertRaisesRegex(
                self.runner.InvestigationQueryError,
                "at least one successful read-only dynamic pivot",
            ),
        ):
            self.runner.apply_investigation_query_loop(
                {
                    "investigation_query_capability": {
                        "enabled": True,
                        "backends": {"elastic": {"enabled": True}},
                    },
                    "_local_investigation_query_context": {
                        "anchor": {
                            "index": (
                                ".ds-logs-suricata.alerts-so-"
                                "2026.07.24-000001"
                            ),
                            "id": "alert-failed-evaluation-pivot",
                        },
                    },
                },
                {
                    "investigation_query_requests": [
                        self.elastic_request()
                    ],
                    "_analysis_model_route": route,
                },
                object(),
                {"agent_models": {"soc-analyst": route}},
                "soc-analyst",
                harness_runtime=harness,
                model_executor=mock.Mock(
                    return_value={
                        "summary": "No evidence was collected.",
                        "_analysis_model_route": route,
                    }
                ),
                query_executor=failed_query_round,
            )

        self.assertIn(("query_round", 1), events)

    def test_normal_shadow_and_no_harness_do_not_force_query_retry(self) -> None:
        route = "codex-cli:gpt-5.5:high"
        settings = {"agent_models": {"soc-analyst": route}}
        baseline = {
            "summary": "A normal shadow run may conclude without a pivot.",
            "_analysis_model_route": route,
        }
        model_executor = mock.Mock()
        shadow = RecordingHarness([], mode="shadow")

        without_freeze = self.runner.apply_investigation_query_loop(
            {},
            copy.deepcopy(baseline),
            object(),
            settings,
            "soc-analyst",
            harness_runtime=shadow,
            model_executor=model_executor,
        )
        with mock.patch.dict(
            self.runner.os.environ,
            {self.runner.EVALUATION_FREEZE_MEMORY_ENV: "1"},
        ):
            without_harness = self.runner.apply_investigation_query_loop(
                {},
                copy.deepcopy(baseline),
                object(),
                settings,
                "soc-analyst",
                model_executor=model_executor,
            )

        self.assertEqual(without_freeze, baseline)
        self.assertEqual(without_harness, baseline)
        model_executor.assert_not_called()

    def test_evaluation_query_planning_retry_enforces_prompt_and_route_bounds(
        self,
    ) -> None:
        route = "codex-cli:gpt-5.5:high"
        settings = {"agent_models": {"soc-analyst": route}}
        model_executor = mock.Mock()
        with (
            mock.patch.dict(
                self.runner.os.environ,
                {self.runner.EVALUATION_FREEZE_MEMORY_ENV: "1"},
            ),
            self.assertRaisesRegex(
                self.runner.InvestigationQueryError,
                "prompt exceeds max_prompt_bytes",
            ),
        ):
            self.runner.apply_investigation_query_loop(
                {"case_id": "case-prompt-bound"},
                {"summary": "no request", "_analysis_model_route": route},
                self.runner.argparse.Namespace(max_prompt_bytes=64),
                settings,
                "soc-analyst",
                harness_runtime=RecordingHarness([], mode="shadow"),
                model_executor=model_executor,
            )
        model_executor.assert_not_called()

        route_events: list[tuple] = []
        with (
            mock.patch.dict(
                self.runner.os.environ,
                {self.runner.EVALUATION_FREEZE_MEMORY_ENV: "1"},
            ),
            self.assertRaisesRegex(
                self.runner.InvestigationQueryError,
                "preserve the assigned model route",
            ),
        ):
            self.runner.apply_investigation_query_loop(
                {},
                {"summary": "no request", "_analysis_model_route": route},
                self.runner.argparse.Namespace(
                    max_prompt_bytes=self.runner.DEFAULT_MAX_PROMPT_BYTES,
                ),
                settings,
                "soc-analyst",
                harness_runtime=RecordingHarness(
                    route_events,
                    mode="shadow",
                ),
                model_executor=mock.Mock(
                    return_value={
                        "investigation_query_requests": [
                            self.elastic_request()
                        ],
                        "_analysis_model_route": (
                            "codex-cli:gpt-5.6-terra:high"
                        ),
                    }
                ),
                query_executor=mock.Mock(),
            )
        self.assertIn(
            ("model_call", "primary-query-planning-retry-1", False),
            route_events,
        )

    def test_evaluation_shadow_trace_failures_are_fail_closed(self) -> None:
        route = "codex-cli:gpt-5.5:high"
        settings = {"agent_models": {"soc-analyst": route}}
        initial_model_executor = mock.Mock()
        initial_harness = RecordingHarness([], mode="shadow")
        initial_harness.preflight_model_call = mock.Mock(
            side_effect=RuntimeError("synthetic initial trace failure")
        )
        with (
            mock.patch.dict(
                self.runner.os.environ,
                {self.runner.EVALUATION_FREEZE_MEMORY_ENV: "1"},
            ),
            mock.patch.object(
                self.runner,
                "analyze_model_route",
                initial_model_executor,
            ),
            self.assertRaisesRegex(
                RuntimeError,
                "synthetic initial trace failure",
            ),
        ):
            self.runner.analyze_with_config(
                {"case_id": "case-initial-trace-failure"},
                object(),
                settings=settings,
                harness_runtime=initial_harness,
            )
        initial_model_executor.assert_not_called()

        query_executor = mock.Mock()
        query_harness = RecordingHarness(
            [],
            mode="shadow",
            fail_authorization=True,
        )
        with (
            mock.patch.dict(
                self.runner.os.environ,
                {self.runner.EVALUATION_FREEZE_MEMORY_ENV: "1"},
            ),
            self.assertRaisesRegex(
                RuntimeError,
                "synthetic shadow observation failure",
            ),
        ):
            self.runner.apply_investigation_query_loop(
                {
                    "investigation_query_capability": {
                        "enabled": True,
                        "backends": {"elastic": {"enabled": True}},
                    },
                    "_local_investigation_query_context": {
                        "anchor": {
                            "index": (
                                ".ds-logs-suricata.alerts-so-"
                                "2026.07.24-000001"
                            ),
                            "id": "alert-query-trace-failure",
                        },
                    },
                },
                {
                    "investigation_query_requests": [
                        self.elastic_request()
                    ],
                    "_analysis_model_route": route,
                },
                object(),
                settings,
                "soc-analyst",
                harness_runtime=query_harness,
                model_executor=mock.Mock(),
                query_executor=query_executor,
            )
        query_executor.assert_not_called()

    def test_evaluation_audit_bindings_match_durable_harness_tool_rows(
        self,
    ) -> None:
        route = "codex-cli:gpt-5.5:high"
        prompt_package = {
            "case_id": "case-durable-query-binding",
            "alert": {
                "alert_id": (
                    ".ds-logs-suricata.alerts-so-2026.07.24-000001:"
                    "alert-durable-query-binding"
                ),
            },
            "investigation_query_capability": {
                "enabled": True,
                "backends": {"elastic": {"enabled": True}},
            },
            "_local_investigation_query_context": {
                "anchor": {
                    "index": ".ds-logs-suricata.alerts-so-2026.07.24-000001",
                    "id": "alert-durable-query-binding",
                },
            },
        }
        self.runner.attach_evidence_reference_contract(prompt_package)
        policy_value = json.loads(
            (
                REPO_ROOT
                / "n8n"
                / "config"
                / "investigation_harness_policy.json"
            ).read_text(encoding="utf-8")
        )
        policy_value["enabled"] = True
        policy_value["mode"] = "enforce"
        policy = self.harness.HarnessPolicy.from_dict(policy_value)
        model_call_count = 0

        def model_executor(
            observed_route,
            _package,
            _args,
            _settings,
        ):
            nonlocal model_call_count
            model_call_count += 1
            self.assertEqual(observed_route, route)
            if model_call_count == 1:
                return {
                    "investigation_query_requests": [self.elastic_request()],
                    "_analysis_model_route": route,
                }
            return {
                "summary": "Durably bound final response.",
                "_analysis_model_route": route,
            }

        with tempfile.TemporaryDirectory() as temp_name:
            runtime = self.harness.start_harness_run(
                run_id="run-durable-query-binding",
                prompt_package=prompt_package,
                role="soc-analyst",
                assigned_route=route,
                configuration={
                    "evaluation_memory_frozen": True,
                    "test": True,
                },
                policy=policy,
                db_path=Path(temp_name) / "harness.sqlite3",
            )
            self.assertIsNotNone(runtime)
            with mock.patch.dict(
                self.runner.os.environ,
                {self.runner.EVALUATION_FREEZE_MEMORY_ENV: "1"},
            ):
                response = self.runner.apply_investigation_query_loop(
                    prompt_package,
                    {
                        "summary": "Initial response omitted a pivot.",
                        "_analysis_model_route": route,
                    },
                    self.runner.argparse.Namespace(
                        max_prompt_bytes=self.runner.DEFAULT_MAX_PROMPT_BYTES,
                    ),
                    {"agent_models": {"soc-analyst": route}},
                    "soc-analyst",
                    harness_runtime=runtime,
                    model_executor=model_executor,
                    query_executor=lambda _package, requests, **kwargs: (
                        self.successful_security_onion_round(
                            requests,
                            round_number=kwargs["round_number"],
                        )
                    ),
                )
            trace = runtime.store.export_trace(runtime.run_id)

        binding = response["_investigation_query_audit"][
            "tool_call_bindings"
        ][0]
        tool_row = trace["tool_calls"][0]
        for key in (
            "call_id",
            "round_number",
            "backend",
            "status",
            "request_digest",
            "result_digest",
        ):
            self.assertEqual(binding[key], tool_row[key])
        self.assertIs(binding["read_only"], True)
        self.assertEqual(bool(tool_row["read_only"]), binding["read_only"])

    def test_query_authorization_and_batch_preflight_precede_executor(
        self,
    ) -> None:
        events: list[tuple] = []
        harness = RecordingHarness(events)
        prompt_package = {
            "investigation_query_capability": {
                "enabled": True,
                "backends": {"elastic": {"enabled": True}},
            },
            "_local_investigation_query_context": {
                "anchor": {
                    "index": ".ds-logs-suricata.alerts-so-2026.07.24-000001",
                    "id": "alert-order",
                },
            },
        }

        def query_executor(
            _package,
            requests,
            *,
            round_number,
            live_osquery_config,
        ):
            self.assertIsNone(live_osquery_config)
            events.append(("query_executor", round_number))
            return {
                "schema": self.runner.INVESTIGATION_QUERY_RESULT_SCHEMA,
                "round": round_number,
                "requests": requests,
                "results": [
                    {
                        "query_id": requests[0]["query_id"],
                        "backend": "elastic",
                        "status": "ok",
                        "read_only": True,
                        "query_digest": "a" * 64,
                        "result_digest": "b" * 64,
                        "returned_hits": 1,
                    }
                ],
                "audit": [],
            }

        response = self.runner.apply_investigation_query_loop(
            prompt_package,
            {"investigation_query_requests": [self.elastic_request()]},
            object(),
            {"agent_models": {"soc-analyst": "codex-cli:gpt-5.5:medium"}},
            "soc-analyst",
            harness_runtime=harness,
            model_executor=mock.Mock(return_value={"summary": "done"}),
            query_executor=query_executor,
        )

        self.assertEqual(response["summary"], "done")
        authorization_position = next(
            index
            for index, event in enumerate(events)
            if event[0] == "authorize_tool"
        )
        preflight_position = next(
            index
            for index, event in enumerate(events)
            if event[0] == "preflight_query_batch"
        )
        execution_position = events.index(("query_executor", 1))
        self.assertLess(authorization_position, preflight_position)
        self.assertLess(preflight_position, execution_position)

    def test_enforce_tool_denial_prevents_query_execution(self) -> None:
        events: list[tuple] = []
        harness = RecordingHarness(
            events,
            mode="enforce",
            tool_allowed=False,
        )
        prompt_package = {
            "investigation_query_capability": {
                "enabled": True,
                "backends": {"elastic": {"enabled": True}},
            },
            "_local_investigation_query_context": {
                "anchor": {
                    "index": ".ds-logs-suricata.alerts-so-2026.07.24-000001",
                    "id": "alert-denied",
                },
            },
        }
        query_executor = mock.Mock()

        response = self.runner.apply_investigation_query_loop(
            prompt_package,
            {"investigation_query_requests": [self.elastic_request()]},
            object(),
            {"agent_models": {"soc-analyst": "codex-cli:gpt-5.5:medium"}},
            "soc-analyst",
            harness_runtime=harness,
            model_executor=mock.Mock(return_value={"summary": "denied"}),
            query_executor=query_executor,
        )

        query_executor.assert_not_called()
        self.assertFalse(
            any(event[0] == "preflight_query_batch" for event in events)
        )
        result = response["_investigation_query_audit"]["rounds"][0]["results"][0]
        self.assertEqual(result["status"], "rejected")
        self.assertIn("harness denied capability", result["error"].lower())

    def test_shadow_observation_failure_does_not_change_normal_response(
        self,
    ) -> None:
        template = {
            "investigation_query_capability": {
                "enabled": True,
                "backends": {"elastic": {"enabled": True}},
            },
            "_local_investigation_query_context": {
                "anchor": {
                    "index": ".ds-logs-suricata.alerts-so-2026.07.24-000001",
                    "id": "alert-shadow",
                },
            },
        }

        def query_executor(
            _package,
            requests,
            *,
            round_number,
            live_osquery_config,
        ):
            self.assertIsNone(live_osquery_config)
            return {
                "schema": self.runner.INVESTIGATION_QUERY_RESULT_SCHEMA,
                "round": round_number,
                "requests": copy.deepcopy(requests),
                "results": [
                    {
                        "query_id": requests[0]["query_id"],
                        "backend": "elastic",
                        "status": "ok",
                        "read_only": True,
                        "query_digest": "c" * 64,
                        "result_digest": "d" * 64,
                        "returned_hits": 2,
                    }
                ],
                "audit": [],
            }

        def execute(prompt_package, harness_runtime=None):
            return self.runner.apply_investigation_query_loop(
                prompt_package,
                {"investigation_query_requests": [self.elastic_request()]},
                object(),
                {
                    "agent_models": {
                        "soc-analyst": "codex-cli:gpt-5.5:medium",
                    }
                },
                "soc-analyst",
                harness_runtime=harness_runtime,
                model_executor=mock.Mock(
                    return_value={"summary": "normal response"}
                ),
                query_executor=query_executor,
            )

        baseline = execute(copy.deepcopy(template))
        events: list[tuple] = []
        shadow = RecordingHarness(
            events,
            mode="shadow",
            fail_authorization=True,
        )
        with mock.patch.object(self.runner.sys, "stderr"):
            observed = execute(copy.deepcopy(template), shadow)

        self.assertEqual(observed, baseline)
        self.assertTrue(
            any(event[0] == "authorize_tool" for event in events)
        )

    def test_result_digest_can_be_recatalogued_after_follow_up_query(
        self,
    ) -> None:
        prompt_package = {
            "case_id": "case-query-result-digest",
            "alert": {
                "alert_id": (
                    ".ds-logs-suricata.alerts-so-2026.07.24-000001:"
                    "alert-result-digest"
                ),
            },
            "investigation_query_capability": {
                "enabled": True,
                "backends": {"elastic": {"enabled": True}},
            },
            "_local_investigation_query_context": {
                "anchor": {
                    "index": ".ds-logs-suricata.alerts-so-2026.07.24-000001",
                    "id": "alert-result-digest",
                },
            },
        }
        self.runner.attach_evidence_reference_contract(prompt_package)
        policy_value = json.loads(
            (
                REPO_ROOT
                / "n8n"
                / "config"
                / "investigation_harness_policy.json"
            ).read_text(encoding="utf-8")
        )
        policy_value["enabled"] = True
        policy_value["mode"] = "enforce"
        policy = self.harness.HarnessPolicy.from_dict(policy_value)
        query_digest = "e" * 64
        result_digest = "f" * 64

        with tempfile.TemporaryDirectory() as temp_name:
            runtime = self.harness.start_harness_run(
                run_id="run-query-result-digest",
                prompt_package=prompt_package,
                role="soc-analyst",
                assigned_route="codex-cli:gpt-5.5:medium",
                configuration={"test": True},
                policy=policy,
                db_path=Path(temp_name) / "harness.sqlite3",
            )
            self.assertIsNotNone(runtime)

            def query_executor(
                _package,
                requests,
                *,
                round_number,
                live_osquery_config,
            ):
                self.assertIsNone(live_osquery_config)
                return {
                    "schema": self.runner.INVESTIGATION_QUERY_RESULT_SCHEMA,
                    "round": round_number,
                    "requests": requests,
                    "results": [
                        {
                            "query_id": requests[0]["query_id"],
                            "backend": "elastic",
                            "pack": "network_flow",
                            "status": "ok",
                            "read_only": True,
                            "query_digest": query_digest,
                            "result_digest": result_digest,
                            "returned_hits": 1,
                            "trusted_query_audit": [
                                {
                                    "query_id": requests[0]["query_id"],
                                    "status": "ok",
                                    "query_digest": query_digest,
                                    "result_digest": result_digest,
                                    "evidence_ref": f"query:{query_digest}",
                                    "returned_hits": 1,
                                }
                            ],
                        }
                    ],
                    "audit": [],
                }

            response = self.runner.apply_investigation_query_loop(
                prompt_package,
                {"investigation_query_requests": [self.elastic_request()]},
                object(),
                {
                    "agent_models": {
                        "soc-analyst": "codex-cli:gpt-5.5:medium",
                    }
                },
                "soc-analyst",
                harness_runtime=runtime,
                model_executor=mock.Mock(
                    return_value={
                        "summary": "digest recatalogued",
                        "_analysis_model_route": (
                            "codex-cli:gpt-5.5:medium"
                        ),
                    }
                ),
                query_executor=query_executor,
            )
            exported = runtime.store.export_trace(runtime.run_id)

        self.assertEqual(response["summary"], "digest recatalogued")
        query_evidence = next(
            item
            for item in exported["evidence"]
            if item["evidence_ref"]
            == f"query:{query_digest}:{result_digest}"
        )
        self.assertEqual(query_evidence["evidence_digest"], result_digest)
        self.assertNotIn(
            f"query:{query_digest}",
            {
                item["evidence_ref"]
                for item in exported["evidence"]
            },
        )

    def test_result_digest_recatalogue_survives_sparse_trusted_audit(
        self,
    ) -> None:
        prompt_package = {
            "case_id": "case-sparse-query-audit",
            "alert": {
                "alert_id": (
                    ".ds-logs-suricata.alerts-so-2026.07.24-000001:"
                    "alert-sparse-query-audit"
                ),
            },
            "investigation_query_capability": {
                "enabled": True,
                "backends": {"elastic": {"enabled": True}},
            },
            "_local_investigation_query_context": {
                "anchor": {
                    "index": (
                        ".ds-logs-suricata.alerts-so-"
                        "2026.07.24-000001"
                    ),
                    "id": "alert-sparse-query-audit",
                },
            },
        }
        self.runner.attach_evidence_reference_contract(prompt_package)
        policy_value = json.loads(
            (
                REPO_ROOT
                / "n8n"
                / "config"
                / "investigation_harness_policy.json"
            ).read_text(encoding="utf-8")
        )
        policy_value["enabled"] = True
        policy_value["mode"] = "enforce"
        policy = self.harness.HarnessPolicy.from_dict(policy_value)
        query_digest = "1" * 64
        result_digest = "2" * 64

        with tempfile.TemporaryDirectory() as temp_name:
            runtime = self.harness.start_harness_run(
                run_id="run-sparse-query-audit",
                prompt_package=prompt_package,
                role="soc-analyst",
                assigned_route="codex-cli:gpt-5.5:medium",
                configuration={"test": True},
                policy=policy,
                db_path=Path(temp_name) / "harness.sqlite3",
            )
            self.assertIsNotNone(runtime)

            def query_executor(
                _package,
                requests,
                *,
                round_number,
                live_osquery_config,
            ):
                self.assertIsNone(live_osquery_config)
                return {
                    "schema": (
                        self.runner.INVESTIGATION_QUERY_RESULT_SCHEMA
                    ),
                    "round": round_number,
                    "requests": requests,
                    "results": [
                        {
                            "query_id": requests[0]["query_id"],
                            "backend": "elastic",
                            "pack": "network_flow",
                            "status": "ok",
                            "read_only": True,
                            "query_digest": query_digest,
                            "result_digest": result_digest,
                            "returned_hits": 0,
                            "trusted_query_audit": [
                                {
                                    "query_id": requests[0]["query_id"],
                                    "status": "ok",
                                    "query_digest": query_digest,
                                    "result_digest": "not-a-digest",
                                    "returned_hits": 0,
                                }
                            ],
                        }
                    ],
                    "audit": [],
                }

            response = self.runner.apply_investigation_query_loop(
                prompt_package,
                {
                    "investigation_query_requests": [
                        self.elastic_request()
                    ]
                },
                object(),
                {
                    "agent_models": {
                        "soc-analyst": "codex-cli:gpt-5.5:medium",
                    }
                },
                "soc-analyst",
                harness_runtime=runtime,
                model_executor=mock.Mock(
                    return_value={
                        "summary": "sparse audit recatalogued",
                        "_analysis_model_route": (
                            "codex-cli:gpt-5.5:medium"
                        ),
                    }
                ),
                query_executor=query_executor,
            )
            exported = runtime.store.export_trace(runtime.run_id)

        self.assertEqual(
            response["summary"],
            "sparse audit recatalogued",
        )
        refs = {
            item["evidence_ref"]: item["evidence_digest"]
            for item in exported["evidence"]
        }
        self.assertEqual(
            refs[f"query:{query_digest}"],
            query_digest,
        )
        self.assertEqual(
            refs[f"query:{query_digest}:{result_digest}"],
            result_digest,
        )

    def test_result_bound_query_references_preserve_full_digests(
        self,
    ) -> None:
        result_digest = "a" * 64
        first_query = "b" * 64
        second_query = "c" * 64
        for namespace in ("pack", "query-id"):
            with self.subTest(namespace=namespace):
                first_ref, first_digest = (
                    self.runner.result_bound_query_reference(
                        first_query.upper(),
                        result_digest.upper(),
                        namespace=namespace,
                        label="long-label-" * 40,
                    )
                )
                second_ref, second_digest = (
                    self.runner.result_bound_query_reference(
                        second_query,
                        result_digest,
                        namespace=namespace,
                        label="long-label-" * 40,
                    )
                )
                self.assertNotEqual(first_ref, second_ref)
                self.assertLessEqual(
                    len(first_ref),
                    self.runner.EVIDENCE_REFERENCE_TEXT_MAX,
                )
                self.assertIn(first_query, first_ref)
                self.assertIn(second_query, second_ref)
                self.assertTrue(first_ref.endswith(result_digest))
                self.assertTrue(second_ref.endswith(result_digest))
                self.assertEqual(first_digest, result_digest)
                self.assertEqual(second_digest, result_digest)

        legacy_ref, legacy_digest = (
            self.runner.result_bound_query_reference(
                first_query.upper(),
                "not-a-digest",
            )
        )
        self.assertEqual(legacy_ref, f"query:{first_query}")
        self.assertEqual(legacy_digest, first_query)
        changed_result_ref, _ = (
            self.runner.result_bound_query_reference(
                first_query,
                "d" * 64,
            )
        )
        self.assertNotEqual(
            changed_result_ref,
            self.runner.result_bound_query_reference(
                first_query,
                result_digest,
            )[0],
        )

        contract = self.runner.evidence_reference_contract(
            {
                "investigation_query_results": {
                    "results": [
                        {
                            "query_id": "query-one",
                            "query_digest": first_query,
                            "result_digest": result_digest,
                            "evidence_ref": f"query:{second_query}",
                            "status": "ok",
                            "returned_hits": 1,
                        }
                    ]
                }
            }
        )
        refs = {item["ref"] for item in contract["references"]}
        self.assertIn(
            f"query:{first_query}:{result_digest}",
            refs,
        )
        self.assertNotIn(f"query:{second_query}", refs)

    def test_reviewer_preflight_precedes_reviewer_execution(self) -> None:
        events: list[tuple] = []
        harness = RecordingHarness(events)
        primary = {
            "summary": "Primary result.",
            "second_opinion_recommended": True,
            "second_opinion_reason": "Independent validation requested.",
        }
        settings = {
            "agent_models": {
                "soc-analyst": "codex-cli:gpt-5.5:medium",
            },
            "agent_second_opinion_models": {
                "soc-analyst": "ollama:reviewer:latest",
            },
        }

        def reviewer_executor(*_args, **_kwargs):
            events.append(("reviewer_executor",))
            raise RuntimeError("synthetic reviewer stop")

        with (
            mock.patch.object(
                self.runner,
                "analyze_model_route",
                side_effect=reviewer_executor,
            ),
            mock.patch.object(
                self.runner,
                "reconcile_incident_response_report",
            ),
        ):
            response = self.runner.apply_configured_second_opinion(
                {},
                primary,
                type(
                    "Args",
                    (),
                    {
                        "second_opinion_prompt_file": Path(
                            "/tmp/synthetic-reviewer-prompt.md"
                        )
                    },
                )(),
                settings,
                "soc-analyst",
                harness_runtime=harness,
            )

        preflight_position = next(
            index
            for index, event in enumerate(events)
            if event[:3]
            == (
                "preflight_model_call",
                "independent-review-1",
                True,
            )
        )
        execution_position = events.index(("reviewer_executor",))
        self.assertLess(preflight_position, execution_position)
        self.assertEqual(response["_second_opinion"]["status"], "failed")

    def test_loop_reuses_exact_route_and_enforces_round_budget(self) -> None:
        prompt_package = {
            "investigation_query_capability": {
                "enabled": True,
                "backends": {"elastic": {"enabled": True}},
            },
            "_local_investigation_query_context": {
                "anchor": {
                    "index": ".ds-logs-suricata.alerts-so-2026.07.24-000001",
                    "id": "alert-1",
                },
                "discovered_observables": [],
            },
        }
        primary = {"investigation_query_requests": [self.elastic_request("initial")]}
        settings = {
            "agent_models": {"soc-analyst": "codex-cli:gpt-5.6-sol:high"}
        }
        model_calls: list[tuple[str, dict]] = []

        def model_executor(route, package, _args, _settings):
            model_calls.append((route, package["investigation_follow_up"].copy()))
            return {
                "summary": f"round {len(model_calls)}",
                "investigation_query_requests": [
                    {
                        **self.elastic_request(f"next-{len(model_calls)}"),
                        "parameters": {
                            **self.elastic_request()["parameters"],
                            "size": 25 + len(model_calls),
                        },
                    }
                ],
            }

        def query_executor(_package, requests, *, round_number, live_osquery_config):
            return {
                "schema": self.runner.INVESTIGATION_QUERY_RESULT_SCHEMA,
                "round": round_number,
                "requests": requests,
                "results": [
                    {
                        "query_id": requests[0]["query_id"],
                        "backend": "elastic",
                        "status": "ok",
                        "evidence": {"source.ip": "198.51.100.5"},
                    }
                ],
                "audit": [],
            }

        response = self.runner.apply_investigation_query_loop(
            prompt_package,
            primary,
            object(),
            settings,
            "soc-analyst",
            model_executor=model_executor,
            query_executor=query_executor,
        )

        self.assertEqual(len(model_calls), self.runner.MAX_INVESTIGATION_QUERY_ROUNDS)
        self.assertTrue(
            all(call[0] == "codex-cli:gpt-5.6-sol:high" for call in model_calls)
        )
        self.assertEqual(
            response["_investigation_query_audit"]["rounds_completed"],
            self.runner.MAX_INVESTIGATION_QUERY_ROUNDS,
        )
        self.assertEqual(
            response["_investigation_query_audit"]["requests_ignored_or_over_budget"],
            1,
        )
        self.assertNotIn("investigation_query_requests", response)
        self.assertEqual(
            len(prompt_package["investigation_query_results"]["rounds"]),
            self.runner.MAX_INVESTIGATION_QUERY_ROUNDS,
        )

    def test_loop_refreshes_citation_contract_before_follow_up_model_call(
        self,
    ) -> None:
        prompt_package = {
            "investigation_query_capability": {
                "enabled": True,
                "backends": {"elastic": {"enabled": True}},
            },
            "_local_investigation_query_context": {
                "anchor": {
                    "index": ".ds-logs-suricata.alerts-so-2026.07.24-000001",
                    "id": "alert-1",
                }
            },
        }
        query_digest = "a" * 64

        def model_executor(_route, package, _args, _settings):
            refs = {
                item["ref"]
                for item in package["evidence_reference_contract"]["references"]
            }
            self.assertIn(f"query:{query_digest}", refs)
            return {"summary": "The trusted query is now citable."}

        self.runner.apply_investigation_query_loop(
            prompt_package,
            {"investigation_query_requests": [self.elastic_request()]},
            object(),
            {"agent_models": {"soc-analyst": "codex-cli:gpt-5.5:medium"}},
            "soc-analyst",
            model_executor=model_executor,
            query_executor=mock.Mock(
                return_value={
                    "schema": self.runner.INVESTIGATION_QUERY_RESULT_SCHEMA,
                    "round": 1,
                    "requests": [self.elastic_request()],
                    "results": [
                        {
                            "query_id": "pivot-1",
                            "backend": "elastic",
                            "pack": "network_flow",
                            "query_digest": query_digest,
                            "status": "ok",
                            "returned_hits": 1,
                            "total_hits": 1,
                        }
                    ],
                    "audit": [],
                }
            ),
        )

    def test_loop_rejects_disabled_or_unadvertised_backend_before_execution(self) -> None:
        prompt_package = {
            "investigation_query_capability": {
                "enabled": True,
                "backends": {"elastic": {"enabled": False}},
            },
            "_local_investigation_query_context": {
                "anchor": {
                    "index": ".ds-logs-suricata.alerts-so-2026.07.24-000001",
                    "id": "alert-1",
                }
            },
        }
        settings = {"agent_models": {"soc-analyst": "codex-cli:gpt-5.5:medium"}}
        query_executor = mock.Mock()

        response = self.runner.apply_investigation_query_loop(
            prompt_package,
            {"investigation_query_requests": [self.elastic_request()]},
            object(),
            settings,
            "soc-analyst",
            model_executor=mock.Mock(return_value={"summary": "No query executed."}),
            query_executor=query_executor,
        )

        query_executor.assert_not_called()
        rejected = prompt_package["investigation_query_results"]["rounds"][0]["results"][0]
        self.assertEqual(rejected["status"], "rejected")
        self.assertIn("disabled", rejected["error"])
        self.assertEqual(
            response["_investigation_query_audit"]["rounds"][0]["results"][0]["status"],
            "rejected",
        )

    def test_loop_rejects_semantically_duplicate_query_across_rounds(self) -> None:
        prompt_package = {
            "investigation_query_capability": {
                "enabled": True,
                "backends": {"elastic": {"enabled": True}},
            },
            "_local_investigation_query_context": {
                "anchor": {
                    "index": ".ds-logs-suricata.alerts-so-2026.07.24-000001",
                    "id": "alert-1",
                }
            },
        }
        settings = {"agent_models": {"soc-analyst": "codex-cli:gpt-5.5:medium"}}
        query_executor = mock.Mock(
            return_value={
                "schema": self.runner.INVESTIGATION_QUERY_RESULT_SCHEMA,
                "round": 1,
                "requests": [self.elastic_request()],
                "results": [],
                "audit": [],
            }
        )
        second = {
            **self.elastic_request("renamed"),
            "purpose": "measure_prevalence",
        }

        response = self.runner.apply_investigation_query_loop(
            prompt_package,
            {"investigation_query_requests": [self.elastic_request()]},
            object(),
            settings,
            "soc-analyst",
            model_executor=mock.Mock(
                side_effect=[
                    {"investigation_query_requests": [second]},
                    {"summary": "final"},
                ]
            ),
            query_executor=query_executor,
        )

        query_executor.assert_called_once()
        duplicate = prompt_package["investigation_query_results"]["rounds"][1]["results"][0]
        self.assertEqual(duplicate["status"], "rejected")
        self.assertIn("already executed", duplicate["error"])
        self.assertGreaterEqual(
            response["_investigation_query_audit"]["requests_ignored_or_over_budget"],
            1,
        )

    def test_semantic_dedup_canonicalizes_order_timezones_and_osquery_limit(self) -> None:
        first = self.runner.normalize_investigation_query_request(
            self.elastic_request("first"),
            round_number=1,
            position=1,
        )
        equivalent = self.elastic_request("second")
        equivalent["parameters"]["window"] = {
            "start": "2026-07-24T12:00:00-06:00",
            "end": "2026-07-24T13:00:00-06:00",
        }
        equivalent["parameters"]["observables"]["ips"] = ["192.0.2.10", "192.0.2.10"]
        second = self.runner.normalize_investigation_query_request(
            equivalent,
            round_number=1,
            position=2,
        )
        self.assertEqual(
            self.runner.investigation_request_semantic_digest(first),
            self.runner.investigation_request_semantic_digest(second),
        )

        implicit = self.runner.normalize_investigation_query_request(
            {
                "backend": "osquery",
                "purpose": "Inspect one bounded endpoint fact.",
                "parameters": {
                    "target_alias": "endpoint-a",
                    "query": "SELECT pid FROM processes",
                },
            },
            round_number=1,
            position=1,
        )
        explicit = self.runner.normalize_investigation_query_request(
            {
                "backend": "osquery",
                "purpose": "Same fact.",
                "parameters": {
                    "target_alias": "endpoint-a",
                    "query": "select pid from processes limit 100;",
                },
            },
            round_number=1,
            position=2,
        )
        self.assertEqual(
            self.runner.investigation_request_semantic_digest(implicit),
            self.runner.investigation_request_semantic_digest(explicit),
        )

    def test_cumulative_prompt_projection_enforces_row_and_byte_caps(self) -> None:
        rows = [
            {"source": {"ip": "192.0.2.1"}, "padding": "x" * 4096}
            for _ in range(800)
        ]
        rounds = [{
            "round": 1,
            "requests": [],
            "audit": [],
            "results": [{
                "query_id": "large",
                "backend": "security_onion",
                "status": "ok",
                "evidence": {"results": [{"hits": rows}]},
                "trusted_query_audit": [],
            }],
        }]
        projected = self.runner._investigation_prompt_payload(rounds)
        encoded = json.dumps(
            projected,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

        self.assertLessEqual(
            len(encoded),
            self.runner.MAX_INVESTIGATION_PROMPT_EVIDENCE_BYTES,
        )
        self.assertLessEqual(
            projected["prompt_projection"]["rows_included"],
            self.runner.MAX_INVESTIGATION_PROMPT_EVIDENCE_ROWS,
        )
        self.assertTrue(projected["prompt_projection"]["truncated"])

    def test_discovered_observables_match_contract_and_never_exceed_shared_cap(self) -> None:
        query_digest = "a" * 64
        hits = [
            {
                "id": f"hit-{index}",
                "index": "logs-suricata.alerts",
                "source": {"source": {"ip": f"198.51.100.{index}"}},
            }
            for index in range(1, 41)
        ]
        hits.extend([
            {"id": "bad-domain", "index": "logs-suricata.alerts",
             "source": {"dns": {"question": {"name": "bad_domain"}}}},
            {"id": "bad-host", "index": "logs-suricata.alerts",
             "source": {"host": {"name": "bad+host"}}},
            {"id": "bad-user", "index": "logs-suricata.alerts",
             "source": {"user": {"name": "bad+user"}}},
        ])
        evidence = [{
            "backend": "security_onion",
            "status": "ok",
            "security_onion_response_digest": "b" * 64,
            "trusted_query_audit": [{
                "query_id": "q1",
                "query_digest": query_digest,
                "status": "ok",
            }],
            "evidence": {
                "controls_valid": True,
                "results": [{
                    "query_id": "q1",
                    "query_digest": query_digest,
                    "status": "ok",
                    "hits": hits,
                }],
            },
        }]

        discovered = self.runner._validated_discovered_observables(
            evidence,
        )

        self.assertEqual(
            len(discovered),
            self.contract.MAX_DISCOVERED_OBSERVABLES,
        )
        self.assertNotIn("bad_domain", {item["value"] for item in discovered})
        self.assertNotIn("bad+host", {item["value"] for item in discovered})
        self.assertNotIn("bad+user", {item["value"] for item in discovered})

    def test_discovery_refs_bind_exact_hits_and_zero_hit_filters_never_promote(self) -> None:
        query_digest = "c" * 64
        security = {
            "backend": "security_onion",
            "status": "ok",
            "security_onion_response_digest": "d" * 64,
            "trusted_query_audit": [{
                "query_id": "exact-q",
                "query_digest": query_digest,
                "status": "ok",
            }],
            "evidence": {
                "controls_valid": True,
                "results": [{
                    "query_id": "exact-q",
                    "query_digest": query_digest,
                    "status": "ok",
                    "hits": [
                        {"id": "hit-one", "index": "index-one",
                         "source": {"source": {"ip": "192.0.2.1"}}},
                        {"id": "hit-two", "index": "index-two",
                         "source": {"source": {"ip": "192.0.2.2"}}},
                    ],
                }],
            },
        }
        discovered = self.runner._validated_discovered_observables([security])
        refs = {item["value"]: item["evidence_ref"] for item in discovered}
        self.assertNotEqual(refs["192.0.2.1"], refs["192.0.2.2"])
        self.assertIn("hit-one", refs["192.0.2.1"])
        self.assertIn("index-one", refs["192.0.2.1"])
        self.assertIn("source.ip", refs["192.0.2.1"])

        forged_filter = {
            "backend": "pcap_zeek",
            "status": "ok",
            "query_id": "derived-q",
            "evidence": {
                "query": {
                    "operation": "tls",
                    "filters": {"sni": "attacker-chosen.example"},
                },
                "query_digest": "e" * 64,
                "result_digest": "f" * 64,
                "evidence_ref": "derived-pcap-zeek:bound",
                "records": [],
            },
            "trusted_query_audit": [{
                "query_id": "derived-q",
                "query_digest": "e" * 64,
                "result_digest": "f" * 64,
                "evidence_ref": "derived-pcap-zeek:bound",
                "status": "ok",
            }],
        }
        self.assertEqual(
            self.runner._validated_discovered_observables([forged_filter]),
            [],
        )

    def test_enabled_osquery_capability_enables_top_level_loop(self) -> None:
        prompt_package = {
            "investigation_query_capability": {
                "enabled": False,
                "backends": {"osquery": {"enabled": False}},
            }
        }
        with tempfile.TemporaryDirectory() as temp_name:
            config_path = Path(temp_name) / "live-osquery.json"
            config_path.write_text("{}", encoding="utf-8")
            with (
                mock.patch.object(
                    self.runner,
                    "DEFAULT_LIVE_OSQUERY_CONFIG_FILE",
                    config_path,
                ),
                mock.patch.object(
                    self.runner,
                    "load_live_osquery_config",
                    return_value={
                        "enabled": True,
                        "allowed_target_aliases": ["endpoint-a"],
                        "allowed_agent_roles": ["soc-analyst"],
                    },
                ),
            ):
                config = self.runner.prepare_live_osquery_context(
                    prompt_package,
                    "soc-analyst",
                )

        self.assertTrue(config["enabled"])
        self.assertTrue(prompt_package["investigation_query_capability"]["enabled"])
        self.assertTrue(
            prompt_package["investigation_query_capability"]["backends"]["osquery"]["enabled"]
        )

    def test_osquery_defaults_to_incident_responder_and_soc_requires_opt_in(self) -> None:
        def prepare(role: str, configured: dict) -> tuple[dict, dict]:
            package = {
                "investigation_query_capability": {
                    "enabled": False,
                    "backends": {"osquery": {"enabled": False}},
                }
            }
            with tempfile.TemporaryDirectory() as temp_name:
                config_path = Path(temp_name) / "live-osquery.json"
                config_path.write_text("{}", encoding="utf-8")
                with (
                    mock.patch.object(
                        self.runner,
                        "DEFAULT_LIVE_OSQUERY_CONFIG_FILE",
                        config_path,
                    ),
                    mock.patch.object(
                        self.runner,
                        "load_live_osquery_config",
                        return_value=configured,
                    ),
                ):
                    scoped = self.runner.prepare_live_osquery_context(package, role)
            return package, scoped

        base = {
            "enabled": True,
            "allowed_target_aliases": ["endpoint-a"],
            "allowed_agent_roles": ["incident-responder"],
        }
        soc_package, soc_config = prepare("soc-analyst", base)
        self.assertFalse(soc_config["enabled"])
        self.assertFalse(
            soc_package["investigation_query_capability"]["backends"]["osquery"]["enabled"]
        )
        ir_package, ir_config = prepare("incident-responder", base)
        self.assertTrue(ir_config["enabled"])
        self.assertTrue(
            ir_package["investigation_query_capability"]["backends"]["osquery"]["enabled"]
        )

    def test_osquery_aliases_cannot_authorize_new_elastic_observables(self) -> None:
        prompt_package = {
            "investigation_query_capability": {
                "enabled": True,
                "backends": {"osquery": {"enabled": True}},
            },
            "_local_investigation_query_context": {
                "discovered_observables": [],
            },
        }
        request = {
            "query_id": "host-pivot",
            "backend": "osquery",
            "purpose": "Inspect a bounded endpoint process fact.",
            "parameters": {
                "target_alias": "endpoint-a",
                "query": "SELECT pid FROM processes LIMIT 1",
            },
        }
        query_executor = mock.Mock(
            return_value={
                "schema": self.runner.INVESTIGATION_QUERY_RESULT_SCHEMA,
                "round": 1,
                "requests": [request],
                "results": [
                    {
                        "query_id": "host-pivot",
                        "backend": "osquery",
                        "status": "ok",
                        "evidence": {"rows": [{"source.ip": "8.8.8.8"}]},
                    }
                ],
                "audit": [],
            }
        )

        self.runner.apply_investigation_query_loop(
            prompt_package,
            {"investigation_query_requests": [request]},
            object(),
            {"agent_models": {"soc-analyst": "codex-cli:gpt-5.5:medium"}},
            "soc-analyst",
            live_osquery_config={"enabled": True},
            model_executor=mock.Mock(return_value={"summary": "final"}),
            query_executor=query_executor,
        )

        self.assertEqual(
            prompt_package["_local_investigation_query_context"]["discovered_observables"],
            [],
        )

    def test_unavailable_security_onion_broker_becomes_evidence_gap(self) -> None:
        request = self.runner.normalize_investigation_query_request(
            self.elastic_request(),
            round_number=1,
            position=1,
        )

        result = self.runner.execute_investigation_query_batch(
            {
                "_local_investigation_query_context": {
                    "case_id": "investigation-test",
                }
            },
            [request],
            round_number=1,
            security_onion_executor=mock.Mock(
                side_effect=self.runner.InvestigationQueryError("broker unavailable")
            ),
        )

        self.assertEqual(result["results"][0]["status"], "error")
        self.assertIn("broker unavailable", result["results"][0]["error"])

    def test_partial_security_onion_batch_is_never_labeled_ok(self) -> None:
        request = self.runner.normalize_investigation_query_request(
            self.elastic_request(),
            round_number=1,
            position=1,
        )

        result = self.runner.execute_investigation_query_batch(
            {"_local_investigation_query_context": {"case_id": "investigation-test"}},
            [request],
            round_number=1,
            security_onion_executor=mock.Mock(
                return_value={
                    "complete": False,
                    "partial": True,
                    "model_evidence": {
                        "results": [{"query_id": "pivot-1", "status": "timeout"}]
                    },
                    "query_audit": [
                        {
                            "query_id": "pivot-1",
                            "dialect": "elastic",
                            "status": "timeout",
                            "query_digest": "a" * 64,
                        }
                    ],
                    "audit": {},
                }
            ),
        )

        self.assertEqual(result["results"][0]["status"], "partial")

    def test_builder_creates_hidden_anchor_and_bounded_visible_capability(self) -> None:
        row = {
            "alert_id": ".ds-logs-suricata.alerts-so-2026.07.24-000001:alert-1",
            "alert_json": json.dumps(
                {
                    "elastic_index": ".ds-logs-suricata.alerts-so-2026.07.24-000001",
                    "elastic_id": "alert-1",
                    "source": {"ip": "192.0.2.10"},
                    "destination": {"ip": "198.51.100.20", "port": 443},
                    "network": {
                        "transport": "tcp",
                        "protocol": "tls",
                        "community_id": "1:trusted-flow=",
                    },
                    "rule": {"id": "2016150"},
                    "dns": {"question": {"name": "example.test"}},
                    "host": {"name": "workstation-1"},
                    "user": {"name": "analyst"},
                }
            ),
            "source_ip": "192.0.2.10",
            "source_port": 49152,
            "destination_ip": "198.51.100.20",
            "destination_port": 443,
            "transport_protocol": "tcp",
            "network_protocol": "tls",
            "rule_id": "2016150",
            "timestamp": "2026-07-24T18:30:00Z",
            "first_seen": "2026-07-24T18:29:00Z",
            "last_seen": "2026-07-24T18:31:00Z",
        }

        capability, local = self.builder.investigation_query_context(
            row,
            [row],
            "group-1",
            "incident-responder",
            True,
        )

        self.assertTrue(capability["enabled"])
        self.assertEqual(local["anchor"]["id"], "alert-1")
        self.assertEqual(local["actor_role"], "incident_responder")
        self.assertTrue(local["context_id"].startswith("context-"))
        self.assertIn("192.0.2.10", capability["permitted_observables"]["ips"])
        self.assertIn("example.test", capability["permitted_observables"]["domains"])
        self.assertEqual(
            capability["request_schema"]["parameters_by_backend"]["elastic"],
            [
                "pack", "window", "observables", "event_tuple", "size",
                "aggregation",
            ],
        )
        self.assertEqual(
            capability["permitted_event_tuples"],
            [{
                "event_tuple": {
                    "source_ip": "192.0.2.10",
                    "destination_ip": "198.51.100.20",
                    "source_port": 49152,
                    "destination_port": 443,
                    "transport": "tcp",
                    "protocol": "tls",
                    "community_id": "1:trusted-flow=",
                    "rule_id": "2016150",
                },
                "role_semantics": "packet_direction",
            }],
        )
        self.assertEqual(
            local["permitted_event_tuples"][0]["event_tuple"],
            capability["permitted_event_tuples"][0]["event_tuple"],
        )
        self.assertIn(
            "never merge",
            capability["request_schema"]["rule"].lower(),
        )
        self.assertEqual(
            capability["budgets"]["max_rounds"],
            self.builder.INVESTIGATION_QUERY_MAX_ROUNDS,
        )
        self.assertNotIn("anchor", capability)

    def test_builder_preserves_every_specialist_role_and_rejects_unknown_role(
        self,
    ) -> None:
        row = {
            "alert_id": ".ds-logs-suricata.alerts-so-2026.07.24-000001:alert-role",
            "alert_json": json.dumps(
                {
                    "elastic_index": ".ds-logs-suricata.alerts-so-2026.07.24-000001",
                    "elastic_id": "alert-role",
                }
            ),
            "source_ip": "192.0.2.10",
            "destination_ip": "198.51.100.20",
            "timestamp": "2026-07-24T18:30:00Z",
        }
        for role in (
            "soc-analyst",
            "incident-responder",
            "siem-engineer",
            "cyber-threat-intel",
            "threat-hunter",
        ):
            with self.subTest(role=role):
                _capability, local = self.builder.investigation_query_context(
                    row,
                    [row],
                    "group-role",
                    role,
                    False,
                )
                self.assertEqual(local["actor_role"], role.replace("-", "_"))
                authorized = self.contract.authorize_investigation_query_request(
                    {
                        "query_contract": self.runner.INVESTIGATION_QUERY_CONTRACT,
                        "batch_id": f"batch-{role}",
                        "queries": [
                            {
                                "query_id": f"query-{role}",
                                "dialect": "elastic",
                                "pack": "network_flow",
                                "purpose": "correlate_observable",
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
                            }
                        ],
                    },
                    local,
                )
                self.assertEqual(
                    authorized["authorization"]["actor_role"],
                    role.replace("-", "_"),
                )

        with self.assertRaisesRegex(ValueError, "unsupported.*actor role"):
            self.builder.investigation_query_context(
                row,
                [row],
                "group-role",
                "unknown-specialist",
                False,
            )

    def test_builder_authorizes_sigma_original_event_system_auth_pivot(self) -> None:
        row = {
            "alert_id": ".ds-logs-detections.alerts-so-2026.07.24-000001:sigma-1",
            "alert_json": json.dumps(
                {
                    "elastic_index": ".ds-logs-detections.alerts-so-2026.07.24-000001",
                    "elastic_id": "sigma-1",
                }
            ),
            "raw_event_json": json.dumps(
                {
                    "event": {"dataset": "sigma.alert"},
                    "event_data": {
                        "event": {
                            "dataset": "system.auth",
                            "outcome": "failure",
                        },
                        "source": {
                            "address": "192.0.2.55",
                            "ip": "192.0.2.55",
                        },
                        "host": {"id": "host-1", "name": "onion"},
                        "agent": {"id": "agent-1", "name": "onion"},
                        "user": {"name": "invalid-user"},
                        "related": {
                            "hosts": ["onion"],
                            "ip": ["192.0.2.55"],
                            "user": ["invalid-user"],
                        },
                    },
                }
            ),
            "source_ip": None,
            "destination_ip": None,
            "timestamp": "2026-07-24T18:30:00Z",
            "first_seen": "2026-07-24T18:29:00Z",
            "last_seen": "2026-07-24T18:31:00Z",
        }

        capability, context = self.builder.investigation_query_context(
            row,
            [row],
            "sigma-group",
            "incident-responder",
            False,
        )

        self.assertIn("192.0.2.55", context["permitted_observables"]["ips"])
        self.assertIn("onion", context["permitted_observables"]["hosts"])
        self.assertIn(
            "invalid-user",
            context["permitted_observables"]["users"],
        )
        self.assertIn(
            "system_auth",
            capability["backends"]["elastic"]["packs"],
        )
        self.assertIn(
            "authentication",
            capability["backends"]["elastic"]["pack_descriptions"][
                "system_auth"
            ].lower(),
        )

        request = self.elastic_request("auth-pivot")
        request["parameters"].update(
            {
                "pack": "system_auth",
                "window": {
                    "start": "2026-07-24T18:00:00Z",
                    "end": "2026-07-24T19:00:00Z",
                },
                "observables": {
                    "ips": ["192.0.2.55"],
                    "domains": [],
                    "hosts": ["onion"],
                    "users": ["invalid-user"],
                },
            }
        )
        normalized = self.runner.normalize_investigation_query_request(
            request,
            round_number=1,
            position=1,
            time_envelope=context["time_envelope"],
        )
        authorized = self.contract.authorize_investigation_query_request(
            {
                "query_contract": self.runner.INVESTIGATION_QUERY_CONTRACT,
                "batch_id": "auth-pivot-batch",
                "queries": [
                    {
                        "query_id": normalized["query_id"],
                        "dialect": normalized["backend"],
                        "pack": normalized["parameters"]["pack"],
                        "purpose": normalized["purpose"],
                        "window": normalized["parameters"]["window"],
                        "observables": normalized["parameters"]["observables"],
                        "size": normalized["parameters"]["size"],
                        "aggregation": normalized["parameters"]["aggregation"],
                    }
                ],
            },
            context,
        )

        self.assertEqual(
            authorized["queries"][0]["pack"],
            "system_auth",
        )

    def test_builder_disables_security_pivots_without_exact_observable(self) -> None:
        row = {
            "alert_id": ".ds-logs-detections.alerts-so-2026.07.24-000001:sigma-empty",
            "alert_json": json.dumps(
                {
                    "elastic_index": ".ds-logs-detections.alerts-so-2026.07.24-000001",
                    "elastic_id": "sigma-empty",
                }
            ),
            "raw_event_json": json.dumps(
                {"event": {"dataset": "sigma.alert"}}
            ),
            "source_ip": None,
            "destination_ip": None,
            "timestamp": "2026-07-24T18:30:00Z",
            "first_seen": "2026-07-24T18:29:00Z",
            "last_seen": "2026-07-24T18:31:00Z",
        }

        capability, context = self.builder.investigation_query_context(
            row,
            [row],
            "sigma-empty-group",
            "incident-responder",
            False,
        )

        self.assertTrue(context["anchor"])
        self.assertFalse(any(context["permitted_observables"].values()))
        self.assertFalse(capability["enabled"])
        self.assertFalse(capability["backends"]["elastic"]["enabled"])
        self.assertFalse(capability["backends"]["oql"]["enabled"])

    def test_builder_clamps_recurring_group_authorization_around_selected_alert(self) -> None:
        selected = {
            "alert_id": ".ds-logs-suricata.alerts-so-2026.07.24-000001:alert-2",
            "alert_json": json.dumps({
                "elastic_index": ".ds-logs-suricata.alerts-so-2026.07.24-000001",
                "elastic_id": "alert-2",
            }),
            "source_ip": "192.0.2.10",
            "destination_ip": "198.51.100.20",
            "timestamp": "2026-07-24T18:30:00Z",
            "first_seen": "2026-07-01T00:00:00Z",
            "last_seen": "2026-07-24T18:30:00Z",
        }
        old_group_row = {
            **selected,
            "alert_id": "old-copy",
            "timestamp": "2026-01-01T00:00:00Z",
            "first_seen": "2026-01-01T00:00:00Z",
            "last_seen": "2026-01-01T00:00:00Z",
        }

        _capability, local = self.builder.investigation_query_context(
            selected,
            [selected, old_group_row],
            "long-running-group",
            "soc-analyst",
            False,
        )

        self.assertEqual(
            local["time_envelope"],
            {
                "start": "2026-07-23T18:30:00.000Z",
                "end": "2026-07-25T18:30:00.000Z",
            },
        )

    def test_builder_context_authorizes_a_real_broker_request(self) -> None:
        row = {
            "alert_id": ".ds-logs-suricata.alerts-so-2026.07.24-000001:alert-3",
            "alert_json": json.dumps({
                "elastic_index": ".ds-logs-suricata.alerts-so-2026.07.24-000001",
                "elastic_id": "alert-3",
            }),
            "source_ip": "192.0.2.10",
            "destination_ip": "198.51.100.20",
            "timestamp": "2026-07-24T18:30:00Z",
            "first_seen": "2026-07-24T18:29:00Z",
            "last_seen": "2026-07-24T18:31:00Z",
        }
        _capability, context = self.builder.investigation_query_context(
            row,
            [row],
            "group-3",
            "soc-analyst",
            False,
        )
        normalized = self.runner.normalize_investigation_query_request(
            self.elastic_request("real-contract"),
            round_number=1,
            position=1,
        )
        proposal = {
            "query_contract": self.runner.INVESTIGATION_QUERY_CONTRACT,
            "batch_id": "real-contract-batch",
            "queries": [
                {
                    "query_id": normalized["query_id"],
                    "dialect": normalized["backend"],
                    "pack": normalized["parameters"]["pack"],
                    "purpose": normalized["purpose"],
                    "window": normalized["parameters"]["window"],
                    "observables": normalized["parameters"]["observables"],
                    "size": normalized["parameters"]["size"],
                    "aggregation": normalized["parameters"]["aggregation"],
                }
            ],
        }

        authorized = self.contract.authorize_investigation_query_request(
            proposal,
            context,
        )

        self.assertEqual(authorized["authorization"]["actor_role"], "soc_analyst")
        self.assertEqual(
            authorized["queries"][0]["observable_provenance"]["ips"][0]["source"],
            "trusted_context",
        )


if __name__ == "__main__":
    unittest.main()
