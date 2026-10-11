from __future__ import annotations

from provider_neutral_investigation_loop_fixtures import (
    BIN_DIR,
    Path,
    REPO_ROOT,
    RecordingHarness,
    argparse,
    ast,
    copy,
    hashlib,
    importlib,
    json,
    load_module,
    mock,
    sys,
    tempfile,
    unittest,
)

class ProviderNeutralInvestigationLoopTestsSecurityPreflightIsolatesOneInvalidObservableCases:
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
            "permitted_enrichment_indicators": {
                "ip": ["192.0.2.10"],
                "domain": [],
                "url": [],
                "hash": [],
                "cve": [],
            },
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
        forwarded_context = security.call_args.args[1]
        self.assertNotIn(
            "permitted_enrichment_indicators",
            forwarded_context,
        )
        self.assertIn("permitted_enrichment_indicators", context)
        rejected = next(
            item for item in result["results"]
            if item.get("query_id") == "invalid"
        )
        self.assertEqual(rejected["status"], "rejected")
        self.assertIn("isolated local authorization", rejected["error"])


    def test_security_context_projection_rejects_unknown_local_fields(self) -> None:
        with self.assertRaisesRegex(
            self.runner.InvestigationQueryContractError,
            "unsupported fields: unexpected",
        ):
            self.runner.security_onion_authorization_context(
                {"unexpected": True}
            )


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


    def test_outcome_summary_marks_successful_repair_as_resolved(self) -> None:
        summary = self.runner.investigation_query_outcome_summary(
            [
                {
                    "requests": [],
                    "results": [
                        {
                            "query_id": "repaired-query",
                            "backend": "contract",
                            "status": "rejected",
                        },
                    ],
                },
                {
                    "requests": [],
                    "results": [
                        {
                            "query_id": "repaired-query",
                            "backend": "security_onion",
                            "status": "ok",
                        },
                    ],
                },
            ],
            queries_admitted=2,
        )

        self.assertEqual(summary["successful_queries"], 1)
        self.assertEqual(summary["rejected_queries"], 1)
        self.assertEqual(
            summary["resolved_retry_query_ids"],
            ["repaired-query"],
        )
        self.assertEqual(summary["resolved_non_success_attempts"], 1)
        self.assertEqual(summary["unresolved_non_success_attempts"], 0)
        self.assertEqual(summary["evidence_gaps"], [])


    def test_binding_summary_marks_successful_bounded_repair_complete(self) -> None:
        summary = self.runner.investigation_query_binding_summary(
            [
                {
                    "query_id": "repaired-query",
                    "normalized_status": "rejected",
                    "read_only": True,
                },
                {
                    "query_id": "repaired-query",
                    "normalized_status": "ok",
                    "read_only": True,
                },
            ],
            queries_admitted=2,
        )

        self.assertTrue(summary["complete"])
        self.assertTrue(summary["evaluation_requirement_satisfied"])


    def test_binding_summary_keeps_unrepaired_rejection_incomplete(self) -> None:
        summary = self.runner.investigation_query_binding_summary(
            [
                {
                    "query_id": "unrepaired-query",
                    "normalized_status": "rejected",
                    "read_only": True,
                },
            ],
            queries_admitted=1,
        )

        self.assertFalse(summary["complete"])


    def test_mixed_batch_uses_injected_read_only_brokers(self) -> None:
        prompt_package = {
            "_local_investigation_query_context": {
                "case_id": "investigation-test",
                "anchor": {
                    "index": ".ds-logs-suricata.alerts-so-2026.07.24-000001",
                    "id": "alert-1",
                },
                "permitted_observables": {
                    "ips": ["192.0.2.10"],
                    "domains": [],
                    "hosts": [],
                    "users": [],
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
        live_query = "SELECT name, path FROM processes LIMIT 20;"
        live_purpose = (
            "Check the endpoint process inventory for the suspected binary."
        )
        osquery = mock.Mock(
            return_value={
                "schema": self.runner.LIVE_OSQUERY_SCHEMA,
                "case_id": self.runner.live_osquery_case_id(prompt_package),
                "generated_at": "2026-07-24T18:31:00Z",
                "read_only": True,
                "complete": True,
                "results": [
                    {
                        "status": "ok",
                        "target_alias": "endpoint-a",
                        "query": live_query,
                        "purpose": live_purpose,
                        "rows": [
                            {
                                "name": "synthetic",
                                "path": "/tmp/synthetic",
                            }
                        ],
                        "total_rows": 1,
                        "truncated": False,
                        "duration_ms": 12,
                        "error": "",
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
            live_osquery_config={
                "enabled": True,
                "target_bindings": {
                    "endpoint-a": {
                        "ips": ["192.0.2.10"],
                        "hosts": [],
                    }
                },
            },
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
        osquery_result = next(
            item for item in result["results"] if item["backend"] == "osquery"
        )
        self.assertEqual(osquery_result["status"], "ok")
        self.assertEqual(
            osquery_result["trusted_query_audit"][0]["returned_rows"],
            1,
        )
        accumulator = prompt_package["_live_osquery_evidence_accumulator"]
        self.assertTrue(accumulator["complete"])
        self.assertEqual(len(accumulator["batches"]), 1)
        self.assertEqual(len(accumulator["results"]), 1)
        self.assertNotIn(
            "_live_osquery_evidence_accumulator",
            self.runner.model_safe_copy(prompt_package),
        )
        live_audit = self.runner.incident_live_osquery_audit(prompt_package)
        self.assertEqual(
            live_audit["query_contract"],
            self.runner.LIVE_OSQUERY_SCHEMA,
        )
        self.assertEqual(live_audit["batches"], 1)
        self.assertEqual(live_audit["queries"][0]["returned_rows"], 1)
        self.assertEqual(
            live_audit["control_plane_write_status"],
            "confirmed",
        )
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


    def test_live_osquery_support_requires_target_and_row_observable_binding(
        self,
    ) -> None:
        prompt_package = {
            "_local_investigation_query_context": {
                "permitted_observables": {
                    "ips": ["192.0.2.10", "198.51.100.20"],
                    "domains": [],
                    "hosts": [],
                    "users": [],
                },
                "permitted_event_tuples": [
                    {
                        "event_tuple": {
                            "source_ip": "192.0.2.10",
                            "destination_ip": "198.51.100.20",
                            "destination_port": 443,
                        }
                    }
                ],
            }
        }
        raw = {
            "query_id": "socket-binding",
            "backend": "osquery",
            "purpose": "Bind an endpoint socket to the alert destination.",
            "parameters": {
                "target_alias": "endpoint-a",
                "query": (
                    "SELECT pid, remote_address, remote_port "
                    "FROM process_open_sockets LIMIT 5"
                ),
            },
        }
        request = self.runner.normalize_investigation_query_request(
            raw,
            round_number=1,
            position=1,
        )
        normalized_query = self.runner.normalize_live_osquery_query(
            raw["parameters"]["query"]
        )
        evidence = {
            "schema": self.runner.LIVE_OSQUERY_SCHEMA,
            "case_id": self.runner.live_osquery_case_id(prompt_package),
            "generated_at": "2026-07-24T18:31:00Z",
            "read_only": True,
            "complete": True,
            "results": [
                {
                    "target_alias": "endpoint-a",
                    "query": normalized_query,
                    "purpose": raw["purpose"],
                    "status": "ok",
                    "rows": [
                        {
                            "pid": "42",
                            "remote_address": "198.51.100.20",
                            "remote_port": "443",
                        }
                    ],
                    "total_rows": 1,
                    "truncated": False,
                    "duration_ms": 5,
                    "error": "",
                }
            ],
        }
        config = {
            "enabled": True,
            "target_bindings": {
                "endpoint-a": {
                    "ips": ["192.0.2.10"],
                    "hosts": [],
                }
            },
        }

        self.runner.execute_investigation_query_batch(
            prompt_package,
            [request],
            round_number=1,
            live_osquery_config=config,
            osquery_executor=mock.Mock(return_value=evidence),
        )

        accumulator = prompt_package["_live_osquery_evidence_accumulator"]
        supports = accumulator["results"][0]["support_bindings"]
        self.assertGreaterEqual(len(supports), 1)
        self.assertTrue(
            self.runner._has_trusted_endpoint_evidence(prompt_package)
        )

        accumulator["results"][0]["rows"][0]["remote_address"] = "203.0.113.9"
        accumulator["results"][0]["rows"][0]["remote_port"] = "8443"
        self.assertFalse(
            self.runner._has_trusted_endpoint_evidence(prompt_package)
        )


    def test_unbound_live_osquery_target_is_rejected_before_dispatch(self) -> None:
        raw = {
            "query_id": "unbound-target",
            "backend": "osquery",
            "purpose": "Inspect the wrong endpoint.",
            "parameters": {
                "target_alias": "endpoint-a",
                "query": "SELECT pid FROM processes LIMIT 1",
            },
        }
        request = self.runner.normalize_investigation_query_request(
            raw,
            round_number=1,
            position=1,
        )
        executor = mock.Mock()
        prompt_package = {
            "_local_investigation_query_context": {
                "permitted_observables": {
                    "ips": ["198.51.100.20"],
                    "domains": [],
                    "hosts": [],
                    "users": [],
                }
            }
        }
        result = self.runner.execute_investigation_query_batch(
            prompt_package,
            [request],
            round_number=1,
            live_osquery_config={
                "enabled": True,
                "target_bindings": {
                    "endpoint-a": {
                        "ips": ["192.0.2.10"],
                        "hosts": [],
                    }
                },
            },
            osquery_executor=executor,
        )

        executor.assert_not_called()
        self.assertEqual(result["results"][0]["status"], "error")
        audit = self.runner.incident_live_osquery_audit(prompt_package)
        self.assertEqual(audit["control_plane_write_status"], "none")
        self.assertIn("not bound", audit["error"])


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
