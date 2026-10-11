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

class ProviderNeutralInvestigationLoopTestsHostedElasticHashProjectionIsIdempotentCases:
    def test_hosted_elastic_hash_projection_is_idempotent(self) -> None:
        certificate_digest = "d" * 64
        file_digest = "e" * 64
        general_digest = "f" * 64
        private_memory_digest = "1" * 64
        package = {
            "sha256": "top-level-local-artifact-digest",
            "agent_memory": {
                "records": [{
                    "kind": "operator-private-hash",
                    "sha256": private_memory_digest,
                }],
            },
            "analyst_state": {
                "arbitrary": {
                    "hash": {
                        "sha256": private_memory_digest,
                    },
                },
            },
            "investigation_query_results": {
                "rounds": [{
                    "results": [{
                        "backend": "security_onion",
                        "evidence": {
                            "unreviewed": {
                                "hash": {
                                    "sha256": private_memory_digest,
                                },
                            },
                            "spoofed_list_path": {
                                "hits": {
                                    "[]": {
                                        "source": {
                                            "hash": {
                                                "sha256": (
                                                    private_memory_digest
                                                ),
                                            },
                                        },
                                    },
                                },
                            },
                            "records": [],
                            "rows": [],
                            "results": [{
                                "hits": [{
                                    "id": "tls-hit",
                                    "index": "logs-zeek-so",
                                    "source": {
                                        "hash": {
                                            "sha256": general_digest,
                                        },
                                        "file": {
                                            "hash": {
                                                "sha256": file_digest,
                                            },
                                            "path": "/private/evidence.bin",
                                        },
                                        "tls": {
                                            "server": {
                                                "hash": {
                                                    "sha256": certificate_digest,
                                                },
                                            },
                                        },
                                        "message": "password=TOPSECRET",
                                    },
                                }, {
                                    "id": "invalid-hash",
                                    "source": {
                                        "hash": {
                                            "sha256": "not-a-canonical-hash",
                                        },
                                    },
                                }],
                            }],
                        },
                    }],
                }],
            },
        }

        first = self.runner.model_safe_copy(package, hosted=True)
        second = self.runner.model_safe_copy(first, hosted=True)

        self.assertEqual(first, second)
        self.assertNotIn("sha256", first)
        encoded = json.dumps(first, sort_keys=True)
        self.assertIn(certificate_digest, encoded)
        self.assertIn(file_digest, encoded)
        self.assertIn(general_digest, encoded)
        self.assertNotIn("TOPSECRET", encoded)
        self.assertNotIn("/private/evidence.bin", encoded)
        self.assertNotIn("not-a-canonical-hash", encoded)
        self.assertNotIn(private_memory_digest, encoded)
        self.assertNotIn(
            "sha256",
            first["agent_memory"]["records"][0],
        )
        self.assertNotIn(
            "sha256",
            first["analyst_state"]["arbitrary"]["hash"],
        )
        source = (
            first["investigation_query_results"]["rounds"][0]["results"][0]
            ["evidence"]["results"][0]["hits"][0]["source"]
        )
        evidence = (
            first["investigation_query_results"]["rounds"][0]["results"][0]
            ["evidence"]
        )
        self.assertEqual(evidence["records"], [])
        self.assertEqual(evidence["rows"], [])
        self.assertNotIn(
            "sha256",
            evidence["unreviewed"]["hash"],
        )
        self.assertNotIn(
            "sha256",
            evidence["spoofed_list_path"]["hits"]["[]"]["source"]["hash"],
        )
        self.assertEqual(source["hash"]["sha256"], general_digest)
        self.assertEqual(source["file"]["hash"]["sha256"], file_digest)
        self.assertEqual(
            source["tls"]["server"]["hash"]["sha256"],
            certificate_digest,
        )


    def test_memory_context_contract_is_identical_across_provider_transports(self) -> None:
        package = {
            "agent_role": "soc-analyst",
            "group_id": "group-provider-neutral",
            "alert": {"alert_id": "alert-provider-neutral"},
            "_local_investigation_query_context": {
                "case_id": "investigation-provider-neutral",
            },
            "evidence_reference_contract": {
                "schema": "onion-sentinel-evidence-reference-contract-v1",
                "references": [],
            },
            "agent_memory": {
                "role_memory": {
                    "snapshot": {
                        "schema": "onion-sentinel-agent-memory-snapshot-v1",
                        "source_digest": "1" * 64,
                        "selected_records_digest": "2" * 64,
                        "selected_record_versions": [],
                    },
                },
                "shared_memory": {
                    "snapshot": {
                        "schema": "onion-sentinel-agent-memory-snapshot-v1",
                        "source_digest": "3" * 64,
                        "selected_records_digest": "4" * 64,
                        "selected_record_versions": [],
                    },
                },
            },
        }
        self.runner.attach_agent_memory_context_contract(
            package,
            evaluation_frozen=True,
        )

        local = self.runner.model_safe_copy(copy.deepcopy(package), hosted=False)
        hosted = self.runner.model_safe_copy(copy.deepcopy(package), hosted=True)

        self.assertEqual(
            local["memory_context_contract"],
            hosted["memory_context_contract"],
        )
        self.assertEqual(
            local["memory_context_contract"]["contract_digest"],
            package["memory_context_contract"]["contract_digest"],
        )


    def test_hosted_synchronization_is_transactional_and_reaches_fixed_point(
        self,
    ) -> None:
        prompt_package = {
            "investigation_query_results": {
                "rounds": [{
                    "results": [{
                        "backend": "security_onion",
                        "evidence": {
                            "results": [{
                                "hits": [{
                                    "source": {
                                        "tls": {
                                            "server": {
                                                "hash": {"sha256": "e" * 64},
                                            },
                                        },
                                    },
                                }],
                            }],
                        },
                    }],
                }],
            },
            "evidence_reference_contract": {
                "schema": "stale-contract",
                "references": [],
            },
        }

        self.runner.synchronize_hosted_investigation_contract(prompt_package)
        synchronized = copy.deepcopy(prompt_package)
        transported = self.runner.model_safe_copy(
            prompt_package,
            hosted=True,
        )
        self.assertEqual(
            prompt_package["investigation_query_results"],
            transported["investigation_query_results"],
        )
        self.assertEqual(
            prompt_package["evidence_reference_contract"],
            transported["evidence_reference_contract"],
        )
        self.runner.synchronize_hosted_investigation_contract(prompt_package)
        self.assertEqual(prompt_package, synchronized)

        original = copy.deepcopy(prompt_package)

        def nonconvergent_transport(value, *, hosted=False, **_kwargs):
            output = copy.deepcopy(value)
            current = (
                value.get("investigation_query_results", {}).get(
                    "transport_generation",
                    0,
                )
                if isinstance(
                    value.get("investigation_query_results"),
                    dict,
                )
                else 0
            )
            output["investigation_query_results"] = {
                "transport_generation": 0 if current == 1 else 1,
            }
            output["evidence_reference_contract"] = {
                "schema": "synthetic-nonconvergent",
                "references": [],
            }
            return output

        with mock.patch.object(
            self.runner,
            "model_safe_copy",
            side_effect=nonconvergent_transport,
        ):
            with self.assertRaisesRegex(
                self.runner.InvestigationQueryError,
                "did not reach a fixed point",
            ):
                self.runner.synchronize_hosted_investigation_contract(
                    prompt_package
                )
        self.assertEqual(prompt_package, original)


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


    def test_normalizer_projects_only_provenance_verified_pack_tuple_fields(
        self,
    ) -> None:
        trusted_tuple = {
            "source_ip": "192.0.2.10",
            "destination_ip": "198.51.100.20",
            "source_port": 49152,
            "destination_port": 443,
            "transport": "tcp",
            "protocol": "tls",
            "community_id": "1:trusted-flow=",
            "rule_id": "2016150",
        }
        context = {
            "permitted_event_tuples": [
                {
                    "event_tuple": trusted_tuple,
                    "role_semantics": "packet_direction",
                    "source": "trusted_context",
                    "evidence_ref": "context:event-tuple:flow-1",
                }
            ]
        }
        request = self.elastic_request("pack-projection")
        request["parameters"]["pack"] = "zeek_tls"
        request["parameters"]["observables"]["ips"].append(
            "198.51.100.20"
        )
        request["parameters"]["event_tuple"] = dict(trusted_tuple)

        normalized = self.runner.normalize_investigation_query_request(
            request,
            round_number=1,
            position=1,
            authorization_context=context,
        )

        self.assertEqual(
            normalized["parameters"]["event_tuple"],
            {
                key: value
                for key, value in trusted_tuple.items()
                if key != "rule_id"
            },
        )
        audit = normalized["normalization"]["event_tuple_projection"]
        self.assertTrue(audit["provenance_verified"])
        self.assertTrue(audit["projection_applied"])
        self.assertEqual(
            audit["dropped_pack_unavailable_fields"],
            ["rule_id"],
        )
        self.assertEqual(
            audit["executed_fields"],
            sorted(set(trusted_tuple).difference({"rule_id"})),
        )
        self.assertEqual(
            audit["match_semantics"],
            "community_id_cross_sensor",
        )
        self.assertRegex(audit["trusted_tuple_digest"], r"^[a-f0-9]{64}$")
        serialized_audit = json.dumps(audit, sort_keys=True)
        self.assertNotIn("192.0.2.10", serialized_audit)
        self.assertNotIn("198.51.100.20", serialized_audit)
        self.assertNotIn("1:trusted-flow=", serialized_audit)

        request["parameters"]["event_tuple"]["destination_port"] = 8443
        with self.assertRaisesRegex(
            self.runner.InvestigationQueryError,
            "trusted role-aware tuple",
        ):
            self.runner.normalize_investigation_query_request(
                request,
                round_number=1,
                position=1,
                authorization_context=context,
            )


    def test_system_auth_tuple_projection_drops_unavailable_destination_role(
        self,
    ) -> None:
        trusted_tuple = {
            "source_ip": "192.0.2.10",
            "destination_ip": "198.51.100.20",
            "source_port": 49152,
            "destination_port": 22,
            "transport": "tcp",
            "protocol": "ssh",
            "community_id": "1:trusted-ssh=",
            "rule_id": "ssh-rule",
        }
        request = self.elastic_request("system-auth-projection")
        request["parameters"]["pack"] = "system_auth"
        request["parameters"]["event_tuple"] = dict(trusted_tuple)
        normalized = self.runner.normalize_investigation_query_request(
            request,
            round_number=1,
            position=1,
            authorization_context={
                "permitted_event_tuples": [
                    {
                        "event_tuple": trusted_tuple,
                        "role_semantics": "packet_direction",
                    }
                ]
            },
        )

        self.assertEqual(
            normalized["parameters"]["event_tuple"],
            {
                "source_ip": "192.0.2.10",
                "source_port": 49152,
            },
        )
        audit = normalized["normalization"]["event_tuple_projection"]
        self.assertEqual(
            audit["dropped_pack_unavailable_fields"],
            [
                "community_id",
                "destination_ip",
                "destination_port",
                "protocol",
                "rule_id",
                "transport",
            ],
        )


    def test_query_loop_executes_only_the_pack_projected_trusted_tuple(
        self,
    ) -> None:
        trusted_tuple = {
            "source_ip": "192.0.2.10",
            "destination_ip": "198.51.100.20",
            "source_port": 49152,
            "destination_port": 443,
            "transport": "tcp",
            "protocol": "tls",
            "community_id": "1:loop-trusted-flow=",
            "rule_id": "2016150",
        }
        request = self.elastic_request("loop-pack-projection")
        request["parameters"]["pack"] = "zeek_tls"
        request["parameters"]["observables"]["ips"].append(
            "198.51.100.20"
        )
        request["parameters"]["event_tuple"] = dict(trusted_tuple)
        prompt_package = {
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
                    "id": "alert-loop-pack-projection",
                },
                "permitted_event_tuples": [
                    {
                        "event_tuple": trusted_tuple,
                        "role_semantics": "packet_direction",
                        "source": "trusted_context",
                    }
                ],
            },
        }
        executed: list[dict] = []

        def query_executor(_package, requests, **kwargs):
            executed.extend(copy.deepcopy(requests))
            return self.successful_security_onion_round(
                requests,
                round_number=kwargs["round_number"],
            )

        response = self.runner.apply_investigation_query_loop(
            prompt_package,
            {"investigation_query_requests": [request]},
            object(),
            {
                "agent_models": {
                    "soc-analyst": "codex-cli:gpt-5.5:medium"
                }
            },
            "soc-analyst",
            model_executor=mock.Mock(
                return_value={"summary": "Projected evidence synthesized."}
            ),
            query_executor=query_executor,
        )

        self.assertEqual(len(executed), 1)
        self.assertNotIn(
            "rule_id",
            executed[0]["parameters"]["event_tuple"],
        )
        projection = executed[0]["normalization"][
            "event_tuple_projection"
        ]
        self.assertTrue(projection["provenance_verified"])
        self.assertEqual(
            projection["dropped_pack_unavailable_fields"],
            ["rule_id"],
        )
        self.assertEqual(
            response["_investigation_query_audit"]["rounds"][0][
                "request_normalizations"
            ][0]["normalization"]["event_tuple_projection"],
            projection,
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


