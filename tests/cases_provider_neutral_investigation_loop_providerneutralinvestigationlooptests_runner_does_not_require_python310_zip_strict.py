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

class ProviderNeutralInvestigationLoopTestsRunnerDoesNotRequirePython310ZipStrictCases:
    def test_runner_does_not_require_python310_zip_strict(self) -> None:
        tree = ast.parse(
            (BIN_DIR / "run-local-ai-analysis.py").read_text(
                encoding="utf-8",
            )
        )
        incompatible_calls = [
            node.lineno
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "zip"
            and any(keyword.arg == "strict" for keyword in node.keywords)
        ]
        self.assertEqual(incompatible_calls, [])


    def test_runner_accepts_only_builder_normalized_campaign_authorization(
        self,
    ) -> None:
        selected = {
            "alert_id": "fixture-alert",
            "alert_json": "{}",
            "timestamp": "2026-07-31T23:10:00Z",
            "first_seen": "2026-07-31T23:10:00Z",
            "last_seen": "2026-07-31T23:10:00Z",
            "rule_id": "2003068",
            "source_ip": "10.77.7.222",
            "source_port": 41000,
            "destination_ip": "192.0.2.20",
            "destination_port": 22,
            "transport_protocol": "tcp",
        }
        authorization = {
            "status": "operator_authorized",
            "policy_id": "authorized-ssh-scan",
            "source_ips": ["10.77.7.222"],
            "destination_ips": ["192.0.2.20"],
            "rule_ids": ["2003068"],
            "source_ports": [41000],
            "destination_ports": [22],
            "destination_port_ranges": [],
            "transport_protocols": ["tcp"],
            "authorization_start": "2026-07-31T23:00:00Z",
            "authorization_end": "2026-07-31T23:20:00Z",
        }
        entry = self.builder.canonical_authorized_activity_entry(
            selected,
            authorization,
            policy_id="authorized-ssh-scan",
        )

        self.assertIsNotNone(entry)
        self.assertTrue(
            self.runner._has_structured_authorization_evidence(
                {
                    "alert": dict(selected),
                    "authorization_evidence": {
                        "status": "operator_authorized",
                        "entries": [entry],
                    }
                }
            )
        )

        mismatched = dict(selected)
        mismatched["destination_port"] = 23
        rejected = self.builder.canonical_authorized_activity_entry(
            mismatched,
            authorization,
            policy_id="authorized-ssh-scan",
        )
        self.assertIsNone(rejected)
        self.assertFalse(
            self.runner._has_structured_authorization_evidence(
                {"authorization_evidence": rejected}
            )
        )


    def test_incident_responder_protocol_plan_is_repeatable_and_truthful(
        self,
    ) -> None:
        trusted_tuple = {
            "source_ip": "192.0.2.10",
            "destination_ip": "198.51.100.20",
            "source_port": 49152,
            "destination_port": 80,
            "transport": "tcp",
            "community_id": "1:repeatable-http-flow=",
            "rule_id": "2013504",
        }
        package = {
            "agent_role": "incident-responder",
            "alert": {
                "timestamp": "2026-07-24T18:30:00Z",
                "rule_name": "Synthetic HTTP user-agent detection",
                "source_ip": "192.0.2.10",
                "source_port": 49152,
                "destination_ip": "198.51.100.20",
                "destination_port": 80,
                "transport_protocol": "tcp",
                "rule_id": "2013504",
                "rule_context": {
                    "deployed_rule": {"protocol": "http"},
                },
            },
            "investigation_query_capability": {
                "enabled": True,
                "anchor_time": "2026-07-24T18:30:00Z",
                "backends": {
                    "elastic": {
                        "enabled": True,
                        "packs": ["zeek_http", "zeek_files"],
                    },
                },
            },
            "_local_investigation_query_context": {
                "anchor_time": "2026-07-24T18:30:00Z",
                "permitted_event_tuples": [
                    {
                        "event_tuple": {
                            "source_ip": "192.0.2.99",
                            "destination_ip": "198.51.100.99",
                            "source_port": 40000,
                            "destination_port": 80,
                            "transport": "tcp",
                            "community_id": "1:historical-decoy-flow=",
                            "rule_id": "2013504",
                        },
                        "role_semantics": "packet_direction",
                        "source": "trusted_context",
                    },
                    {
                        "event_tuple": trusted_tuple,
                        "role_semantics": "packet_direction",
                        "source": "trusted_context",
                    },
                ],
            },
        }

        first = self.runner.deterministic_incident_pivot_requests(package)
        second = self.runner.deterministic_incident_pivot_requests(
            copy.deepcopy(package)
        )

        self.assertEqual(first, second)
        self.assertEqual(
            [item["query_id"] for item in first],
            ["deterministic-zeek_http", "deterministic-zeek_files"],
        )
        self.assertEqual(
            first[0]["parameters"]["window"],
            {
                "start": "2026-07-24T18:25:00.000Z",
                "end": "2026-07-24T18:35:00.000Z",
            },
        )
        self.assertEqual(
            first[0]["parameters"]["event_tuple"]["community_id"],
            trusted_tuple["community_id"],
        )
        serialized = json.dumps(first, sort_keys=True)
        self.assertNotIn("query_dsl", serialized)
        self.assertNotIn("kql", serialized.lower())
        self.assertNotIn("oql", serialized.lower())


    def test_protocol_plan_prefers_selected_raw_alert_over_group_peer(
        self,
    ) -> None:
        selected_tuple = {
            "source_ip": "192.0.2.10",
            "destination_ip": "198.51.100.20",
            "source_port": 49152,
            "destination_port": 443,
            "transport": "tcp",
            "protocol": "tls",
            "community_id": "1:selected-alert-flow=",
            "rule_id": "2026001",
        }
        peer_tuple = {
            **selected_tuple,
            "source_port": 40000,
            "community_id": "1:group-peer-flow=",
        }
        package = {
            "agent_role": "incident-responder",
            "alert": {
                "rule_name": "Synthetic TLS detection",
                # The normalized case summary can be sparse. The collector-owned
                # raw subset still identifies the exact selected alert.
                "source_ip": "192.0.2.10",
                "destination_ip": "198.51.100.20",
                "raw_alert_subset": {
                    "source": {"ip": "192.0.2.10", "port": 49152},
                    "destination": {
                        "ip": "198.51.100.20",
                        "port": 443,
                    },
                    "network": {
                        "transport": "tcp",
                        "protocol": "tls",
                        "community_id": "1:selected-alert-flow=",
                    },
                },
                "rule_context": {
                    "record_rule_id": "2026001",
                    "deployed_rule": {"protocol": "tls"},
                },
            },
            "investigation_query_capability": {
                "enabled": True,
                "anchor_time": "2026-07-24T18:30:00Z",
                "backends": {
                    "elastic": {
                        "enabled": True,
                        "packs": ["zeek_tls", "zeek_anomalies"],
                    },
                },
            },
            "_local_investigation_query_context": {
                "anchor_time": "2026-07-24T18:30:00Z",
                "permitted_event_tuples": [
                    {
                        "event_tuple": peer_tuple,
                        "role_semantics": "packet_direction",
                    },
                    {
                        "event_tuple": selected_tuple,
                        "role_semantics": "packet_direction",
                    },
                ],
            },
        }

        plan = self.runner.deterministic_incident_pivot_requests(package)

        self.assertEqual(len(plan), 2)
        for request in plan:
            self.assertEqual(
                request["parameters"]["event_tuple"]["community_id"],
                selected_tuple["community_id"],
            )
            self.assertEqual(
                request["parameters"]["event_tuple"]["source_port"],
                selected_tuple["source_port"],
            )


    def test_protocol_plan_omits_unsafe_cross_sensor_tuple_without_join_key(
        self,
    ) -> None:
        package = {
            "agent_role": "incident-responder",
            "alert": {
                "rule_name": "Synthetic STUN request",
                "rule_context": {
                    "deployed_rule": {"protocol": "udp"},
                },
            },
            "investigation_query_capability": {
                "enabled": True,
                "anchor_time": "2026-07-24T18:30:00Z",
                "backends": {
                    "elastic": {
                        "enabled": True,
                        "packs": ["zeek_stun", "network_flow"],
                    },
                },
            },
            "_local_investigation_query_context": {
                "permitted_event_tuples": [
                    {
                        "event_tuple": {
                            "source_ip": "192.0.2.10",
                            "destination_ip": "198.51.100.20",
                            "source_port": 50000,
                            "destination_port": 3478,
                            "transport": "udp",
                        },
                        "role_semantics": "packet_direction",
                    },
                ],
            },
        }

        plan = self.runner.deterministic_incident_pivot_requests(package)

        self.assertEqual(len(plan), 2)
        self.assertNotIn("event_tuple", plan[0]["parameters"])
        self.assertNotIn("event_tuple", plan[1]["parameters"])
        self.assertEqual(
            plan[0]["parameters"]["observables"]["ips"],
            ["192.0.2.10", "198.51.100.20"],
        )


    def test_protocol_plan_derives_v1_anchor_from_authorized_envelope(
        self,
    ) -> None:
        package = {
            "agent_role": "incident-responder",
            "alert": {
                "timestamp": "2026-07-24  12:30:00-06:00",
                "rule_name": "Synthetic TLS SNI detection",
                "source_ip": "192.0.2.10",
                "destination_ip": "198.51.100.20",
                "rule_context": {
                    "deployed_rule": {"protocol": "tls"},
                },
            },
            "investigation_query_capability": {
                "enabled": True,
                "backends": {
                    "elastic": {
                        "enabled": True,
                        "packs": ["zeek_tls", "zeek_anomalies"],
                    },
                },
            },
            "_local_investigation_query_context": {
                "time_envelope": {
                    "start": "2026-07-23T18:30:00.000Z",
                    "end": "2026-07-25T18:30:00.000Z",
                },
                "permitted_event_tuples": [
                    {
                        "event_tuple": {
                            "source_ip": "192.0.2.10",
                            "destination_ip": "198.51.100.20",
                            "community_id": "1:v1-authorized-flow=",
                        },
                        "source": "trusted_context",
                        "evidence_ref": "context:v1-tuple",
                    },
                ],
            },
        }

        plan = self.runner.deterministic_incident_pivot_requests(package)

        self.assertEqual(len(plan), 2)
        self.assertEqual(
            plan[0]["parameters"]["window"],
            {
                "start": "2026-07-24T18:25:00.000Z",
                "end": "2026-07-24T18:35:00.000Z",
            },
        )


    def test_protocol_plan_adds_bounded_exact_pair_endpoint_attribution(
        self,
    ) -> None:
        package = {
            "agent_role": "incident-responder",
            "alert": {
                "timestamp": "2026-07-24T18:30:00Z",
                "rule_name": "Synthetic TLS SNI detection",
                "source_ip": "192.0.2.10",
                "destination_ip": "198.51.100.20",
                "rule_context": {
                    "deployed_rule": {"protocol": "tls"},
                },
            },
            "investigation_query_capability": {
                "enabled": True,
                "anchor_time": "2026-07-24T18:30:00Z",
                "backends": {
                    "elastic": {
                        "enabled": True,
                        "packs": [
                            "zeek_tls",
                            "zeek_anomalies",
                            "osquery_history",
                        ],
                    },
                },
            },
            "_local_investigation_query_context": {
                "anchor_time": "2026-07-24T18:30:00Z",
                "time_envelope": {
                    "start": "2026-07-24T12:00:00Z",
                    "end": "2026-07-25T00:00:00Z",
                },
                "permitted_event_tuples": [
                    {
                        "event_tuple": {
                            "source_ip": "192.0.2.10",
                            "destination_ip": "198.51.100.20",
                            "source_port": 49152,
                            "destination_port": 443,
                            "transport": "tcp",
                            "protocol": "tls",
                            "community_id": "1:exact-flow=",
                            "rule_id": "2026001",
                        },
                        "role_semantics": "packet_direction",
                    }
                ],
            },
        }

        plan = self.runner.deterministic_incident_pivot_requests(package)

        self.assertEqual(
            [item["query_id"] for item in plan],
            [
                "deterministic-zeek_tls",
                "deterministic-zeek_anomalies",
                "deterministic-osquery-history-attribution",
            ],
        )
        attribution = plan[-1]
        self.assertEqual(attribution["parameters"]["pack"], "osquery_history")
        self.assertEqual(
            attribution["parameters"]["aggregation"],
            "anchor_nearest",
        )
        self.assertEqual(
            attribution["parameters"]["window"],
            {
                "start": "2026-07-24T12:00:00.000Z",
                "end": "2026-07-25T00:00:00.000Z",
            },
        )
        self.assertEqual(
            attribution["parameters"]["event_tuple"],
            {
                "source_ip": "192.0.2.10",
                "destination_ip": "198.51.100.20",
                "destination_port": 443,
                "transport": "tcp",
            },
        )
        self.assertNotIn(
            "source_port",
            attribution["parameters"]["event_tuple"],
        )


    def test_soc_analyst_gets_only_justified_historical_endpoint_pivot(
        self,
    ) -> None:
        package = {
            "agent_role": "soc-analyst",
            "alert": {
                "timestamp": "2026-07-24T18:30:00Z",
                "rule_name": "Synthetic TLS SNI detection",
                "source_ip": "192.0.2.10",
                "destination_ip": "198.51.100.20",
                "rule_context": {
                    "deployed_rule": {"protocol": "tls"},
                },
            },
            "investigation_query_capability": {
                "enabled": True,
                "anchor_time": "2026-07-24T18:30:00Z",
                "backends": {
                    "elastic": {
                        "enabled": True,
                        "packs": [
                            "zeek_tls",
                            "zeek_anomalies",
                            "osquery_history",
                        ],
                    },
                    "osquery": {"enabled": False},
                },
            },
            "_local_investigation_query_context": {
                "anchor_time": "2026-07-24T18:30:00Z",
                "time_envelope": {
                    "start": "2026-07-24T12:00:00Z",
                    "end": "2026-07-25T00:00:00Z",
                },
                "permitted_event_tuples": [{
                    "event_tuple": {
                        "source_ip": "192.0.2.10",
                        "destination_ip": "198.51.100.20",
                        "destination_port": 443,
                        "transport": "tcp",
                        "protocol": "tls",
                        "community_id": "1:exact-soc-flow=",
                    },
                    "role_semantics": "packet_direction",
                }],
            },
        }

        plan = self.runner.deterministic_incident_pivot_requests(package)

        self.assertEqual(
            [item["query_id"] for item in plan],
            ["deterministic-osquery-history-attribution"],
        )
        self.assertEqual(plan[0]["backend"], "elastic")
        self.assertEqual(plan[0]["parameters"]["pack"], "osquery_history")
        self.assertFalse(
            package["investigation_query_capability"]["backends"]["osquery"][
                "enabled"
            ]
        )


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
