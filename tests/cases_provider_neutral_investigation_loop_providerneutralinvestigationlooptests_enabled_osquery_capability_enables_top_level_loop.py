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

class ProviderNeutralInvestigationLoopTestsEnabledOsqueryCapabilityEnablesTopLevelLoopCases:
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
                        "target_bindings": {
                            "endpoint-a": {
                                "ips": ["192.0.2.10"],
                            }
                        },
                        "relay_host": "relay.internal",
                        "identity_file": "/private/identity",
                    },
                ),
            ):
                config = self.runner.prepare_live_osquery_context(
                    prompt_package,
                    "soc-analyst",
                    config_path=config_path,
                )

        self.assertTrue(config["enabled"])
        self.assertTrue(prompt_package["investigation_query_capability"]["enabled"])
        self.assertTrue(
            prompt_package["investigation_query_capability"]["backends"]["osquery"]["enabled"]
        )
        top_level = prompt_package["live_osquery_capability"]
        nested = prompt_package["investigation_query_capability"]["backends"]["osquery"]
        for descriptor in (top_level, nested):
            self.assertEqual(descriptor["target_platform"], "darwin")
            self.assertEqual(descriptor["osquery_version"], "5.15.0")
            self.assertIn("system_info", descriptor["table_schemas"])
            self.assertIn("hostname", descriptor["table_schemas"]["system_info"])
            self.assertNotIn("deb_packages", descriptor["allowed_tables"])
            self.assertNotIn("suid_bin", descriptor["allowed_tables"])
        transported = self.runner.model_safe_copy(prompt_package, hosted=True)
        self.assertEqual(
            transported["live_osquery_capability"]["table_schemas"],
            top_level["table_schemas"],
        )
        encoded = json.dumps(transported, sort_keys=True)
        for forbidden in (
            "target_bindings",
            "relay.internal",
            "/private/identity",
            "192.0.2.10",
        ):
            self.assertNotIn(forbidden, encoded)


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
                    scoped = self.runner.prepare_live_osquery_context(
                        package,
                        role,
                        config_path=config_path,
                    )
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
        self.assertEqual(soc_package["live_osquery_capability"]["target_platform"], "")
        self.assertEqual(soc_package["live_osquery_capability"]["osquery_version"], "")
        self.assertEqual(soc_package["live_osquery_capability"]["table_schemas"], {})
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
