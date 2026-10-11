from __future__ import annotations

from investigation_query_pivots_fixtures import (
    ALERT_INDEX_SCOPE,
    BIN_DIR,
    BROKER_PATH,
    COLLECTOR_PATH,
    COMPAT_V1_COLLECTOR_PATH,
    EVENT_TUPLE_FIELDS,
    EVENT_TUPLE_PATHS,
    INVESTIGATION_QUERY_CONTRACT,
    InvestigationQueryContractError,
    OBSERVABLE_FIELDS,
    PACKS,
    Path,
    QUERY_AUTHORIZATION,
    QUERY_RESPONSE,
    RELAY_APP_DIR,
    REPO_ROOT,
    WRAPPER_PATH,
    authorize_investigation_query_request,
    build_query_dsl,
    canonical_digest,
    context,
    contextlib,
    controls_for,
    copy,
    hashlib,
    importlib,
    inspect,
    io,
    json,
    kql_equivalent,
    load_source_module,
    mock,
    oql_equivalent,
    proposal,
    query_endpoint,
    result_coverage,
    role_aware_context,
    role_aware_proposal,
    search_result_for,
    subprocess,
    sys,
    tempfile,
    unittest,
    valid_response,
    validate_investigation_query_response,
)

class InvestigationQueryContractTestsAuthorizationCompatibilitySurfaceAndSignaturesAreStableCases:
    def test_authorization_compatibility_surface_and_signatures_are_stable(self) -> None:
        names = sorted(
            name for name in vars(QUERY_AUTHORIZATION)
            if not name.startswith("__")
        )
        self.assertEqual(len(names), 67)
        self.assertEqual(
            hashlib.sha256("\n".join(names).encode("utf-8")).hexdigest(),
            "18d9e072355674eaab2750d2b1cd1ff7b8de8fa987cc27198bd197d82d727bf0",
        )
        self.assertIsNone(getattr(QUERY_AUTHORIZATION, "__all__", None))
        expected_signatures = {
            "authorize_investigation_query_request": "(proposal: 'object', authorization_context: 'object') -> 'dict[str, Any]'",
            "validate_investigation_query_request": "(payload: 'object', *, authorization_context: 'object | None' = None, allowed_observables: 'object | None' = None, allowed_windows: 'object | None' = None) -> 'dict[str, Any]'",
            "validate_authorized_investigation_query_request": "(payload: 'object') -> 'dict[str, Any]'",
        }
        self.assertEqual(
            {
                name: str(inspect.signature(getattr(QUERY_AUTHORIZATION, name)))
                for name in expected_signatures
            },
            expected_signatures,
        )


    def test_authorization_imports_from_an_isolated_flat_bin(self) -> None:
        sources = [
            BIN_DIR / name
            for name in (
                "investigation_query_schema.py",
                "investigation_query_normalization_primitives.py",
                "investigation_query_observable_normalization.py",
                "investigation_query_event_tuple_normalization.py",
                "investigation_query_authorization_normalization.py",
                "investigation_query_normalization.py",
                "investigation_query_authorization_adapter.py",
                "investigation_query_authorization_manifest.py",
                "investigation_query_authorization_proposal.py",
                "investigation_query_authorization_request.py",
                "investigation_query_authorization.py",
            )
        ]
        with tempfile.TemporaryDirectory() as directory:
            for source in sources:
                (Path(directory) / source.name).write_bytes(source.read_bytes())
            result = subprocess.run(
                [
                    sys.executable, "-I", "-B", "-c",
                    (
                        "import sys; sys.path.insert(0, sys.argv[1]); "
                        "import investigation_query_authorization"
                    ),
                    directory,
                ],
                text=True,
                capture_output=True,
                timeout=10,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)


    def test_response_compatibility_surface_and_signatures_are_stable(self) -> None:
        expected_names = {
            "ALLOWED_AGGREGATIONS", "ALLOWED_DIALECTS", "ALLOWED_PURPOSES",
            "EVENT_TUPLE_FIELDS", "EVENT_TUPLE_PATHS",
            "INVESTIGATION_QUERY_CONTRACT", "InvestigationQueryContractError",
            "SAFE_ATOM_RE", "authorize_investigation_query_request",
            "build_query_dsl", "canonical_digest", "kql_equivalent",
            "oql_equivalent", "pack_event_tuple_fields", "result_coverage",
            "tuple_match_semantics", "validate_pack_observables",
            "validate_authorized_investigation_query_request",
            "validate_investigation_query_request",
            "validate_investigation_query_response", "_leaf_items",
            "_path_values", "_observable_matches",
            "_event_tuple_value_matches", "_validate_hit_source",
            "_validate_pivot_result", "_validate_control",
            "_index_matches_scope", "_normalize_event_tuple",
            "_normalize_observable", "_parse_utc", "_require_exact_keys",
            "_require_mapping", "_event_tuple_query_fields",
            "_expected_execution_digest",
        }
        self.assertFalse(expected_names.difference(vars(QUERY_RESPONSE)))
        self.assertEqual(
            QUERY_RESPONSE.__all__,
            [
                "ALLOWED_AGGREGATIONS", "ALLOWED_DIALECTS",
                "ALLOWED_PURPOSES", "EVENT_TUPLE_FIELDS",
                "EVENT_TUPLE_PATHS", "INVESTIGATION_QUERY_CONTRACT",
                "InvestigationQueryContractError", "SAFE_ATOM_RE",
                "authorize_investigation_query_request", "build_query_dsl",
                "canonical_digest", "kql_equivalent", "oql_equivalent",
                "pack_event_tuple_fields", "result_coverage",
                "tuple_match_semantics", "validate_pack_observables",
                "validate_authorized_investigation_query_request",
                "validate_investigation_query_request",
                "validate_investigation_query_response",
            ],
        )
        expected_signatures = {
            "_leaf_items": "(value: 'object', prefix: 'str' = '') -> 'list[tuple[str, object]]'",
            "_path_values": "(source: 'dict[str, Any]', path: 'str') -> 'list[object]'",
            "_observable_matches": "(kind: 'str', expected: 'str', candidate: 'object') -> 'bool'",
            "_event_tuple_value_matches": "(field: 'str', expected: 'Any', candidate: 'object') -> 'bool'",
            "_validate_hit_source": "(source: 'object', expected_query: 'dict[str, Any]') -> 'None'",
            "result_coverage": "(query: 'dict[str, Any]', *, status: 'str', total_hits: 'int', total_hits_relation: 'str', returned_hits: 'int') -> 'dict[str, Any]'",
            "_validate_pivot_result": "(result: 'object', expected_query: 'dict[str, Any]') -> 'bool'",
            "_validate_control": "(value: 'object', *, anchor: 'dict[str, str]', positive: 'bool') -> 'bool'",
            "validate_investigation_query_response": "(response: 'object', request: 'object') -> 'dict[str, Any]'",
        }
        self.assertEqual(
            {
                name: str(inspect.signature(getattr(QUERY_RESPONSE, name)))
                for name in expected_signatures
            },
            expected_signatures,
        )


    def test_response_imports_from_an_isolated_flat_bin(self) -> None:
        sources = [
            BIN_DIR / name
            for name in (
                "investigation_query_schema.py",
                "historical_osquery_schema.py",
                "investigation_query_normalization_primitives.py",
                "investigation_query_observable_normalization.py",
                "investigation_query_event_tuple_normalization.py",
                "investigation_query_authorization_normalization.py",
                "investigation_query_normalization.py",
                "investigation_query_authorization_adapter.py",
                "investigation_query_authorization_manifest.py",
                "investigation_query_authorization_proposal.py",
                "investigation_query_authorization_request.py",
                "investigation_query_authorization.py",
                "investigation_query_rendering.py",
                "investigation_query_response_control.py",
                "investigation_query_response_result.py",
                "investigation_query_response_source.py",
                "investigation_query_response.py",
            )
        ]
        with tempfile.TemporaryDirectory() as directory:
            for source in sources:
                (Path(directory) / source.name).write_bytes(source.read_bytes())
            result = subprocess.run(
                [
                    sys.executable, "-I", "-B", "-c",
                    (
                        "import sys; sys.path.insert(0, sys.argv[1]); "
                        "import investigation_query_response"
                    ),
                    directory,
                ],
                text=True,
                capture_output=True,
                timeout=10,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)


    def test_authorizes_base_and_evidence_discovered_observables(self) -> None:
        request = authorize_investigation_query_request(proposal(), context())

        provenance = request["queries"][0]["observable_provenance"]
        self.assertEqual(provenance["ips"][0]["source"], "trusted_context")
        self.assertEqual(provenance["domains"][0], {
            "kind": "domains",
            "value": "example.test",
            "source": "prior_evidence",
            "evidence_ref": "elastic:prior-query:hit-1",
        })
        self.assertEqual(
            request["authorization"]["manifest_digest"],
            canonical_digest({
                key: value
                for key, value in request["authorization"].items()
                if key != "manifest_digest"
            }),
        )


    def test_model_cannot_supply_dsl_indices_fields_or_shell(self) -> None:
        for field, value in (
            ("query_dsl", {"match_all": {}}),
            ("indices", ["*"]),
            ("fields", ["*"]),
            ("shell", "id"),
        ):
            candidate = proposal()
            candidate["queries"][0][field] = value
            with self.subTest(field=field), self.assertRaises(
                InvestigationQueryContractError
            ):
                authorize_investigation_query_request(candidate, context())


    def test_untrusted_new_observable_and_out_of_envelope_window_fail(self) -> None:
        candidate = proposal()
        candidate["queries"][0]["observables"]["domains"] = ["untrusted.test"]
        with self.assertRaisesRegex(
            InvestigationQueryContractError,
            "outside its trusted authorization context",
        ):
            authorize_investigation_query_request(candidate, context())

        candidate = proposal()
        candidate["queries"][0]["window"]["end"] = "2026-07-24T17:00:00.000Z"
        with self.assertRaisesRegex(InvestigationQueryContractError, "time envelope"):
            authorize_investigation_query_request(candidate, context())


    def test_anchor_index_cannot_expand_the_exact_positive_control_scope(self) -> None:
        candidate_context = context()
        candidate_context["anchor"]["index"] = (
            ".ds-logs-suricata.alerts-so-2026.07.24-000001,"
            "logs-endpoint.events.process-default"
        )

        with self.assertRaisesRegex(
            InvestigationQueryContractError,
            "anchor index",
        ):
            authorize_investigation_query_request(proposal(), candidate_context)


    def test_real_oql_and_compiled_dsl_are_built_locally(self) -> None:
        query = authorize_investigation_query_request(
            proposal(), context()
        )["queries"][0]
        rendered = oql_equivalent(query)
        dsl = build_query_dsl(query)

        self.assertIn('dns.question.name:"example.test"', rendered)
        self.assertIn("| sortby @timestamp^", rendered)
        self.assertNotIn("==", rendered)
        self.assertEqual(
            dsl["sort"][0]["@timestamp"]["order"],
            "asc",
        )
        self.assertEqual(
            dsl["_source"],
            PACKS["dns_activity"]["fields"],
        )


    def test_role_aware_event_tuple_is_provenance_bound_and_anded(self) -> None:
        request = authorize_investigation_query_request(
            role_aware_proposal(),
            role_aware_context(),
        )
        query = request["queries"][0]
        expected_tuple = role_aware_context()["permitted_event_tuples"][0][
            "event_tuple"
        ]
        self.assertEqual(query["event_tuple"], expected_tuple)
        self.assertEqual(
            query["event_tuple_provenance"],
            request["authorization"]["event_tuples"][0],
        )

        dsl = build_query_dsl(query)
        tuple_filter = dsl["query"]["bool"]["filter"][3]["bool"]["filter"]
        self.assertEqual(
            tuple_filter,
            [
                (
                    {"term": {EVENT_TUPLE_PATHS[field][0]: value}}
                    if len(EVENT_TUPLE_PATHS[field]) == 1
                    else {
                        "bool": {
                            "should": [
                                {"term": {path: value}}
                                for path in EVENT_TUPLE_PATHS[field]
                            ],
                            "minimum_should_match": 1,
                        }
                    }
                )
                for field, value in expected_tuple.items()
            ],
        )
        kql = kql_equivalent(query)
        oql = oql_equivalent(query)
        for text in (
            'source.ip : "192.0.2.10"',
            'destination.ip : "198.51.100.20"',
            "source.port : 49152",
            "destination.port : 443",
            'network.transport : "tcp"',
            'network.protocol : "tls"',
            'network.community_id : "1:trusted-flow="',
            'rule.id : "2016150"',
            'rule.uuid : "2016150"',
        ):
            self.assertIn(text, kql)
            self.assertIn(text.replace(" : ", ":"), oql)


    def test_event_tuple_cannot_swap_roles_or_cross_product_trusted_rows(self) -> None:
        candidate = role_aware_proposal()
        candidate["queries"][0]["event_tuple"].update({
            "source_ip": "198.51.100.20",
            "destination_ip": "192.0.2.10",
        })
        with self.assertRaisesRegex(
            InvestigationQueryContractError,
            "trusted role-aware event tuple",
        ):
            authorize_investigation_query_request(candidate, role_aware_context())

        candidate_context = role_aware_context()
        candidate_context["permitted_event_tuples"].append({
            "event_tuple": {
                "source_ip": "203.0.113.30",
                "destination_ip": "192.0.2.10",
                "destination_port": 53,
                "transport": "udp",
                "protocol": "dns",
            },
            "role_semantics": "packet_direction",
            "source": "trusted_context",
            "evidence_ref": "context:event-tuple:second-flow",
        })
        candidate_context["permitted_observables"]["ips"].append("203.0.113.30")
        candidate = role_aware_proposal()
        candidate["queries"][0]["observables"]["ips"].append("203.0.113.30")
        candidate["queries"][0]["event_tuple"] = {
            "source_ip": "203.0.113.30",
            "destination_ip": "198.51.100.20",
        }
        with self.assertRaisesRegex(
            InvestigationQueryContractError,
            "trusted role-aware event tuple",
        ):
            authorize_investigation_query_request(candidate, candidate_context)


    def test_event_tuple_rejects_unauthorized_or_unprojected_constraints(self) -> None:
        candidate = role_aware_proposal()
        candidate["queries"][0]["event_tuple"]["destination_port"] = 8443
        with self.assertRaisesRegex(
            InvestigationQueryContractError,
            "trusted role-aware event tuple",
        ):
            authorize_investigation_query_request(candidate, role_aware_context())

        candidate = role_aware_proposal()
        candidate["queries"][0]["event_tuple"]["community_id"] = (
            '1:trusted-flow=" OR *'
        )
        with self.assertRaisesRegex(
            InvestigationQueryContractError,
            "community_id is invalid",
        ):
            authorize_investigation_query_request(candidate, role_aware_context())

        candidate = role_aware_proposal()
        candidate["queries"][0]["event_tuple"] = {
            "destination_port": 443,
            "transport": "tcp",
        }
        with self.assertRaisesRegex(
            InvestigationQueryContractError,
            "source or destination IP role",
        ):
            authorize_investigation_query_request(candidate, role_aware_context())

        candidate = role_aware_proposal()
        candidate["queries"][0]["pack"] = "system_auth"
        candidate["queries"][0]["event_tuple"] = {"rule_id": "2016150"}
        with self.assertRaisesRegex(
            InvestigationQueryContractError,
            "unavailable in pack",
        ):
            authorize_investigation_query_request(candidate, role_aware_context())


    def test_system_auth_and_zeek_protocol_packs_compile_exact_fields(self) -> None:
        auth_proposal = proposal()
        auth_proposal["queries"][0].update(
            {
                "dialect": "elastic",
                "pack": "system_auth",
                "observables": {
                    "ips": ["192.0.2.10"],
                    "domains": [],
                    "hosts": [],
                    "users": [],
                },
                "aggregation": "events",
            }
        )
        auth_query = authorize_investigation_query_request(
            auth_proposal,
            context(),
        )["queries"][0]
        auth_dsl = build_query_dsl(auth_query)
        self.assertEqual(
            auth_dsl["_source"],
            PACKS["system_auth"]["fields"],
        )
        self.assertNotIn("message", auth_dsl["_source"])
        self.assertIn(
            {"term": {"event.dataset": "system.auth"}},
            auth_dsl["query"]["bool"]["filter"][1]["bool"]["should"],
        )

        tls_context = context()
        tls_proposal = proposal()
        tls_proposal["queries"][0].update(
            {
                "pack": "zeek_tls",
                "observables": {
                    "ips": [],
                    "domains": ["example.test"],
                    "hosts": [],
                    "users": [],
                },
                "aggregation": "events",
            }
        )
        tls_query = authorize_investigation_query_request(
            tls_proposal,
            tls_context,
        )["queries"][0]
        tls_dsl = build_query_dsl(tls_query)
        observable_terms = tls_dsl["query"]["bool"]["filter"][2]["bool"][
            "should"
        ]
        self.assertIn(
            {"term": {"ssl.server_name": "example.test"}},
            observable_terms,
        )
        self.assertNotIn(
            {"term": {"dns.query.name": "example.test"}},
            observable_terms,
        )


    def test_pack_rejects_observable_kinds_it_cannot_query(self) -> None:
        candidate_context = context()
        candidate_context["permitted_observables"] = {
            "ips": [],
            "domains": [],
            "hosts": ["host-only"],
            "users": [],
        }
        candidate_context["discovered_observables"] = []
        candidate = proposal()
        candidate["queries"][0].update({
            "pack": "zeek_tls",
            "observables": {
                "ips": [],
                "domains": [],
                "hosts": ["host-only"],
                "users": [],
            },
        })

        with self.assertRaisesRegex(
            InvestigationQueryContractError,
            "unsupported by pack zeek_tls: hosts",
        ):
            authorize_investigation_query_request(
                candidate,
                candidate_context,
            )


    def test_empty_boolean_and_coverage_ambiguity_fail_closed(self) -> None:
        query = authorize_investigation_query_request(
            proposal(),
            context(),
        )["queries"][0]
        empty_query = copy.deepcopy(query)
        empty_query["observables"] = {
            "ips": [],
            "domains": [],
            "hosts": [],
            "users": [],
        }
        with self.assertRaisesRegex(
            InvestigationQueryContractError,
            "no observable query clauses",
        ):
            build_query_dsl(empty_query)

        self.assertEqual(
            result_coverage(
                query,
                status="ok",
                total_hits=50,
                total_hits_relation="eq",
                returned_hits=25,
            )["coverage_status"],
            "bounded_sample",
        )
        incomplete = result_coverage(
            query,
            status="timeout",
            total_hits=0,
            total_hits_relation="eq",
            returned_hits=0,
        )
        self.assertEqual(incomplete["coverage_status"], "partial")
        self.assertFalse(incomplete["zero_hits"])


    def test_cross_sensor_packet_tuple_compiles_only_community_id_join(self) -> None:
        candidate = role_aware_proposal()
        candidate["queries"][0]["pack"] = "network_flow"
        request = authorize_investigation_query_request(
            candidate,
            role_aware_context(),
        )
        query = request["queries"][0]

        self.assertEqual(
            query["match_semantics"],
            "community_id_cross_sensor",
        )
        tuple_filter = build_query_dsl(query)["query"]["bool"]["filter"][3]
        self.assertEqual(
            tuple_filter,
            {
                "bool": {
                    "filter": [{
                        "term": {
                            "network.community_id": "1:trusted-flow=",
                        }
                    }]
                }
            },
        )

        missing_join = role_aware_proposal()
        missing_join["queries"][0]["pack"] = "network_flow"
        missing_join["queries"][0]["event_tuple"].pop("community_id")
        with self.assertRaisesRegex(
            InvestigationQueryContractError,
            "requires community_id",
        ):
            authorize_investigation_query_request(
                missing_join,
                role_aware_context(),
            )


    def test_anchor_nearest_uses_trusted_anchor_and_is_elastic_only(self) -> None:
        candidate = proposal()
        candidate["queries"][0].update({
            "dialect": "elastic",
            "aggregation": "anchor_nearest",
        })
        query = authorize_investigation_query_request(
            candidate,
            context(),
        )["queries"][0]
        dsl = build_query_dsl(query)

        self.assertEqual(query["anchor_time"], context()["anchor_time"])
        self.assertEqual(query["match_semantics"], "observable_exact_any_field")
        self.assertEqual(
            dsl["query"]["function_score"]["gauss"]["@timestamp"]["origin"],
            context()["anchor_time"],
        )
        self.assertEqual(dsl["sort"][0], {"_score": "desc"})

        candidate["queries"][0]["dialect"] = "oql"
        with self.assertRaisesRegex(
            InvestigationQueryContractError,
            "only through compiled Elastic DSL",
        ):
            authorize_investigation_query_request(candidate, context())


    def test_response_dsl_scope_and_projection_tampering_fail_closed(self) -> None:
        request = authorize_investigation_query_request(proposal(), context())
        response = valid_response(request)
        self.assertIs(validate_investigation_query_response(response, request), response)

        changed_dsl = copy.deepcopy(response)
        changed_dsl["results"][0]["query_dsl"]["query"] = {"match_all": {}}
        with self.assertRaisesRegex(InvestigationQueryContractError, "DSL"):
            validate_investigation_query_response(changed_dsl, request)

        extra_source = copy.deepcopy(response)
        extra_source["results"][0]["hits"][0]["source"]["secret"] = "not projected"
        with self.assertRaisesRegex(InvestigationQueryContractError, "projection"):
            validate_investigation_query_response(extra_source, request)


    def test_response_event_tuple_hit_mismatch_fails_closed(self) -> None:
        request = authorize_investigation_query_request(
            role_aware_proposal(),
            role_aware_context(),
        )
        response = valid_response(request)
        response["results"][0]["hits"][0] = {
            "id": "hit-1",
            "index": ".ds-logs-suricata.alerts-so-2026.07.24-000001",
            "source": {
                "@timestamp": "2026-07-24T11:30:00.000Z",
                "event": {"dataset": "suricata.alert"},
                "source": {"ip": "192.0.2.10", "port": 49152},
                "destination": {"ip": "198.51.100.20", "port": 443},
                "network": {
                    "transport": "tcp",
                    "protocol": "tls",
                    "community_id": "1:trusted-flow=",
                },
                "rule": {"id": "2016150"},
            },
        }
        self.assertIs(
            validate_investigation_query_response(response, request),
            response,
        )
        response["results"][0]["hits"][0]["source"]["destination"]["port"] = 8443
        with self.assertRaisesRegex(
            InvestigationQueryContractError,
            "event tuple",
        ):
            validate_investigation_query_response(response, request)


    def test_response_rejects_forged_time_dataset_and_observable(self) -> None:
        request = authorize_investigation_query_request(proposal(), context())
        response = valid_response(request)

        forged_time = copy.deepcopy(response)
        forged_time["results"][0]["hits"][0]["source"]["@timestamp"] = (
            "2026-07-24T12:30:00.000Z"
        )
        with self.assertRaisesRegex(InvestigationQueryContractError, "window"):
            validate_investigation_query_response(forged_time, request)

        forged_dataset = copy.deepcopy(response)
        forged_dataset["results"][0]["hits"][0]["source"]["event"]["dataset"] = (
            "zeek.http"
        )
        with self.assertRaisesRegex(InvestigationQueryContractError, "dataset"):
            validate_investigation_query_response(forged_dataset, request)

        substituted = copy.deepcopy(response)
        substituted["results"][0]["hits"][0]["source"]["dns"]["question"]["name"] = (
            "unrelated.test"
        )
        with self.assertRaisesRegex(InvestigationQueryContractError, "observable"):
            validate_investigation_query_response(substituted, request)

        incomplete_shards = copy.deepcopy(response)
        incomplete_shards["results"][0]["shards"].update({
            "total": 10,
            "successful": 1,
            "failed": 0,
        })
        with self.assertRaisesRegex(InvestigationQueryContractError, "shard coverage"):
            validate_investigation_query_response(incomplete_shards, request)


    def test_false_control_is_authenticated_and_does_not_skip_other_control(self) -> None:
        request = authorize_investigation_query_request(proposal(), context())
        response = valid_response(request)
        positive = response["controls"]["positive_anchor"]
        positive.update({
            "passed": False,
            "total_hits": 0,
            "returned_hits": 0,
            "hits": [],
        })
        response.update({"complete": False, "partial": True})
        response["semantic_validity"].update({
            "controls_valid": False,
            "semantic_valid": False,
        })

        self.assertIs(validate_investigation_query_response(response, request), response)

        # The negative control must still be authenticated even though the
        # independently valid positive control returned passed=false.
        response["controls"]["negative_filter"]["query_dsl"] = {"match_all": {}}
        with self.assertRaisesRegex(
            InvestigationQueryContractError,
            "negative_filter.*DSL",
        ):
            validate_investigation_query_response(response, request)


    def test_control_rejects_forged_digest_and_nonexact_positive_scope(self) -> None:
        request = authorize_investigation_query_request(proposal(), context())
        response = valid_response(request)
        response["controls"]["positive_anchor"]["index_scope"] = ALERT_INDEX_SCOPE
        with self.assertRaisesRegex(
            InvestigationQueryContractError,
            "positive_anchor.*index scope",
        ):
            validate_investigation_query_response(response, request)

        response = valid_response(request)
        response["controls"]["negative_filter"]["passed"] = False
        response["controls"]["negative_filter"]["query_digest"] = "0" * 64
        with self.assertRaisesRegex(
            InvestigationQueryContractError,
            "negative_filter.*digest",
        ):
            validate_investigation_query_response(response, request)
