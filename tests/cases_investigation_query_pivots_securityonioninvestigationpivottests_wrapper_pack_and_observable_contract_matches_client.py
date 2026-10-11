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

class SecurityOnionInvestigationPivotTestsWrapperPackAndObservableContractMatchesClientCases:
    def test_wrapper_pack_and_observable_contract_matches_client(self) -> None:
        self.assertEqual(self.wrapper.PACKS, PACKS)
        self.assertEqual(self.wrapper.OBSERVABLE_FIELDS, OBSERVABLE_FIELDS)
        self.assertEqual(self.wrapper.EVENT_TUPLE_FIELDS, EVENT_TUPLE_FIELDS)
        self.assertEqual(self.wrapper.EVENT_TUPLE_PATHS, EVENT_TUPLE_PATHS)
        self.assertEqual(
            PACKS["system_auth"]["indices"],
            ["logs-system.auth-*"],
        )
        self.assertEqual(
            PACKS["zeek_tls"]["datasets"],
            ["zeek.ssl"],
        )
        self.assertIn("dns.query.name", PACKS["dns_activity"]["fields"])
        self.assertIn("ssl.server_name", OBSERVABLE_FIELDS["domains"])


    def test_baseline_pack_scopes_observable_dsl_and_display_kql(self) -> None:
        window = {
            "start": "2026-07-24T00:00:00Z",
            "end": "2026-07-24T01:00:00Z",
        }
        observables = {
            "ips": ["192.0.2.10"],
            "domains": [],
            "hosts": [],
            "users": [],
        }
        observable_terms = self.wrapper.observable_clause(
            observables,
            "dns_activity",
        )["bool"]["should"]
        rendered = self.wrapper.kql_equivalent(
            window,
            "dns_activity",
            observables,
        )
        scoped_fields = self.wrapper.pack_observable_fields("dns_activity")[
            "ips"
        ]

        self.assertEqual(
            observable_terms,
            [
                {"term": {field: "192.0.2.10"}}
                for field in scoped_fields
            ],
        )
        for field in scoped_fields:
            self.assertIn(f'{field} : "192.0.2.10"', rendered)
        self.assertNotIn('related.ip : "192.0.2.10"', rendered)


    def test_wrapper_independently_validates_exact_authorized_request(self) -> None:
        request = authorize_investigation_query_request(proposal(), context())
        self.assertEqual(self.wrapper.validated_pivot_request(request), request)

        candidate = copy.deepcopy(request)
        candidate["queries"][0]["index"] = "*"
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit):
                self.wrapper.validated_pivot_request(candidate)


    def test_wrapper_event_tuple_parity_and_tampering_fail_closed(self) -> None:
        request = authorize_investigation_query_request(
            role_aware_proposal(),
            role_aware_context(),
        )
        self.assertEqual(self.wrapper.validated_pivot_request(request), request)
        query = request["queries"][0]
        self.assertEqual(
            self.wrapper.pivot_query_dsl(query),
            build_query_dsl(query),
        )
        self.assertEqual(
            self.wrapper.pivot_kql_equivalent(query),
            kql_equivalent(query),
        )
        self.assertEqual(
            self.wrapper.pivot_oql_equivalent(query),
            oql_equivalent(query),
        )

        tampered = copy.deepcopy(request)
        tampered["queries"][0]["event_tuple"]["destination_port"] = 8443
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit):
                self.wrapper.validated_pivot_request(tampered)


    def test_wrapper_executes_compiled_oql_equivalent_not_caller_query(self) -> None:
        request = authorize_investigation_query_request(proposal(), context())
        query = request["queries"][0]
        payload = {
            "took": 3,
            "timed_out": False,
            "_shards": {
                "total": 2,
                "successful": 2,
                "skipped": 0,
                "failed": 0,
            },
            "hits": {"total": {"value": 0, "relation": "eq"}, "hits": []},
        }
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=json.dumps(payload).encode(),
            stderr=b"",
        )
        with mock.patch.object(
            self.wrapper,
            "run_bounded_command",
            return_value=completed,
        ) as run:
            result = self.wrapper.execute_pivot_query(query)

        submitted = json.loads(run.call_args.args[0][3])
        self.assertEqual(submitted, build_query_dsl(query))
        self.assertEqual(result["execution_semantics"], "compiled_oql_equivalent")
        self.assertIn("event.dataset:", result["oql_equivalent"])
        self.assertNotIn("==", result["oql_equivalent"])
        self.assertEqual(
            result["result_coverage"]["coverage_status"],
            "exact_zero",
        )
        self.assertTrue(result["result_coverage"]["zero_hits"])


    def test_wrapper_count_is_exact_aggregate_not_truncated_sample(self) -> None:
        candidate = proposal()
        candidate["queries"][0]["aggregation"] = "count"
        query = authorize_investigation_query_request(
            candidate,
            context(),
        )["queries"][0]
        response = {
            "status": "ok",
            "semantic_valid": True,
            "total_hits": 37,
            "total_hits_relation": "eq",
            "returned_hits": 0,
            "truncated": True,
            "duration_ms": 5,
            "timed_out": False,
            "took_ms": 3,
            "shards": {
                "total": 2,
                "successful": 2,
                "skipped": 0,
                "failed": 0,
                "failures": [],
            },
            "hits": [],
        }
        with mock.patch.object(
            self.wrapper,
            "execute_search",
            return_value=response,
        ):
            result = self.wrapper.execute_pivot_query(query)

        self.assertFalse(result["truncated"])
        self.assertEqual(
            result["result_coverage"]["coverage_status"],
            "exact_aggregate",
        )
        self.assertFalse(
            result["result_coverage"]["event_bodies_complete"],
        )


    def test_wrapper_controls_bind_positive_to_exact_index(self) -> None:
        anchor = context()["anchor"]

        def fake_search(body: dict, scope: list[str]) -> dict:
            if scope == [anchor["index"]]:
                return {
                    "status": "ok",
                    "total_hits_relation": "eq",
                    "total_hits": 1,
                    "returned_hits": 1,
                    "hits": [{
                        "id": anchor["id"],
                        "index": anchor["index"],
                        "source": {},
                    }],
                }
            return {
                "status": "ok",
                "total_hits_relation": "eq",
                "total_hits": 0,
                "returned_hits": 0,
                "hits": [],
            }

        with mock.patch.object(
            self.wrapper,
            "execute_search",
            side_effect=fake_search,
        ) as execute:
            controls = self.wrapper.execute_controls(anchor)

        self.assertTrue(controls["positive_anchor"]["passed"])
        self.assertTrue(controls["negative_filter"]["passed"])
        self.assertEqual(execute.call_args_list[0].args[1], [anchor["index"]])
        self.assertEqual(execute.call_args_list[1].args[1], ALERT_INDEX_SCOPE)


    def test_bounded_wrapper_helper_stops_oversized_stdout(self) -> None:
        with self.assertRaises(self.wrapper.BoundedCommandError) as caught:
            self.wrapper.run_bounded_command(
                [
                    sys.executable,
                    "-c",
                    "import os; os.write(1, b'x' * 65536)",
                ],
                timeout_seconds=5,
                max_stdout_bytes=1024,
                max_stderr_bytes=1024,
            )

        self.assertEqual(caught.exception.reason, "output_limit")


    def test_wrapper_accepts_real_nested_projection_and_rejects_substitution(self) -> None:
        request = authorize_investigation_query_request(proposal(), context())
        query = request["queries"][0]
        source = {
            "@timestamp": "2026-07-24T11:30:00.000Z",
            "event": {"dataset": "zeek.dns"},
            "source": {"ip": "192.0.2.10"},
            "dns": {"question": {"name": "example.test"}},
        }
        self.assertTrue(self.wrapper.valid_pivot_hit_source(source, query))

        replaced = copy.deepcopy(source)
        replaced["source"]["ip"] = "192.0.2.99"
        replaced["dns"]["question"]["name"] = "unrelated.test"
        self.assertFalse(self.wrapper.valid_pivot_hit_source(replaced, query))

        unprojected = copy.deepcopy(source)
        unprojected["event"]["original"] = "sensitive raw event"
        self.assertFalse(self.wrapper.valid_pivot_hit_source(unprojected, query))


    def test_wrapper_authenticates_every_role_aware_tuple_field_in_hits(self) -> None:
        request = authorize_investigation_query_request(
            role_aware_proposal(),
            role_aware_context(),
        )
        query = request["queries"][0]
        source = {
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
        }
        self.assertTrue(self.wrapper.valid_pivot_hit_source(source, query))

        for path, replacement in (
            (("source", "ip"), "198.51.100.20"),
            (("destination", "port"), 8443),
            (("network", "transport"), "udp"),
            (("network", "protocol"), "dns"),
            (("network", "community_id"), "1:other-flow="),
            (("rule", "id"), "9999999"),
        ):
            candidate = copy.deepcopy(source)
            candidate[path[0]][path[1]] = replacement
            with self.subTest(path=path):
                self.assertFalse(
                    self.wrapper.valid_pivot_hit_source(candidate, query)
                )


    def test_wrapper_accepts_rule_uuid_and_reversed_zeek_flow_via_community_id(self) -> None:
        alert_query = authorize_investigation_query_request(
            role_aware_proposal(),
            role_aware_context(),
        )["queries"][0]
        alert_source = {
            "@timestamp": "2026-07-24T11:30:00.000Z",
            "event": {"dataset": "suricata.alert"},
            "source": {"ip": "192.0.2.10", "port": 49152},
            "destination": {"ip": "198.51.100.20", "port": 443},
            "network": {
                "transport": "tcp",
                "protocol": "tls",
                "community_id": "1:trusted-flow=",
            },
            "rule": {"uuid": "2016150"},
        }
        self.assertTrue(
            self.wrapper.valid_pivot_hit_source(
                alert_source,
                alert_query,
            )
        )

        candidate = role_aware_proposal()
        candidate["queries"][0]["pack"] = "network_flow"
        flow_query = authorize_investigation_query_request(
            candidate,
            role_aware_context(),
        )["queries"][0]
        reversed_zeek = {
            "@timestamp": "2026-07-24T11:30:00.000Z",
            "event": {"dataset": "zeek.conn"},
            "source": {"ip": "198.51.100.20", "port": 443},
            "destination": {"ip": "192.0.2.10", "port": 49152},
            "network": {
                "transport": "tcp",
                "protocol": "tls",
                "community_id": "1:trusted-flow=",
            },
        }
        self.assertTrue(
            self.wrapper.valid_pivot_hit_source(
                reversed_zeek,
                flow_query,
            )
        )
