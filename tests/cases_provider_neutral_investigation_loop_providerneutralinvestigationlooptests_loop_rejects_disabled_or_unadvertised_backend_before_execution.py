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

class ProviderNeutralInvestigationLoopTestsLoopRejectsDisabledOrUnadvertisedBackendBeforeExecutionCases:
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
        self.assertEqual(rejected["error"], "backend_unavailable")
        self.assertRegex(rejected["error_sha256"], r"^[a-f0-9]{64}$")
        self.assertEqual(
            response["_investigation_query_audit"]["rounds"][0]["results"][0]["status"],
            "rejected",
        )
        self.assertIn(
            "disabled",
            response["_investigation_query_audit"]["rounds"][0][
                "results"
            ][0]["error"],
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
        self.assertEqual(duplicate["error"], "duplicate_request")
        self.assertRegex(duplicate["error_sha256"], r"^[a-f0-9]{64}$")
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
        self.assertEqual(
            self.runner.MAX_INVESTIGATION_PROMPT_EVIDENCE_ROWS,
            self.harness.DEFAULT_BUDGETS["max_prompt_evidence_rows"],
        )
        self.assertEqual(
            self.runner.MAX_INVESTIGATION_PROMPT_EVIDENCE_ROWS,
            1_200,
        )
        rows = [
            {"source": {"ip": "192.0.2.1"}, "padding": "x" * 4096}
            for _ in range(1_500)
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
        self.assertEqual(
            projected["prompt_projection"]["max_rows"],
            1_200,
        )
        self.assertEqual(
            projected["prompt_projection"]["rows_included"],
            1_200,
        )
        self.assertTrue(projected["prompt_projection"]["truncated"])


    def test_cumulative_prompt_projection_compacts_query_audit_without_losing_evidence_provenance(
        self,
    ) -> None:
        trusted_query_audit = []
        for index in range(4):
            query_digest = f"{index + 1:064x}"
            result_digest = f"{index + 101:064x}"
            trusted_query_audit.append({
                "query_id": f"pivot-{index + 1}",
                "backend": "security_onion",
                "dialect": "elastic",
                "pack": "network_flow",
                "purpose": "Confirm the exact result-bound network pivot.",
                "status": "ok",
                "semantic_valid": True,
                "returned_hits": index + 1,
                "query_digest": query_digest,
                "result_digest": result_digest,
                "evidence_ref": f"query:{query_digest}:{result_digest}",
                "query_dsl": {
                    "query": {
                        "bool": {
                            "filter": [
                                {
                                    "term": {
                                        "event.dataset": (
                                            "logs-zeek.conn-" + ("x" * 12_000)
                                        )
                                    }
                                }
                            ]
                        }
                    }
                },
                "kql_equivalent": "source.ip:192.0.2.1 " + ("k" * 12_000),
                "oql_equivalent": "source.ip == 192.0.2.1 " + ("o" * 12_000),
            })
        evidence = {
            "controls_valid": True,
            "complete": True,
            "partial": False,
            "results": [
                {
                    "query_id": f"pivot-{index + 1}",
                    "status": "ok",
                    "semantic_valid": True,
                    "query_digest": item["query_digest"],
                    "returned_hits": index + 1,
                    "hits": [{"source": {"source": {"ip": "192.0.2.1"}}}],
                }
                for index, item in enumerate(trusted_query_audit)
            ],
        }
        rounds = [{
            "round": 1,
            "requests": [],
            "audit": [],
            "results": [{
                "backend": "security_onion",
                "query_ids": [
                    item["query_id"] for item in trusted_query_audit
                ],
                "status": "ok",
                "read_only": True,
                "security_onion_response_digest": "f" * 64,
                "evidence": evidence,
                "trusted_query_audit": trusted_query_audit,
            }],
        }]
        original = copy.deepcopy(rounds)

        projected = self.runner._investigation_prompt_payload(
            rounds,
            maximum_bytes=12 * 1024,
        )
        repeated = self.runner._investigation_prompt_payload(
            rounds,
            maximum_bytes=12 * 1024,
        )
        encoded = json.dumps(
            projected,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

        self.assertEqual(projected, repeated)
        self.assertEqual(rounds, original)
        self.assertLessEqual(len(encoded), 12 * 1024)
        self.assertEqual(
            projected["prompt_projection"]["encoded_bytes"],
            len(encoded),
        )
        self.assertEqual(
            projected["prompt_projection"][
                "trusted_query_audits_compacted"
            ],
            4,
        )
        self.assertEqual(
            projected["prompt_projection"]["evidence_bodies_omitted"],
            0,
        )
        result = projected["rounds"][0]["results"][0]
        self.assertEqual(result["evidence"], evidence)
        for source, compact in zip(
            trusted_query_audit,
            result["trusted_query_audit"],
        ):
            self.assertEqual(
                compact["prompt_projection"],
                "compacted_due_to_cumulative_byte_budget",
            )
            self.assertEqual(compact["query_id"], source["query_id"])
            self.assertEqual(
                compact["query_digest"],
                source["query_digest"],
            )
            self.assertEqual(
                compact["result_digest"],
                source["result_digest"],
            )
            self.assertEqual(
                compact["evidence_ref"],
                source["evidence_ref"],
            )
            source_bytes = json.dumps(
                source,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            self.assertEqual(compact["audit_bytes"], len(source_bytes))
            self.assertEqual(
                compact["audit_sha256"],
                hashlib.sha256(source_bytes).hexdigest(),
            )
            self.assertNotIn("query_dsl", compact)
            self.assertNotIn("kql_equivalent", compact)
            self.assertNotIn("oql_equivalent", compact)


    def test_rank_nineteen_shape_preserves_evidence_under_eleven_kib_budget(
        self,
    ) -> None:
        def sized_audit(
            target_bytes: int,
            *,
            query_id: str,
            query_digest: str,
            result_digest: str,
        ) -> dict:
            audit = {
                "query_id": query_id,
                "backend": "security_onion",
                "dialect": "elastic",
                "pack": "network_flow",
                "purpose": "Validate the bounded network-flow pivot.",
                "status": "ok",
                "semantic_valid": True,
                "returned_hits": 1,
                "query_digest": query_digest,
                "result_digest": result_digest,
                "evidence_ref": (
                    f"query:{query_digest}:{result_digest}"
                ),
                "query_dsl": {"padding": ""},
            }
            empty_size = len(json.dumps(
                audit,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8"))
            self.assertGreater(target_bytes, empty_size)
            audit["query_dsl"]["padding"] = "x" * (
                target_bytes - empty_size
            )
            self.assertEqual(
                len(json.dumps(
                    audit,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")),
                target_bytes,
            )
            return audit

        rounds = []
        evidence_by_round = []
        audit_sizes = (4612, 10497)
        for round_number, audit_size in enumerate(audit_sizes, 1):
            query_digest = f"{round_number:064x}"
            result_digest = f"{round_number + 20:064x}"
            evidence = {
                "controls_valid": True,
                "complete": True,
                "partial": False,
                "results": [{
                    "query_id": f"pivot-{round_number}",
                    "status": "ok",
                    "semantic_valid": True,
                    "query_digest": query_digest,
                    "result_digest": result_digest,
                    "returned_hits": 1,
                    "hits": [{
                        "source": {
                            "source": {"ip": "192.0.2.10"},
                            "destination": {"ip": "198.51.100.20"},
                        },
                    }],
                }],
            }
            evidence_by_round.append(evidence)
            rounds.append({
                "round": round_number,
                "requests": [],
                "audit": [],
                "results": [{
                    "backend": "security_onion",
                    "query_ids": [f"pivot-{round_number}"],
                    "status": "ok",
                    "read_only": True,
                    "evidence": evidence,
                    "trusted_query_audit": [sized_audit(
                        audit_size,
                        query_id=f"pivot-{round_number}",
                        query_digest=query_digest,
                        result_digest=result_digest,
                    )],
                }],
            })

        projected = self.runner._investigation_prompt_payload(
            rounds,
            maximum_bytes=11091,
        )
        encoded = json.dumps(
            projected,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

        self.assertLessEqual(len(encoded), 11091)
        self.assertFalse(
            projected["prompt_projection"].get(
                "columnar_provenance_fallback",
                False,
            )
        )
        self.assertGreaterEqual(
            projected["prompt_projection"][
                "trusted_query_audits_compacted"
            ],
            1,
        )
        self.assertEqual(
            projected["prompt_projection"]["evidence_bodies_omitted"],
            0,
        )
        self.assertEqual(
            [
                item["results"][0]["evidence"]
                for item in projected["rounds"]
            ],
            evidence_by_round,
        )


    def test_complete_follow_up_admission_includes_refreshed_contract_under_runtime_ceiling(
        self,
    ) -> None:
        maximum = self.runner.CODEX_CLI_MAX_PROMPT_PACKAGE_BYTES
        query_digest = "a" * 64
        result_digest = "b" * 64
        prompt_package = {
            "package_type": "soc-ai-investigation-prompt",
            "agent_role": "soc-analyst",
            "padding": "p" * (maximum - 14_000),
            "evidence_reference_contract": {
                "schema": "stale-contract-must-be-replaced",
                "references": [],
            },
        }
        rounds = [{
            "round": 1,
            "requests": [],
            "audit": [],
            "results": [{
                "query_id": "pivot-1",
                "backend": "elastic",
                "status": "ok",
                "read_only": True,
                "evidence": {
                    "query_id": "pivot-1",
                    "pack": "network_flow",
                    "status": "ok",
                    "query_digest": query_digest,
                    "result_digest": result_digest,
                    "returned_hits": 1,
                    "hits": [{"source": {"padding": "e" * 20_000}}],
                },
                "trusted_query_audit": [{
                    "query_id": "pivot-1",
                    "backend": "elastic",
                    "pack": "network_flow",
                    "aggregation": "events",
                    "purpose": "Confirm exact prompt admission evidence.",
                    "status": "ok",
                    "query_digest": query_digest,
                    "result_digest": result_digest,
                    "evidence_ref": (
                        f"query:{query_digest}:{result_digest}"
                    ),
                    "returned_hits": 1,
                    "query_dsl": {"padding": "q" * 20_000},
                }],
            }],
        }]

        admitted_size = self.runner._admit_investigation_query_prompt(
            prompt_package,
            rounds,
            maximum_prompt_bytes=maximum,
            hosted=True,
        )
        actual_size = len(json.dumps(
            self.runner.model_safe_copy(prompt_package, hosted=True),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8"))

        self.assertEqual(admitted_size, actual_size)
        self.assertLessEqual(actual_size, maximum)
        contract = prompt_package["evidence_reference_contract"]
        self.assertEqual(
            contract["schema"],
            "onion-sentinel-evidence-reference-contract-v1",
        )
        self.assertIn(
            f"query:{query_digest}:{result_digest}",
            {item["ref"] for item in contract["references"]},
        )


    def test_follow_up_admission_commits_exact_hosted_tls_hash_fixed_point(
        self,
    ) -> None:
        certificate_digest = "c" * 64
        second_certificate_digest = "9" * 64
        query_digest = "a" * 64
        result_digest = "b" * 64
        prompt_package = {
            "package_type": "soc-ai-investigation-prompt",
            "agent_role": "soc-analyst",
        }
        rounds = [{
            "round": 1,
            "requests": [],
            "audit": [],
            "results": [{
                "query_id": "tls-certificate-pivot",
                "backend": "elastic",
                "status": "ok",
                "read_only": True,
                "evidence": {
                    "query_id": "tls-certificate-pivot",
                    "pack": "zeek_tls",
                    "status": "ok",
                    "query_digest": query_digest,
                    "result_digest": result_digest,
                    "returned_hits": 1,
                    "hits": [{
                        "source": {
                            "tls": {
                                "server": {
                                    "hash": {
                                        "sha256": certificate_digest,
                                    },
                                },
                            },
                        },
                    }],
                },
                "trusted_query_audit": [{
                    "query_id": "tls-certificate-pivot",
                    "backend": "elastic",
                    "pack": "zeek_tls",
                    "aggregation": "events",
                    "purpose": "Confirm the observed TLS certificate hash.",
                    "status": "ok",
                    "query_digest": query_digest,
                    "result_digest": result_digest,
                    "returned_hits": 1,
                }],
            }],
        }]
        second_round = copy.deepcopy(rounds[0])
        second_round["round"] = 2
        second_result = second_round["results"][0]
        second_result["query_id"] = "tls-certificate-pivot-2"
        second_result["evidence"]["query_id"] = "tls-certificate-pivot-2"
        second_result["evidence"]["query_digest"] = "3" * 64
        second_result["evidence"]["result_digest"] = "4" * 64
        second_result["evidence"]["returned_hits"] = 45
        second_result["evidence"]["hits"] = [
            {
                "source": {
                    "tls": {
                        "server": {
                            "hash": {
                                "sha256": second_certificate_digest,
                            },
                        },
                    },
                },
            }
            for _ in range(45)
        ]
        second_audit = second_result["trusted_query_audit"][0]
        second_audit["query_id"] = "tls-certificate-pivot-2"
        second_audit["query_digest"] = "3" * 64
        second_audit["result_digest"] = "4" * 64
        second_audit["returned_hits"] = 45
        rounds.append(second_round)

        first_admitted_size = self.runner._admit_investigation_query_prompt(
            prompt_package,
            rounds[:1],
            maximum_prompt_bytes=(
                self.runner.CODEX_CLI_MAX_PROMPT_PACKAGE_BYTES
            ),
            hosted=True,
        )
        self.assertLessEqual(
            first_admitted_size,
            self.runner.CODEX_CLI_MAX_PROMPT_PACKAGE_BYTES,
        )
        admitted_size = self.runner._admit_investigation_query_prompt(
            prompt_package,
            rounds,
            maximum_prompt_bytes=(
                self.runner.CODEX_CLI_MAX_PROMPT_PACKAGE_BYTES
            ),
            hosted=True,
        )
        transported = self.runner.model_safe_copy(
            prompt_package,
            hosted=True,
        )
        actual_size = len(json.dumps(
            transported,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8"))

        self.assertEqual(admitted_size, actual_size)
        self.assertLessEqual(
            actual_size,
            self.runner.CODEX_CLI_MAX_PROMPT_PACKAGE_BYTES,
        )
        self.assertEqual(
            transported,
            self.runner.model_safe_copy(transported, hosted=True),
        )
        self.assertIn(
            certificate_digest,
            json.dumps(transported, sort_keys=True),
        )
        self.assertIn(
            second_certificate_digest,
            json.dumps(transported, sort_keys=True),
        )


    def test_follow_up_admission_measures_staged_fixed_point_at_exact_ceiling(
        self,
    ) -> None:
        maximum = 4096

        def synthetic_projection(_rounds, *, maximum_bytes):
            return {
                "schema": "synthetic-query-results",
                "rounds": [{"schema": "synthetic-round"}],
                "transport_generation": 0,
                "transport_padding": "",
                "prompt_projection": {
                    "max_bytes": maximum_bytes,
                    "encoded_bytes": 1,
                    "truncated": False,
                },
            }

        def staged_transport(value, *, hosted=False, **_kwargs):
            output = copy.deepcopy(value)
            if not hosted:
                return output
            results = output.get("investigation_query_results")
            if isinstance(results, dict):
                current = results.get("transport_generation", 0)
                if isinstance(current, bool) or not isinstance(current, int):
                    current = 0
                generation = min(2, max(0, current) + 1)
                results["transport_generation"] = generation
                results["transport_padding"] = "s" * (generation * 17)
                output["evidence_reference_contract"] = {
                    "schema": "synthetic-staged-contract",
                    "generation": generation,
                    "references": [],
                }
            return output

        rounds: list[dict] = []
        with (
            mock.patch.object(
                self.runner,
                "_investigation_prompt_payload",
                side_effect=synthetic_projection,
            ),
            mock.patch.object(
                self.runner,
                "model_safe_copy",
                side_effect=staged_transport,
            ),
        ):
            calibration = {"padding": ""}
            calibration_size = (
                self.runner._admit_investigation_query_prompt(
                    calibration,
                    rounds,
                    maximum_prompt_bytes=maximum,
                    hosted=True,
                )
            )
            self.assertLess(calibration_size, maximum)

            prompt_package = {
                "padding": "p" * (maximum - calibration_size),
            }
            admitted_size = self.runner._admit_investigation_query_prompt(
                prompt_package,
                rounds,
                maximum_prompt_bytes=maximum,
                hosted=True,
            )
            transported = self.runner.model_safe_copy(
                prompt_package,
                hosted=True,
            )

        self.assertEqual(admitted_size, maximum)
        self.assertEqual(
            len(self.runner._investigation_prompt_json_bytes(transported)),
            maximum,
        )
        self.assertEqual(
            prompt_package["investigation_query_results"][
                "transport_generation"
            ],
            2,
        )
        self.assertEqual(
            transported["investigation_query_results"][
                "transport_generation"
            ],
            2,
        )


