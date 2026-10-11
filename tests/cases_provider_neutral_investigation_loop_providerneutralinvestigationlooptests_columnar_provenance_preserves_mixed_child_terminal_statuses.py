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

class ProviderNeutralInvestigationLoopTestsColumnarProvenancePreservesMixedChildTerminalStatusesCases:
    def test_columnar_provenance_preserves_mixed_child_terminal_statuses(
        self,
    ) -> None:
        statuses = ("ok", "timeout", "error", "rejected")
        trusted = []
        nested = []
        expected_refs = {}
        for index, status in enumerate(statuses, 1):
            query_digest = f"{index:064x}"
            result_digest = f"{index + 60:064x}"
            evidence_ref = f"query:{query_digest}:{result_digest}"
            expected_refs[evidence_ref] = status
            trusted.append({
                "query_id": f"pivot-{index}",
                "backend": "elastic",
                "pack": "network_flow",
                "aggregation": "events",
                "purpose": "Confirm exact grouped-query coverage.",
                "status": "ok",
                "query_digest": query_digest,
                "result_digest": result_digest,
                "evidence_ref": evidence_ref,
                "returned_hits": 1,
            })
            nested.append({
                "query_id": f"pivot-{index}",
                "status": status,
                "query_digest": query_digest,
                "result_digest": result_digest,
                "returned_hits": 1,
                "semantic_valid": status == "ok",
            })
        projected = self.runner._columnar_investigation_prompt_payload(
            [{
                "round": 1,
                "results": [{
                    "query_ids": [
                        f"pivot-{index}"
                        for index in range(1, len(statuses) + 1)
                    ],
                    "backend": "security_onion",
                    "status": "partial",
                    "read_only": True,
                    "evidence": {
                        "controls_valid": True,
                        "results": nested,
                    },
                    "trusted_query_audit": trusted,
                }],
            }],
            maximum_bytes=8192,
        )
        self.assertIsNotNone(projected)
        columnar = projected["rounds"][0]
        status_values = columnar["status_values"]
        columns = columnar["columns"]
        observed_statuses = [
            status_values[
                dict(zip(columns, row))["status_index"]
            ]
            for row in columnar["rows"]
        ]
        self.assertEqual(observed_statuses, list(statuses))

        references = {
            item["ref"]: item
            for item in self.runner.evidence_reference_contract({
                "investigation_query_results": projected,
            })["references"]
        }
        for evidence_ref, status in expected_refs.items():
            self.assertEqual(references[evidence_ref]["status"], status)
            self.assertEqual(
                references[evidence_ref]["corroborating"],
                status == "ok",
            )


    def test_grouped_columnar_provenance_requires_exact_query_id_coverage(
        self,
    ) -> None:
        def child(query_id: str, index: int) -> dict:
            return {
                "query_id": query_id,
                "backend": "elastic",
                "pack": "network_flow",
                "aggregation": "events",
                "purpose": "Confirm exact grouped-query coverage.",
                "status": "ok",
                "query_digest": f"{index:064x}",
                "result_digest": f"{index + 50:064x}",
                "returned_hits": 1,
            }

        baseline = {
            "query_ids": ["q1", "q2"],
            "backend": "security_onion",
            "status": "ok",
            "read_only": True,
            "evidence": {
                "results": [
                    child("q1", 1),
                    child("q2", 2),
                ],
            },
            "trusted_query_audit": [
                child("q1", 1),
                child("q2", 2),
            ],
        }
        cases = {
            "trusted-missing": lambda item: item[
                "trusted_query_audit"
            ].pop(),
            "trusted-extra": lambda item: item[
                "trusted_query_audit"
            ].append(child("q3", 3)),
            "trusted-duplicate": lambda item: item[
                "trusted_query_audit"
            ].append(child("q1", 1)),
            "nested-missing": lambda item: item["evidence"][
                "results"
            ].pop(),
            "nested-extra": lambda item: item["evidence"][
                "results"
            ].append(child("q3", 3)),
            "nested-duplicate": lambda item: item["evidence"][
                "results"
            ].append(child("q1", 1)),
            "declared-duplicate": lambda item: item[
                "query_ids"
            ].append("q1"),
        }
        for label, mutate in cases.items():
            with self.subTest(label=label):
                grouped = copy.deepcopy(baseline)
                mutate(grouped)
                self.assertIsNone(
                    self.runner._columnar_investigation_prompt_payload(
                        [{"round": 1, "results": [grouped]}],
                        maximum_bytes=4096,
                    )
                )


    def test_columnar_provenance_rejects_malformed_children_and_scalar_mismatch(
        self,
    ) -> None:
        def valid_result() -> dict:
            return {
                "query_id": "q1",
                "backend": "elastic",
                "status": "ok",
                "read_only": True,
                "evidence": {
                    "results": [{
                        "query_id": "q1",
                        "status": "ok",
                        "query_digest": "a" * 64,
                        "result_digest": "b" * 64,
                        "returned_hits": 1,
                    }],
                },
                "trusted_query_audit": [{
                    "query_id": "q1",
                    "backend": "elastic",
                    "pack": "network_flow",
                    "purpose": "Confirm the exact scalar query identity.",
                    "status": "ok",
                    "query_digest": "a" * 64,
                    "result_digest": "b" * 64,
                    "returned_hits": 1,
                }],
            }

        valid_round = {
            "round": 1,
            "results": [valid_result()],
        }
        malformed_rounds = [
            [copy.deepcopy(valid_round), None],
            [{
                "round": 1,
                "results": [valid_result(), None],
            }],
        ]
        trusted_child = valid_result()
        trusted_child["trusted_query_audit"].append(None)
        malformed_rounds.append([{
            "round": 1,
            "results": [trusted_child],
        }])
        nested_child = valid_result()
        nested_child["evidence"]["results"].append(None)
        malformed_rounds.append([{
            "round": 1,
            "results": [nested_child],
        }])
        scalar_mismatch = valid_result()
        scalar_mismatch["trusted_query_audit"][0][
            "query_id"
        ] = "q2"
        malformed_rounds.append([{
            "round": 1,
            "results": [scalar_mismatch],
        }])

        for index, rounds in enumerate(malformed_rounds, 1):
            with self.subTest(case=index):
                self.assertIsNone(
                    self.runner._columnar_investigation_prompt_payload(
                        rounds,
                        maximum_bytes=4096,
                    )
                )


    def test_columnar_semantics_distinguish_same_pack_query_intent(
        self,
    ) -> None:
        audits = []
        nested = []
        expected = []
        expected_refs = []
        for index, (
            purpose,
            observable,
            start,
            match_semantics,
        ) in enumerate((
            (
                "Confirm source activity.",
                "192.0.2.10",
                "2026-07-24T12:00:00Z",
                "source.ip exact",
            ),
            (
                "Confirm destination activity.",
                "198.51.100.20",
                "2026-07-24T13:00:00Z",
                "destination.ip exact",
            ),
        ), 1):
            query_digest = f"{index:064x}"
            result_digest = f"{index + 90:064x}"
            expected_refs.append(
                f"query:{query_digest}:{result_digest}"
            )
            window = {
                "start": start,
                "end": start.replace(":00:00Z", ":05:00Z"),
            }
            observables = {"ips": [observable]}
            filters = {"field": match_semantics.split()[0]}
            query = {"term": {filters["field"]: observable}}
            expected.append({
                "purpose": purpose,
                "observables": observables,
                "window": window,
                "match_semantics": match_semantics,
                "query": query,
                "filters": filters,
            })
            audits.append({
                "query_id": f"pivot-{index}",
                "backend": "elastic",
                "pack": "network_flow",
                "aggregation": "events",
                "purpose": purpose,
                "observables": observables,
                "window": window,
                "match_semantics": match_semantics,
                "query": query,
                "filters": filters,
                "status": "ok",
                "query_digest": query_digest,
                "result_digest": result_digest,
                "returned_hits": 1,
            })
            nested.append({
                "query_id": f"pivot-{index}",
                "status": "ok",
                "query_digest": query_digest,
                "result_digest": result_digest,
                "returned_hits": 1,
            })

        projected = self.runner._columnar_investigation_prompt_payload(
            [{
                "round": 1,
                "results": [{
                    "query_ids": ["pivot-1", "pivot-2"],
                    "backend": "security_onion",
                    "status": "ok",
                    "read_only": True,
                    "evidence": {"results": nested},
                    "trusted_query_audit": audits,
                }],
            }],
            maximum_bytes=8192,
        )
        self.assertIsNotNone(projected)
        columnar = projected["rounds"][0]
        columns = columnar["columns"]
        semantic_documents = [
            json.loads(columnar["semantics_values"][
                dict(zip(columns, row))["semantics_index"]
            ])
            for row in columnar["rows"]
        ]
        self.assertEqual(semantic_documents, [
            {
                "aggregation": "events",
                "backend": "elastic",
                "filters": item["filters"],
                "match_semantics": item["match_semantics"],
                "observables": item["observables"],
                "pack": "network_flow",
                "purpose": item["purpose"],
                "query": item["query"],
                "window": item["window"],
            }
            for item in expected
        ])
        self.assertNotEqual(
            columnar["rows"][0][columns.index("semantics_index")],
            columnar["rows"][1][columns.index("semantics_index")],
        )
        references = {
            item["ref"]
            for item in self.runner.evidence_reference_contract({
                "investigation_query_results": projected,
            })["references"]
        }
        self.assertTrue(set(expected_refs).issubset(references))


    def test_columnar_pack_name_alone_is_not_query_semantics(self) -> None:
        self.assertIsNone(
            self.runner._columnar_investigation_prompt_payload(
                [{
                    "round": 1,
                    "results": [{
                        "query_id": "pack-only",
                        "backend": "elastic",
                        "status": "ok",
                        "read_only": True,
                        "trusted_query_audit": [{
                            "query_id": "pack-only",
                            "backend": "elastic",
                            "pack": "network_flow",
                            "aggregation": "events",
                            "status": "ok",
                            "query_digest": "a" * 64,
                            "result_digest": "b" * 64,
                            "returned_hits": 1,
                        }],
                    }],
                }],
                maximum_bytes=4096,
            )
        )


    def test_all_canonical_query_success_statuses_are_corroborating(
        self,
    ) -> None:
        statuses = ("ok", "success", "completed", "complete", "succeeded")
        rounds = [{"round": 1, "results": []}]
        expected_refs = []
        for index, status in enumerate(statuses, 1):
            query_digest = f"{index + 20:064x}"
            result_digest = f"{index + 120:064x}"
            expected_refs.append(
                f"query:{query_digest}:{result_digest}"
            )
            rounds[0]["results"].append({
                "query_id": f"success-{index}",
                "backend": "elastic",
                "status": status,
                "read_only": True,
                "trusted_query_audit": [{
                    "query_id": f"success-{index}",
                    "backend": "elastic",
                    "pack": "network_flow",
                    "aggregation": "events",
                    "purpose": "Confirm the canonical success result.",
                    "status": status,
                    "query_digest": query_digest,
                    "result_digest": result_digest,
                    "returned_hits": 1,
                }],
            })

        projected = self.runner._columnar_investigation_prompt_payload(
            rounds,
            maximum_bytes=8192,
        )
        self.assertIsNotNone(projected)
        compact_refs = {
            item["ref"]: item
            for item in self.runner.evidence_reference_contract({
                "investigation_query_results": projected,
            })["references"]
        }
        regular_refs = {
            item["ref"]: item
            for item in self.runner.evidence_reference_contract({
                "investigation_query_results": {
                    "schema": (
                        self.runner.INVESTIGATION_QUERY_RESULT_SCHEMA
                    ),
                    "rounds": rounds,
                },
            })["references"]
        }
        for evidence_ref in expected_refs:
            self.assertTrue(compact_refs[evidence_ref]["corroborating"])
            self.assertTrue(regular_refs[evidence_ref]["corroborating"])


    def test_columnar_invalid_counts_are_never_corroborating(self) -> None:
        invalid_counts = (
            False,
            -1,
            None,
            "1",
            1.0,
            1.75,
            float("nan"),
            float("inf"),
            [],
            2**63,
        )
        for value in (*invalid_counts, object()):
            with self.subTest(canonical_count=value):
                self.assertIsNone(
                    self.runner._canonical_investigation_count(value)
                )
        maximum = self.runner.MAX_INVESTIGATION_RESULT_COUNT
        for value in (0, 1, maximum):
            with self.subTest(canonical_count=value):
                self.assertEqual(
                    self.runner._canonical_investigation_count(value),
                    value,
                )
        self.assertIsNone(
            self.runner._columnar_investigation_prompt_payload(
                [{
                    "round": 1,
                    "results": [{
                        "query_id": "object-count",
                        "backend": "elastic",
                        "status": "ok",
                        "read_only": True,
                        "trusted_query_audit": [{
                            "query_id": "object-count",
                            "backend": "elastic",
                            "pack": "network_flow",
                            "purpose": (
                                "Reject an unserializable result count."
                            ),
                            "status": "ok",
                            "query_digest": "a" * 64,
                            "result_digest": "b" * 64,
                            "returned_hits": object(),
                        }],
                    }],
                }],
                maximum_bytes=4096,
            )
        )
        rounds = [{"round": 1, "results": []}]
        expected_refs = []
        for index, count in enumerate(invalid_counts, 1):
            query_digest = f"{index + 10:064x}"
            result_digest = f"{index + 80:064x}"
            evidence_ref = f"query:{query_digest}:{result_digest}"
            expected_refs.append(evidence_ref)
            audit = {
                "query_id": f"pivot-{index}",
                "backend": "elastic",
                "pack": "network_flow",
                "aggregation": "events",
                "purpose": "Confirm strict result-count handling.",
                "status": "ok",
                "query_digest": query_digest,
                "result_digest": result_digest,
                "evidence_ref": evidence_ref,
                "evidence_summary": {
                    "collection": "returned count unavailable",
                },
            }
            if count is not None:
                audit["returned_hits"] = count
            rounds[0]["results"].append({
                "query_id": f"pivot-{index}",
                "backend": "elastic",
                "status": "ok",
                "read_only": True,
                "trusted_query_audit": [audit],
            })
        projected = self.runner._columnar_investigation_prompt_payload(
            rounds,
            maximum_bytes=4096,
        )
        self.assertIsNotNone(projected)
        references = {
            item["ref"]: item
            for item in self.runner.evidence_reference_contract({
                "investigation_query_results": projected,
            })["references"]
        }
        for evidence_ref in expected_refs:
            self.assertIsNone(references[evidence_ref]["returned"])
            self.assertFalse(references[evidence_ref]["corroborating"])
            self.assertEqual(
                references[evidence_ref]["status"],
                "invalid_result_count",
            )

        maximum_query_digest = "e" * 64
        maximum_result_digest = "f" * 64
        maximum_ref = (
            f"query:{maximum_query_digest}:{maximum_result_digest}"
        )
        maximum_projection = (
            self.runner._columnar_investigation_prompt_payload(
                [{
                    "round": 1,
                    "results": [{
                        "query_id": "maximum-count",
                        "backend": "elastic",
                        "status": "ok",
                        "read_only": True,
                        "trusted_query_audit": [{
                            "query_id": "maximum-count",
                            "backend": "elastic",
                            "pack": "network_flow",
                            "purpose": (
                                "Confirm the maximum canonical result count."
                            ),
                            "status": "ok",
                            "query_digest": maximum_query_digest,
                            "result_digest": maximum_result_digest,
                            "returned_hits": maximum,
                        }],
                    }],
                }],
                maximum_bytes=4096,
            )
        )
        self.assertIsNotNone(maximum_projection)
        maximum_reference = {
            item["ref"]: item
            for item in self.runner.evidence_reference_contract({
                "investigation_query_results": maximum_projection,
            })["references"]
        }[maximum_ref]
        self.assertEqual(maximum_reference["returned"], maximum)
        self.assertTrue(maximum_reference["corroborating"])

        overflow_projection = copy.deepcopy(maximum_projection)
        overflow_columns = overflow_projection["rounds"][0]["columns"]
        overflow_projection["rounds"][0]["rows"][0][
            overflow_columns.index("returned")
        ] = maximum + 1
        for _ in range(8):
            overflow_size = len(json.dumps(
                overflow_projection,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8"))
            if (
                overflow_projection["prompt_projection"]["encoded_bytes"]
                == overflow_size
            ):
                break
            overflow_projection["prompt_projection"]["encoded_bytes"] = (
                overflow_size
            )
        overflow_reference = {
            item["ref"]: item
            for item in self.runner.evidence_reference_contract({
                "investigation_query_results": overflow_projection,
            })["references"]
        }[maximum_ref]
        self.assertIsNone(overflow_reference["returned"])
        self.assertFalse(overflow_reference["corroborating"])
        self.assertEqual(
            overflow_reference["status"],
            "invalid_result_count",
        )


    def test_columnar_fallback_refuses_zero_or_incomplete_provenance(self) -> None:
        self.assertIsNone(
            self.runner._columnar_investigation_prompt_payload(
                [],
                maximum_bytes=4096,
            )
        )
        self.assertIsNone(
            self.runner._columnar_investigation_prompt_payload(
                [{
                    "round": 1,
                    "results": [{
                        "query_id": "pivot-without-provenance",
                        "backend": "elastic",
                        "status": "ok",
                        "read_only": True,
                    }],
                }],
                maximum_bytes=4096,
            )
        )


    def test_cumulative_prompt_projection_fails_closed_below_provenance_floor(
        self,
    ) -> None:
        rounds = [{
            "round": 1,
            "requests": [],
            "audit": [],
            "results": [{
                "query_id": "pivot-1",
                "backend": "elastic",
                "status": "ok",
                "read_only": True,
            }],
        }]

        with self.assertRaisesRegex(
            self.runner.InvestigationQueryError,
            "exceeds its cumulative byte budget",
        ):
            self.runner._investigation_prompt_payload(
                rounds,
                maximum_bytes=128,
            )


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
