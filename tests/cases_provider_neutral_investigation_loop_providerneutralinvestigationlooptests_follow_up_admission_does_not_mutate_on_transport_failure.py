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

class ProviderNeutralInvestigationLoopTestsFollowUpAdmissionDoesNotMutateOnTransportFailureCases:
    def test_follow_up_admission_does_not_mutate_on_transport_failure(
        self,
    ) -> None:
        prompt_package = {
            "package_type": "soc-ai-investigation-prompt",
            "sentinel": {"unchanged": True},
        }
        original = copy.deepcopy(prompt_package)
        rounds = [{
            "round": 1,
            "requests": [],
            "audit": [],
            "results": [{
                "query_id": "pivot",
                "backend": "elastic",
                "status": "ok",
                "read_only": True,
                "evidence": {
                    "query_digest": "a" * 64,
                    "result_digest": "b" * 64,
                    "returned_hits": 0,
                },
                "trusted_query_audit": [],
            }],
        }]

        with mock.patch.object(
            self.runner,
            "synchronize_hosted_investigation_contract",
            side_effect=self.runner.InvestigationQueryError(
                "synthetic transport failure"
            ),
        ):
            with self.assertRaisesRegex(
                self.runner.InvestigationQueryError,
                "synthetic transport failure",
            ):
                self.runner._admit_investigation_query_prompt(
                    prompt_package,
                    rounds,
                    maximum_prompt_bytes=(
                        self.runner.CODEX_CLI_MAX_PROMPT_PACKAGE_BYTES
                    ),
                    hosted=True,
                )
        self.assertEqual(prompt_package, original)


    def test_follow_up_admission_finds_exact_nonmonotonic_floor_boundary(
        self,
    ) -> None:
        maximum = self.runner.CODEX_CLI_MAX_PROMPT_PACKAGE_BYTES
        exact_projection_budget = 843

        def synthetic_projection(_rounds, *, maximum_bytes):
            if maximum_bytes < exact_projection_budget:
                raise self.runner.InvestigationQueryError(
                    "synthetic provenance floor"
                )
            projection = {
                "schema": self.runner.INVESTIGATION_QUERY_RESULT_SCHEMA,
                "rounds": [{
                    "schema": "synthetic-admission-state",
                    "padding": (
                        ""
                        if maximum_bytes == exact_projection_budget
                        else "z" * 4096
                    ),
                }],
                "prompt_projection": {
                    "max_bytes": maximum_bytes,
                    "truncated": True,
                    "encoded_bytes": 0,
                },
            }
            for _ in range(8):
                encoded = len(json.dumps(
                    projection,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8"))
                if projection["prompt_projection"]["encoded_bytes"] == encoded:
                    break
                projection["prompt_projection"]["encoded_bytes"] = encoded
            return projection

        exact_projection = synthetic_projection(
            [],
            maximum_bytes=exact_projection_budget,
        )
        empty_candidate = {
            "padding": "",
            "investigation_query_results": exact_projection,
        }
        self.runner.attach_evidence_reference_contract(empty_candidate)
        empty_size = len(json.dumps(
            self.runner.model_safe_copy(empty_candidate, hosted=True),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8"))
        self.assertLess(empty_size, maximum)
        prompt_package = {
            "padding": "p" * (maximum - empty_size),
        }

        with mock.patch.object(
            self.runner,
            "_investigation_prompt_payload",
            side_effect=synthetic_projection,
        ):
            admitted_size = self.runner._admit_investigation_query_prompt(
                prompt_package,
                [],
                maximum_prompt_bytes=maximum,
                hosted=True,
            )

        self.assertEqual(admitted_size, maximum)
        self.assertEqual(
            prompt_package["investigation_query_results"][
                "prompt_projection"
            ]["max_bytes"],
            exact_projection_budget,
        )


    def test_cumulative_prompt_projection_has_four_kib_provenance_fallback_for_twelve_queries(
        self,
    ) -> None:
        rounds = []
        expected = []
        for round_number in range(1, 4):
            results = []
            for position in range(4):
                index = ((round_number - 1) * 4) + position + 1
                query_digest = f"{index:064x}"
                result_digest = f"{index + 100:064x}"
                evidence_ref = (
                    f"query:{query_digest}:{result_digest}"
                )
                expected.append({
                    "round": round_number,
                    "query_id": f"pivot-{index}",
                    "query_digest": query_digest,
                    "result_digest": result_digest,
                    "evidence_ref": evidence_ref,
                })
                results.append({
                    "query_id": f"pivot-{index}",
                    "backend": "elastic",
                    "status": "ok",
                    "read_only": True,
                    "evidence": {
                        "query_digest": query_digest,
                        "result_digest": result_digest,
                        "evidence_ref": evidence_ref,
                        "results": [{
                            "query_id": f"pivot-{index}",
                            "status": "ok",
                            "query_digest": query_digest,
                            "result_digest": result_digest,
                            "evidence_ref": evidence_ref,
                            "returned_hits": index,
                            "hits": [{
                                "source": {
                                    "padding": "e" * 2_000,
                                },
                            }],
                        }],
                    },
                    "trusted_query_audit": [{
                        "query_id": f"pivot-{index}",
                        "backend": "elastic",
                        "pack": "network_flow",
                        "aggregation": "events",
                        "purpose": "Confirm bounded network-flow evidence.",
                        "status": "ok",
                        "query_digest": query_digest,
                        "result_digest": result_digest,
                        "evidence_ref": evidence_ref,
                        "query_dsl": {"padding": "q" * 5_000},
                    }],
                })
            rounds.append({
                "round": round_number,
                "requests": [],
                "audit": [],
                "results": results,
            })

        projected = self.runner._investigation_prompt_payload(
            rounds,
            maximum_bytes=4096,
        )
        encoded = json.dumps(
            projected,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

        self.assertLessEqual(len(encoded), 4096)
        self.assertEqual(
            projected["prompt_projection"]["encoded_bytes"],
            len(encoded),
        )
        self.assertTrue(
            projected["prompt_projection"][
                "columnar_provenance_fallback"
            ]
        )
        columnar = projected["rounds"][0]
        self.assertEqual(columnar["omitted_rows"], 0)
        self.assertEqual(len(columnar["rows"]), 12)
        self.assertEqual(
            columnar["source_sha256"],
            hashlib.sha256(
                json.dumps(
                    rounds,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest(),
        )
        columns = columnar["columns"]
        for source, row in zip(expected, columnar["rows"]):
            values = dict(zip(columns, row))
            self.assertEqual(values["round"], source["round"])
            self.assertEqual(values["query_id"], source["query_id"])
            self.assertEqual(
                values["query_digest"],
                source["query_digest"],
            )
            self.assertEqual(
                values["result_digest"],
                source["result_digest"],
            )
            self.assertEqual(values["evidence_ref_or_empty"], "")

        references = {
            item["ref"]
            for item in self.runner.evidence_reference_contract({
                "investigation_query_results": projected,
            })["references"]
        }
        for source in expected:
            self.assertIn(source["evidence_ref"], references)


    def test_hosted_copy_preserves_exact_columnar_provenance_structure(
        self,
    ) -> None:
        query_digest = "a" * 64
        result_digest = "b" * 64
        evidence_ref = "collector-evidence:pivot-hosted"
        projected = self.runner._columnar_investigation_prompt_payload(
            [{
                "round": 1,
                "results": [{
                    "query_ids": ["pivot-hosted"],
                    "backend": "security_onion",
                    "status": "ok",
                    "read_only": True,
                    "evidence": {
                        "results": [{
                            "query_id": "pivot-hosted",
                            "status": "ok",
                            "returned_hits": 2,
                            "query_digest": query_digest,
                            "result_digest": result_digest,
                        }],
                    },
                    "trusted_query_audit": [{
                        "query_id": "pivot-hosted",
                        "backend": "elastic",
                        "pack": "network_flow",
                        "purpose": "Confirm the selected source flow.",
                        "observables": {"ips": ["192.0.2.10"]},
                        "window": {
                            "start": "2026-07-24T12:00:00Z",
                            "end": "2026-07-24T12:05:00Z",
                        },
                        "match_semantics": "source.ip exact",
                        "status": "ok",
                        "query_digest": query_digest,
                        "result_digest": result_digest,
                        "evidence_ref": evidence_ref,
                        "returned_hits": 2,
                    }],
                }],
            }],
            maximum_bytes=4096,
        )
        self.assertIsNotNone(projected)

        hosted = self.runner.model_safe_copy(
            {"investigation_query_results": projected},
            hosted=True,
        )["investigation_query_results"]
        original_columnar = projected["rounds"][0]
        hosted_columnar = hosted["rounds"][0]
        self.assertEqual(
            len(hosted_columnar["rows"]),
            len(original_columnar["rows"]),
        )
        self.assertTrue(all(
            isinstance(row, list)
            and len(row)
            == len(self.runner.INVESTIGATION_COLUMNAR_PROVENANCE_COLUMNS)
            for row in hosted_columnar["rows"]
        ))
        self.assertEqual(
            hosted_columnar["semantics_values"],
            original_columnar["semantics_values"],
        )
        self.assertEqual(
            hosted_columnar["result_summary_values"],
            original_columnar["result_summary_values"],
        )
        columns = hosted_columnar["columns"]
        hosted_row = dict(
            zip(columns, hosted_columnar["rows"][0])
        )
        self.assertEqual(
            hosted_row["evidence_ref_or_empty"],
            evidence_ref,
        )
        hosted_references = {
            item["ref"]
            for item in self.runner.evidence_reference_contract({
                "investigation_query_results": hosted,
            })["references"]
        }
        self.assertIn(evidence_ref, hosted_references)

        boolean_omission = copy.deepcopy(projected)
        boolean_omission["rounds"][0]["omitted_rows"] = False
        self.assertFalse(
            self.runner._exact_hosted_columnar_envelope(
                boolean_omission,
                require_encoded_accounting=False,
            )
        )
        stripped = self.runner.model_safe_copy(
            {"investigation_query_results": boolean_omission},
            hosted=True,
        )["investigation_query_results"]
        self.assertEqual(stripped["rounds"][0]["rows"], [])


    def test_hosted_columnar_redaction_refreshes_accounting_and_contract(
        self,
    ) -> None:
        query_digest = "c" * 64
        result_digest = "d" * 64
        canonical_ref = f"query:{query_digest}:{result_digest}"
        sensitive_marker = "marker-for-hosted-redaction"
        stale_evidence_ref = (
            f"collector:password={sensitive_marker}"
        )
        projected = self.runner._columnar_investigation_prompt_payload(
            [{
                "round": 1,
                "results": [{
                    "query_id": "hosted-sensitive",
                    "backend": "elastic",
                    "status": "ok",
                    "read_only": True,
                    "trusted_query_audit": [{
                        "query_id": "hosted-sensitive",
                        "backend": "elastic",
                        "pack": "network_flow",
                        "purpose": (
                            "Confirm flow using "
                            f"password={sensitive_marker}"
                        ),
                        "status": "ok",
                        "query_digest": query_digest,
                        "result_digest": result_digest,
                        "evidence_ref": stale_evidence_ref,
                        "returned_hits": 1,
                    }],
                }],
            }],
            maximum_bytes=4096,
        )
        self.assertIsNotNone(projected)
        prompt_package = {
            "investigation_query_results": projected,
        }
        self.runner.attach_evidence_reference_contract(prompt_package)

        transported = self.runner.model_safe_copy(
            prompt_package,
            hosted=True,
        )
        serialized = json.dumps(
            transported,
            sort_keys=True,
            separators=(",", ":"),
        )
        self.assertNotIn(sensitive_marker, serialized)
        hosted_results = transported["investigation_query_results"]
        hosted_encoded = len(json.dumps(
            hosted_results,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8"))
        self.assertEqual(
            hosted_results["prompt_projection"]["encoded_bytes"],
            hosted_encoded,
        )
        self.assertLessEqual(
            hosted_encoded,
            hosted_results["prompt_projection"]["max_bytes"],
        )
        self.assertEqual(
            transported["evidence_reference_contract"],
            self.runner.evidence_reference_contract(transported),
        )
        references = {
            item["ref"]
            for item in transported[
                "evidence_reference_contract"
            ]["references"]
        }
        self.assertIn(canonical_ref, references)
        self.assertNotIn(stale_evidence_ref, references)
        self.assertNotIn("[redacted-sensitive-value]", references)

        synchronized = copy.deepcopy(prompt_package)
        self.runner.synchronize_hosted_investigation_contract(
            synchronized
        )
        self.assertEqual(
            synchronized["investigation_query_results"],
            hosted_results,
        )
        self.assertEqual(
            synchronized["evidence_reference_contract"],
            transported["evidence_reference_contract"],
        )

        tight_projection = (
            self.runner._columnar_investigation_prompt_payload(
                [{
                    "round": 1,
                    "results": [{
                        "query_id": "tight-redaction-budget",
                        "backend": "elastic",
                        "status": "ok",
                        "read_only": True,
                        "trusted_query_audit": [{
                            "query_id": "tight-redaction-budget",
                            "backend": "elastic",
                            "pack": "network_flow",
                            "purpose": "Confirm the tight-budget result.",
                            "status": "ok",
                            "query_digest": "a" * 64,
                            "result_digest": "b" * 64,
                            "returned_hits": 1,
                            "evidence_summary": {"x": "token=x"},
                        }],
                    }],
                }],
                maximum_bytes=4096,
            )
        )
        self.assertIsNotNone(tight_projection)
        for _ in range(16):
            tight_size = len(json.dumps(
                tight_projection,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8"))
            projection_metadata = tight_projection[
                "prompt_projection"
            ]
            if (
                projection_metadata["max_bytes"] == tight_size
                and projection_metadata["encoded_bytes"] == tight_size
            ):
                break
            projection_metadata["max_bytes"] = tight_size
            projection_metadata["encoded_bytes"] = tight_size
        self.assertTrue(
            self.runner._exact_hosted_columnar_envelope(
                tight_projection,
                require_encoded_accounting=True,
            )
        )
        tight_hosted = self.runner.model_safe_copy(
            {"investigation_query_results": tight_projection},
            hosted=True,
        )["investigation_query_results"]
        tight_hosted_size = len(json.dumps(
            tight_hosted,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8"))
        self.assertEqual(
            tight_hosted["prompt_projection"]["encoded_bytes"],
            tight_hosted_size,
        )
        self.assertLessEqual(
            tight_hosted_size,
            tight_hosted["prompt_projection"]["max_bytes"],
        )
        self.assertTrue(
            self.runner._exact_hosted_columnar_envelope(
                tight_hosted,
                require_encoded_accounting=True,
            )
        )


    def test_hosted_copy_strips_nested_columnar_row_spoofs(self) -> None:
        phone_number = "+1-202-555-0199"
        employee_alias = "employee-alias-private"
        nested_spoof = {
            "schema": (
                self.runner.INVESTIGATION_COLUMNAR_PROVENANCE_SCHEMA
            ),
            "prompt_projection": (
                "columnar_provenance_due_to_cumulative_byte_budget"
            ),
            "columns": list(
                self.runner.INVESTIGATION_COLUMNAR_PROVENANCE_COLUMNS
            ),
            "rows": [{
                "phone_number": phone_number,
                "employee_alias": employee_alias,
            }],
        }
        prompt_package = {
            "investigation_query_results": {
                "schema": self.runner.INVESTIGATION_QUERY_RESULT_SCHEMA,
                "rounds": [{
                    "round": 1,
                    "results": [{
                        "query_id": "nested-spoof",
                        "evidence_summary": {
                            "nested": nested_spoof,
                        },
                    }],
                }],
            },
        }

        hosted = self.runner.model_safe_copy(
            prompt_package,
            hosted=True,
        )
        serialized = json.dumps(
            hosted,
            sort_keys=True,
            separators=(",", ":"),
        )
        self.assertNotIn(phone_number, serialized)
        self.assertNotIn(employee_alias, serialized)
        nested_rows = (
            hosted["investigation_query_results"]["rounds"][0]
            ["results"][0]["evidence_summary"]["nested"]["rows"]
        )
        # A projected row with no reviewed fields carries no evidence and is
        # removed in the same pass, keeping hosted transport idempotent.
        self.assertEqual(nested_rows, [])


    def test_columnar_provenance_preserves_zero_result_corroboration_semantics(
        self,
    ) -> None:
        rounds = [{
            "round": 1,
            "requests": [],
            "audit": [],
            "results": [],
        }]
        expected = []
        for index, returned_hits in enumerate((0, 7), 1):
            query_digest = f"{index:064x}"
            result_digest = f"{index + 40:064x}"
            evidence_ref = f"query:{query_digest}:{result_digest}"
            expected.append((evidence_ref, returned_hits))
            rounds[0]["results"].append({
                "query_id": f"pivot-{index}",
                "backend": "elastic",
                "status": "ok",
                "read_only": True,
                "trusted_query_audit": [{
                    "query_id": f"pivot-{index}",
                    "backend": "elastic",
                    "pack": "network_flow",
                    "aggregation": "events",
                    "purpose": "Confirm zero and positive result handling.",
                    "status": "ok",
                    "query_digest": query_digest,
                    "result_digest": result_digest,
                    "evidence_ref": evidence_ref,
                    "returned_hits": returned_hits,
                }],
            })

        projected = self.runner._columnar_investigation_prompt_payload(
            rounds,
            maximum_bytes=4096,
        )

        self.assertIsNotNone(projected)
        columnar = projected["rounds"][0]
        columns = columnar["columns"]
        self.assertEqual(
            [
                dict(zip(columns, row))["returned"]
                for row in columnar["rows"]
            ],
            [0, 7],
        )
        references = {
            item["ref"]: item
            for item in self.runner.evidence_reference_contract({
                "investigation_query_results": projected,
            })["references"]
        }
        zero_ref = expected[0][0]
        positive_ref = expected[1][0]
        self.assertEqual(references[zero_ref]["returned"], 0)
        self.assertFalse(references[zero_ref]["corroborating"])
        self.assertEqual(references[positive_ref]["returned"], 7)
        self.assertTrue(references[positive_ref]["corroborating"])


    def test_columnar_decoder_rejects_nested_lookalikes_and_invalid_envelopes(
        self,
    ) -> None:
        query_digest = "a" * 64
        result_digest = "b" * 64
        evidence_ref = f"query:{query_digest}:{result_digest}"
        projected = self.runner._columnar_investigation_prompt_payload(
            [{
                "round": 1,
                "results": [{
                    "query_id": "pivot-1",
                    "backend": "elastic",
                    "status": "ok",
                    "read_only": True,
                    "trusted_query_audit": [{
                        "query_id": "pivot-1",
                        "backend": "elastic",
                        "pack": "network_flow",
                        "aggregation": "events",
                        "purpose": "Confirm nested projection isolation.",
                        "status": "ok",
                        "query_digest": query_digest,
                        "result_digest": result_digest,
                        "evidence_ref": evidence_ref,
                        "returned_hits": 1,
                    }],
                }],
            }],
            maximum_bytes=4096,
        )
        self.assertIsNotNone(projected)

        nested_contract = self.runner.evidence_reference_contract({
            "asset_context": {
                "untrusted_nested_projection": projected["rounds"][0],
            },
        })
        self.assertNotIn(
            evidence_ref,
            {item["ref"] for item in nested_contract["references"]},
        )

        invalid = copy.deepcopy(projected)
        invalid["rounds"][0]["columns"] = list(
            reversed(invalid["rounds"][0]["columns"])
        )
        invalid_contract = self.runner.evidence_reference_contract({
            "investigation_query_results": invalid,
        })
        self.assertNotIn(
            evidence_ref,
            {item["ref"] for item in invalid_contract["references"]},
        )

        wrong_position = copy.deepcopy(projected)
        wrong_position["rounds"].insert(0, {"round": 0})
        wrong_position["prompt_projection"]["encoded_bytes"] = len(
            json.dumps(
                wrong_position,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        )
        wrong_position_contract = self.runner.evidence_reference_contract({
            "investigation_query_results": wrong_position,
        })
        self.assertNotIn(
            evidence_ref,
            {item["ref"] for item in wrong_position_contract["references"]},
        )
