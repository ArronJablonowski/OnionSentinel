from __future__ import annotations

from incident_evidence_contract_fixtures import (
    BIN_DIR,
    BUILDER_PATH,
    CONTRACT_PATH,
    Path,
    REPO_ROOT,
    copy,
    digest,
    elastic_result,
    evidence_artifact,
    execution_digest,
    hashlib,
    importlib,
    json,
    load_builder_module,
    load_contract_module,
    shutil,
    subprocess,
    sys,
    tempfile,
    unittest,
)

class IncidentEvidenceContractTestsAcceptsCompleteDigestMatchedKqlAndDslCases:
    def test_accepts_complete_digest_matched_kql_and_dsl(self) -> None:
        artifact = evidence_artifact()

        validated = self.contract.validate_incident_evidence_artifact(artifact)

        self.assertIs(validated, artifact)


    def test_fail_closed_contract_errors_preserve_exact_validation_order(self) -> None:
        cases = (
            (
                "schema",
                lambda artifact: artifact.__setitem__("schema", "unsupported"),
                "incident evidence schema is unsupported",
            ),
            (
                "response success",
                lambda artifact: artifact["security_onion_response"].__setitem__(
                    "ok", False
                ),
                "Security Onion evidence response is not successful",
            ),
            (
                "read-only response",
                lambda artifact: artifact["security_onion_response"].__setitem__(
                    "read_only", False
                ),
                "Security Onion evidence response is not read-only",
            ),
            (
                "query contract",
                lambda artifact: artifact["security_onion_response"].__setitem__(
                    "query_contract", "unsupported"
                ),
                "Security Onion query contract is unsupported",
            ),
            (
                "duplicate packs",
                lambda artifact: artifact["request"].__setitem__(
                    "packs", ["network_flow", "network_flow"]
                ),
                "incident evidence request contains duplicate packs",
            ),
            (
                "observables",
                lambda artifact: artifact["security_onion_response"].__setitem__(
                    "observables", {}
                ),
                "response observables do not match the request",
            ),
            (
                "request size",
                lambda artifact: artifact["request"].__setitem__("size", True),
                "incident evidence request size is invalid",
            ),
            (
                "window index",
                lambda artifact: artifact["security_onion_response"]["results"][
                    0
                ].__setitem__("window_index", True),
                "query window_index must be an integer",
            ),
            (
                "window identity",
                lambda artifact: artifact["security_onion_response"]["results"][
                    0
                ].__setitem__("window", {}),
                "query result window does not match the request",
            ),
            (
                "empty KQL",
                lambda artifact: artifact["security_onion_response"]["results"][
                    0
                ].__setitem__("kql_equivalent", ""),
                "query KQL equivalent must be non-empty",
            ),
            (
                "OSquery target",
                lambda artifact: artifact["security_onion_response"][
                    "osquery_results"
                ][0].__setitem__("target", "endpoint"),
                "OSquery target is not the Security Onion local host",
            ),
            (
                "OSquery returned rows",
                lambda artifact: artifact["security_onion_response"][
                    "osquery_results"
                ][0].__setitem__("returned_rows", 2),
                "OSquery returned_rows does not match its row set",
            ),
            (
                "OSquery total rows",
                lambda artifact: artifact["security_onion_response"][
                    "osquery_results"
                ][0].__setitem__("total_rows", -1),
                "OSquery total_rows is invalid",
            ),
            (
                "OSquery duration",
                lambda artifact: artifact["security_onion_response"][
                    "osquery_results"
                ][0].__setitem__("duration_ms", True),
                "OSquery duration_ms must be a non-negative integer",
            ),
            (
                "control anchor",
                lambda artifact: artifact["security_onion_response"][
                    "controls"
                ].__setitem__("anchor", None),
                "query control anchor does not match the request",
            ),
            (
                "semantic reasons",
                lambda artifact: artifact["security_onion_response"][
                    "semantic_validity"
                ].__setitem__("reasons", ["unexpected"]),
                "semantic validity reasons are inconsistent",
            ),
            (
                "complete flag",
                lambda artifact: artifact["security_onion_response"].__setitem__(
                    "complete", False
                ),
                "response complete flag does not match query results",
            ),
        )

        for label, mutate, expected in cases:
            with self.subTest(label=label):
                artifact = evidence_artifact()
                mutate(artifact)
                with self.assertRaises(
                    self.contract.IncidentEvidenceContractError
                ) as raised:
                    self.contract.validate_incident_evidence_artifact(artifact)
                self.assertEqual(str(raised.exception), expected)


    def test_prompt_hit_projection_preserves_a_valid_auditable_contract(self) -> None:
        artifact = evidence_artifact()
        result = artifact["security_onion_response"]["results"][0]
        result["hits"] = [
            {
                "id": f"flow-{index}",
                "index": ".ds-logs-zeek-so-2026.07.22-000001",
                "source": {
                    "@timestamp": f"2026-07-22T18:30:{index:02d}Z",
                    "source": {"ip": "192.0.2.10"},
                },
            }
            for index in range(25)
        ]
        result["returned_hits"] = 25
        result["total_hits"] = 25
        result["truncated"] = False
        self.contract.validate_incident_evidence_artifact(artifact)

        projected = self.builder.project_incident_evidence_hits(
            artifact,
            limit=20,
            reason="unit_initial_projection",
        )

        self.assertEqual(projected, 1)
        self.contract.validate_incident_evidence_artifact(artifact)
        self.assertEqual(result["returned_hits"], 20)
        self.assertEqual(len(result["hits"]), 20)
        self.assertTrue(result["truncated"])
        projection = result["prompt_projection"]
        self.assertEqual(projection["source_returned_hits"], 25)
        self.assertEqual(projection["source_total_hits"], 25)
        self.assertRegex(projection["source_hits_sha256"], r"^[0-9a-f]{64}$")
        self.assertGreater(
            projection["source_hits_bytes"],
            projection["retained_hits_bytes"],
        )
        self.assertRegex(
            projection["retained_hits_sha256"],
            r"^[0-9a-f]{64}$",
        )

        self.builder.project_incident_evidence_hits(
            artifact,
            limit=5,
            reason="unit_budget_projection",
        )

        self.contract.validate_incident_evidence_artifact(artifact)
        self.assertEqual(result["returned_hits"], 5)
        self.assertEqual(len(result["hits"]), 5)
        self.assertEqual(result["prompt_projection"]["source_returned_hits"], 25)
        self.assertEqual(
            result["prompt_projection"]["reasons"],
            ["unit_initial_projection", "unit_budget_projection"],
        )
        tampered = copy.deepcopy(artifact)
        tampered_result = tampered["security_onion_response"]["results"][0]
        tampered_result["prompt_projection"]["source_hits_sha256"] = "0" * 63
        with self.assertRaisesRegex(
            self.contract.IncidentEvidenceContractError,
            "source digest is invalid",
        ):
            self.contract.validate_incident_evidence_artifact(tampered)
        unknown_field = copy.deepcopy(artifact)
        unknown_field["security_onion_response"]["results"][0][
            "prompt_projection"
        ]["unexpected"] = True
        with self.assertRaisesRegex(
            self.contract.IncidentEvidenceContractError,
            "projection fields are invalid",
        ):
            self.contract.validate_incident_evidence_artifact(unknown_field)
        inconsistent_bytes = copy.deepcopy(artifact)
        byte_projection = inconsistent_bytes["security_onion_response"][
            "results"
        ][0]["prompt_projection"]
        byte_projection["source_hits_bytes"] = byte_projection[
            "retained_hits_bytes"
        ]
        with self.assertRaisesRegex(
            self.contract.IncidentEvidenceContractError,
            "projection metadata is inconsistent",
        ):
            self.contract.validate_incident_evidence_artifact(
                inconsistent_bytes
            )


    def test_prompt_osquery_projection_preserves_query_identity_and_row_provenance(
        self,
    ) -> None:
        artifact = evidence_artifact()
        result = artifact["security_onion_response"]["osquery_results"][0]
        result["rows"] = [
            {
                "hostname": f"security-onion-{index:02d}",
                "hardware_model": "fixture",
            }
            for index in range(20)
        ]
        result["returned_rows"] = 20
        result["total_rows"] = 20
        result["truncated"] = False
        original_rows = copy.deepcopy(result["rows"])
        original_query = result["query"]
        original_digest = result["query_digest"]
        original_status = result["status"]
        original_encoded = json.dumps(
            original_rows,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        self.contract.validate_incident_evidence_artifact(artifact)

        projected = self.builder.project_incident_evidence_osquery_rows(
            artifact,
            limit=5,
            max_retained_bytes=4096,
            max_row_bytes=1024,
            reason="unit_budget_projection",
        )

        self.assertEqual(projected, 1)
        self.contract.validate_incident_evidence_artifact(artifact)
        self.assertEqual(result["rows"], original_rows[:5])
        self.assertEqual(result["returned_rows"], 5)
        self.assertEqual(result["total_rows"], 20)
        self.assertTrue(result["truncated"])
        self.assertEqual(result["query"], original_query)
        self.assertEqual(result["query_digest"], original_digest)
        self.assertEqual(result["status"], original_status)
        projection = result["prompt_projection"]
        self.assertEqual(projection["source_returned_rows"], 20)
        self.assertEqual(projection["source_total_rows"], 20)
        self.assertEqual(projection["source_rows_bytes"], len(original_encoded))
        self.assertEqual(
            projection["source_rows_sha256"],
            hashlib.sha256(original_encoded).hexdigest(),
        )
        self.assertEqual(projection["retained_rows"], 5)

        self.builder.project_incident_evidence_osquery_rows(
            artifact,
            limit=0,
            max_retained_bytes=2,
            max_row_bytes=0,
            reason="unit_row_omission",
        )

        self.contract.validate_incident_evidence_artifact(artifact)
        self.assertEqual(result["rows"], [])
        self.assertEqual(result["prompt_projection"]["source_returned_rows"], 20)
        self.assertEqual(
            result["prompt_projection"]["reasons"],
            ["unit_budget_projection", "unit_row_omission"],
        )
        tampered = copy.deepcopy(artifact)
        tampered_projection = tampered["security_onion_response"][
            "osquery_results"
        ][0]["prompt_projection"]
        tampered_projection["retained_rows_sha256"] = "0" * 64
        with self.assertRaisesRegex(
            self.contract.IncidentEvidenceContractError,
            "projection metadata is inconsistent",
        ):
            self.contract.validate_incident_evidence_artifact(tampered)
        unknown_field = copy.deepcopy(artifact)
        unknown_field["security_onion_response"]["osquery_results"][0][
            "prompt_projection"
        ]["unexpected"] = True
        with self.assertRaisesRegex(
            self.contract.IncidentEvidenceContractError,
            "projection fields are invalid",
        ):
            self.contract.validate_incident_evidence_artifact(unknown_field)
        inconsistent_bytes = copy.deepcopy(artifact)
        byte_projection = inconsistent_bytes["security_onion_response"][
            "osquery_results"
        ][0]["prompt_projection"]
        byte_projection["source_rows_bytes"] = byte_projection[
            "retained_rows_bytes"
        ]
        with self.assertRaisesRegex(
            self.contract.IncidentEvidenceContractError,
            "projection metadata is inconsistent",
        ):
            self.contract.validate_incident_evidence_artifact(
                inconsistent_bytes
            )


    def test_raw_collector_input_rejects_existing_prompt_projection(self) -> None:
        artifact = evidence_artifact()
        projected = self.builder.project_incident_evidence_osquery_rows(
            artifact,
            limit=0,
            max_retained_bytes=2,
            max_row_bytes=0,
            reason="unit_projection",
        )
        self.assertEqual(projected, 1)
        self.contract.validate_incident_evidence_artifact(artifact)

        with self.assertRaisesRegex(
            ValueError,
            "raw incident evidence collector artifact must not contain",
        ):
            self.builder.reject_preprojected_incident_evidence_source(
                artifact
            )


    def test_prompt_osquery_projection_omits_an_oversized_row_as_a_whole(
        self,
    ) -> None:
        artifact = evidence_artifact()
        result = artifact["security_onion_response"]["osquery_results"][0]
        result["rows"] = [
            {"hostname": "x" * 5000},
            {"hostname": "smaller-row-is-not-reordered-ahead"},
        ]
        result["returned_rows"] = 2
        result["total_rows"] = 2
        result["truncated"] = False
        original_encoded = json.dumps(
            result["rows"],
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")

        projected = self.builder.project_incident_evidence_osquery_rows(
            artifact,
            limit=10,
            max_retained_bytes=16 * 1024,
            max_row_bytes=4 * 1024,
            reason="unit_large_row_projection",
        )

        self.assertEqual(projected, 1)
        self.assertEqual(result["rows"], [])
        self.assertEqual(result["returned_rows"], 0)
        self.assertTrue(result["truncated"])
        self.assertEqual(
            result["prompt_projection"]["source_rows_sha256"],
            hashlib.sha256(original_encoded).hexdigest(),
        )
        self.contract.validate_incident_evidence_artifact(artifact)


    def test_prompt_budget_compacts_osquery_before_higher_value_elastic_hits(
        self,
    ) -> None:
        artifact = evidence_artifact()
        artifact["alert_id"] = "fixture-alert"
        artifact["group_id"] = "fixture-group"
        elastic_result = artifact["security_onion_response"]["results"][0]
        elastic_result["hits"] = [
            {
                "id": f"flow-{index:02d}",
                "index": ".ds-logs-zeek-so-2026.07.22-000001",
                "source": {
                    "@timestamp": f"2026-07-22T18:30:{index:02d}Z",
                    "source": {"ip": "192.0.2.10"},
                    "network": {"community_id": f"fixture-{index:02d}"},
                },
            }
            for index in range(25)
        ]
        elastic_result["returned_hits"] = 25
        elastic_result["total_hits"] = 25
        elastic_result["truncated"] = False
        original_hits = copy.deepcopy(elastic_result["hits"])
        result = artifact["security_onion_response"]["osquery_results"][0]
        result["rows"] = [
            {
                "hostname": f"security-onion-{index:03d}",
                "hardware_model": "x" * 1800,
            }
            for index in range(200)
        ]
        result["returned_rows"] = 200
        result["total_rows"] = 200
        result["truncated"] = False
        original_rows = copy.deepcopy(result["rows"])
        original_query = result["query"]
        original_query_digest = result["query_digest"]
        package = {
            "package_type": "soc-ai-investigation-prompt",
            "agent_role": "incident-responder",
            "group_id": "fixture-group",
            "manual_reanalysis": True,
            "alert": {
                "alert_id": "fixture-alert",
                "rule_id": "999999",
                "rule_name": "fixture",
            },
            "instructions": {
                "role": "Senior incident responder",
                "grounding": ["Use only supplied evidence."],
                "task": "Investigate the alert.",
            },
            "response_schema": {"conclusion": "string"},
            "detection_validation": {"rule_intent_match": "unknown"},
            "incident_response_evidence": artifact,
        }
        original_query_provenance = (
            self.builder.incident_prompt_immutable_query_provenance(artifact)
        )
        original_grounding_digest = (
            self.builder.incident_prompt_mandatory_grounding_digest(package)
        )
        elastic_provenance = original_query_provenance["elastic_results"][0]
        osquery_provenance = original_query_provenance["osquery_results"][0]
        for field in (
            "query_dsl",
            "kql_equivalent",
            "query_digest",
            "execution_digest",
            "status",
            "window",
            "index_scope",
            "total_hits",
            "duration_ms",
        ):
            self.assertIn(field, elastic_provenance)
        for field in (
            "query",
            "query_digest",
            "target",
            "status",
            "total_rows",
            "duration_ms",
        ):
            self.assertIn(field, osquery_provenance)
        for field in ("hits", "returned_hits", "truncated", "prompt_projection"):
            self.assertNotIn(field, elastic_provenance)
        for field in ("rows", "returned_rows", "truncated", "prompt_projection"):
            self.assertNotIn(field, osquery_provenance)
        elastic_source = elastic_provenance["source_evidence_provenance"]
        osquery_source = osquery_provenance["source_evidence_provenance"]
        original_hits_encoded = json.dumps(
            original_hits,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        original_rows_encoded = json.dumps(
            original_rows,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        self.assertEqual(elastic_source["source_returned"], 25)
        self.assertEqual(
            elastic_source["source_samples_bytes"],
            len(original_hits_encoded),
        )
        self.assertEqual(
            elastic_source["source_samples_sha256"],
            hashlib.sha256(original_hits_encoded).hexdigest(),
        )
        self.assertEqual(osquery_source["source_returned"], 200)
        self.assertEqual(
            osquery_source["source_samples_bytes"],
            len(original_rows_encoded),
        )
        self.assertEqual(
            osquery_source["source_samples_sha256"],
            hashlib.sha256(original_rows_encoded).hexdigest(),
        )
        tampered_timing = copy.deepcopy(package)
        tampered_timing["incident_response_evidence"][
            "security_onion_response"
        ]["osquery_results"][0]["duration_ms"] += 1
        self.assertNotEqual(
            self.builder.incident_prompt_mandatory_grounding_digest(
                tampered_timing
            ),
            original_grounding_digest,
        )
        tampered_kql = copy.deepcopy(package)
        tampered_kql["incident_response_evidence"][
            "security_onion_response"
        ]["results"][0]["kql_equivalent"] += " "
        self.assertNotEqual(
            self.builder.incident_prompt_mandatory_grounding_digest(
                tampered_kql
            ),
            original_grounding_digest,
        )
        initial_bytes = len(
            json.dumps(
                package,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        )
        self.assertGreater(initial_bytes, 327_680)

        first_package, first_output = self.builder.compact_package_to_budget(
            copy.deepcopy(package),
            327_680,
        )
        second_package, second_output = self.builder.compact_package_to_budget(
            copy.deepcopy(package),
            327_680,
        )

        self.assertEqual(first_output, second_output)
        self.assertEqual(first_package, second_package)
        self.assertLessEqual(len(first_output.encode("utf-8")), 327_680)
        self.assertEqual(json.loads(first_output), first_package)
        self.assertIn(
            "incident_response_osquery_row_samples",
            first_package["package_budget"]["compaction_steps"],
        )
        steps = first_package["package_budget"]["compaction_steps"]
        self.assertLess(
            steps.index("incident_response_hit_samples"),
            steps.index("incident_response_osquery_row_samples"),
        )
        self.assertNotIn("incident_response_minimal_hit_samples", steps)
        self.assertNotIn("incident_response_hits", steps)
        self.assertTrue(
            first_package["package_budget"]["mandatory_grounding_preserved"]
        )
        self.assertRegex(
            first_package["package_budget"]["mandatory_grounding_sha256"],
            r"^[0-9a-f]{64}$",
        )
        self.assertEqual(first_package["alert"], package["alert"])
        self.assertEqual(first_package["instructions"], package["instructions"])
        self.assertEqual(
            first_package["detection_validation"],
            package["detection_validation"],
        )
        self.assertEqual(
            self.builder.incident_prompt_immutable_query_provenance(
                first_package["incident_response_evidence"]
            ),
            original_query_provenance,
        )
        compact_result = first_package["incident_response_evidence"][
            "security_onion_response"
        ]["osquery_results"][0]
        compact_elastic_result = first_package["incident_response_evidence"][
            "security_onion_response"
        ]["results"][0]
        self.assertEqual(compact_elastic_result["hits"], original_hits[:5])
        self.assertEqual(compact_elastic_result["returned_hits"], 5)
        self.assertTrue(compact_elastic_result["truncated"])
        self.assertEqual(compact_result["query"], original_query)
        self.assertEqual(compact_result["query_digest"], original_query_digest)
        self.assertEqual(compact_result["status"], "ok")
        retained_count = compact_result["returned_rows"]
        self.assertGreater(retained_count, 0)
        self.assertLessEqual(retained_count, 10)
        self.assertEqual(
            compact_result["rows"],
            original_rows[:retained_count],
        )
        self.assertEqual(compact_result["total_rows"], 200)
        self.assertTrue(compact_result["truncated"])
        self.contract.validate_incident_evidence_artifact(
            first_package["incident_response_evidence"]
        )


    def test_oversized_incident_prompt_fails_closed_without_alert_identity(
        self,
    ) -> None:
        artifact = evidence_artifact()
        artifact["alert_id"] = "fixture-alert"
        artifact["group_id"] = "fixture-group"
        result = artifact["security_onion_response"]["osquery_results"][0]
        result["rows"] = [
            {"hostname": f"security-onion-{index}", "value": "x" * 2000}
            for index in range(200)
        ]
        result["returned_rows"] = 200
        result["total_rows"] = 200
        package = {
            "package_type": "soc-ai-investigation-prompt",
            "agent_role": "incident-responder",
            "group_id": "fixture-group",
            "instructions": {
                "role": "Senior incident responder",
                "grounding": ["Use only supplied evidence."],
                "task": "Investigate the alert.",
            },
            "response_schema": {"conclusion": "string"},
            "detection_validation": {"rule_intent_match": "unknown"},
            "incident_response_evidence": artifact,
        }

        with self.assertRaisesRegex(
            ValueError,
            "mandatory alert identity",
        ):
            self.builder.compact_package_to_budget(package, 327_680)


    def test_accepts_partial_query_as_an_explicit_evidence_gap(self) -> None:
        artifact = evidence_artifact(status="timeout")

        validated = self.contract.validate_incident_evidence_artifact(artifact)

        self.assertTrue(validated["security_onion_response"]["partial"])


    def test_rejects_an_empty_query_audit(self) -> None:
        artifact = evidence_artifact()
        artifact["security_onion_response"]["results"] = []

        with self.assertRaisesRegex(
            self.contract.IncidentEvidenceContractError,
            "must contain 1 query result",
        ):
            self.contract.validate_incident_evidence_artifact(artifact)


    def test_rejects_missing_kql_or_exact_dsl(self) -> None:
        for field in ("kql_equivalent", "query_dsl"):
            with self.subTest(field=field):
                artifact = evidence_artifact()
                artifact["security_onion_response"]["results"][0].pop(field)
                with self.assertRaises(self.contract.IncidentEvidenceContractError):
                    self.contract.validate_incident_evidence_artifact(artifact)


    def test_rejects_dsl_that_no_longer_matches_wrapper_digest(self) -> None:
        artifact = copy.deepcopy(evidence_artifact())
        artifact["security_onion_response"]["results"][0]["query_dsl"]["size"] = 50

        with self.assertRaisesRegex(
            self.contract.IncidentEvidenceContractError,
            "does not match its wrapper digest",
        ):
            self.contract.validate_incident_evidence_artifact(artifact)


    def test_rejects_v2_artifact_without_semantic_controls(self) -> None:
        artifact = evidence_artifact()
        artifact["security_onion_response"].pop("controls")
        artifact["security_onion_response"].pop("semantic_validity")

        with self.assertRaises(self.contract.IncidentEvidenceContractError):
            self.contract.validate_incident_evidence_artifact(artifact)


    def test_rejects_hit_from_an_index_outside_the_reviewed_pack(self) -> None:
        artifact = evidence_artifact()
        result = artifact["security_onion_response"]["results"][0]
        result["hits"] = [{
            "id": "wrong-index-hit",
            "index": ".ds-logs-unreviewed.secret-default-2026.07.22-000001",
            "source": {"@timestamp": "2026-07-22T18:30:00Z"},
        }]
        result["returned_hits"] = 1
        result["total_hits"] = 1

        with self.assertRaisesRegex(
            self.contract.IncidentEvidenceContractError,
            "out-of-scope hit index",
        ):
            self.contract.validate_incident_evidence_artifact(artifact)


    def test_rejects_success_claim_when_elasticsearch_reported_failed_shards(self) -> None:
        artifact = evidence_artifact()
        result = artifact["security_onion_response"]["results"][0]
        result["shards"] = {
            "total": 2,
            "successful": 1,
            "skipped": 0,
            "failed": 1,
            "failures": [{"index": "unit", "reason": "synthetic shard failure"}],
        }

        with self.assertRaisesRegex(
            self.contract.IncidentEvidenceContractError,
            "semantic_valid flag is inconsistent",
        ):
            self.contract.validate_incident_evidence_artifact(artifact)


    def test_zero_hit_pack_cannot_be_complete_when_anchor_control_fails(self) -> None:
        artifact = evidence_artifact()
        response = artifact["security_onion_response"]
        positive = response["controls"]["positive_anchor"]
        positive["hits"] = []
        positive["returned_hits"] = 0
        positive["total_hits"] = 0
        positive["passed"] = False
        response["semantic_validity"]["controls_valid"] = False
        response["semantic_validity"]["semantic_valid"] = False
        response["semantic_validity"]["reasons"] = [
            "representative alert controls did not both pass",
        ]
        response["complete"] = False
        response["partial"] = True

        validated = self.contract.validate_incident_evidence_artifact(artifact)

        self.assertFalse(validated["security_onion_response"]["complete"])
