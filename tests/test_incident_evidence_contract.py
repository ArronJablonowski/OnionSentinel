#!/usr/bin/env python3
"""Regression tests for restricted Security Onion query provenance."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
BIN_DIR = REPO_ROOT / "n8n" / "bin"
CONTRACT_PATH = BIN_DIR / "incident_evidence_contract.py"
BUILDER_PATH = BIN_DIR / "build-ai-investigation-prompt.py"


def load_contract_module():
    if str(BIN_DIR) not in sys.path:
        sys.path.insert(0, str(BIN_DIR))
    spec = importlib.util.spec_from_file_location("incident_evidence_contract_test", CONTRACT_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def load_builder_module():
    if str(BIN_DIR) not in sys.path:
        sys.path.insert(0, str(BIN_DIR))
    spec = importlib.util.spec_from_file_location(
        "incident_evidence_prompt_builder_test",
        BUILDER_PATH,
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def digest(query_dsl: dict) -> str:
    encoded = json.dumps(query_dsl, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def execution_digest(query_dsl: dict, index_scope: list[str], endpoint: str) -> str:
    encoded = json.dumps(
        {
            "index_scope": index_scope,
            "query_endpoint": endpoint,
            "query_dsl": query_dsl,
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def elastic_result(
    query_dsl: dict,
    index_scope: list[str],
    *,
    status: str = "ok",
    hits: list[dict] | None = None,
) -> dict:
    hits = list(hits or [])
    endpoint = (
        f"{','.join(index_scope)}/_search"
        "?ignore_unavailable=true&expand_wildcards=open"
        "&preference=onion-sentinel-incident-evidence"
    )
    semantic_valid = status == "ok"
    return {
        "status": status,
        "semantic_valid": semantic_valid,
        "query_digest": digest(query_dsl),
        "execution_digest": execution_digest(query_dsl, index_scope, endpoint),
        "query_dsl": query_dsl,
        "index_scope": index_scope,
        "query_endpoint": endpoint,
        "total_hits": len(hits),
        "total_hits_relation": "eq",
        "returned_hits": len(hits),
        "truncated": False,
        "duration_ms": 12,
        "timed_out": status == "timeout",
        "took_ms": 4,
        "shards": {
            "total": 1,
            "successful": 1,
            "skipped": 0,
            "failed": 0,
            "failures": [],
        },
        "hits": hits,
    }


def evidence_artifact(*, status: str = "ok") -> dict:
    contract = load_contract_module()
    window = {"start": "2026-07-22T18:00:00Z", "end": "2026-07-22T19:00:00Z"}
    query_dsl = {
        "size": 25,
        "query": {"bool": {"filter": [{"term": {"source.ip": "192.0.2.10"}}]}},
    }
    anchor = {
        "index": ".ds-logs-suricata.alerts-so-2026.07.22-000001",
        "id": "elastic-anchor-unit",
    }
    positive_dsl = {
        "size": 1,
        "track_total_hits": True,
        "timeout": "30s",
        "_source": ["@timestamp", "event.dataset"],
        "query": {"ids": {"values": [anchor["id"]]}},
    }
    negative_dsl = {
        "size": 1,
        "track_total_hits": True,
        "timeout": "30s",
        "_source": ["@timestamp", "event.dataset"],
        "query": {
            "bool": {
                "filter": [{"ids": {"values": [anchor["id"]]}}],
                "must_not": [{"ids": {"values": [anchor["id"]]}}],
            },
        },
    }
    positive = elastic_result(
        positive_dsl,
        [anchor["index"]],
        hits=[{
            "id": anchor["id"],
            "index": anchor["index"],
            "source": {
                "@timestamp": "2026-07-22T18:30:00Z",
                "event": {"dataset": "suricata.alert"},
            },
        }],
    )
    positive["passed"] = True
    negative = elastic_result(negative_dsl, contract.ALERT_INDEX_SCOPE)
    negative["passed"] = True
    complete = status == "ok"
    pack_result = elastic_result(
        query_dsl,
        contract.PACK_INDEX_SCOPES["network_flow"],
        status=status,
    )
    pack_result.update({
        "pack": "network_flow",
        "kql_equivalent": 'source.ip : "192.0.2.10"',
        "window_index": 0,
        "window": window,
    })
    return {
        "schema": "onion-sentinel-incident-evidence-v2",
        "generated_at": "2026-07-22  13:00:00-06:00",
        "request": {
            "packs": ["network_flow"],
            "osquery_packs": ["system_inventory"],
            "windows": [window],
            "observables": {
                "ips": ["192.0.2.10"],
                "domains": [],
                "hosts": [],
                "users": [],
            },
            "size": 25,
            "anchor": anchor,
        },
        "security_onion_response": {
            "ok": True,
            "complete": complete,
            "partial": not complete,
            "read_only": True,
            "query_contract": "onion-sentinel-incident-evidence-v2",
            "observables": {
                "ips": ["192.0.2.10"],
                "domains": [],
                "hosts": [],
                "users": [],
            },
            "results": [pack_result],
            "osquery_results": [{
                "pack": "system_inventory",
                "target": "security-onion-local-host",
                "status": status,
                "query": contract.OSQUERY_PACKS["system_inventory"],
                "query_digest": hashlib.sha256(
                    contract.OSQUERY_PACKS["system_inventory"].encode("utf-8")
                ).hexdigest(),
                "total_rows": 1 if status == "ok" else 0,
                "returned_rows": 1 if status == "ok" else 0,
                "truncated": False,
                "duration_ms": 12,
                "rows": [{"hostname": "security-onion-test"}] if status == "ok" else [],
            }],
            "controls": {
                "anchor": anchor,
                "positive_anchor": positive,
                "negative_filter": negative,
            },
            "semantic_validity": {
                "transport_valid": True,
                "controls_valid": True,
                "query_execution_valid": complete,
                "coverage_valid": complete,
                "semantic_valid": complete,
                "reasons": [] if complete else [
                    "one or more Elasticsearch packs failed semantic validation",
                ],
            },
        },
    }


class IncidentEvidenceContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = load_contract_module()
        cls.builder = load_builder_module()

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

    def test_anchorless_v2_request_is_accepted_only_as_semantically_partial(self) -> None:
        artifact = evidence_artifact()
        response = artifact["security_onion_response"]
        artifact["request"]["anchor"] = None
        response["controls"] = {
            "anchor": None,
            "positive_anchor": {
                "status": "not_requested",
                "passed": False,
                "semantic_valid": False,
                "error": "A representative Security Onion alert anchor was not supplied",
            },
            "negative_filter": {
                "status": "not_requested",
                "passed": False,
                "semantic_valid": False,
                "error": "A representative Security Onion alert anchor was not supplied",
            },
        }
        response["semantic_validity"]["controls_valid"] = False
        response["semantic_validity"]["semantic_valid"] = False
        response["semantic_validity"]["reasons"] = [
            "representative alert controls did not both pass",
        ]
        response["complete"] = False
        response["partial"] = True

        validated = self.contract.validate_incident_evidence_artifact(artifact)

        self.assertFalse(validated["security_onion_response"]["complete"])

    def test_rejects_complete_claim_when_anchor_control_failed(self) -> None:
        artifact = evidence_artifact()
        response = artifact["security_onion_response"]
        positive = response["controls"]["positive_anchor"]
        positive["hits"] = []
        positive["returned_hits"] = 0
        positive["total_hits"] = 0
        positive["passed"] = False

        with self.assertRaisesRegex(
            self.contract.IncidentEvidenceContractError,
            "semantic validity controls_valid flag is inconsistent",
        ):
            self.contract.validate_incident_evidence_artifact(artifact)

    def test_rejects_query_endpoint_scope_tampering(self) -> None:
        artifact = evidence_artifact()
        result = artifact["security_onion_response"]["results"][0]
        result["query_endpoint"] = "/_search"

        with self.assertRaisesRegex(
            self.contract.IncidentEvidenceContractError,
            "outside its reviewed index scope",
        ):
            self.contract.validate_incident_evidence_artifact(artifact)

    def test_rejects_unreviewed_or_modified_osquery_sql(self) -> None:
        artifact = evidence_artifact()
        artifact["security_onion_response"]["osquery_results"][0]["query"] = (
            "SELECT * FROM processes;"
        )

        with self.assertRaisesRegex(
            self.contract.IncidentEvidenceContractError,
            "does not match its reviewed pack",
        ):
            self.contract.validate_incident_evidence_artifact(artifact)

    def test_accepts_legacy_v1_artifact_without_live_osquery(self) -> None:
        artifact = evidence_artifact()
        artifact["schema"] = "onion-sentinel-incident-evidence-v1"
        artifact["security_onion_response"]["query_contract"] = (
            "onion-sentinel-incident-evidence-v1"
        )
        artifact["request"].pop("osquery_packs")
        artifact["security_onion_response"].pop("osquery_results")

        validated = self.contract.validate_incident_evidence_artifact(artifact)

        self.assertIs(validated, artifact)

    def test_incident_prompt_builder_has_no_empty_evidence_fallback(self) -> None:
        builder = (BIN_DIR / "build-ai-investigation-prompt.py").read_text(
            encoding="utf-8"
        )
        assembler = (BIN_DIR / "prompt_package_view_model.py").read_text(
            encoding="utf-8"
        )
        orchestrator = (BIN_DIR / "prompt_package_orchestrator.py").read_text(
            encoding="utf-8"
        )

        self.assertIn("build_prepared_prompt_package(", builder)
        self.assertIn("assemble_prepared_prompt_package(", orchestrator)
        self.assertIn("assemble_prompt_package(", assembler)
        self.assertIn("requires validated restricted Security Onion evidence", assembler)
        self.assertNotIn(
            '"security_onion_response": {"complete": False, "partial": True, "results": []}',
            builder + orchestrator + assembler,
        )

    def test_mac_installer_deploys_incident_evidence_runtime_dependencies(self) -> None:
        installer = (BIN_DIR / "install-macstudio-stack.zsh").read_text(encoding="utf-8")
        example = json.loads(
            (REPO_ROOT / "n8n" / "config" / "incident-evidence.example.json").read_text(
                encoding="utf-8"
            )
        )
        collector = (BIN_DIR / "collect-incident-evidence.py").read_text(
            encoding="utf-8"
        )

        self.assertIn("incident_evidence_contract.py", installer)
        for name in (
            "incident_evidence_validation.py",
            "incident_evidence_primitives.py",
            "incident_evidence_search_contract.py",
            "incident_evidence_osquery_contract.py",
            "incident_evidence_control_contract.py",
            "incident_evidence_artifact_contract.py",
        ):
            self.assertIn(
                f'cp "$REPO_DIR/n8n/bin/{name}" "$STACK_DIR/bin/{name}"',
                installer,
            )
        self.assertIn("collect-incident-evidence.py", installer)
        self.assertIn("incident-evidence.example.json", installer)
        self.assertIn('if "timeout_seconds" not in config:', installer)
        self.assertIn('config["timeout_seconds"] = 420', installer)
        self.assertEqual(example["timeout_seconds"], 420)
        self.assertIn('config.get("timeout_seconds", 420)', collector)

    def test_incident_evidence_facade_imports_from_an_isolated_flat_bin(self) -> None:
        names = (
            "incident_evidence_validation.py",
            "incident_evidence_primitives.py",
            "incident_evidence_search_contract.py",
            "incident_evidence_osquery_contract.py",
            "incident_evidence_control_contract.py",
            "incident_evidence_artifact_contract.py",
            "incident_evidence_contract.py",
        )
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory)
            for name in names:
                shutil.copy2(BIN_DIR / name, runtime / name)
            result = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    str(runtime / "incident_evidence_contract.py"),
                ],
                text=True,
                capture_output=True,
                timeout=10,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_incident_responder_prompt_requires_framework_and_query_audits(self) -> None:
        prompt = (
            REPO_ROOT / "n8n" / "config" / "incident_responder_system_prompt.md"
        ).read_text(encoding="utf-8")

        self.assertIn("SIEM Detection Outcome Classification", prompt)
        self.assertIn("True Positive - Malicious", prompt)
        self.assertIn("False Negative", prompt)
        self.assertIn("exact OSQuery SQL", prompt)
        self.assertIn("query digest", prompt)


if __name__ == "__main__":
    unittest.main()
