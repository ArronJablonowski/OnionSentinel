#!/usr/bin/env python3
"""Regression tests for restricted Security Onion query provenance."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import sys
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
        source = (BIN_DIR / "build-ai-investigation-prompt.py").read_text(encoding="utf-8")

        self.assertIn("requires validated restricted Security Onion evidence", source)
        self.assertNotIn('"security_onion_response": {"complete": False, "partial": True, "results": []}', source)

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
        self.assertIn("collect-incident-evidence.py", installer)
        self.assertIn("incident-evidence.example.json", installer)
        self.assertIn('if "timeout_seconds" not in config:', installer)
        self.assertIn('config["timeout_seconds"] = 420', installer)
        self.assertEqual(example["timeout_seconds"], 420)
        self.assertIn('config.get("timeout_seconds", 420)', collector)

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
