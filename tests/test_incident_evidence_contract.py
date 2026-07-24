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


def load_contract_module():
    if str(BIN_DIR) not in sys.path:
        sys.path.insert(0, str(BIN_DIR))
    spec = importlib.util.spec_from_file_location("incident_evidence_contract_test", CONTRACT_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def digest(query_dsl: dict) -> str:
    encoded = json.dumps(query_dsl, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def evidence_artifact(*, status: str = "ok") -> dict:
    window = {"start": "2026-07-22T18:00:00Z", "end": "2026-07-22T19:00:00Z"}
    query_dsl = {
        "size": 25,
        "query": {"bool": {"filter": [{"term": {"source.ip": "192.0.2.10"}}]}},
    }
    complete = status == "ok"
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
            "results": [{
                "pack": "network_flow",
                "status": status,
                "query_digest": digest(query_dsl),
                "query_dsl": query_dsl,
                "kql_equivalent": 'source.ip : "192.0.2.10"',
                "window_index": 0,
                "window": window,
                "hits": [],
            }],
            "osquery_results": [{
                "pack": "system_inventory",
                "target": "security-onion-local-host",
                "status": status,
                "query": load_contract_module().OSQUERY_PACKS["system_inventory"],
                "query_digest": hashlib.sha256(
                    load_contract_module().OSQUERY_PACKS["system_inventory"].encode("utf-8")
                ).hexdigest(),
                "total_rows": 1 if status == "ok" else 0,
                "returned_rows": 1 if status == "ok" else 0,
                "truncated": False,
                "duration_ms": 12,
                "rows": [{"hostname": "security-onion-test"}] if status == "ok" else [],
            }],
        },
    }


class IncidentEvidenceContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = load_contract_module()

    def test_accepts_complete_digest_matched_kql_and_dsl(self) -> None:
        artifact = evidence_artifact()

        validated = self.contract.validate_incident_evidence_artifact(artifact)

        self.assertIs(validated, artifact)

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

        self.assertIn("incident_evidence_contract.py", installer)
        self.assertIn("collect-incident-evidence.py", installer)

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
