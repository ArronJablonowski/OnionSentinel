#!/usr/bin/env python3
"""Direct contracts for immutable incident prompt grounding."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))

from prompt_incident_grounding import (  # noqa: E402
    IncidentGroundingSources,
    immutable_query_provenance,
    mandatory_grounding_digest,
)


def canonical_bytes(value):
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def evidence():
    return {
        "schema": "fixture-v1",
        "alert_id": "alert-1",
        "group_id": "group-1",
        "request": {"read_only": True},
        "security_onion_response": {
            "ok": True,
            "complete": True,
            "partial": False,
            "read_only": True,
            "query_contract": "fixture-query-v1",
            "observables": {"ips": ["192.0.2.10"]},
            "controls": {"writes": False},
            "semantic_validity": {"valid": True},
            "results": [{
                "pack": "network_flow",
                "query_digest": "a" * 64,
                "execution_digest": "b" * 64,
                "status": "ok",
                "hits": [{"id": "one"}, {"id": "two"}],
                "returned_hits": 2,
                "total_hits": 2,
                "truncated": False,
            }],
            "osquery_results": [{
                "query": "SELECT hostname FROM system_info LIMIT 1",
                "query_digest": "c" * 64,
                "status": "ok",
                "rows": [{"hostname": "sensor"}],
                "returned_rows": 1,
                "total_rows": 1,
                "truncated": False,
            }],
        },
    }


def package():
    return {
        "package_type": "soc-ai-investigation-prompt",
        "agent_role": "incident-responder",
        "group_id": "group-1",
        "manual_reanalysis": True,
        "alert": {"alert_id": "alert-1", "rule_name": "fixture"},
        "instructions": {
            "role": "Senior incident responder",
            "task": "Investigate the supplied alert.",
            "grounding": ["Use only supplied evidence."],
        },
        "response_schema": {"conclusion": "string"},
        "detection_validation": {"rule_intent_match": "unknown"},
        "incident_response_evidence": evidence(),
    }


class PromptIncidentGroundingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.validated = []
        self.sources = IncidentGroundingSources(
            validate_incident_evidence=lambda item: self.validated.append(item),
        )

    def test_query_provenance_excludes_mutable_samples(self):
        artifact = evidence()
        provenance = immutable_query_provenance(artifact)

        elastic = provenance["elastic_results"][0]
        osquery = provenance["osquery_results"][0]
        self.assertEqual(elastic["query_digest"], "a" * 64)
        self.assertEqual(osquery["query"], "SELECT hostname FROM system_info LIMIT 1")
        self.assertNotIn("hits", elastic)
        self.assertNotIn("returned_hits", elastic)
        self.assertNotIn("rows", osquery)
        self.assertNotIn("returned_rows", osquery)
        expected = canonical_bytes([{"id": "one"}, {"id": "two"}])
        self.assertEqual(
            elastic["source_evidence_provenance"]["source_samples_sha256"],
            hashlib.sha256(expected).hexdigest(),
        )

    def test_projection_metadata_preserves_original_provenance(self):
        artifact = evidence()
        original = immutable_query_provenance(artifact)
        result = artifact["security_onion_response"]["results"][0]
        source_hits = copy.deepcopy(result["hits"])
        encoded = canonical_bytes(source_hits)
        result["hits"] = source_hits[:1]
        result["returned_hits"] = 1
        result["truncated"] = True
        result["prompt_projection"] = {
            "source_returned_hits": 2,
            "source_total_hits": 2,
            "source_truncated": False,
            "source_hits_bytes": len(encoded),
            "source_hits_sha256": hashlib.sha256(encoded).hexdigest(),
        }

        projected = immutable_query_provenance(artifact)

        self.assertEqual(projected, original)

    def test_digest_validates_evidence_and_changes_with_query_identity(self):
        initial = package()
        digest = mandatory_grounding_digest(self.sources, initial)
        changed = copy.deepcopy(initial)
        changed["incident_response_evidence"]["security_onion_response"][
            "results"
        ][0]["query_digest"] = "d" * 64

        changed_digest = mandatory_grounding_digest(self.sources, changed)

        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        self.assertNotEqual(changed_digest, digest)
        self.assertEqual(self.validated, [initial["incident_response_evidence"], changed["incident_response_evidence"]])

    def test_missing_or_mismatched_identity_fails_closed(self):
        missing = package()
        missing["alert"] = {}
        with self.assertRaisesRegex(ValueError, "mandatory alert identity"):
            mandatory_grounding_digest(self.sources, missing)

        mismatched = package()
        mismatched["incident_response_evidence"]["group_id"] = "other-group"
        with self.assertRaisesRegex(ValueError, "identity does not match"):
            mandatory_grounding_digest(self.sources, mismatched)

    def test_blank_grounding_instruction_fails_before_evidence_validation(self):
        value = package()
        value["instructions"]["grounding"] = [""]

        with self.assertRaisesRegex(ValueError, "grounding instructions"):
            mandatory_grounding_digest(self.sources, value)

        self.assertEqual(self.validated, [])


if __name__ == "__main__":
    unittest.main()
