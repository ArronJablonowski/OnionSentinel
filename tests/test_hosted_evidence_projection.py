#!/usr/bin/env python3
"""Direct contracts for hosted evidence positive projection and redaction."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ROOT = ROOT / "n8n"
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

from onion_sentinel.analysis.evidence import hosted_projection  # noqa: E402


class HostedEvidenceProjectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.sentinel = object()
        self.policy = hosted_projection.Policy(
            provenance_schema="columnar-v1",
            columns=("evidence_ref_or_empty",),
            maximum_queries=12,
            list_path_sentinel=self.sentinel,
        )

    def test_result_rows_use_backend_specific_positive_projection(self) -> None:
        hits = hosted_projection.project_result_rows("hits", [{
            "id": "hit-1",
            "index": "logs-test",
            "source": {
                "source": {"ip": "192.0.2.10"},
                "message": "password=do-not-disclose",
            },
        }], self.policy)
        records = hosted_projection.project_result_rows("records", [{
            "source_ip": "192.0.2.10",
            "status_message": "Authorization: Bearer secret-value",
        }], self.policy)
        rows = hosted_projection.project_result_rows("rows", [{
            "pid": "42",
            "name": "safe-process",
            "username": "private-alias",
        }], self.policy)

        self.assertEqual(hits[0]["source"], {"source": {"ip": "192.0.2.10"}})
        self.assertEqual(records, [{"source_ip": "192.0.2.10"}])
        self.assertEqual(rows, [{"pid": "42", "name": "safe-process"}])

    def test_recursive_sanitizer_redacts_values_and_preserves_empty_results(self) -> None:
        value = {
            "summary": "password=private-value",
            "query_digest": "a" * 64,
            "api_token": "private-value",
            "rows": [],
            "nested": {"path": "/Users/alice/private/file"},
        }

        projected = hosted_projection.sanitize(value, policy=self.policy)
        projected = hosted_projection.prune_empty(projected)

        self.assertEqual(projected["summary"], "[redacted-sensitive-value]")
        self.assertEqual(projected["query_digest"], "a" * 64)
        self.assertNotIn("api_token", projected)
        self.assertEqual(projected["rows"], [])
        self.assertNotIn("nested", projected)
        self.assertEqual(
            hosted_projection.sanitize(projected, policy=self.policy),
            projected,
        )

    def test_columnar_reference_redaction_reverts_to_canonical_empty_marker(self) -> None:
        value = {
            "schema": "columnar-v1",
            "prompt_projection": "columnar_provenance_due_to_cumulative_byte_budget",
            "columns": ["evidence_ref_or_empty"],
            "rows": [["collector:password=private-value"]],
        }

        projected = hosted_projection.sanitize(
            value,
            path=("investigation_query_results", "rounds"),
            preserve_columnar_rows=True,
            policy=self.policy,
        )

        self.assertEqual(projected["rows"], [[""]])

    def test_reviewed_sha_path_requires_exact_positive_projection_ancestry(self) -> None:
        valid = (
            "investigation_query_results", "rounds", 0, "hits",
            self.sentinel, "source", "file", "hash",
        )
        self.assertTrue(hosted_projection.reviewed_sha256_path(valid, self.policy))
        self.assertFalse(hosted_projection.reviewed_sha256_path(
            (*valid[:-2], "unreviewed", "hash"), self.policy
        ))

    def test_refinalization_recomputes_exact_serialized_size(self) -> None:
        value = {"prompt_projection": {"encoded_bytes": 99}, "rounds": []}
        encoded = lambda item: json.dumps(
            item, sort_keys=True, separators=(",", ":")
        ).encode()
        dependencies = hosted_projection.Dependencies(
            exact_columnar_envelope=lambda *_args, **_kwargs: True,
            prompt_json_bytes=encoded,
        )

        result = hosted_projection.refinalize_columnar(
            value, maximum_passes=8, dependencies=dependencies
        )

        self.assertEqual(
            result["prompt_projection"]["encoded_bytes"], len(encoded(result))
        )


if __name__ == "__main__":
    unittest.main()
