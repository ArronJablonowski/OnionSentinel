"""Direct contracts for route-safe evidence transport composition."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.analysis.evidence import transport  # noqa: E402


SENTINEL = object()
POLICY = transport.Policy(
    internal_keys=frozenset({"sha256", "analysis_dir"}),
    hosted_forbidden_keys=frozenset({"payload"}),
    list_path_sentinel=SENTINEL,
    fixed_point_max_passes=8,
)


def dependencies() -> transport.Dependencies:
    return transport.Dependencies(
        redact_asset_owners=lambda value: {
            **value, "redacted": True,
        } if isinstance(value, dict) else value,
        reviewed_sha256_path=lambda path: path == (
            "investigation_query_results", "hits", SENTINEL, "source", "hash",
        ),
        exact_columnar_envelope=lambda _value, **_kwargs: False,
        sanitize_hosted_evidence=lambda value, _path, **_kwargs: value,
        refinalize_columnar_envelope=lambda value: value,
        evidence_reference_contract=lambda _value: {"schema": "fresh-contract"},
    )


class EvidenceTransportPackageTests(unittest.TestCase):
    def test_hosted_copy_enforces_internal_forbidden_and_hash_paths(self) -> None:
        digest = "a" * 64
        package = {
            "analysis_dir": "/private", "payload": "secret", "sha256": "local",
            "_local_context": {"secret": True},
            "investigation_query_results": {"hits": [{"source": {"hash": {"sha256": digest}}}]},
        }
        result = transport.model_safe_copy(
            package, hosted=True, reviewer_safe=False, path=(),
            policy=POLICY, dependencies=dependencies(),
        )
        self.assertNotIn("analysis_dir", result)
        self.assertNotIn("payload", result)
        self.assertNotIn("_local_context", result)
        self.assertNotIn("sha256", result)
        self.assertEqual(
            result["investigation_query_results"]["hits"][0]["source"]["hash"]["sha256"],
            digest,
        )
        self.assertEqual(result["evidence_reference_contract"]["schema"], "fresh-contract")

    def test_reviewer_copy_redacts_owners_without_hosted_projection(self) -> None:
        package = {"payload": "kept", "asset_context": {"matched_assets": []}}
        result = transport.model_safe_copy(
            package, hosted=False, reviewer_safe=True, path=(),
            policy=POLICY, dependencies=dependencies(),
        )
        self.assertEqual(result["payload"], "kept")
        self.assertTrue(result["asset_context"]["redacted"])

    def test_synchronization_reaches_fixed_point_and_commits_only_transport_fields(self) -> None:
        package = {"stable": True, "investigation_query_results": {"generation": 0}}

        def project(value: dict) -> dict:
            result = copy.deepcopy(value)
            generation = result["investigation_query_results"]["generation"]
            result["investigation_query_results"]["generation"] = min(2, generation + 1)
            result["evidence_reference_contract"] = {
                "generation": result["investigation_query_results"]["generation"],
            }
            return result

        transport.synchronize_hosted_contract(
            package, maximum_passes=8,
            dependencies=transport.SynchronizationDependencies(
                model_safe_copy=project,
                prompt_json_bytes=lambda value: json.dumps(value, sort_keys=True).encode(),
                validation_error=ValueError,
            ),
        )
        self.assertTrue(package["stable"])
        self.assertEqual(package["investigation_query_results"]["generation"], 2)
        self.assertEqual(package["evidence_reference_contract"]["generation"], 2)

    def test_synchronization_failure_is_transactional(self) -> None:
        package = {"stable": True, "investigation_query_results": {"generation": 0}}
        original = copy.deepcopy(package)

        def oscillate(value: dict) -> dict:
            result = copy.deepcopy(value)
            current = result["investigation_query_results"]["generation"]
            result["investigation_query_results"]["generation"] = 0 if current else 1
            return result

        with self.assertRaisesRegex(ValueError, "fixed point"):
            transport.synchronize_hosted_contract(
                package, maximum_passes=8,
                dependencies=transport.SynchronizationDependencies(
                    model_safe_copy=oscillate,
                    prompt_json_bytes=lambda value: json.dumps(value, sort_keys=True).encode(),
                    validation_error=ValueError,
                ),
            )
        self.assertEqual(package, original)

    def test_package_has_no_io_primitives(self) -> None:
        source = (ROOT / "n8n/onion_sentinel/analysis/evidence/transport.py").read_text()
        for primitive in ("subprocess", "urlopen", "requests.", "open("):
            self.assertNotIn(primitive, source)


if __name__ == "__main__":
    unittest.main()
