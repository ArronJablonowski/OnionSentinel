#!/usr/bin/env python3
"""Characterization and architecture gates for harness query binding."""
from __future__ import annotations

import ast
import copy
import inspect
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))

import harness_query_contract as QUERY_CONTRACT  # noqa: E402


EXPECTED_NAMESPACE = {
    "Any", "DIGEST_RE", "MAX_EVENT_ITEMS", "Mapping",
    "QUERY_SUCCESS_STATUSES", "RETURNED_COUNT_KEYS",
    "SECURITY_ONION_QUERY_STATUSES", "Sequence", "annotations", "hmac",
    "observed_returned_count", "observed_truncation", "resolve_query_binding",
}

EXPECTED_SIGNATURES = {
    "observed_returned_count": "(value: 'Any', *, depth: 'int' = 0) -> 'int | None'",
    "observed_truncation": "(value: 'Any', *, depth: 'int' = 0) -> 'bool'",
    "resolve_query_binding": "(result: 'Mapping[str, Any]', query_id: 'str') -> 'tuple[str, Any]'",
}

OWNER_MODULES = (
    "harness_query_observation.py",
    "harness_query_binding_envelope.py",
    "harness_query_binding_validation.py",
    "harness_query_binding.py",
)


def batch_result(*, outer_status: str = "partial") -> dict:
    query_ids = ["query-ok", "query-timeout"]
    statuses = ["ok", "timeout"]
    query_digests = ["a" * 64, "c" * 64]
    result_digests = ["b" * 64, "d" * 64]
    nested = []
    audits = []
    for index, query_id in enumerate(query_ids):
        status = statuses[index]
        row = {
            "query_id": query_id,
            "status": status,
            "semantic_valid": status == "ok",
            "query_digest": query_digests[index],
            "result_digest": result_digests[index],
            "returned_hits": index + 1,
        }
        nested.append(row)
        audits.append({
            **row,
            "timed_out": status == "timeout",
            "shards": {
                "total": 2,
                "successful": 2,
                "skipped": 0,
                "failed": 0,
                "failures": [],
            },
        })
    return {
        "status": outer_status,
        "backend": "security_onion",
        "read_only": True,
        "security_onion_response_digest": "e" * 64,
        "query_ids": query_ids,
        "evidence": {
            "read_only": True,
            "partial": outer_status == "partial",
            "complete": outer_status == "ok",
            "controls_valid": True,
            "results": nested,
        },
        "trusted_query_audit": audits,
    }


class HarnessQueryContractCharacterizationTests(unittest.TestCase):
    def test_namespace_and_signatures_are_stable(self) -> None:
        self.assertEqual(
            {name for name in vars(QUERY_CONTRACT) if not name.startswith("__")},
            EXPECTED_NAMESPACE,
        )
        self.assertEqual(
            {
                name: str(inspect.signature(getattr(QUERY_CONTRACT, name)))
                for name in EXPECTED_SIGNATURES
            },
            EXPECTED_SIGNATURES,
        )

    def test_returned_count_is_bounded_recursive_and_never_invents_a_value(self) -> None:
        value = {
            "returned": 2,
            "nested": [
                {"returned_hits": "7"},
                {"returned_rows": True},
                {"records_returned": -1},
                {"total_hits": "bad"},
                {"total_rows": 5},
            ],
        }
        self.assertEqual(QUERY_CONTRACT.observed_returned_count(value), 7)
        self.assertIsNone(QUERY_CONTRACT.observed_returned_count({"hits": [1]}))
        self.assertIsNone(
            QUERY_CONTRACT.observed_returned_count({"returned": 9}, depth=9)
        )
        bounded = [{"returned": index} for index in range(
            QUERY_CONTRACT.MAX_EVENT_ITEMS + 1
        )]
        self.assertEqual(
            QUERY_CONTRACT.observed_returned_count(bounded),
            QUERY_CONTRACT.MAX_EVENT_ITEMS - 1,
        )

    def test_truncation_is_bounded_recursive_and_requires_literal_true(self) -> None:
        self.assertTrue(QUERY_CONTRACT.observed_truncation({
            "nested": [{"model_projection_truncated": True}],
        }))
        self.assertFalse(QUERY_CONTRACT.observed_truncation({
            "truncated": 1,
            "nested": "truncated=true",
        }))
        self.assertFalse(
            QUERY_CONTRACT.observed_truncation({"truncated": True}, depth=9)
        )
        bounded = [{} for _ in range(QUERY_CONTRACT.MAX_EVENT_ITEMS)]
        bounded.append({"truncated": True})
        self.assertFalse(QUERY_CONTRACT.observed_truncation(bounded))

    def test_valid_binding_preserves_nested_and_audit_object_identity(self) -> None:
        result = batch_result()
        status, observation = QUERY_CONTRACT.resolve_query_binding(
            result, "query-ok"
        )
        self.assertEqual(status, "ok")
        self.assertEqual(set(observation), {"result", "audit"})
        self.assertIs(observation["result"], result["evidence"]["results"][0])
        self.assertIs(observation["audit"], result["trusted_query_audit"][0])

        status, observation = QUERY_CONTRACT.resolve_query_binding(
            result, "query-timeout"
        )
        self.assertEqual(status, "timeout")
        self.assertIs(observation["result"], result["evidence"]["results"][1])

    def test_ordinary_and_early_rejected_batches_return_the_outer_identity(self) -> None:
        ordinary = {
            "status": "ok", "backend": "elastic", "read_only": True,
        }
        status, observation = QUERY_CONTRACT.resolve_query_binding(
            ordinary, "query-ok"
        )
        self.assertEqual(status, "ok")
        self.assertIs(observation, ordinary)

        mutations = (
            lambda value: value.__setitem__("read_only", False),
            lambda value: value.__setitem__("security_onion_response_digest", "bad"),
            lambda value: value["evidence"].__setitem__("controls_valid", False),
            lambda value: value["query_ids"].append("query-ok"),
            lambda value: value["evidence"]["results"].reverse(),
            lambda value: value["trusted_query_audit"].pop(),
            lambda value: value["trusted_query_audit"][0].__setitem__(
                "result_digest", "f" * 64
            ),
        )
        for mutate in mutations:
            candidate = batch_result()
            mutate(candidate)
            with self.subTest(candidate=candidate):
                status, observation = QUERY_CONTRACT.resolve_query_binding(
                    candidate, "query-ok"
                )
                self.assertEqual(status, "partial")
                self.assertIs(observation, candidate)

    def test_post_binding_failures_return_the_bound_observation(self) -> None:
        mutations = (
            lambda value: value["evidence"]["results"][0].__setitem__(
                "semantic_valid", False
            ),
            lambda value: value["trusted_query_audit"][0].__setitem__(
                "timed_out", True
            ),
            lambda value: value["trusted_query_audit"][0]["shards"].__setitem__(
                "successful", 1
            ),
            lambda value: value["trusted_query_audit"][0]["shards"].__setitem__(
                "failures", [{}]
            ),
        )
        for mutate in mutations:
            candidate = batch_result()
            mutate(candidate)
            status, observation = QUERY_CONTRACT.resolve_query_binding(
                candidate, "query-ok"
            )
            with self.subTest(candidate=candidate):
                self.assertEqual(status, "partial")
                self.assertIsNot(observation, candidate)
                self.assertIs(
                    observation["result"], candidate["evidence"]["results"][0]
                )
                self.assertIs(
                    observation["audit"], candidate["trusted_query_audit"][0]
                )

    def test_binding_rejects_unknown_status_and_accepts_closed_failure_status(self) -> None:
        unknown = batch_result()
        for row in (
            unknown["evidence"]["results"][1],
            unknown["trusted_query_audit"][1],
        ):
            row["status"] = "unknown"
        status, observation = QUERY_CONTRACT.resolve_query_binding(
            unknown, "query-timeout"
        )
        self.assertEqual(status, "partial")
        self.assertIs(observation, unknown)

        failure = batch_result()
        for row in (
            failure["evidence"]["results"][1],
            failure["trusted_query_audit"][1],
        ):
            row["status"] = "invalid_response"
            row["semantic_valid"] = False
        failure["trusted_query_audit"][1]["timed_out"] = False
        status, observation = QUERY_CONTRACT.resolve_query_binding(
            failure, "query-timeout"
        )
        self.assertEqual(status, "invalid_response")
        self.assertIs(
            observation["result"], failure["evidence"]["results"][1]
        )

    def test_facade_and_owners_remain_bounded_and_acyclic(self) -> None:
        facade = BIN / "harness_query_contract.py"
        self.assertLessEqual(len(facade.read_text(encoding="utf-8").splitlines()), 250)
        for name in OWNER_MODULES:
            path = BIN / name
            self.assertLess(len(path.read_text(encoding="utf-8").splitlines()), 800)
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            imported = {
                node.module
                for node in ast.walk(tree)
                if isinstance(node, ast.ImportFrom) and node.module
            }
            self.assertNotIn("harness_query_contract", imported)

    def test_facade_imports_from_an_isolated_flat_bin(self) -> None:
        sources = [
            *sorted(BIN.glob("harness_policy*.py")),
            *(BIN / name for name in OWNER_MODULES),
            BIN / "harness_query_contract.py",
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for source in sources:
                (root / source.name).write_bytes(source.read_bytes())
            result = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    "-c",
                    (
                        "import sys; sys.path.insert(0, sys.argv[1]); "
                        "import harness_query_contract as module; "
                        "assert callable(module.resolve_query_binding)"
                    ),
                    directory,
                ],
                text=True,
                capture_output=True,
                timeout=10,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
