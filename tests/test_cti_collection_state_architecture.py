from __future__ import annotations

import ast
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD_DIR = ROOT / "onion-sentinel-dashboard"
VALIDATION_PATH = DASHBOARD_DIR / "cti_program_validation.py"
sys.path.insert(0, str(DASHBOARD_DIR))

import cti_program  # noqa: E402
import cti_program_validation  # noqa: E402


def function_metrics(name: str) -> tuple[int, int]:
    tree = ast.parse(VALIDATION_PATH.read_text(encoding="utf-8"))
    match_type = getattr(ast, "Match", ())
    target = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == name
    )
    complexity = 1
    for node in ast.walk(target):
        if isinstance(node, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.IfExp)):
            complexity += 1
        elif isinstance(node, ast.Try):
            complexity += len(node.handlers)
        elif isinstance(node, ast.BoolOp):
            complexity += max(0, len(node.values) - 1)
        elif isinstance(node, match_type):
            complexity += 1 + len(node.cases)
        elif isinstance(node, ast.comprehension):
            complexity += 1 + len(node.ifs)
    return target.end_lineno - target.lineno + 1, complexity


class CTICollectionStateArchitectureTests(unittest.TestCase):
    def collection_state(self, **overrides: object) -> dict[str, str]:
        value: dict[object, object] = {
            "collection_status": "unknown",
            "last_attempt_at": "",
            "last_success_at": "",
            "failure_code": "",
        }
        value.update(overrides)
        return cti_program_validation._source_collection_state(value, "sources[3]")

    def test_collection_state_facade_meets_function_policy(self):
        lines, complexity = function_metrics("_source_collection_state")
        self.assertLessEqual(lines, 50)
        self.assertLessEqual(complexity, 10)

    def test_unknown_and_healthy_states_project_canonical_fields(self):
        self.assertEqual(
            self.collection_state(),
            {
                "collection_status": "unknown",
                "last_attempt_at": "",
                "last_success_at": "",
                "failure_code": "",
            },
        )
        self.assertEqual(
            self.collection_state(
                collection_status=" healthy ",
                last_attempt_at="2026-08-14T12:00:00+00:00",
                last_success_at="2026-08-14T11:59:59Z",
            ),
            {
                "collection_status": "healthy",
                "last_attempt_at": "2026-08-14T12:00:00Z",
                "last_success_at": "2026-08-14T11:59:59Z",
                "failure_code": "",
            },
        )

    def test_degraded_and_failed_states_require_redacted_failure_provenance(self):
        for status in ("degraded", "failed"):
            with self.subTest(status=status):
                self.assertEqual(
                    self.collection_state(
                        collection_status=status,
                        last_attempt_at="2026-08-14T12:00:00Z",
                        last_success_at="2026-08-14T11:00:00Z",
                        failure_code="upstream-timeout",
                    )["failure_code"],
                    "upstream-timeout",
                )
                with self.assertRaisesRegex(
                    cti_program.CTIProgramError,
                    rf"sources\[3\] {status} collection state requires last_attempt_at and failure_code\.",
                ):
                    self.collection_state(
                        collection_status=status,
                        last_attempt_at="2026-08-14T12:00:00Z",
                    )

    def test_status_failures_precede_failure_compatibility_and_temporal_failures(self):
        with self.assertRaises(cti_program.CTIProgramError) as raised:
            self.collection_state(
                collection_status="degraded",
                last_attempt_at="",
                last_success_at="2026-08-14T13:00:00Z",
                failure_code="",
            )
        self.assertEqual(
            str(raised.exception),
            "sources[3] degraded collection state requires last_attempt_at and failure_code.",
        )

        with self.assertRaises(cti_program.CTIProgramError) as raised:
            self.collection_state(
                collection_status="healthy",
                last_attempt_at="2026-08-14T12:00:00Z",
                last_success_at="",
                failure_code="upstream-timeout",
            )
        self.assertEqual(
            str(raised.exception),
            "sources[3] healthy collection state requires last_success_at.",
        )

    def test_failure_compatibility_precedes_temporal_consistency(self):
        with self.assertRaises(cti_program.CTIProgramError) as raised:
            self.collection_state(
                collection_status="unknown",
                last_attempt_at="2026-08-14T12:00:00Z",
                last_success_at="2026-08-14T13:00:00Z",
                failure_code="upstream-timeout",
            )
        self.assertEqual(
            str(raised.exception),
            "sources[3].failure_code requires degraded or failed collection status.",
        )

    def test_success_cannot_follow_attempt(self):
        with self.assertRaisesRegex(
            cti_program.CTIProgramError,
            r"sources\[3\]\.last_success_at cannot follow last_attempt_at\.",
        ):
            self.collection_state(
                collection_status="healthy",
                last_attempt_at="2026-08-14T12:00:00Z",
                last_success_at="2026-08-14T12:00:01Z",
            )


if __name__ == "__main__":
    unittest.main()
