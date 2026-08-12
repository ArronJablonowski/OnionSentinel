from __future__ import annotations

import ast
import copy
import importlib
import inspect
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))

OWNER = importlib.import_module("harness_store_hypothesis_persistence")


def function_metrics(name: str) -> tuple[int, int]:
    tree = ast.parse(
        (BIN / "harness_store_hypothesis_persistence.py").read_text(
            encoding="utf-8"
        )
    )
    target = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == name
    )
    complexity = 1
    for node in ast.walk(target):
        if node is target:
            continue
        if isinstance(node, (ast.If, ast.For, ast.While, ast.IfExp, ast.Assert)):
            complexity += 1
        elif isinstance(node, ast.Try):
            complexity += len(node.handlers)
        elif isinstance(node, ast.BoolOp):
            complexity += max(0, len(node.values) - 1)
        elif isinstance(node, ast.comprehension):
            complexity += 1 + len(node.ifs)
    return target.end_lineno - target.lineno + 1, complexity


class TraceDict(dict):
    def __init__(self, trace, values):
        super().__init__(values)
        self.trace = trace

    def get(self, key, default=None):
        self.trace.append(("get", key, default))
        return super().get(key, default)


class HarnessStoreHypothesisNormalizationTests(unittest.TestCase):
    def test_static_signature_and_current_complexity_debt(self) -> None:
        self.assertEqual(
            str(inspect.signature(OWNER._normalize_hypothesis)),
            "(item: 'Any', index: 'int', known_refs: 'set[str]') -> "
            "'dict[str, str] | None'",
        )
        self.assertEqual(function_metrics("_normalize_hypothesis"), (41, 12))

    def test_non_dictionary_is_rejected_without_helper_calls(self) -> None:
        with (
            mock.patch.object(OWNER.re, "sub") as regex,
            mock.patch.object(OWNER, "_redacted_string") as redact,
            mock.patch.object(OWNER, "_known_references") as references,
            mock.patch.object(OWNER, "digest_json") as digest,
            mock.patch.object(OWNER, "canonical_json") as canonical,
        ):
            self.assertIsNone(
                OWNER._normalize_hypothesis(["not", "a", "dict"], 7, set())
            )
        regex.assert_not_called()
        redact.assert_not_called()
        references.assert_not_called()
        digest.assert_not_called()
        canonical.assert_not_called()

    def test_full_projection_preserves_call_order_arguments_and_output_order(
        self,
    ) -> None:
        trace = []
        item = TraceDict(
            trace,
            {
                "id": " raw identity ",
                "statement": " raw statement ",
                "status": " SUPPORTED ",
                "supporting_evidence": ["known"],
                "contradicting_evidence": ["other"],
                "next_discriminator": " next step ",
            },
        )

        def regex(pattern, replacement, value):
            trace.append(("regex", pattern, replacement, value))
            return "normalized-id"

        def redact(value, limit):
            trace.append(("redact", value, limit))
            return "statement-redacted" if limit == 4_000 else "next-redacted"

        def references(value, key, known_refs):
            trace.append(("references", value, key, known_refs))
            return [f"{key}-known"]

        def digest(value):
            trace.append(("digest", value))
            return "statement-digest"

        def canonical(value):
            trace.append(("canonical", value))
            return f"json:{value[0]}"

        with (
            mock.patch.object(OWNER.re, "sub", side_effect=regex),
            mock.patch.object(OWNER, "_redacted_string", side_effect=redact),
            mock.patch.object(OWNER, "_known_references", side_effect=references),
            mock.patch.object(OWNER, "digest_json", side_effect=digest),
            mock.patch.object(OWNER, "canonical_json", side_effect=canonical),
        ):
            result = OWNER._normalize_hypothesis(item, 3, {"known", "other"})

        self.assertEqual(
            result,
            {
                "hypothesis_id": "normalized-id",
                "statement": "statement-redacted",
                "statement_digest": "statement-digest",
                "status": "supported",
                "supporting_json": "json:supporting_evidence-known",
                "contradicting_json": "json:contradicting_evidence-known",
                "next_discriminator": "next-redacted",
            },
        )
        self.assertEqual(
            list(result),
            [
                "hypothesis_id",
                "statement",
                "statement_digest",
                "status",
                "supporting_json",
                "contradicting_json",
                "next_discriminator",
            ],
        )
        self.assertEqual(
            trace,
            [
                ("get", "id", None),
                ("regex", r"[^A-Za-z0-9._-]+", "-", " raw identity "),
                ("get", "statement", None),
                ("redact", "raw statement", 4_000),
                ("get", "status", None),
                ("references", item, "supporting_evidence", {"known", "other"}),
                ("references", item, "contradicting_evidence", {"known", "other"}),
                ("digest", "statement-redacted"),
                ("canonical", ["supporting_evidence-known"]),
                ("canonical", ["contradicting_evidence-known"]),
                ("get", "next_discriminator", None),
                ("redact", " next step ", 2_000),
            ],
        )

    def test_default_identity_status_and_actual_sanitization_are_preserved(self) -> None:
        result = OWNER._normalize_hypothesis(
            {"statement": "  viable statement  "},
            -7,
            set(),
        )
        self.assertEqual(result["hypothesis_id"], "hypothesis--7")
        self.assertEqual(result["statement"], "viable statement")
        self.assertEqual(result["status"], "unresolved")
        self.assertEqual(result["supporting_json"], "[]")
        self.assertEqual(result["contradicting_json"], "[]")
        self.assertEqual(result["next_discriminator"], "")

        long_identity = " --a b/c-- " + "z" * 80
        result = OWNER._normalize_hypothesis(
            {"id": long_identity, "statement": "statement"},
            1,
            set(),
        )
        self.assertEqual(result["hypothesis_id"], ("a-b-c---" + "z" * 80)[:64])
        self.assertEqual(len(result["hypothesis_id"]), 64)

    def test_invalid_identity_statement_and_status_reject_before_references(
        self,
    ) -> None:
        cases = [
            ({"id": "///", "statement": "statement"}, 1),
            ({"id": "id", "statement": "   "}, 2),
            ({"id": "id", "statement": "statement", "status": "maybe"}, 3),
        ]
        for item, index in cases:
            with self.subTest(index=index), mock.patch.object(
                OWNER, "_known_references"
            ) as references:
                self.assertIsNone(OWNER._normalize_hypothesis(item, index, set()))
                references.assert_not_called()

    def test_reference_filtering_preserves_order_duplicates_bounds_and_coercion(
        self,
    ) -> None:
        class Ref:
            def __init__(self, value):
                self.value = value

            def __str__(self):
                return self.value

        original_limit = OWNER.MAX_DECISION_EVIDENCE_REFS
        self.addCleanup(
            setattr,
            OWNER,
            "MAX_DECISION_EVIDENCE_REFS",
            original_limit,
        )
        OWNER.MAX_DECISION_EVIDENCE_REFS = 4
        long_ref = "x" * 520
        item = {
            "statement": "statement",
            "supporting_evidence": [
                Ref("known"),
                "missing",
                "known",
                long_ref,
                "ignored-after-bound",
            ],
            "contradicting_evidence": "not-a-list",
        }
        before = copy.deepcopy(
            {
                "statement": item["statement"],
                "supporting_evidence": [str(value) for value in item["supporting_evidence"]],
                "contradicting_evidence": item["contradicting_evidence"],
            }
        )

        result = OWNER._normalize_hypothesis(
            item,
            1,
            {"known", long_ref, "ignored-after-bound"},
        )

        self.assertEqual(
            result["supporting_json"],
            OWNER.canonical_json(["known", "known", long_ref[:512]]),
        )
        self.assertEqual(result["contradicting_json"], "[]")
        self.assertEqual(
            before,
            {
                "statement": item["statement"],
                "supporting_evidence": [str(value) for value in item["supporting_evidence"]],
                "contradicting_evidence": item["contradicting_evidence"],
            },
        )

    def test_evidence_dependent_status_downgrades_are_exact(self) -> None:
        cases = [
            ("supported", [], ["c"], "unresolved"),
            ("supported", ["s"], [], "supported"),
            ("contradicted", ["s"], [], "unresolved"),
            ("contradicted", [], ["c"], "contradicted"),
            ("unresolved", ["s"], ["c"], "unresolved"),
        ]
        for status, supporting, contradicting, expected in cases:
            with self.subTest(status=status, supporting=supporting, contradicting=contradicting):
                result = OWNER._normalize_hypothesis(
                    {
                        "statement": "statement",
                        "status": status,
                        "supporting_evidence": supporting,
                        "contradicting_evidence": contradicting,
                    },
                    1,
                    {"s", "c"},
                )
                self.assertEqual(result["status"], expected)

    def test_helper_exception_precedence_and_input_non_mutation(self) -> None:
        item = {
            "id": "id",
            "statement": "statement",
            "status": "supported",
            "supporting_evidence": ["s"],
            "contradicting_evidence": ["c"],
            "next_discriminator": "next",
        }
        original = copy.deepcopy(item)
        with mock.patch.object(
            OWNER,
            "_known_references",
            side_effect=[RuntimeError("supporting failure")],
        ):
            with self.assertRaisesRegex(RuntimeError, "supporting failure"):
                OWNER._normalize_hypothesis(item, 1, {"s", "c"})
        self.assertEqual(item, original)

        with (
            mock.patch.object(
                OWNER,
                "_known_references",
                side_effect=[["s"], ["c"]],
            ),
            mock.patch.object(OWNER, "digest_json", side_effect=ValueError("digest failure")),
            mock.patch.object(OWNER, "canonical_json") as canonical,
        ):
            with self.assertRaisesRegex(ValueError, "digest failure"):
                OWNER._normalize_hypothesis(item, 1, {"s", "c"})
            canonical.assert_not_called()
        self.assertEqual(item, original)


if __name__ == "__main__":
    unittest.main()
