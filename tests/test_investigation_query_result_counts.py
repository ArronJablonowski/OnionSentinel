"""Characterize fail-closed investigation result-count validation."""

from __future__ import annotations

import ast
import copy
import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
SCRIPT = BIN / "investigation_query_response_result.py"
sys.path.insert(0, str(BIN))


def load_module():
    spec = importlib.util.spec_from_file_location(
        "investigation_query_response_result_counts_characterized",
        SCRIPT,
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


RESULT = load_module()


def function_metrics(name: str) -> tuple[int, int]:
    tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
    target = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == name
    )

    class Complexity(ast.NodeVisitor):
        def __init__(self):
            self.value = 1

        def visit_FunctionDef(self, node):
            return

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_If(self, node):
            self.value += 1
            self.generic_visit(node)

        visit_For = visit_If
        visit_While = visit_If

        def visit_Try(self, node):
            self.value += len(node.handlers)
            self.generic_visit(node)

        def visit_BoolOp(self, node):
            self.value += max(0, len(node.values) - 1)
            self.generic_visit(node)

        def visit_IfExp(self, node):
            self.value += 1
            self.generic_visit(node)

        def visit_comprehension(self, node):
            self.value += 1 + len(node.ifs)
            self.generic_visit(node)

    complexity = Complexity()
    for statement in target.body:
        complexity.visit(statement)
    return target.end_lineno - target.lineno + 1, complexity.value


def query(*, aggregation: str = "events") -> dict[str, object]:
    return {"aggregation": aggregation, "match_semantics": "all"}


def valid_value(
    expected_query: dict[str, object],
    hits: list[object],
    *,
    status: str = "ok",
    total_hits: int | None = None,
    relation: str = "eq",
) -> dict[str, object]:
    total = len(hits) if total_hits is None else total_hits
    truncated = relation != "eq" or (
        expected_query["aggregation"] != "count" and total > len(hits)
    )
    return {
        "returned_hits": len(hits),
        "total_hits": total,
        "total_hits_relation": relation,
        "truncated": truncated,
        "result_coverage": RESULT.result_coverage(
            expected_query,
            status=status,
            total_hits=total,
            total_hits_relation=relation,
            returned_hits=len(hits),
        ),
    }


class InvestigationQueryResultCountTests(unittest.TestCase):
    def test_changed_owner_architecture_is_bounded(self):
        names = (
            "_validate_hit_count_consistency",
            "_validated_total_hits_relation",
            "_validate_result_truncation",
            "_validate_result_coverage_semantics",
            "_validate_count_aggregation_hits",
            "_validate_result_counts",
        )
        for name in names:
            with self.subTest(name=name):
                lines, complexity = function_metrics(name)
                self.assertLessEqual(lines, 50)
                self.assertLessEqual(complexity, 10)
        self.assertLessEqual(len(SCRIPT.read_text().splitlines()), 600)

    def assert_contract_error(self, message: str, call) -> None:
        with self.assertRaisesRegex(
            RESULT.InvestigationQueryContractError,
            f"^{message}$",
        ):
            call()

    def test_exact_complete_event_counts_return_the_relation_without_mutation(self):
        expected_query = query()
        hits = [{"id": "one"}, {"id": "two"}]
        value = valid_value(expected_query, hits)
        before = copy.deepcopy((value, expected_query, hits))

        relation = RESULT._validate_result_counts(
            value,
            expected_query,
            "ok",
            hits,
        )

        self.assertEqual(relation, "eq")
        self.assertEqual((value, expected_query, hits), before)
        self.assertEqual(
            value["result_coverage"],
            {
                "coverage_status": "complete_events",
                "match_semantics": "all",
                "sample_strategy": "newest_first",
                "scope": "authorized_exact_filters_and_time_window",
                "exact_total_hits": True,
                "zero_hits": False,
                "event_bodies_complete": True,
                "interpretation": "complete_matching_event_set",
            },
        )

    def test_lower_bound_and_bounded_sample_counts_are_accepted(self):
        cases = (
            ("gte", 5, "lower_bound_only", "partial"),
            ("eq", 5, "sample_only_not_complete_event_set", "bounded_sample"),
        )
        for relation, total, interpretation, coverage_status in cases:
            with self.subTest(relation=relation):
                expected_query = query(aggregation="timeline")
                hits = [object(), object()]
                value = valid_value(
                    expected_query,
                    hits,
                    total_hits=total,
                    relation=relation,
                )

                self.assertEqual(
                    RESULT._validate_result_counts(
                        value, expected_query, "ok", hits
                    ),
                    relation,
                )
                self.assertEqual(
                    value["result_coverage"]["interpretation"], interpretation
                )
                self.assertEqual(
                    value["result_coverage"]["coverage_status"], coverage_status
                )

    def test_failed_status_uses_partial_execution_coverage(self):
        expected_query = query(aggregation="anchor_nearest")
        value = valid_value(expected_query, [], status="error")

        self.assertEqual(
            RESULT._validate_result_counts(value, expected_query, "error", []),
            "eq",
        )
        self.assertEqual(
            value["result_coverage"]["interpretation"],
            "query_execution_incomplete",
        )

    def test_nonnegative_count_validation_is_exact_and_ordered(self):
        invalid_values = (None, False, True, -1, 0.0, 1.0, "0", [], {})
        for field in ("returned_hits", "total_hits"):
            for invalid in invalid_values:
                with self.subTest(field=field, invalid=invalid):
                    expected_query = query()
                    value = valid_value(expected_query, [])
                    value[field] = invalid
                    if field == "returned_hits":
                        value["total_hits"] = invalid
                    self.assert_contract_error(
                        f"result {field} is invalid",
                        lambda: RESULT._validate_result_counts(
                            value, expected_query, "ok", []
                        ),
                    )

    def test_missing_returned_count_precedes_missing_total_count(self):
        expected_query = query()
        value = valid_value(expected_query, [])
        del value["returned_hits"]
        del value["total_hits"]

        self.assert_contract_error(
            "result returned_hits is invalid",
            lambda: RESULT._validate_result_counts(value, expected_query, "ok", []),
        )

    def test_hit_count_relationships_fail_before_relation_validation(self):
        expected_query = query()
        hits = [object(), object()]
        cases = (
            {"returned_hits": 1, "total_hits": 2},
            {"returned_hits": 2, "total_hits": 1},
        )
        for replacement in cases:
            with self.subTest(replacement=replacement):
                value = valid_value(expected_query, hits)
                value.update(replacement)
                value["total_hits_relation"] = "invalid"
                self.assert_contract_error(
                    "result hit counts are inconsistent",
                    lambda: RESULT._validate_result_counts(
                        value, expected_query, "ok", hits
                    ),
                )

    def test_relation_is_exact_and_checked_before_truncation(self):
        for relation in (None, "", "EQ", "gt", 0, True):
            with self.subTest(relation=relation):
                expected_query = query()
                value = valid_value(expected_query, [])
                value["total_hits_relation"] = relation
                value["truncated"] = "invalid"
                self.assert_contract_error(
                    "result total-hits relation is invalid",
                    lambda: RESULT._validate_result_counts(
                        value, expected_query, "ok", []
                    ),
                )

    def test_truncation_requires_boolean_identity_and_precedes_coverage(self):
        expected_query = query()
        for replacement in (True, 0, 1, None, "false"):
            with self.subTest(replacement=replacement):
                value = valid_value(expected_query, [])
                value["truncated"] = replacement
                value["result_coverage"] = "invalid"
                self.assert_contract_error(
                    "result truncation flag is inconsistent",
                    lambda: RESULT._validate_result_counts(
                        value, expected_query, "ok", []
                    ),
                )

    def test_coverage_requires_exact_object_before_count_body_check(self):
        expected_query = query(aggregation="count")
        hits = [object()]
        value = valid_value(expected_query, hits)
        value["result_coverage"] = {"coverage_status": "exact_aggregate"}

        self.assert_contract_error(
            "result evidence coverage semantics are inconsistent",
            lambda: RESULT._validate_result_counts(
                value, expected_query, "ok", hits
            ),
        )

        value = valid_value(expected_query, hits)
        self.assert_contract_error(
            "count aggregation returned event bodies",
            lambda: RESULT._validate_result_counts(
                value, expected_query, "ok", hits
            ),
        )

    def test_zero_count_aggregation_is_exact_and_body_free(self):
        expected_query = query(aggregation="count")
        value = valid_value(expected_query, [])

        self.assertEqual(
            RESULT._validate_result_counts(value, expected_query, "ok", []),
            "eq",
        )
        self.assertEqual(value["result_coverage"]["coverage_status"], "exact_aggregate")
        self.assertTrue(value["result_coverage"]["zero_hits"])
        self.assertFalse(value["result_coverage"]["event_bodies_complete"])


if __name__ == "__main__":
    unittest.main()
