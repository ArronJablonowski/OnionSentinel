from __future__ import annotations

import ast
import copy
import importlib.util
import inspect
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXPORTER_PATH = ROOT / "n8n/bin/export-adjudicated-analysis-replays.py"


def load_exporter():
    spec = importlib.util.spec_from_file_location(
        "adjudication_verdict_contradictions_architecture", EXPORTER_PATH
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def function_metrics(name: str) -> tuple[int, int]:
    tree = ast.parse(EXPORTER_PATH.read_text(encoding="utf-8"))
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

        def visit_ListComp(self, node):
            self.value += sum(
                1 + len(generator.ifs) for generator in node.generators
            )
            self.generic_visit(node)

        visit_SetComp = visit_ListComp
        visit_GeneratorExp = visit_ListComp
        visit_DictComp = visit_ListComp

    visitor = Complexity()
    for child in target.body:
        visitor.visit(child)
    return target.end_lineno - target.lineno + 1, visitor.value


class TrackingRunner:
    trace = []
    legacy = {}
    derived = "inconclusive"

    @classmethod
    def legacy_verdict_factors(cls, outcome):
        cls.trace.append(["legacy_verdict_factors", outcome])
        return copy.deepcopy(cls.legacy)

    @classmethod
    def derive_legacy_detection_outcome(cls, factors):
        cls.trace.append(
            ["derive_legacy_detection_outcome", copy.deepcopy(factors)]
        )
        return cls.derived


class BadText:
    def __str__(self):
        raise RuntimeError("synthetic contradiction text conversion failure")


class AdjudicationVerdictContradictionsArchitectureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.exporter = load_exporter()

    def setUp(self) -> None:
        TrackingRunner.trace = []
        TrackingRunner.legacy = {
            "event_status": "unknown",
            "detection_validity": "unknown",
            "activity_disposition": "unknown",
            "handling": "investigate",
            "duplicate_of": None,
        }
        TrackingRunner.derived = "inconclusive"

    def test_signature_current_debt_and_call_site_are_exact(self) -> None:
        signature = inspect.signature(
            self.exporter.adjudication_verdict_contradictions
        )
        self.assertEqual(
            list(signature.parameters),
            ["runner", "outcome", "explicit_factors"],
        )
        self.assertEqual(str(signature.return_annotation), "list[str]")
        self.assertEqual(
            function_metrics("adjudication_verdict_contradictions"),
            (48, 21),
        )
        source = EXPORTER_PATH.read_text(encoding="utf-8")
        self.assertEqual(source.count("adjudication_verdict_contradictions("), 2)
        self.assertLessEqual(len(source.splitlines()), 800)

    def test_absent_factors_short_circuit_without_runner_callbacks(self) -> None:
        for factors in ({}, {"event_status": None}, {"handling": ""}):
            before = copy.deepcopy(factors)
            self.assertEqual(
                self.exporter.adjudication_verdict_contradictions(
                    TrackingRunner, "inconclusive", factors
                ),
                [],
            )
            self.assertEqual(factors, before)
            self.assertEqual(TrackingRunner.trace, [])

    def test_factor_merge_runner_callbacks_and_mismatch_are_exact(self) -> None:
        explicit = {
            "event_status": None,
            "handling": "contain",
            "activity_disposition": "malicious",
            "duplicate_of": "group-1",
            "ignored_empty": "",
        }
        before = copy.deepcopy(explicit)
        TrackingRunner.derived = "synthetic-derived"
        result = self.exporter.adjudication_verdict_contradictions(
            TrackingRunner,
            "false_positive_logic_rule",
            explicit,
        )
        merged = {
            **TrackingRunner.legacy,
            "handling": "contain",
            "activity_disposition": "malicious",
            "duplicate_of": "group-1",
        }
        self.assertEqual(
            TrackingRunner.trace,
            [
                ["legacy_verdict_factors", "false_positive_logic_rule"],
                ["derive_legacy_detection_outcome", merged],
            ],
        )
        self.assertEqual(
            result,
            [
                "factored verdict derives synthetic-derived, not false_positive_logic_rule",
                "a duplicate record cannot independently authorize containment or escalation",
                "a false-positive label cannot classify activity as malicious or suspicious",
                "a false-positive label cannot authorize containment or escalation",
            ],
        )
        self.assertEqual(explicit, before)

    def test_every_orthogonal_contradiction_message_and_order_are_exact(self) -> None:
        cases = [
            (
                "inconclusive",
                {
                    "event_status": "not_observed",
                    "detection_validity": "matched_intent",
                },
                [
                    "an unobserved event cannot be a validated detection-intent match"
                ],
            ),
            (
                "inconclusive",
                {
                    "activity_disposition": "malicious",
                    "handling": "monitor",
                },
                ["malicious activity cannot use monitor/no_action handling"],
            ),
            (
                "inconclusive",
                {
                    "activity_disposition": "authorized_benign",
                    "handling": "contain",
                },
                ["benign or authorized activity cannot use contain handling"],
            ),
            (
                "inconclusive",
                {"duplicate_of": "  group-1  ", "handling": "escalate"},
                [
                    "a duplicate record cannot independently authorize containment or escalation"
                ],
            ),
            (
                "false_positive_logic_rule",
                {
                    "activity_disposition": "suspicious",
                    "handling": "escalate",
                },
                [
                    "a false-positive label cannot classify activity as malicious or suspicious",
                    "a false-positive label cannot authorize containment or escalation",
                ],
            ),
        ]
        for outcome, explicit, expected in cases:
            with self.subTest(outcome=outcome, explicit=explicit):
                TrackingRunner.trace = []
                TrackingRunner.derived = outcome
                self.assertEqual(
                    self.exporter.adjudication_verdict_contradictions(
                        TrackingRunner, outcome, explicit
                    ),
                    expected,
                )

    def test_conversion_failure_propagates_without_cause_or_mutation(self) -> None:
        value = BadText()
        explicit = {"event_status": value}
        TrackingRunner.derived = "inconclusive"
        with self.assertRaisesRegex(
            RuntimeError, "synthetic contradiction text conversion failure"
        ) as raised:
            self.exporter.adjudication_verdict_contradictions(
                TrackingRunner, "inconclusive", explicit
            )
        self.assertIsNone(raised.exception.__cause__)
        self.assertIs(explicit["event_status"], value)
        self.assertEqual(
            [entry[0] for entry in TrackingRunner.trace],
            ["legacy_verdict_factors", "derive_legacy_detection_outcome"],
        )


if __name__ == "__main__":
    unittest.main()
