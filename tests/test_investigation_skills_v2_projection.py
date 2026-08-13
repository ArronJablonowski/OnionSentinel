"""Characterize governed v2 manifest validation and identity resolution."""

from __future__ import annotations

import ast
import copy
import importlib.util
import json
import unittest
from pathlib import Path
from typing import Any
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "n8n/bin/investigation_skills_v2.py"
CANDIDATE = (
    ROOT
    / "n8n/config/investigation-skills-v2-candidates/dns-triage-v2.candidate.json"
)
SPEC = importlib.util.spec_from_file_location(
    "investigation_skills_v2_projection", MODULE_PATH
)
skills = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(skills)


def function_metrics(name: str) -> tuple[int, int]:
    tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
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

    visitor = Complexity()
    for child in target.body:
        visitor.visit(child)
    return target.end_lineno - target.lineno + 1, visitor.value


def candidate() -> dict[str, Any]:
    return json.loads(CANDIDATE.read_text(encoding="utf-8"))


def promotable(identifier: str = "network.dns.triage") -> dict[str, Any]:
    value = candidate()
    value["id"] = identifier
    value["version"] = "2.0.0"
    value["maintainer"]["reviewer"] = "independent-reviewer"
    value["verification"] = {
        "unit_tests": True,
        "replay_cases": 5,
        "independent_query_review": True,
        "adversarial_tests": True,
        "human_approved": True,
    }
    value["artifact_digest"] = skills.artifact_digest(value)
    return value


class TrackingMapping(dict):
    def __init__(self, values):
        super().__init__(values)
        self.trace: list[tuple[str, object]] = []

    def get(self, key, default=None):
        self.trace.append(("get", key))
        return super().get(key, default)


class InvestigationSkillsV2ProjectionTests(unittest.TestCase):
    def test_changed_phases_meet_architecture_contract(self) -> None:
        names = (
            "_validate_manifest_contract",
            "_validate_manifest_identity",
            "_validate_manifest_access",
            "_validate_manifest_safety",
            "_validate_manifest_budgets",
            "_validate_manifest_match",
            "_validate_query_template",
            "_validate_manifest_templates",
            "_validate_manifest_output",
            "validate_manifest",
            "_verification_failures",
            "_promotion_failures",
            "promotion_eligible",
            "_record_identity",
            "_context_dimensions",
            "_validated_record",
            "_admission_rejection",
            "_resolve_record",
            "resolve_manifests",
        )
        for name in names:
            with self.subTest(name=name):
                lines, complexity = function_metrics(name)
                self.assertLessEqual(lines, 50)
                self.assertLessEqual(complexity, 10)

    def test_manifest_validation_deep_copies_and_preserves_field_order(self) -> None:
        raw = candidate()
        before = copy.deepcopy(raw)
        result = skills.validate_manifest(raw)
        self.assertEqual(raw, before)
        self.assertEqual(result, raw)
        self.assertIsNot(result, raw)
        self.assertIsNot(result["safety"], raw["safety"])
        self.assertEqual(list(result), list(raw))

    def test_manifest_contract_preserves_early_error_precedence(self) -> None:
        cases = []
        raw = candidate()
        raw["schema"] = "bad"
        raw["id"] = "BAD"
        raw["artifact_digest"] = "bad"
        cases.append((raw, "unsupported manifest schema"))
        raw = candidate()
        raw["id"] = "BAD"
        raw["version"] = "bad"
        raw["artifact_digest"] = "bad"
        cases.append((raw, "manifest id is invalid"))
        raw = candidate()
        raw["version"] = "01.0.0"
        raw["artifact_digest"] = "bad"
        cases.append((raw, "manifest version is invalid"))
        raw = candidate()
        raw["artifact_digest"] = "0" * 64
        raw["roles"] = []
        cases.append((raw, "manifest artifact digest mismatch"))
        for raw, message in cases:
            with self.subTest(message=message):
                with self.assertRaises(ValueError) as raised:
                    skills.validate_manifest(raw)
                self.assertEqual(str(raised.exception), message)

    def test_safety_budget_match_template_and_output_fail_closed(self) -> None:
        mutations = (
            (lambda raw: raw.update(safety=[]), "manifest safety contract is invalid"),
            (
                lambda raw: raw["safety"].update(read_only=1),
                "v2 skills cannot grant mutation authority",
            ),
            (
                lambda raw: raw["safety"].update(
                    active_operation=True,
                    requires_approval=False,
                ),
                "active operation must require approval",
            ),
            (lambda raw: raw.update(budgets={}), "manifest budgets are invalid"),
            (
                lambda raw: raw["budgets"].update(max_queries=0),
                "manifest max_queries is outside its bound",
            ),
            (lambda raw: raw.update(match={}), "manifest match contract is invalid"),
            (
                lambda raw: raw.update(query_templates=[]),
                "query_templates must contain 1-12 templates",
            ),
            (
                lambda raw: raw["query_templates"][0].update(backend="unsafe"),
                "query template backend or language is unsupported",
            ),
            (lambda raw: raw.update(output_contract={}), "skill output contract is unsafe"),
        )
        for mutate, message in mutations:
            raw = candidate()
            mutate(raw)
            raw["artifact_digest"] = skills.artifact_digest(raw)
            with self.subTest(message=message):
                with self.assertRaises(ValueError) as raised:
                    skills.validate_manifest(raw)
                self.assertEqual(str(raised.exception), message)

    def test_promotion_failure_order_deduplication_and_input_are_exact(self) -> None:
        raw = candidate()
        before = copy.deepcopy(raw)
        result = skills.promotion_eligible(raw, "active")
        self.assertEqual(raw, before)
        self.assertEqual(
            result,
            (
                False,
                [
                    "adversarial_tests",
                    "human_approved",
                    "independent_query_review",
                    "independent_reviewer",
                    "replay_cases",
                    "unit_tests",
                ],
            ),
        )

        missing = copy.deepcopy(raw)
        missing["verification"] = None
        self.assertEqual(
            skills.promotion_eligible(missing, "shadow"),
            (False, ["verification_missing"]),
        )
        with self.assertRaisesRegex(ValueError, "target must be shadow or active"):
            skills.promotion_eligible(raw, "candidate")

    def test_promotion_validates_after_gate_collection(self) -> None:
        raw = promotable()
        raw["objective"] = "tampered"
        calls: list[str] = []

        def validate(value):
            calls.append("validate")
            raise ValueError("synthetic validation failure")

        with mock.patch.object(skills, "validate_manifest", side_effect=validate):
            result = skills.promotion_eligible(raw, "active")
        self.assertEqual(calls, ["validate"])
        self.assertEqual(result, (False, ["manifest_validation"]))

    def test_resolution_rejection_order_identity_sort_and_truncation(self) -> None:
        active = promotable("network.zeta.skill")
        another = promotable("network.alpha.skill")
        records = [
            {"state": "candidate", "manifest": active},
            {"state": "active", "manifest": {"id": "invalid"}},
            {"state": "active", "manifest": active},
            {"state": "active", "manifest": another},
        ]
        context = {
            "task": "alert-triage",
            "protocol": "dns",
            "alert_family": "dns",
            "data_source": "elastic",
        }
        permitted = active["capabilities"]
        before = copy.deepcopy(records)
        result = skills.resolve_manifests(
            records,
            context,
            "soc-analyst",
            permitted,
        )
        self.assertEqual(records, before)
        self.assertEqual(
            [item["id"] for item in result["selected"]],
            ["network.alpha.skill", "network.zeta.skill"],
        )
        self.assertEqual(
            result["rejected"],
            [
                {"id": "invalid", "reason": "manifest_validation_failed"},
                {
                    "id": "network.zeta.skill",
                    "reason": "lifecycle_state_unavailable",
                },
            ],
        )
        self.assertEqual(list(result["selected"][0]), ["id", "version", "artifact_digest"])
        self.assertNotIn("query_templates", json.dumps(result))

    def test_resolution_context_get_order_and_shadow_gate_are_exact(self) -> None:
        value = promotable()
        context = TrackingMapping(
            {
                "task": "alert-triage",
                "protocol": "dns",
                "alert_family": "dns",
                "data_source": "elastic",
            }
        )
        shadow = skills.resolve_manifests(
            [{"state": "shadow", "manifest": value}],
            context,
            "soc-analyst",
            value["capabilities"],
            allow_shadow=False,
        )
        self.assertEqual(shadow["selected"], [])
        self.assertEqual(context.trace, [])

        active = skills.resolve_manifests(
            [{"state": "active", "manifest": value}],
            context,
            "soc-analyst",
            value["capabilities"],
        )
        self.assertEqual(active["selected_count"], 1)
        self.assertEqual(
            context.trace,
            [
                ("get", "task"),
                ("get", "protocol"),
                ("get", "alert_family"),
                ("get", "data_source"),
            ],
        )


if __name__ == "__main__":
    unittest.main()
