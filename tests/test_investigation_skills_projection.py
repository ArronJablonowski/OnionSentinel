"""Characterize investigation-skill validation, loading, and matching."""

from __future__ import annotations

import ast
import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "n8n/bin/investigation_skills.py"
REGISTRY_PATH = ROOT / "n8n/config/investigation_skills.json"
SPEC = importlib.util.spec_from_file_location(
    "investigation_skills_projection", MODULE_PATH
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


def checked_payload() -> dict[str, Any]:
    return json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))


class TrackingDict(dict):
    def __init__(self, values):
        super().__init__(values)
        self.trace: list[tuple[str, object]] = []

    def get(self, key, default=None):
        self.trace.append(("get", key))
        return super().get(key, default)


class FakeRegistryPath:
    def __init__(self, *, stat_size=0, raw=b"", missing=False):
        self.stat_size = stat_size
        self.raw = raw
        self.missing = missing
        self.trace: list[str] = []

    def stat(self):
        self.trace.append("stat")
        if self.missing:
            raise FileNotFoundError("synthetic missing registry")
        return SimpleNamespace(st_size=self.stat_size)

    def read_bytes(self):
        self.trace.append("read_bytes")
        return self.raw


class InvestigationSkillsProjectionTests(unittest.TestCase):
    def test_changed_phases_meet_architecture_contract(self) -> None:
        for name in (
            "_match_mapping",
            "_normalized_match_lists",
            "_normalized_destination_ports",
            "_validate_match",
            "_skill_identity",
            "_skill_projection",
            "_validate_skill",
            "_read_registry_bytes",
            "_empty_registry",
            "_registry_payload",
            "_validated_skills",
            "_learning_policy",
            "load_investigation_skills",
            "_context_match_values",
            "_trigger_checks",
            "_matches",
        ):
            with self.subTest(name=name):
                lines, complexity = function_metrics(name)
                self.assertLessEqual(lines, 50)
                self.assertLessEqual(complexity, 10)

    def test_match_projection_preserves_order_normalization_and_input(self) -> None:
        raw = {
            "destination_ports": [53, 53, True],
            "rule_name_contains": [" DNS ", "dns", "Lookup"],
            "protocols": [" UDP ", "udp"],
            "event_datasets": [" Suricata.Alert ", "suricata.alert"],
        }
        before = copy.deepcopy(raw)
        result = skills._validate_match(raw, "dns-skill")
        self.assertEqual(raw, before)
        self.assertEqual(
            result,
            {
                "event_datasets": ["suricata.alert"],
                "protocols": ["udp"],
                "rule_name_contains": ["dns", "lookup"],
                "destination_ports": [53, True],
            },
        )
        self.assertEqual(
            list(result),
            [
                "event_datasets",
                "protocols",
                "rule_name_contains",
                "destination_ports",
            ],
        )

    def test_match_rejects_shape_unknown_ports_and_empty_triggers(self) -> None:
        cases = (
            (None, "dns.match must be an object"),
            ({"z": [], "a": []}, "dns.match has unsupported keys: ['a', 'z']"),
            ({"destination_ports": "53"}, "dns.match.destination_ports is invalid"),
            ({"destination_ports": [0]}, "dns.match.destination_ports is invalid"),
            ({"destination_ports": [65536]}, "dns.match.destination_ports is invalid"),
            ({"destination_ports": [53.0]}, "dns.match.destination_ports is invalid"),
            ({"protocols": []}, "dns.match must define a bounded deterministic trigger"),
            ({}, "dns.match must define a bounded deterministic trigger"),
        )
        for value, message in cases:
            with self.subTest(value=value):
                with self.assertRaises(ValueError) as raised:
                    skills._validate_match(value, "dns")
                self.assertEqual(str(raised.exception), message)

    def test_skill_projection_order_default_digest_and_input_are_exact(self) -> None:
        raw = copy.deepcopy(checked_payload()["skills"][0])
        raw.pop("known_false_positive_patterns", None)
        before = copy.deepcopy(raw)
        result = skills._validate_skill(raw, 7)
        self.assertEqual(raw, before)
        self.assertEqual(
            list(result),
            [
                "id",
                "version",
                "status",
                "roles",
                "match",
                "objective",
                "required_evidence",
                "pivot_plan",
                "alternative_hypotheses",
                "stop_conditions",
                "confidence_limiters",
                "known_false_positive_patterns",
                "verification",
                "skill_sha256",
            ],
        )
        self.assertEqual(result["known_false_positive_patterns"], [])
        digest_input = {key: value for key, value in result.items() if key != "skill_sha256"}
        self.assertEqual(result["skill_sha256"], skills._sha256(digest_input))

    def test_skill_validation_preserves_early_error_precedence(self) -> None:
        base = copy.deepcopy(checked_payload()["skills"][0])
        cases = []
        invalid = copy.deepcopy(base)
        invalid["id"] = "INVALID SPACE"
        invalid["version"] = 0
        cases.append((invalid, "skills[3].id is invalid"))
        invalid = copy.deepcopy(base)
        invalid["version"] = True
        invalid["status"] = "unsupported"
        cases.append((invalid, "dns-activity-investigation.status is unsupported"))
        invalid = copy.deepcopy(base)
        invalid["version"] = 0
        invalid["status"] = "unsupported"
        cases.append(
            (
                invalid,
                "dns-activity-investigation.version must be a positive integer",
            )
        )
        for raw, message in cases:
            with self.subTest(message=message):
                with self.assertRaises(ValueError) as raised:
                    skills._validate_skill(raw, 3)
                self.assertEqual(str(raised.exception), message)

    def test_loader_missing_and_both_byte_limits_preserve_call_order(self) -> None:
        missing = FakeRegistryPath(missing=True)
        result = skills.load_investigation_skills(missing)
        empty = {
            "schema": skills.REGISTRY_SCHEMA,
            "version": 0,
            "mode": "shadow",
            "skills": [],
        }
        self.assertEqual(result, {**empty, "registry_sha256": skills._sha256(empty)})
        self.assertEqual(missing.trace, ["stat"])

        oversized = FakeRegistryPath(stat_size=skills.MAX_REGISTRY_BYTES + 1)
        with self.assertRaisesRegex(ValueError, "exceeds its byte limit"):
            skills.load_investigation_skills(oversized)
        self.assertEqual(oversized.trace, ["stat"])

        grew = FakeRegistryPath(raw=b"x" * (skills.MAX_REGISTRY_BYTES + 1))
        with self.assertRaisesRegex(ValueError, "exceeds its byte limit"):
            skills.load_investigation_skills(grew)
        self.assertEqual(grew.trace, ["stat", "read_bytes"])

    def test_loader_normalization_digest_uniqueness_and_strict_policy(self) -> None:
        payload = checked_payload()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "skills.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            result = skills.load_investigation_skills(path)
        self.assertEqual(
            list(result),
            [
                "schema",
                "version",
                "mode",
                "learning_policy",
                "skills",
                "registry_sha256",
            ],
        )
        normalized = {
            key: value for key, value in result.items() if key != "registry_sha256"
        }
        self.assertEqual(result["registry_sha256"], skills._sha256(normalized))

        duplicate = checked_payload()
        duplicate["skills"].append(copy.deepcopy(duplicate["skills"][0]))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text(json.dumps(duplicate), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "id/version pairs must be unique"):
                skills.load_investigation_skills(path)

        policy = checked_payload()
        policy["learning_policy"]["agent_may_propose"] = 1
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_text(json.dumps(policy), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "promotion gates"):
                skills.load_investigation_skills(path)

    def test_context_match_conjoins_triggers_and_preserves_inputs(self) -> None:
        skill = {
            "match": {
                "event_datasets": ["suricata.alert"],
                "protocols": ["udp"],
                "destination_ports": [53],
                "rule_name_contains": ["dns", "lookup"],
            }
        }
        context = {
            "event_dataset": " Suricata.Alert ",
            "transport_protocol": " UDP ",
            "network_protocol": "tcp",
            "destination_port": "53",
            "rule_name": "ET INFO dns request",
        }
        before_skill = copy.deepcopy(skill)
        before_context = copy.deepcopy(context)
        self.assertTrue(skills._matches(skill, context))
        self.assertEqual(skill, before_skill)
        self.assertEqual(context, before_context)
        context["rule_name"] = "unrelated"
        self.assertFalse(skills._matches(skill, context))
        self.assertFalse(skills._matches({"match": {}}, context))

    def test_context_match_get_order_fallback_and_port_coercion_are_exact(self) -> None:
        skill = TrackingDict({"match": {"protocols": ["udp"]}})
        context = TrackingDict(
            {
                "event_dataset": "",
                "transport_protocol": "udp",
                "network_protocol": "tcp",
                "destination_port": object(),
                "rule_name": "",
            }
        )
        self.assertTrue(skills._matches(skill, context))
        self.assertEqual(skill.trace[:2], [("get", "match"), ("get", "match")])
        self.assertEqual(
            context.trace,
            [
                ("get", "event_dataset"),
                ("get", "transport_protocol"),
                ("get", "rule_name"),
                ("get", "destination_port"),
                ("get", "evidence_sources"),
            ],
        )

        fallback = TrackingDict(
            {
                "transport_protocol": "",
                "network_protocol": "UDP",
                "destination_port": True,
            }
        )
        self.assertTrue(
            skills._matches(
                {"match": {"protocols": ["udp"], "destination_ports": [1]}},
                fallback,
            )
        )
        self.assertEqual(
            fallback.trace[:3],
            [
                ("get", "event_dataset"),
                ("get", "transport_protocol"),
                ("get", "network_protocol"),
            ],
        )


if __name__ == "__main__":
    unittest.main()
