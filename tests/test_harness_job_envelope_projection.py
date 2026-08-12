#!/usr/bin/env python3
"""Characterize immutable harness job-envelope field projection."""
from __future__ import annotations

import ast
import copy
import hashlib
import sys
import unittest
from collections.abc import Mapping
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
BIN_DIR = REPO_ROOT / "n8n" / "bin"
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))

import harness_contract_job as JOB  # noqa: E402


def function_metrics(name: str) -> tuple[int, int]:
    tree = ast.parse((BIN_DIR / "harness_contract_job.py").read_text())
    target = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == name
    )
    complexity = 1
    for node in ast.walk(target):
        if isinstance(node, (ast.If, ast.For, ast.While, ast.IfExp)):
            complexity += 1
        elif isinstance(node, ast.Try):
            complexity += len(node.handlers)
        elif isinstance(node, ast.BoolOp):
            complexity += max(0, len(node.values) - 1)
        elif isinstance(node, ast.comprehension):
            complexity += 1 + len(node.ifs)
    return target.end_lineno - target.lineno + 1, complexity


class TracedMapping(Mapping):
    def __init__(self, values: dict[str, Any]) -> None:
        self.values = values
        self.events: list[str] = []

    def __getitem__(self, key: str) -> Any:
        self.events.append(f"item:{key}")
        return self.values[key]

    def __iter__(self):
        self.events.append("iter")
        return iter(self.values)

    def __len__(self) -> int:
        self.events.append("len")
        return len(self.values)

    def get(self, key: str, default: Any = None) -> Any:
        self.events.append(f"get:{key}")
        return self.values.get(key, default)


class DependencyHarness:
    def __init__(self, prompt: Mapping[str, Any], configuration: Mapping[str, Any]):
        self.prompt = prompt
        self.configuration = configuration
        self.events: list[tuple[Any, ...]] = []

    def valid_identifier(
        self,
        value: Any,
        label: str,
        maximum: int = 256,
    ) -> str:
        self.events.append(("valid", value, label, maximum))
        return "normalized-run" if label == "run_id" else str(value)

    def model_route(
        self,
        value: Any,
        label: str,
        *,
        allow_empty: bool = False,
    ) -> str:
        self.events.append(("route", value, label, allow_empty))
        return str(value or "")

    def digest_value(self, value: Any) -> str:
        owner = (
            "prompt"
            if value is self.prompt
            else "configuration"
            if value is self.configuration
            else "contract"
        )
        self.events.append(("digest", owner))
        return f"digest-{owner}"

    def task_kind_value(self, role: str, **kwargs: Any) -> str:
        self.events.append(("task", role, kwargs))
        return "task-kind"

    def skill_attestation(self, prompt: Mapping[str, Any]) -> dict[str, Any]:
        self.events.append(("skills", prompt is self.prompt))
        return {"mode": "characterized"}

    def now_value(self) -> str:
        self.events.append(("now",))
        return "2026-08-12T00:00:00Z"

    def project(self, **overrides: Any) -> dict[str, Any]:
        values = {
            "run_id": "run-1",
            "prompt_package": self.prompt,
            "role": "soc-analyst",
            "assigned_route": "primary-route",
            "configuration": self.configuration,
            "reanalysis_attempt_id": "attempt-1",
            "valid_identifier": self.valid_identifier,
            "model_route": self.model_route,
            "digest_value": self.digest_value,
            "task_kind_value": self.task_kind_value,
            "skill_attestation": self.skill_attestation,
            "now_value": self.now_value,
        }
        values.update(overrides)
        return JOB.job_envelope_values(**values)


class HarnessJobEnvelopeProjectionCharacterizationTests(unittest.TestCase):
    def test_projection_owners_stay_small_and_cohesive(self) -> None:
        for name in (
            "_validate_role",
            "_prompt_identity_values",
            "_identity_fields",
            "_execution_contract_fields",
            "_parent_run_id",
            "job_envelope_values",
        ):
            with self.subTest(name=name):
                lines, complexity = function_metrics(name)
                self.assertLessEqual(lines, 50)
                self.assertLessEqual(complexity, 10)

    def test_exact_result_and_dependency_order_use_validated_run_identity(self) -> None:
        prompt = TracedMapping(
            {
                "alert": {"alert_id": "alert-1"},
                "incident_response_evidence": {"case_id": "case-1"},
                "group_id": "group-1",
                "evidence_reference_contract": {"references": ["one"]},
                "manual_reanalysis": True,
                "parent_analysis_id": "parent-1",
            }
        )
        configuration = TracedMapping({"reviewer_route": "reviewer-route"})
        dependencies = DependencyHarness(prompt, configuration)

        result = dependencies.project()

        self.assertEqual(
            list(result),
            [
                "run_id", "trace_id", "correlation_id", "case_id",
                "alert_id", "role", "task_kind", "assigned_route",
                "assigned_reviewer_route", "prompt_digest",
                "evidence_manifest_digest", "configuration_digest",
                "skill_selection_attestation", "parent_run_id", "created_at",
            ],
        )
        self.assertEqual(
            result,
            {
                "run_id": "normalized-run",
                "trace_id": hashlib.sha256(
                    f"{JOB.HARNESS_SCHEMA}:normalized-run".encode("utf-8")
                ).hexdigest()[:32],
                "correlation_id": "group-1",
                "case_id": "case-1",
                "alert_id": "alert-1",
                "role": "soc-analyst",
                "task_kind": "task-kind",
                "assigned_route": "primary-route",
                "assigned_reviewer_route": "reviewer-route",
                "prompt_digest": "digest-prompt",
                "evidence_manifest_digest": "digest-contract",
                "configuration_digest": "digest-configuration",
                "skill_selection_attestation": {"mode": "characterized"},
                "parent_run_id": "parent-1",
                "created_at": "2026-08-12T00:00:00Z",
            },
        )
        self.assertEqual(
            dependencies.events,
            [
                ("task", "soc-analyst", {
                    "reanalysis_attempt_id": "attempt-1",
                    "manual_reanalysis": True,
                }),
                ("valid", "run-1", "run_id", 128),
                ("valid", "group-1", "correlation_id", 256),
                ("valid", "case-1", "case_id", 256),
                ("valid", "alert-1", "alert_id", 256),
                ("route", "primary-route", "assigned primary route", False),
                ("route", "reviewer-route", "assigned reviewer route", True),
                ("digest", "prompt"),
                ("digest", "contract"),
                ("digest", "configuration"),
                ("skills", True),
                ("now",),
            ],
        )
        self.assertEqual(
            prompt.events,
            [
                "get:alert", "get:incident_response_evidence",
                "get:grouped_alert_context", "get:group_id",
                "get:evidence_reference_contract", "get:manual_reanalysis",
                "get:parent_analysis_id",
            ],
        )
        self.assertEqual(configuration.events, ["get:reviewer_route"])

    def test_fallback_identifiers_and_parent_access_order_are_exact(self) -> None:
        prompt = TracedMapping(
            {
                "alert_id": "top-alert",
                "case_id": "top-case",
                "grouped_alert_context": {"group_id": "nested-group"},
                "prior_analysis_id": "prior-1",
            }
        )
        configuration = TracedMapping({})
        dependencies = DependencyHarness(prompt, configuration)

        result = dependencies.project(reanalysis_attempt_id="")

        self.assertEqual(result["alert_id"], "top-alert")
        self.assertEqual(result["case_id"], "top-case")
        self.assertEqual(result["correlation_id"], "nested-group")
        self.assertEqual(result["parent_run_id"], "prior-1")
        self.assertEqual(
            prompt.events,
            [
                "get:alert", "get:incident_response_evidence", "get:alert_id",
                "get:case_id", "get:grouped_alert_context", "get:group_id",
                "get:evidence_reference_contract", "get:manual_reanalysis",
                "get:parent_analysis_id", "get:prior_analysis_id",
            ],
        )

    def test_nested_mapping_subclasses_are_not_admitted_as_dict_fields(self) -> None:
        nested_alert = TracedMapping({"alert_id": "ignored-alert"})
        nested_incident = TracedMapping({"case_id": "ignored-case"})
        prompt = {
            "alert": nested_alert,
            "incident_response_evidence": nested_incident,
        }
        configuration: dict[str, Any] = {}
        dependencies = DependencyHarness(prompt, configuration)

        result = dependencies.project()

        self.assertEqual(result["alert_id"], "")
        self.assertEqual(result["case_id"], "run-1")
        self.assertEqual(result["correlation_id"], "run-1")
        self.assertEqual(nested_alert.events, [])
        self.assertEqual(nested_incident.events, [])

    def test_unsupported_role_precedes_mapping_and_dependency_access(self) -> None:
        prompt = TracedMapping({})
        configuration = TracedMapping({})
        dependencies = DependencyHarness(prompt, configuration)

        with self.assertRaisesRegex(
            JOB.HarnessPolicyError,
            "^unsupported agent role: invalid-role$",
        ) as raised:
            dependencies.project(role="invalid-role")

        self.assertIsInstance(raised.exception.__cause__, ValueError)
        self.assertEqual(prompt.events, [])
        self.assertEqual(configuration.events, [])
        self.assertEqual(dependencies.events, [])

    def test_run_validation_occurs_after_projection_reads_and_task_selection(self) -> None:
        prompt = TracedMapping({})
        configuration = TracedMapping({})
        dependencies = DependencyHarness(prompt, configuration)

        def reject_identifier(value: Any, label: str, maximum: int = 256) -> str:
            dependencies.events.append(("reject", value, label, maximum))
            raise RuntimeError("invalid run")

        with self.assertRaisesRegex(RuntimeError, "^invalid run$"):
            dependencies.project(valid_identifier=reject_identifier)

        self.assertEqual(
            prompt.events,
            [
                "get:alert", "get:incident_response_evidence", "get:alert_id",
                "get:case_id", "get:grouped_alert_context", "get:group_id",
                "get:evidence_reference_contract", "get:manual_reanalysis",
            ],
        )
        self.assertEqual(
            dependencies.events,
            [
                ("task", "soc-analyst", {
                    "reanalysis_attempt_id": "attempt-1",
                    "manual_reanalysis": False,
                }),
                ("reject", "run-1", "run_id", 128),
            ],
        )
        self.assertEqual(configuration.events, [])

    def test_parent_identity_is_stringified_then_bounded_to_128_characters(self) -> None:
        prompt = {"parent_analysis_id": 7, "prior_analysis_id": "ignored"}
        configuration: dict[str, Any] = {}
        dependencies = DependencyHarness(prompt, configuration)
        self.assertEqual(dependencies.project()["parent_run_id"], "7")

        prompt["parent_analysis_id"] = "p" * 140
        self.assertEqual(dependencies.project()["parent_run_id"], "p" * 128)

    def test_inputs_are_not_mutated(self) -> None:
        prompt = {
            "alert": {"alert_id": "alert-1"},
            "incident_response_evidence": {"case_id": "case-1"},
            "evidence_reference_contract": {"references": [{"id": "one"}]},
        }
        configuration = {"reviewer_route": "reviewer-route", "limits": [1, 2]}
        before_prompt = copy.deepcopy(prompt)
        before_configuration = copy.deepcopy(configuration)
        dependencies = DependencyHarness(prompt, configuration)

        dependencies.project()

        self.assertEqual(prompt, before_prompt)
        self.assertEqual(configuration, before_configuration)


if __name__ == "__main__":
    unittest.main()
