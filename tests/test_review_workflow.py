#!/usr/bin/env python3
"""Direct contracts for independent-review workflow orchestration."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ROOT = ROOT / "n8n"
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

from onion_sentinel.analysis.review import workflow  # noqa: E402


class ReviewError(RuntimeError):
    pass


class ReviewWorkflowTests(unittest.TestCase):
    def dependencies(self, **overrides):
        phases: list[tuple] = []
        required: list[tuple] = []
        values = {
            "trigger": lambda _response, _package: "review required",
            "notify_phase": lambda *args, **kwargs: phases.append((args, kwargs)),
            "route_identity": lambda route, _settings: route,
            "role_prompt_file": lambda root, role: root / f"{role}.md",
            "route_is_hosted": lambda _route, _settings: False,
            "independent_package": lambda package, **_kwargs: dict(package),
            "monotonic": lambda: 1.0,
            "warning": lambda _message: None,
            "analyze_route": lambda *_args, **_kwargs: {"candidate": True},
            "validate_reviewer": lambda candidate, _package: dict(candidate),
            "reviewer_validation_error": ReviewError,
            "validation_failure": lambda **kwargs: {
                "message": str(kwargs["error"]),
                "attempt": kwargs["attempt"],
            },
            "repair_error_category": lambda _message: "schema",
            "repair_guidance": lambda _message: ["return the contract"],
            "validate_response": lambda response, _package: dict(response),
            "supplemental_pivot": lambda _package, response, *_args, **_kwargs: (
                response,
                {"executed": False},
            ),
            "compare": lambda _primary, _reviewer: {
                "agreement": "agreement",
                "material_disagreement": False,
            },
            "automation_authorization": lambda *_args: {
                "authorized": True,
                "memory_writeback_authorized": True,
                "reason": "corroborated",
            },
            "adjudicate": lambda *_args: {},
            "apply_adjudication_projection": lambda *_args: False,
            "reconcile_report": lambda *_args: None,
            "apply_disagreement_gate": lambda *_args: None,
            "apply_completed_gate": lambda *_args, **_kwargs: None,
            "apply_required_gate": lambda *args, **kwargs: required.append((args, kwargs)),
            "apply_tuning_guard": lambda *_args: None,
        }
        values.update(overrides)
        return workflow.Dependencies(**values), phases, required

    @staticmethod
    def context(response=None, settings=None):
        return workflow.Context(
            prompt_package={"alert": {"alert_id": "case-1"}},
            primary_response=response or {},
            args=type("Args", (), {"second_opinion_prompt_file": Path("/review.md")})(),
            settings=settings or {
                "agent_models": {"soc-analyst": "primary"},
                "agent_second_opinion_models": {"soc-analyst": "reviewer"},
            },
            agent_role="soc-analyst",
        )

    def test_no_trigger_removes_forged_review_and_skips_model(self) -> None:
        analyze_calls: list[bool] = []
        deps, phases, _required = self.dependencies(
            trigger=lambda _response, _package: "",
            analyze_route=lambda *_args, **_kwargs: analyze_calls.append(True),
        )
        response = {"_second_opinion": {"status": "forged"}}

        result = workflow.execute(
            self.context(response), workflow.Policy(Path("/default.md")), deps
        )

        self.assertNotIn("_second_opinion", result)
        self.assertEqual(result["final_disposition_status"], "primary_not_reviewed")
        self.assertEqual(analyze_calls, [])
        self.assertEqual(phases[0][0][1], "post_processing")

    def test_identical_route_fails_closed_before_model_execution(self) -> None:
        analyze_calls: list[bool] = []
        settings = {
            "agent_models": {"soc-analyst": "same"},
            "agent_second_opinion_models": {"soc-analyst": "same"},
        }
        deps, _phases, required = self.dependencies(
            analyze_route=lambda *_args, **_kwargs: analyze_calls.append(True)
        )

        result = workflow.execute(
            self.context(settings=settings), workflow.Policy(Path("/default.md")), deps
        )

        self.assertEqual(result["_second_opinion"]["status"], "not_independent")
        self.assertEqual(required[0][1]["status"], "review_required_not_independent")
        self.assertEqual(analyze_calls, [])

    def test_validation_failure_retries_once_with_bounded_repair(self) -> None:
        validations = 0
        packages: list[dict] = []

        def analyze(_route, package, *_args, **_kwargs):
            packages.append(dict(package))
            return {"candidate": len(packages)}

        def validate(candidate, _package):
            nonlocal validations
            validations += 1
            if validations == 1:
                raise ReviewError("wrong schema")
            return candidate

        deps, _phases, _required = self.dependencies(
            analyze_route=analyze,
            validate_reviewer=validate,
        )

        result = workflow.execute(
            self.context(), workflow.Policy(Path("/default.md")), deps
        )

        record = result["_second_opinion"]
        self.assertEqual(record["status"], "completed")
        self.assertEqual(record["attempts"], 2)
        self.assertEqual(len(record["validation_failures"]), 1)
        self.assertNotIn("review_contract_repair", packages[0])
        self.assertEqual(packages[1]["review_contract_repair"]["attempt"], 1)
        self.assertEqual(result["final_disposition_status"], "corroborated")


if __name__ == "__main__":
    unittest.main()
