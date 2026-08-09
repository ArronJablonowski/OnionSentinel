from __future__ import annotations

import copy
import unittest
from pathlib import Path

from n8n.onion_sentinel.analysis.review import adjudication_workflow as workflow


class ValidationError(ValueError):
    pass


class Harness:
    envelope = type("Envelope", (), {"assigned_reviewer_route": "reviewer"})()

    def __init__(self) -> None:
        self.preflights = []
        self.calls = []

    def preflight_model_call(self, **kwargs) -> None:
        self.preflights.append(kwargs)

    def model_call(self, **kwargs) -> None:
        self.calls.append(kwargs)


class ReviewAdjudicationWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.phases = []
        self.inputs = []
        self.candidates = [{"decision": "unresolved"}]
        self.policy = workflow.Policy(default_prompt_file=Path("/default.md"))
        self.dependencies = workflow.Dependencies(
            route_identity=lambda route, _settings: str(route or ""),
            notify_phase=lambda *args: self.phases.append(args),
            build_package=lambda *_args, **_kwargs: {"contract": "closed"},
            route_is_hosted=lambda route, _settings: route.startswith("hosted"),
            analyze_route=self._analyze,
            validate=self._validate,
            reconcile_endpoint_gaps=lambda value, _package: {
                **value, "reconciled": True,
            },
            monotonic=lambda: 10.0,
            validation_error=ValidationError,
        )

    def _context(self, **updates) -> workflow.Context:
        values = {
            "prompt_package": {},
            "primary_response": {},
            "reviewer_response": {},
            "comparison": {},
            "args": type("Args", (), {})(),
            "settings": {
                "agent_models": {"soc-analyst": "primary"},
                "agent_second_opinion_models": {"soc-analyst": "reviewer"},
                "agent_adjudicator_models": {"soc-analyst": "adjudicator"},
            },
            "agent_role": "soc-analyst",
            "phase_callback": None,
            "harness_runtime": None,
        }
        values.update(updates)
        return workflow.Context(**values)

    def _analyze(self, _route, package, *_args, **_kwargs):
        self.inputs.append(copy.deepcopy(package))
        return self.candidates.pop(0)

    @staticmethod
    def _validate(candidate, _package):
        if candidate.get("decision") != "unresolved":
            raise ValidationError("closed decision required")
        return dict(candidate)

    def test_missing_or_non_independent_route_never_executes(self) -> None:
        settings = self._context().settings
        settings["agent_adjudicator_models"]["soc-analyst"] = ""
        missing = workflow.run(
            self._context(settings=settings),
            policy=self.policy,
            dependencies=self.dependencies,
        )
        settings["agent_adjudicator_models"]["soc-analyst"] = "primary"
        same = workflow.run(
            self._context(settings=settings),
            policy=self.policy,
            dependencies=self.dependencies,
        )

        self.assertEqual(missing["status"], "not_configured")
        self.assertEqual(same["status"], "not_independent")
        self.assertEqual(self.inputs, [])

    def test_frozen_reviewer_route_is_attested_and_allowed(self) -> None:
        harness = Harness()
        result = workflow.run(
            self._context(harness_runtime=harness),
            policy=self.policy,
            dependencies=self.dependencies,
        )

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["route_source"], "frozen_reviewer_route")
        self.assertEqual(result["response"]["reconciled"], True)
        self.assertEqual(harness.preflights[0]["requested_route"], "reviewer")
        self.assertEqual(harness.calls[0]["requested_route"], "reviewer")
        self.assertTrue(harness.calls[0]["independent_review"])

    def test_one_validation_repair_is_bounded_and_audited(self) -> None:
        self.candidates = [{"decision": "invented"}, {"decision": "unresolved"}]

        result = workflow.run(
            self._context(), policy=self.policy, dependencies=self.dependencies
        )

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["attempts"], 2)
        self.assertEqual(len(result["validation_failures"]), 1)
        self.assertNotIn("adjudication_contract_repair", self.inputs[0])
        self.assertEqual(
            self.inputs[1]["adjudication_contract_repair"]["attempt"], 1
        )

    def test_terminal_validation_failure_preserves_both_attempts(self) -> None:
        self.candidates = [{"decision": "invented"}, {"decision": "invented"}]

        result = workflow.run(
            self._context(), policy=self.policy, dependencies=self.dependencies
        )

        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["attempts"], 2)
        self.assertEqual(len(result["validation_failures"]), 2)
        self.assertIn("ValidationError", result["error"])


if __name__ == "__main__":
    unittest.main()
