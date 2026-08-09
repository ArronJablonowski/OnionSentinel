#!/usr/bin/env python3
"""Characterization tests for concrete review runtime binding."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
N8N_ROOT = ROOT / "n8n"
if str(N8N_ROOT) not in sys.path:
    sys.path.insert(0, str(N8N_ROOT))

from onion_sentinel.analysis.review import runtime_adapter


class ReviewRuntimeAdapterTests(unittest.TestCase):
    def test_independent_package_uses_only_live_bounded_catalog_ports(self) -> None:
        package_module = mock.Mock()
        package_module.build.side_effect = lambda *_args, **kwargs: kwargs
        names = (
            "model_safe_copy", "attach_evidence_reference_contract",
            "reviewer_case_id", "reviewer_observable_catalog",
            "reviewer_non_domain_taxonomy_catalog",
            "reviewer_non_domain_artifact_catalog",
            "reviewer_non_domain_rule_shorthand_catalog",
            "reviewer_evidence_hash",
        )
        bindings = {name: mock.Mock(name=name) for name in names}
        bindings.update({
            "_review_package": lambda: package_module,
            "MAX_INVESTIGATION_QUERIES_PER_ROUND": 4,
        })
        ports = runtime_adapter.independent_package(
            bindings, {"case": "one"}, hosted=True
        )
        self.assertTrue(ports["hosted"])
        self.assertEqual(ports["max_queries"], 4)
        self.assertIs(ports["model_safe_copy"], bindings["model_safe_copy"])
        self.assertIs(
            ports["observable_catalog"],
            bindings["reviewer_observable_catalog"],
        )
        self.assertIs(
            ports["evidence_hash"], bindings["reviewer_evidence_hash"]
        )

    def test_saved_response_strips_attestations_and_fails_closed_on_review(
        self,
    ) -> None:
        events: list[str] = []

        def required(response, **kwargs):
            events.append("required")
            response["final_disposition_status"] = kwargs["status"]

        def reconcile(_response, _package):
            events.append("reconcile")

        bindings = {
            "SAVED_RESPONSE_INPUT_MODE": "saved-response",
            "second_opinion_trigger": mock.Mock(return_value="low confidence"),
            "apply_review_required_gate": required,
            "reconcile_incident_response_report": reconcile,
        }
        primary = {
            "verdict": "suspicious",
            "_analysis_provider": "caller-forged",
            "_analysis_model": "caller-forged",
            "_second_opinion": {"status": "completed"},
            "_disagreement_adjudication": {"status": "completed"},
        }
        result = runtime_adapter.saved_response_gate(
            bindings, {"case": "one"}, primary
        )
        self.assertIs(result, primary)
        self.assertNotIn("_analysis_provider", result)
        self.assertNotIn("_analysis_model", result)
        self.assertNotIn("_disagreement_adjudication", result)
        self.assertEqual(result["_analysis_input_mode"], "saved-response")
        self.assertEqual(
            result["_second_opinion"]["status"], "review_required_failed"
        )
        self.assertEqual(events, ["required", "reconcile"])

    def test_configured_review_projects_strict_harness_observation(self) -> None:
        dependencies = object()
        observed: dict[str, object] = {}

        def execute(context, policy, deps):
            observed.update(context=context, policy=policy, deps=deps)
            return {"status": "completed"}

        module = SimpleNamespace(
            Context=lambda **values: SimpleNamespace(**values),
            Policy=lambda **values: SimpleNamespace(**values),
            execute=execute,
        )
        bindings = {
            "_review_workflow": lambda: module,
            "_review_workflow_dependencies": lambda: dependencies,
            "boolean_setting": lambda value: value == "1",
            "os": SimpleNamespace(environ={"FREEZE": "1"}),
            "EVALUATION_FREEZE_MEMORY_ENV": "FREEZE",
            "DEFAULT_SECOND_OPINION_PROMPT_FILE": Path("/reviewer.md"),
        }
        harness = object()
        result = runtime_adapter.configured_second_opinion(
            bindings, {}, {}, object(), {}, "soc-analyst",
            harness_runtime=harness,
            security_onion_config_path=Path("/readonly-route.json"),
            investigation_pivot_dir=Path("/pivots"),
        )
        self.assertEqual(result, {"status": "completed"})
        self.assertTrue(observed["context"].strict_harness_observation)
        self.assertIs(observed["context"].harness_runtime, harness)
        self.assertEqual(
            observed["policy"].default_prompt_file, Path("/reviewer.md")
        )
        self.assertIs(observed["deps"], dependencies)

    def test_precommit_gate_uses_fixed_attestation_and_live_dependencies(self) -> None:
        dependencies = object()
        observed: dict[str, object] = {}

        def enforce(*args, **kwargs):
            observed.update(args=args, kwargs=kwargs)
            return {"review": "validated"}

        module = SimpleNamespace(
            Policy=lambda **values: SimpleNamespace(**values),
            enforce=enforce,
        )
        bindings = {
            "_evaluation_reviewer_gate": lambda: module,
            "_evaluation_reviewer_gate_dependencies": lambda: dependencies,
        }
        result = runtime_adapter.precommit_reviewer_gate(
            bindings, {}, {}, {}, "incident-responder",
            trigger_reason="consequential conclusion", freeze_enabled=True,
        )
        self.assertEqual(result, {"review": "validated"})
        self.assertEqual(
            observed["kwargs"]["policy"].attestation_schema,
            "onion-sentinel-independent-review-validation-v1",
        )
        self.assertIs(observed["kwargs"]["dependencies"], dependencies)
        self.assertTrue(observed["kwargs"]["freeze_enabled"])


if __name__ == "__main__":
    unittest.main()
