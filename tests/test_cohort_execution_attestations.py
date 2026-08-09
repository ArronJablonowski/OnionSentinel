#!/usr/bin/env python3
"""Boundary tests for extracted cohort execution attestations."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import re
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
OPERATIONS = ROOT / "operations"
if str(OPERATIONS) not in sys.path:
    sys.path.insert(0, str(OPERATIONS))

import cohort_execution_models  # noqa: E402
import cohort_execution_skills  # noqa: E402
import cohort_execution_tools  # noqa: E402
import cohort_execution_trace  # noqa: E402
import cohort_execution_render  # noqa: E402
import cohort_execution_result  # noqa: E402
import cohort_export  # noqa: E402
import cohort_evaluation_job_proof  # noqa: E402
import cohort_evaluation_harness_gate  # noqa: E402
import cohort_evaluation_execution_admission  # noqa: E402
import cohort_evaluation_result_member  # noqa: E402
import cohort_evaluation_result_export  # noqa: E402


def load_legacy_cohort():
    path = OPERATIONS / "run-incident-harness-cohort.py"
    spec = importlib.util.spec_from_file_location("cohort_attestation_test", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load cohort runner")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_cohort_evaluator():
    path = OPERATIONS / "evaluate-investigation-cohort.py"
    spec = importlib.util.spec_from_file_location("cohort_evaluator_test", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load cohort evaluator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CohortExecutionAttestationBoundaryTests(unittest.TestCase):
    def test_legacy_runner_uses_extracted_attestation_services(self):
        legacy = load_legacy_cohort()

        self.assertIs(
            legacy.evaluate_model_execution,
            cohort_execution_models.evaluate_model_execution,
        )
        self.assertIs(
            legacy.validate_skill_attestation,
            cohort_execution_skills.validate_skill_attestation,
        )
        self.assertIs(
            legacy.evaluate_tool_execution,
            cohort_execution_tools.evaluate_tool_execution,
        )
        self.assertIs(
            legacy.evaluate_trace_execution,
            cohort_execution_trace.evaluate_trace_execution,
        )
        self.assertIs(
            legacy.render_execution_proof,
            cohort_execution_render.render_execution_proof,
        )
        self.assertIs(
            legacy.evaluate_result_execution,
            cohort_execution_result.evaluate_result_execution,
        )
        self.assertIs(
            legacy.collect_prior_analysis_ids,
            cohort_execution_result.prior_analysis_ids,
        )
        sources = legacy._cohort_export_sources()
        self.assertIsInstance(sources, cohort_export.CohortExportSources)
        self.assertIs(
            sources.harness_execution_proof,
            legacy._harness_execution_proof,
        )

    def test_offline_evaluator_uses_extracted_skill_proof_validator(self):
        evaluator = load_cohort_evaluator()

        self.assertIs(
            evaluator.validate_exported_skill_summary,
            cohort_execution_skills.validate_exported_skill_summary,
        )

    def test_offline_evaluator_uses_extracted_durable_job_validator(self):
        evaluator = load_cohort_evaluator()

        self.assertIs(
            evaluator.derive_expected_dispatch_id,
            cohort_evaluation_job_proof.expected_dispatch_id,
        )
        self.assertIs(
            evaluator.validate_durable_job_proof,
            cohort_evaluation_job_proof.validate_durable_job_proof,
        )

    def test_offline_evaluator_uses_extracted_harness_gate(self):
        evaluator = load_cohort_evaluator()

        self.assertIs(
            evaluator.validate_harness_gate,
            cohort_evaluation_harness_gate.validate_harness_gate,
        )

    def test_offline_evaluator_uses_extracted_execution_admission(self):
        evaluator = load_cohort_evaluator()

        self.assertIs(
            evaluator.admit_fresh_analysis,
            cohort_evaluation_execution_admission.admit_fresh_analysis,
        )
        self.assertIs(
            evaluator.validate_response_binding,
            cohort_evaluation_execution_admission.validate_response_binding,
        )
        self.assertIs(
            evaluator.admit_public_proof,
            cohort_evaluation_execution_admission.admit_public_proof,
        )

    def test_offline_evaluator_uses_extracted_result_member_normalizer(self):
        evaluator = load_cohort_evaluator()

        self.assertIs(
            evaluator.normalize_export_member,
            cohort_evaluation_result_member.normalize_export_member,
        )

    def test_offline_evaluator_uses_extracted_result_export_normalizer(self):
        evaluator = load_cohort_evaluator()

        self.assertIs(
            evaluator.normalize_result_export,
            cohort_evaluation_result_export.normalize_result_export,
        )

    def test_skill_projection_rejects_extra_identity_fields(self):
        policy = cohort_execution_skills.SkillAttestationPolicy(
            skill_id_pattern=re.compile(r"[a-z-]+"),
            sha256_pattern=re.compile(r"[a-f0-9]{64}"),
            maximum_selected=4,
        )
        attestation = {
            "present": True,
            "legacy": False,
            "valid": True,
            "available": True,
            "job_digest_bound": True,
            "mandatory_ready": True,
            "error_count": 0,
            "errors": [],
            "registry_version": 1,
            "registry_sha256": "a" * 64,
            "selected": [
                {
                    "id": "zeek-review",
                    "version": 1,
                    "skill_sha256": "b" * 64,
                    "unbound": "not-allowed",
                }
            ],
            "selected_count": 1,
            "truncated": False,
            "advisory_mode": "advisory_only",
        }

        summary, valid = cohort_execution_skills.validate_skill_attestation(
            attestation, policy
        )

        self.assertFalse(valid)
        self.assertEqual(summary["selected"], [])


if __name__ == "__main__":
    unittest.main()
