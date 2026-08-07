from __future__ import annotations

import copy
import unittest

from n8n.onion_sentinel.analysis.query import prompt_admission


class QueryPromptAdmissionPackageTests(unittest.TestCase):
    class ContractError(ValueError):
        pass

    def dependencies(self, projection, *, model_safe_copy=None):
        def attach(candidate):
            candidate["evidence_reference_contract"] = {
                "projection_stage": candidate["investigation_query_results"]["stage"]
            }

        return prompt_admission.Dependencies(
            projection=projection,
            attach_contract=attach,
            synchronize_hosted=lambda candidate: candidate.update(hosted_ready=True),
            model_safe_copy=model_safe_copy or (lambda value, _hosted: copy.deepcopy(value)),
        )

    def test_invalid_or_projectionless_budget_does_not_mutate_package(self) -> None:
        original = {
            "base": "trusted",
            "investigation_query_results": {"old": True},
            "evidence_reference_contract": {"old": True},
        }
        for invalid in (True, 0, -1, "100"):
            package = copy.deepcopy(original)
            with self.subTest(invalid=invalid):
                with self.assertRaises(self.ContractError):
                    prompt_admission.admit(
                        package,
                        [],
                        maximum_prompt_bytes=invalid,
                        hosted=False,
                        policy=prompt_admission.Policy(maximum_evidence_bytes=200),
                        dependencies=self.dependencies(lambda _rounds, _budget: {}),
                        error_type=self.ContractError,
                    )
                self.assertEqual(package, original)

        def unavailable(_rounds, _budget):
            raise self.ContractError("below complete provenance floor")

        package = copy.deepcopy(original)
        with self.assertRaisesRegex(self.ContractError, "no safe prompt budget"):
            prompt_admission.admit(
                package,
                [],
                maximum_prompt_bytes=200,
                hosted=False,
                policy=prompt_admission.Policy(maximum_evidence_bytes=200),
                dependencies=self.dependencies(unavailable),
                error_type=self.ContractError,
            )
        self.assertEqual(package, original)

    def test_richest_complete_state_that_fits_is_committed_atomically(self) -> None:
        def projection(_rounds, budget):
            if budget < 50:
                raise self.ContractError("below floor")
            if budget < 100:
                return {
                    "stage": "compact",
                    "payload": "c" * 20,
                    "prompt_projection": {"max_bytes": budget, "encoded_bytes": 1},
                }
            return {
                "stage": "rich",
                "payload": "r" * 1_000,
                "prompt_projection": {"max_bytes": budget, "encoded_bytes": 2},
            }

        package = {
            "base": "trusted",
            "investigation_query_results": {"stale": True},
            "evidence_reference_contract": {"stale": True},
        }
        size = prompt_admission.admit(
            package,
            [{"round": 1}],
            maximum_prompt_bytes=300,
            hosted=False,
            policy=prompt_admission.Policy(maximum_evidence_bytes=200),
            dependencies=self.dependencies(projection),
            error_type=self.ContractError,
        )
        self.assertEqual(package["investigation_query_results"]["stage"], "compact")
        self.assertEqual(
            package["evidence_reference_contract"]["projection_stage"], "compact"
        )
        self.assertLessEqual(size, 300)
        self.assertNotIn("stale", str(package))

    def test_final_size_drift_fails_without_committing_candidate(self) -> None:
        calls = 0

        def safe_copy(value, _hosted):
            nonlocal calls
            calls += 1
            copied = copy.deepcopy(value)
            if calls > 1:
                copied["drift"] = "changed-after-measurement"
            return copied

        package = {"base": "trusted"}
        original = copy.deepcopy(package)
        with self.assertRaisesRegex(self.ContractError, "changed after admission"):
            prompt_admission.admit(
                package,
                [],
                maximum_prompt_bytes=500,
                hosted=False,
                policy=prompt_admission.Policy(maximum_evidence_bytes=100),
                dependencies=self.dependencies(
                    lambda _rounds, budget: {
                        "stage": "only",
                        "prompt_projection": {"max_bytes": budget, "encoded_bytes": 1},
                    },
                    model_safe_copy=safe_copy,
                ),
                error_type=self.ContractError,
            )
        self.assertEqual(package, original)


if __name__ == "__main__":
    unittest.main()
