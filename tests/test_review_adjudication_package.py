"""Direct contracts for bounded disagreement adjudication."""

from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.analysis.review import adjudication  # noqa: E402


class AdjudicationError(ValueError):
    pass


def build_package() -> dict:
    def blind(source, *, hosted=False):
        result = copy.deepcopy(source)
        result["second_opinion_review"] = {}
        result["review_contract"] = {}
        return result

    deps = adjudication.PackageDependencies(
        independent_package=blind,
        case_id=lambda _package: "case-1",
        model_safe_copy=lambda value, **_kwargs: copy.deepcopy(value),
    )
    return adjudication.build_package(
        {"evidence_reference_contract": {"references": [
            {"ref": "current:alert", "corroborating": True},
        ]}},
        {"bluf": "primary", "evidence_used": ["current:alert"]},
        {"bluf": "reviewer", "evidence_used": ["current:alert"]},
        {
            "primary": {"handling": "monitor"},
            "reviewer": {"handling": "investigate"},
            "disputed_fields": [{"field": "handling", "material": True}],
        },
        hosted=False,
        deps=deps,
    )


def response(package: dict, **overrides) -> dict:
    contract = package["adjudication_contract"]
    value = {
        "adjudication_case_id": contract["case_id"],
        "adjudication_evidence_hash": contract["evidence_hash"],
        "decision": "primary_supported",
        "confidence": "high",
        "confidence_score": 0.9,
        "resolved_fields": ["handling"],
        "remaining_disagreements": [],
        "evidence_used": ["current:alert"],
        "rationale": "Current evidence supports the primary position.",
        "additional_evidence_needed": [],
    }
    value.update(overrides)
    return value


class ReviewAdjudicationPackageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.deps = adjudication.ValidationDependencies(
            error_type=AdjudicationError,
            bounded_reference=lambda value: str(value or "")[:300],
        )

    def test_package_withholds_review_contract_and_binds_identity(self) -> None:
        package = build_package()
        self.assertNotIn("review_contract", package)
        self.assertNotIn("second_opinion_review", package)
        self.assertEqual(package["adjudication_contract"]["case_id"], "case-1")
        self.assertEqual(len(package["adjudication_contract"]["evidence_hash"]), 64)
        self.assertFalse(package["adjudication_contract"]["automation_authorized"])

    def test_supported_position_requires_and_accepts_corroboration(self) -> None:
        package = build_package()
        result = adjudication.validate(response(package), package, self.deps)
        self.assertEqual(result["decision"], "primary_supported")
        self.assertFalse(result["_adjudication_contract_validation"]["automation_authorized"])

    def test_disagreement_fields_must_form_closed_partition(self) -> None:
        package = build_package()
        with self.assertRaisesRegex(AdjudicationError, "partition every disagreement"):
            adjudication.validate(
                response(package, resolved_fields=[], remaining_disagreements=[]),
                package,
                self.deps,
            )

    def test_identity_and_choices_normalize_valid_closed_values(self) -> None:
        package = build_package()
        contract = package["adjudication_contract"]
        errors: list[str] = []

        decision, confidence, score = adjudication._identity_and_choices(
            response(
                package,
                decision="  REVIEWER_SUPPORTED  ",
                confidence="  Medium  ",
                confidence_score="1",
            ),
            contract,
            errors,
        )

        self.assertEqual(errors, [])
        self.assertEqual(decision, "reviewer_supported")
        self.assertEqual(confidence, "medium")
        self.assertEqual(score, 1.0)

    def test_identity_and_choices_preserve_error_order_and_score_sentinel(self) -> None:
        package = build_package()
        contract = package["adjudication_contract"]
        errors: list[str] = []

        result = adjudication._identity_and_choices(
            {
                "adjudication_case_id": "wrong-case",
                "adjudication_evidence_hash": "wrong-hash",
                "decision": "compromise",
                "confidence": "certain",
                "confidence_score": object(),
            },
            contract,
            errors,
        )

        self.assertEqual(result, ("compromise", "certain", -1.0))
        self.assertEqual(
            errors,
            [
                "adjudication_case_id does not match the contract",
                "adjudication_evidence_hash does not match the contract",
                "decision is outside the closed vocabulary",
                "confidence is outside the closed vocabulary",
                "confidence_score must be between 0 and 1",
            ],
        )

    def test_identity_and_choices_reject_non_finite_and_out_of_range_scores(self) -> None:
        package = build_package()
        contract = package["adjudication_contract"]

        for value in ("nan", "inf", "-inf", -0.001, 1.001):
            with self.subTest(value=value):
                errors: list[str] = []
                _, _, score = adjudication._identity_and_choices(
                    response(package, confidence_score=value),
                    contract,
                    errors,
                )
                self.assertEqual(
                    errors,
                    ["confidence_score must be between 0 and 1"],
                )
                self.assertEqual(str(score), str(float(value)))


if __name__ == "__main__":
    unittest.main()
