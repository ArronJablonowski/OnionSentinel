"""Direct contracts for frozen-evaluation reviewer precommit admission."""
from __future__ import annotations

from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.evaluation import reviewer_gate  # noqa: E402


class GateError(RuntimeError):
    pass


class ValidationError(ValueError):
    pass


POLICY = reviewer_gate.Policy(
    attestation_schema="review-validation-v1",
)


def settings(primary: str = "primary", reviewer: str = "reviewer") -> dict:
    return {
        "agent_models": {"soc-analyst": primary},
        "agent_second_opinion_models": {"soc-analyst": reviewer},
    }


def response(*, status="completed", attempts=1, failures=None, attestation=True) -> dict:
    reviewer = {"summary": "bounded review"}
    if attestation:
        reviewer["_review_contract_validation"] = {
            "schema": "review-validation-v1", "valid": True,
            "case_id": "case-1", "evidence_hash": "hash-1",
        }
    return {"_second_opinion": {
        "status": status, "attempts": attempts,
        "validation_failures": [] if failures is None else failures,
        "response": reviewer,
    }}


def dependencies(**overrides) -> reviewer_gate.Dependencies:
    values = {
        "route_identity": lambda route, _settings: route,
        "route_is_hosted": lambda route, _settings: route.startswith("hosted"),
        "build_review_package": lambda _package, **_kwargs: {
            "review_contract": {"case_id": "case-1", "evidence_hash": "hash-1"},
        },
        "validate_reviewer": lambda value, _package: value,
        "validate_response": lambda _value, _package: None,
        "validation_errors": (ValidationError,),
        "gate_error": GateError,
    }
    values.update(overrides)
    return reviewer_gate.Dependencies(**values)


class EvaluationReviewerGatePackageTests(unittest.TestCase):
    def enforce(self, result: dict, **kwargs):
        return reviewer_gate.enforce(
            {"case": "case-1"}, result,
            kwargs.pop("settings_value", settings()), "soc-analyst",
            trigger_reason=kwargs.pop("trigger_reason", "low confidence"),
            freeze_enabled=kwargs.pop("freeze_enabled", True),
            policy=POLICY, dependencies=kwargs.pop("deps", dependencies()),
        )

    def test_nonfrozen_or_untriggered_review_remains_advisory(self) -> None:
        result = response()
        build = mock.Mock(side_effect=AssertionError("must not build"))
        self.assertIs(
            self.enforce(result, freeze_enabled=False, deps=dependencies(
                build_review_package=build,
            )),
            result["_second_opinion"]["response"],
        )
        self.assertIs(
            self.enforce(result, trigger_reason="", deps=dependencies(
                build_review_package=build,
            )),
            result["_second_opinion"]["response"],
        )

    def test_same_route_does_not_create_an_independent_review_requirement(self) -> None:
        result = response()
        self.assertIs(
            self.enforce(result, settings_value=settings("same", "same")),
            result["_second_opinion"]["response"],
        )

    def test_missing_triggered_response_fails_closed_with_status(self) -> None:
        with self.assertRaisesRegex(GateError, "status=failed; error=timeout"):
            self.enforce({"_second_opinion": {"status": "failed", "error": "timeout"}})

    def test_attempt_history_is_strictly_one_repair_bounded(self) -> None:
        for attempts, failures in ((True, []), (0, []), (2, []), (3, ["a", "b"])):
            with self.subTest(attempts=attempts), self.assertRaisesRegex(
                GateError, "one-repair contract",
            ):
                self.enforce(response(attempts=attempts, failures=failures))

    def test_retained_response_is_revalidated_before_attestation(self) -> None:
        def reject(_value, _package):
            raise ValidationError("foreign observable")

        with self.assertRaisesRegex(GateError, "foreign observable"):
            self.enforce(response(), deps=dependencies(validate_reviewer=reject))

    def test_attestation_must_bind_current_case_and_evidence_hash(self) -> None:
        result = response()
        result["_second_opinion"]["response"]["_review_contract_validation"][
            "evidence_hash"
        ] = "foreign-hash"
        with self.assertRaisesRegex(GateError, "does not bind this case"):
            self.enforce(result)

    def test_valid_repaired_review_is_returned_by_identity(self) -> None:
        result = response(attempts=2, failures=[{"category": "repair"}])
        self.assertIs(self.enforce(result), result["_second_opinion"]["response"])

    def test_package_has_no_io_primitives(self) -> None:
        source = (ROOT / "n8n/onion_sentinel/evaluation/reviewer_gate.py").read_text()
        for primitive in ("subprocess", "urlopen(", "import requests", "open("):
            self.assertNotIn(primitive, source)


if __name__ == "__main__":
    unittest.main()
