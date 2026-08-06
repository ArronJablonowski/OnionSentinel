"""Direct contracts for reviewer identity binding and safe repair guidance."""
from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.analysis.review import contracts  # noqa: E402


def safe_copy(value, **_kwargs):
    if isinstance(value, dict):
        return {key: safe_copy(child) for key, child in value.items()}
    if isinstance(value, list):
        return [safe_copy(child) for child in value]
    return value


class ReviewContractsPackageTests(unittest.TestCase):
    def test_case_identity_prefers_local_then_incident_then_alert(self) -> None:
        package = {
            "_local_investigation_query_context": {"case_id": "local-case"},
            "incident_response_evidence": {"case_id": "incident-case"},
            "alert": {"alert_id": "alert-id"},
        }
        self.assertEqual(
            contracts.case_id(
                package, bounded_reference=lambda value: str(value or "")[:128],
                model_safe_copy=safe_copy,
            ),
            "local-case",
        )

    def test_fallback_case_identity_is_deterministic_and_nonempty(self) -> None:
        kwargs = {"bounded_reference": lambda _value: "", "model_safe_copy": safe_copy}
        first = contracts.case_id({"alert": {"rule": "test"}}, **kwargs)
        second = contracts.case_id({"alert": {"rule": "test"}}, **kwargs)
        self.assertEqual(first, second)
        self.assertRegex(first, r"^review-[a-f0-9]{32}$")

    def test_hash_excludes_repair_and_self_hash_but_binds_contract(self) -> None:
        package = {
            "alert": {"id": "a"},
            "review_contract": {"case_id": "case", "evidence_hash": "old"},
            "review_contract_repair": {"untrusted": "repair text"},
        }
        first = contracts.evidence_hash(package, model_safe_copy=safe_copy)
        package["review_contract"]["evidence_hash"] = "different"
        package["review_contract_repair"] = {"untrusted": "different repair"}
        self.assertEqual(first, contracts.evidence_hash(package, model_safe_copy=safe_copy))
        package["review_contract"]["case_id"] = "other-case"
        self.assertNotEqual(first, contracts.evidence_hash(package, model_safe_copy=safe_copy))

    def test_foreign_observable_repair_category_never_echoes_value(self) -> None:
        foreign = "203.0.113.99"
        category = contracts.repair_error_category(
            f"reviewer used foreign observables: ip:{foreign}", message_max=2000,
        )
        self.assertIn("outside review_contract.allowed_observables", category)
        self.assertNotIn(foreign, category)

    def test_failure_telemetry_contains_digests_not_model_output(self) -> None:
        response = {"summary": "sensitive rejected model output"}
        failure = contracts.validation_failure(
            attempt=2, call_id="review-call", error=ValueError("invalid"),
            input_value={"case": "a"}, response=response, schema="failure-v1",
            message_max=100, digest_json=lambda value: f"digest:{len(str(value))}",
        )
        self.assertNotIn("sensitive", str(failure))
        self.assertEqual(failure["attempt"], 2)
        self.assertIn("output_digest", failure)


if __name__ == "__main__":
    unittest.main()
