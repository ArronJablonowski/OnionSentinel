"""Direct contracts for independent-review validation stages."""

from __future__ import annotations

from pathlib import Path
import re
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.analysis.conclusions import claim_evidence  # noqa: E402
from onion_sentinel.analysis.review import text, validation  # noqa: E402


class ReviewError(ValueError):
    pass


def dependencies(**overrides) -> validation.Dependencies:
    values = {
        "error_type": ReviewError,
        "evidence_hash": lambda _package: "hash-1",
        "taxonomy_catalog": lambda _package: [],
        "artifact_catalog": lambda _package: [],
        "rule_shorthand_catalog": lambda _package: [],
        "bounded_reference": lambda value: str(value or "")[:300],
        "response_strings": text.response_strings,
        "repetition_reasons": text.repetition_reasons,
        "ipv4_re": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        "domain_re": re.compile(r"\b[a-zA-Z0-9-]+\.[a-zA-Z]{2,}\b"),
        "community_id_re": re.compile(r"\b1:[A-Za-z0-9+/=]+\b"),
        "known_field_paths": frozenset(),
        "non_domain_suffixes": frozenset(),
        "required_keys": frozenset({"summary", "observables_used", "evidence_used", "hypotheses"}),
        "observable_max": 10,
        "evidence_used_max": 10,
        "hypotheses_max": 5,
    }
    values.update(overrides)
    return validation.Dependencies(**values)


def review_package() -> dict:
    return {
        "review_contract": {
            "case_id": "case-1",
            "evidence_hash": "hash-1",
            "allowed_observables": [{"kind": "ip", "value": "10.0.0.1"}],
            "allowed_non_domain_taxonomy_tokens": [],
            "allowed_non_domain_artifact_tokens": [],
            "allowed_non_domain_rule_shorthand_tokens": [],
        },
        "evidence_reference_contract": {
            "references": [{"ref": "current:alert", "corroborating": True}],
        },
    }


def response(**overrides) -> dict:
    value = {
        "review_case_id": "case-1",
        "review_evidence_hash": "hash-1",
        "summary": "Observed traffic from 10.0.0.1.",
        "observables_used": [],
        "evidence_used": ["current:alert"],
        "hypotheses": [],
    }
    value.update(overrides)
    return value


class ReviewValidationPackageTests(unittest.TestCase):
    def test_advertised_claim_graph_is_validated_before_reviewer_admission(self) -> None:
        package = review_package()
        package["response_schema"] = {"claim_evidence_graph": {}}
        candidate = response(claim_evidence_graph={
            "schema": claim_evidence.SCHEMA,
            "claims": [{
                "id": "unsupported-final", "claim_kind": "final_determination",
                "statement": "The event is malicious.", "material": True,
                "claim_scope": "activity_disposition", "report_fields": [],
                "certainty": "confirmed", "supporting_evidence_refs": [],
                "contradicting_evidence_refs": [],
                "decisive_missing_evidence": [], "supersedes_claim_id": None,
                "correction_reason": "",
            }],
        })
        graph_deps = claim_evidence.Dependencies(
            error_type=ReviewError,
            bounded_reference=lambda value: str(value or "")[:300],
        )

        with self.assertRaisesRegex(ReviewError, "has no evidence edge"):
            validation.validate(
                candidate,
                package,
                dependencies(validate_claim_graph=lambda value, current: (
                    claim_evidence.validate(
                        value.get("claim_evidence_graph"), value, current, graph_deps,
                    )
                )),
            )

    def test_derives_narrative_observable_and_records_audit(self) -> None:
        result = validation.validate(response(), review_package(), dependencies())
        self.assertEqual(
            result["observables_used"],
            [{"kind": "ip", "value": "10.0.0.1"}],
        )
        audit = result["_review_contract_validation"]
        self.assertTrue(audit["valid"])
        self.assertEqual(audit["observable_normalization"]["derived_count"], 1)
        self.assertEqual(audit["corroborating_evidence_count"], 1)

    def test_rejects_foreign_narrative_observable(self) -> None:
        with self.assertRaisesRegex(ReviewError, "foreign IP address"):
            validation.validate(
                response(summary="Observed traffic from 10.0.0.2."),
                review_package(),
                dependencies(),
            )

    def test_size_limit_fails_before_normalization(self) -> None:
        with self.assertRaisesRegex(ReviewError, "exceeds the maximum of 1"):
            validation.validate(
                response(observables_used=[
                    {"kind": "ip", "value": "10.0.0.1"},
                    {"kind": "ip", "value": "10.0.0.1"},
                ]),
                review_package(),
                dependencies(observable_max=1),
            )

    def test_missing_corroboration_fails_closed(self) -> None:
        package = review_package()
        package["evidence_reference_contract"]["references"][0]["corroborating"] = False
        with self.assertRaisesRegex(ReviewError, "no current corroborating"):
            validation.validate(response(), package, dependencies())

    def test_narrative_domains_admit_domains_and_dotted_hosts_case_insensitively(self) -> None:
        allowed = {
            ("domain", "Example.COM"),
            ("host", "Api.COM"),
            ("host", "bare-host"),
        }
        errors: list[str] = []

        narrative, admitted = validation._narrative_domains(
            "example.com and API.COM were observed",
            allowed,
            (set(), set(), set()),
            errors,
            dependencies(),
        )

        self.assertEqual(narrative, {"example.com", "api.com"})
        self.assertEqual(admitted, {"example.com", "api.com"})
        self.assertEqual(errors, [])

    def test_narrative_domains_exclude_each_non_domain_catalog(self) -> None:
        deps = dependencies(
            known_field_paths=frozenset({"alert.signature"}),
            non_domain_suffixes=frozenset({"local"}),
        )
        errors: list[str] = []

        narrative, allowed = validation._narrative_domains(
            "alert.signature taxonomy.token artifact.bin shorthand.rule host.local foreign.example",
            set(),
            ({"taxonomy.token"}, {"artifact.bin"}, {"shorthand.rule"}),
            errors,
            deps,
        )

        self.assertEqual(narrative, {"foreign.example"})
        self.assertEqual(allowed, set())
        self.assertEqual(
            errors,
            ["reviewer introduced foreign domain or FQDN value(s): foreign.example"],
        )

    def test_narrative_domains_sort_deduplicate_and_cap_foreign_error(self) -> None:
        candidates = " ".join(
            ["z.example", "a.example", "z.example"]
            + [f"d{index}.example" for index in range(12)]
        )
        errors: list[str] = []

        narrative, _ = validation._narrative_domains(
            candidates,
            set(),
            (set(), set(), set()),
            errors,
            dependencies(),
        )

        self.assertEqual(len(narrative), 14)
        self.assertEqual(
            errors,
            [
                "reviewer introduced foreign domain or FQDN value(s): "
                + ",".join(sorted(narrative)[:10])
            ],
        )

    def test_validation_audit_accounts_for_duplicates_discards_bare_and_derived(self) -> None:
        package = review_package()
        package["review_contract"]["allowed_observables"] = [
            {"kind": "ip", "value": "10.0.0.1"},
            {"kind": "ip", "value": "10.0.0.2"},
            {"kind": "user", "value": "analyst"},
        ]
        supplied = [
            {"kind": "ip", "value": "10.0.0.2"},
            {"kind": "ip", "value": "10.0.0.2"},
            {"kind": "user", "value": "analyst"},
        ]

        result = validation.validate(
            response(observables_used=supplied),
            package,
            dependencies(),
        )

        self.assertEqual(
            result["observables_used"],
            [
                {"kind": "ip", "value": "10.0.0.1"},
                {"kind": "user", "value": "analyst"},
            ],
        )
        audit = result["_review_contract_validation"]["observable_normalization"]
        self.assertEqual(audit["model_supplied_count"], 3)
        self.assertEqual(audit["canonical_model_supplied_count"], 2)
        self.assertEqual(audit["retained_model_supplied_count"], 1)
        self.assertEqual(audit["duplicate_count"], 1)
        self.assertEqual(audit["discarded_unused_bounded_count"], 1)
        self.assertEqual(audit["explicit_bare_model_observable_count"], 1)
        self.assertEqual(audit["derived_count"], 1)
        self.assertTrue(audit["normalization_applied"])
        self.assertEqual(supplied[0]["value"], "10.0.0.2")

    def test_validation_accumulates_stage_errors_in_public_order(self) -> None:
        package = review_package()
        invalid = response(
            review_case_id="wrong-case",
            review_evidence_hash="wrong-hash",
            summary="Observed traffic from 10.0.0.2.",
            observables_used="not-an-array",
            evidence_used="not-an-array",
            hypotheses="not-an-array",
        )

        with self.assertRaises(ReviewError) as raised:
            validation.validate(
                invalid,
                package,
                dependencies(repetition_reasons=lambda _response: ["repetition error"]),
            )

        self.assertEqual(
            str(raised.exception).split("; "),
            [
                "review_case_id did not echo the current case",
                "review_evidence_hash did not echo the current evidence",
                "observables_used must be an array",
                "reviewer introduced foreign IP address(es): 10.0.0.2",
                "evidence_used must be an array",
                "reviewer cited no current corroborating collector-owned evidence",
                "hypotheses must be an array",
                "repetition error",
            ],
        )


if __name__ == "__main__":
    unittest.main()
