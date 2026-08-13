"""Direct contracts for independent-review validation stages."""

from __future__ import annotations

from pathlib import Path
import re
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
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


if __name__ == "__main__":
    unittest.main()
