#!/usr/bin/env python3
"""Regression tests for deterministic independent-review observables."""
from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from unittest import mock
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
BIN_DIR = REPO_ROOT / "n8n" / "bin"
RUNNER_PATH = BIN_DIR / "run-local-ai-analysis.py"


def load_runner():
    if str(BIN_DIR) not in sys.path:
        sys.path.insert(0, str(BIN_DIR))
    spec = importlib.util.spec_from_file_location(
        "run_local_ai_analysis_reviewer_observable_normalization",
        RUNNER_PATH,
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class ReviewerObservableNormalizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.runner = load_runner()

    def review_package(self, evidence: dict) -> dict:
        return self.runner.independent_reviewer_package(evidence)

    def response(
        self,
        review_package: dict,
        *,
        summary: str,
        observables_used: list[dict[str, str]] | None = None,
    ) -> dict:
        references = review_package["evidence_reference_contract"][
            "references"
        ]
        corroborating_ref = next(
            str(item["ref"])
            for item in references
            if item.get("corroborating") is True
        )
        return {
            **self.runner.DEFAULT_RESPONSE_VALUES,
            **self.runner.STRICT_RESPONSE_VALUES,
            "bluf": "Inconclusive: bounded evidence requires review.",
            "summary": summary,
            "likely_meaning": "The activity remains unconfirmed.",
            "severity_reasoning": "The supplied evidence is bounded.",
            "alert_frequency_assessment": "One synthetic case was reviewed.",
            "evidence_used": [corroborating_ref],
            "evidence_gaps": [],
            "review_case_id": review_package["review_contract"]["case_id"],
            "review_evidence_hash": review_package["review_contract"][
                "evidence_hash"
            ],
            "observables_used": list(observables_used or []),
        }

    def test_prefix_ip_is_not_mistaken_for_shorter_allowed_ip(self) -> None:
        review_package = self.review_package(
            {
                "alert": {
                    "alert_id": "prefix-ip-case",
                    "source_ip": "192.168.100.14",
                },
                "related_alerts": [
                    {"destination_ip": "192.168.100.1"},
                ],
            }
        )

        validated = self.runner.validate_reviewer_response(
            self.response(
                review_package,
                summary="The observed source was 192.168.100.14.",
            ),
            review_package,
        )

        self.assertEqual(
            validated["observables_used"],
            [{"kind": "ip", "value": "192.168.100.14"}],
        )
        normalization = validated["_review_contract_validation"][
            "observable_normalization"
        ]
        self.assertEqual(normalization["derived_count"], 1)
        self.assertNotIn(
            {"kind": "ip", "value": "192.168.100.1"},
            normalization["derived_observables"],
        )

    def test_exact_allowlisted_material_values_are_added_canonically(
        self,
    ) -> None:
        community_id = "1:gVOca2cr2eIKwoIKZ8QnLwW2gqU="
        review_package = self.review_package(
            {
                "alert": {
                    "alert_id": "canonical-observable-case",
                    "source_ip": "192.168.100.14",
                    "destination_ip": "192.168.100.1",
                    "domain": "allowed.example",
                    "host_name": "sensor.allowed.example",
                    "community_id": community_id,
                },
            }
        )

        validated = self.runner.validate_reviewer_response(
            self.response(
                review_package,
                summary=(
                    "The 192.168.100.14 connection to 192.168.100.1 used "
                    "allowed.example and sensor.allowed.example with Community "
                    f"ID {community_id}."
                ),
                observables_used=[
                    {"kind": "ip", "value": "192.168.100.14"},
                    {"kind": "ip", "value": "192.168.100.14"},
                ],
            ),
            review_package,
        )

        self.assertEqual(
            validated["observables_used"],
            [
                {"kind": "community_id", "value": community_id},
                {"kind": "domain", "value": "allowed.example"},
                {"kind": "host", "value": "sensor.allowed.example"},
                {"kind": "ip", "value": "192.168.100.1"},
                {"kind": "ip", "value": "192.168.100.14"},
            ],
        )
        normalization = validated["_review_contract_validation"][
            "observable_normalization"
        ]
        self.assertTrue(normalization["normalization_applied"])
        self.assertEqual(normalization["model_supplied_count"], 2)
        self.assertEqual(normalization["canonical_model_supplied_count"], 1)
        self.assertEqual(normalization["duplicate_count"], 1)
        self.assertEqual(normalization["derived_count"], 4)

    def test_typed_dataset_is_not_a_domain_but_foreign_domain_still_fails(
        self,
    ) -> None:
        review_package = self.review_package(
            {
                "alert": {
                    "alert_id": "dataset-token-case",
                    "event_dataset": "suricata.alert",
                },
                "detection_validation": {
                    "event": {"module": "zeek.notice"},
                },
            }
        )
        self.assertEqual(
            review_package["review_contract"][
                "allowed_non_domain_taxonomy_tokens"
            ],
            ["suricata.alert", "zeek.notice"],
        )

        validated = self.runner.validate_reviewer_response(
            self.response(
                review_package,
                summary=(
                    "The suricata.alert dataset and zeek.notice module were "
                    "reviewed."
                ),
            ),
            review_package,
        )
        self.assertEqual(validated["observables_used"], [])
        self.assertEqual(
            validated["_review_contract_validation"][
                "observable_normalization"
            ]["allowed_non_domain_taxonomy_count"],
            2,
        )

        with self.assertRaisesRegex(
            self.runner.ReviewerValidationError,
            r"foreign domain or FQDN value\(s\): foreign\.example",
        ):
            self.runner.validate_reviewer_response(
                self.response(
                    review_package,
                    summary=(
                        "The suricata.alert dataset allegedly contacted "
                        "foreign.example."
                    ),
                ),
                review_package,
            )

    def test_generic_type_value_pair_cannot_exempt_a_foreign_domain(
        self,
    ) -> None:
        review_package = self.review_package(
            {
                "alert": {"alert_id": "untrusted-taxonomy-shape"},
                "investigation_query_results": {
                    "results": [
                        {
                            "type": "dataset",
                            "value": "foreign.example",
                        }
                    ]
                },
            }
        )
        self.assertNotIn(
            "foreign.example",
            review_package["review_contract"][
                "allowed_non_domain_taxonomy_tokens"
            ],
        )

        with self.assertRaisesRegex(
            self.runner.ReviewerValidationError,
            r"foreign domain or FQDN value\(s\): foreign\.example",
        ):
            self.runner.validate_reviewer_response(
                self.response(
                    review_package,
                    summary="The dataset label was foreign.example.",
                ),
                review_package,
            )

    def test_taxonomy_contract_cannot_exempt_a_forged_domain(self) -> None:
        review_package = self.review_package(
            {
                "alert": {
                    "alert_id": "forged-taxonomy-contract",
                    "event_dataset": "suricata.alert",
                }
            }
        )
        review_package["review_contract"][
            "allowed_non_domain_taxonomy_tokens"
        ].append("foreign.example")

        with self.assertRaisesRegex(
            self.runner.ReviewerValidationError,
            "taxonomy catalog did not match collector-owned evidence",
        ):
            self.runner.validate_reviewer_response(
                self.response(
                    review_package,
                    summary="The dataset allegedly was foreign.example.",
                ),
                review_package,
            )

    def test_foreign_or_malformed_observables_remain_fail_closed(self) -> None:
        review_package = self.review_package(
            {
                "alert": {
                    "alert_id": "strict-observable-case",
                    "source_ip": "192.0.2.10",
                }
            }
        )
        for observables, expected in (
            (
                [{"kind": "ip", "value": "198.51.100.20"}],
                "reviewer used foreign observables",
            ),
            (
                [{"kind": "ip", "value": "192.0.2.10", "extra": True}],
                "malformed observable",
            ),
            (
                [{"kind": "ip", "value": 192}],
                "malformed observable",
            ),
        ):
            with self.subTest(observables=observables):
                with self.assertRaisesRegex(
                    self.runner.ReviewerValidationError,
                    expected,
                ):
                    self.runner.validate_reviewer_response(
                        self.response(
                            review_package,
                            summary="The source was 192.0.2.10.",
                            observables_used=observables,
                        ),
                        review_package,
                    )

    def test_unused_bounded_observable_is_removed_from_canonical_ledger(
        self,
    ) -> None:
        review_package = self.review_package(
            {
                "alert": {
                    "alert_id": "unused-observable-case",
                    "source_ip": "192.0.2.10",
                    "destination_ip": "192.0.2.20",
                    "user_name": "alice",
                }
            }
        )

        validated = self.runner.validate_reviewer_response(
            self.response(
                review_package,
                summary="The source was 192.0.2.10.",
                observables_used=[
                    {"kind": "ip", "value": "192.0.2.20"},
                    # Bare users and hosts have no unambiguous generic syntax,
                    # so exact allowlisted entries remain model-declared.
                    {"kind": "user", "value": "alice"},
                ],
            ),
            review_package,
        )

        self.assertEqual(
            validated["observables_used"],
            [
                {"kind": "ip", "value": "192.0.2.10"},
                {"kind": "user", "value": "alice"},
            ],
        )
        normalization = validated["_review_contract_validation"][
            "observable_normalization"
        ]
        self.assertEqual(normalization["discarded_unused_bounded_count"], 1)
        self.assertEqual(
            normalization["discarded_unused_bounded_observables"],
            [{"kind": "ip", "value": "192.0.2.20"}],
        )
        self.assertEqual(
            normalization["explicit_bare_model_observable_count"],
            1,
        )
        self.assertEqual(
            normalization["explicit_bare_model_observables"],
            [{"kind": "user", "value": "alice"}],
        )

    def test_evidence_package_mutation_invalidates_contract_hash(self) -> None:
        review_package = self.review_package(
            {
                "alert": {
                    "alert_id": "tampered-evidence-case",
                    "source_ip": "192.0.2.10",
                    "collector_note": "original",
                }
            }
        )
        response = self.response(
            review_package,
            summary="The source was 192.0.2.10.",
        )
        review_package["alert"]["collector_note"] = "tampered"

        with self.assertRaisesRegex(
            self.runner.ReviewerValidationError,
            "evidence hash did not match the current review package",
        ):
            self.runner.validate_reviewer_response(
                response,
                review_package,
            )

    def test_observable_contract_mutation_invalidates_contract_hash(self) -> None:
        review_package = self.review_package(
            {
                "alert": {
                    "alert_id": "tampered-observable-contract",
                    "source_ip": "192.0.2.10",
                }
            }
        )
        response = self.response(
            review_package,
            summary="The source was 192.0.2.10.",
        )
        review_package["review_contract"]["allowed_observables"].append(
            {"kind": "domain", "value": "foreign.example"}
        )

        with self.assertRaisesRegex(
            self.runner.ReviewerValidationError,
            "evidence hash did not match the current review package",
        ):
            self.runner.validate_reviewer_response(
                response,
                review_package,
            )

    def test_repair_guidance_does_not_change_bound_evidence_hash(self) -> None:
        review_package = self.review_package(
            {
                "alert": {
                    "alert_id": "repair-guidance-case",
                    "source_ip": "192.0.2.10",
                }
            }
        )
        original_hash = review_package["review_contract"]["evidence_hash"]
        review_package["review_contract_repair"] = {
            "attempt": 2,
            "guidance": ["Correct the observable ledger."],
        }

        self.assertEqual(
            self.runner.reviewer_evidence_hash(review_package),
            original_hash,
        )
        validated = self.runner.validate_reviewer_response(
            self.response(
                review_package,
                summary="The source was 192.0.2.10.",
            ),
            review_package,
        )
        self.assertTrue(
            validated["_review_contract_validation"]["valid"]
        )

    def test_second_opinion_contract_metadata_is_hash_bound(self) -> None:
        review_package = self.review_package(
            {
                "alert": {
                    "alert_id": "second-opinion-binding-case",
                    "source_ip": "192.0.2.10",
                }
            }
        )
        response = self.response(
            review_package,
            summary="The source was 192.0.2.10.",
        )
        review_package["second_opinion_review"][
            "primary_conclusion_withheld"
        ] = False

        with self.assertRaisesRegex(
            self.runner.ReviewerValidationError,
            "evidence hash did not match the current review package",
        ):
            self.runner.validate_reviewer_response(
                response,
                review_package,
            )

    def test_bare_user_in_ordinary_prose_is_not_auto_derived(self) -> None:
        review_package = self.review_package(
            {
                "alert": {
                    "alert_id": "ambiguous-bare-user-case",
                    "user_name": "root",
                }
            }
        )

        validated = self.runner.validate_reviewer_response(
            self.response(
                review_package,
                summary="The root cause remains unconfirmed.",
            ),
            review_package,
        )

        self.assertEqual(validated["observables_used"], [])
        normalization = validated["_review_contract_validation"][
            "observable_normalization"
        ]
        self.assertEqual(
            normalization["explicit_bare_model_observable_count"],
            0,
        )

    def test_hosted_review_contract_cannot_reintroduce_forbidden_evidence(
        self,
    ) -> None:
        hidden_ip = "203.0.113.77"
        private_case_id = "private-local-case-203.0.113.88"
        source = {
            "alert": {"alert_id": "hosted-privacy-case"},
            "raw_payload": f"sensitive source {hidden_ip}",
            "_local_investigation_query_context": {
                "case_id": private_case_id,
            },
        }

        review_package = self.runner.independent_reviewer_package(
            source,
            hosted=True,
        )
        transported = self.runner.model_safe_copy(
            review_package,
            hosted=True,
        )
        serialized = json.dumps(
            transported,
            sort_keys=True,
        )

        self.assertNotIn("raw_payload", transported)
        self.assertNotIn(hidden_ip, serialized)
        self.assertNotIn(private_case_id, serialized)
        self.assertEqual(
            transported["review_contract"]["case_id"],
            "hosted-privacy-case",
        )
        self.assertEqual(
            transported["second_opinion_review"]["evidence_boundary"],
            "hosted-redacted",
        )
        self.assertEqual(
            self.runner.reviewer_evidence_hash(transported),
            transported["review_contract"]["evidence_hash"],
        )

        local_package = self.runner.independent_reviewer_package(
            source,
            hosted=False,
        )
        self.assertIn("raw_payload", local_package)
        self.assertIn(
            {"kind": "ip", "value": hidden_ip},
            local_package["review_contract"]["allowed_observables"],
        )

    def test_ollama_route_preserves_bound_reviewer_metadata(self) -> None:
        settings = self.runner.default_ai_settings()
        settings["enabled_ollama_models"] = ["reviewer:latest"]
        review_package = self.runner.independent_reviewer_package(
            {"alert": {"alert_id": "ollama-bound-package"}},
            hosted=False,
        )
        args = type("Args", (), {})()

        with mock.patch.object(
            self.runner,
            "_ollama_chat_for_model",
            return_value={
                "summary": "Synthetic response",
                "_analysis_model": "reviewer:latest",
                "_analysis_model_path": "ollama",
                "_analysis_provider": "ollama",
            },
        ) as request:
            self.runner.analyze_model_route(
                "ollama:reviewer:latest",
                review_package,
                args,
                settings,
                independent_review=True,
            )

        sent = request.call_args.args[0]
        self.assertEqual(
            sent["second_opinion_review"],
            review_package["second_opinion_review"],
        )
        self.assertEqual(
            self.runner.reviewer_evidence_hash(sent),
            sent["review_contract"]["evidence_hash"],
        )


if __name__ == "__main__":
    unittest.main()
