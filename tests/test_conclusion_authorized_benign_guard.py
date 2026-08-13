"""Characterization for the unsupported authorized-benign conclusion guard."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.analysis.conclusions import authorization


def dependencies(calls, *, incident=True, supported=False):
    return authorization.Dependencies(
        is_incident_responder=lambda package: calls.append(
            ("incident", package)
        ) or incident,
        has_authorization_evidence=lambda package: calls.append(
            ("authorization", package)
        ) or supported,
        has_trusted_endpoint_evidence=lambda package: calls.append(
            ("endpoint", package)
        ) or False,
        derive_legacy_outcome=lambda value: calls.append(
            ("derive", value)
        ) or "derived-outcome",
        control_tuning_values=frozenset({"suppress", "drop"}),
        factored_verdict_keys=frozenset(
            {"activity_disposition", "handling"}
        ),
    )


class ConclusionAuthorizedBenignGuardTests(unittest.TestCase):
    def test_non_ir_and_nonmatching_disposition_return_same_object(self) -> None:
        for incident, disposition, expected_calls in (
            (False, "authorized_benign", ["incident"]),
            (True, "benign", ["incident"]),
            (True, None, ["incident"]),
        ):
            calls = []
            response = {"activity_disposition": disposition, "sentinel": 1}
            before = dict(response)
            result = authorization.apply_authorized_benign(
                response,
                {"prompt": 1},
                dependencies(calls, incident=incident),
            )
            self.assertIs(result, response)
            self.assertEqual(response, before)
            self.assertEqual([call[0] for call in calls], expected_calls)

    def test_disposition_comparison_is_stripped_and_case_insensitive(self) -> None:
        calls = []
        response = {"activity_disposition": " Authorized_Benign "}
        authorization.apply_authorized_benign(
            response,
            {"prompt": 1},
            dependencies(calls, supported=True),
        )
        self.assertEqual(
            [call[0] for call in calls],
            ["incident", "authorization"],
        )
        self.assertEqual(response["activity_disposition"], " Authorized_Benign ")

    def test_supported_claim_adds_exact_nonoverride_audit_only(self) -> None:
        calls = []
        response = {
            "activity_disposition": "authorized_benign",
            "handling": "no_action",
            "tuning_recommendation": "suppress",
        }
        before = dict(response)
        result = authorization.apply_authorized_benign(
            response,
            {"prompt": 1},
            dependencies(calls, supported=True),
        )
        self.assertIs(result, response)
        self.assertEqual(
            {key: value for key, value in response.items() if key != "_authorization_evidence_guard"},
            before,
        )
        self.assertEqual(
            response["_authorization_evidence_guard"],
            {
                "version": 1,
                "authorization_supported": True,
                "override_applied": False,
                "required_sources": [
                    "approved_change",
                    "human_adjudication",
                    "operator_assertion",
                    "policy_exception",
                ],
            },
        )
        self.assertEqual([call[0] for call in calls], ["incident", "authorization"])

    def test_unsupported_claim_preserves_exact_helper_and_mutation_order(self) -> None:
        calls = []
        response = {
            "detection_outcome": "model-outcome",
            "activity_disposition": "authorized_benign",
            "handling": "no_action",
            "tuning_recommendation": "suppress",
            "evidence_gaps": ["existing-gap"],
            "_verdict_validation": {"warnings": ["existing-warning"]},
        }

        def snapshot(value):
            calls.append(("snapshot", dict(value)))
            return {"snapshot": len([c for c in calls if c[0] == "snapshot"])}

        with (
            mock.patch.object(authorization, "_verdict_snapshot", side_effect=snapshot),
            mock.patch.object(
                authorization,
                "_downgrade_tuning",
                side_effect=lambda value, reason, deps: calls.append(
                    ("downgrade", dict(value), reason, deps)
                ),
            ),
            mock.patch.object(
                authorization,
                "_derive_outcome",
                side_effect=lambda value, deps: calls.append(
                    ("derive_helper", dict(value), deps)
                ),
            ),
            mock.patch.object(
                authorization,
                "_append_gap",
                side_effect=lambda value, gap: calls.append(
                    ("gap", dict(value), gap)
                ),
            ),
            mock.patch.object(
                authorization,
                "_append_warning",
                side_effect=lambda value, warning: calls.append(
                    ("warning", dict(value), warning)
                ),
            ),
        ):
            result = authorization.apply_authorized_benign(
                response,
                {"prompt": 1},
                dependencies(calls),
            )

        self.assertIs(result, response)
        self.assertEqual(
            [call[0] for call in calls],
            [
                "incident",
                "authorization",
                "snapshot",
                "downgrade",
                "derive_helper",
                "gap",
                "warning",
                "snapshot",
            ],
        )
        self.assertEqual(response["activity_disposition"], "benign")
        self.assertEqual(response["handling"], "monitor")
        self.assertEqual(
            response["_authorization_evidence_guard"],
            {
                "version": 1,
                "authorization_supported": False,
                "override_applied": True,
                "required_sources": [
                    "approved_change",
                    "human_adjudication",
                    "operator_assertion",
                    "policy_exception",
                ],
                "original_verdict": {"snapshot": 1},
                "guarded_verdict": {"snapshot": 2},
            },
        )
        self.assertIn("no structured operator authorization evidence", calls[3][2])
        self.assertIn("No structured operator authorization evidence", calls[5][2])
        self.assertEqual(
            calls[6][2],
            "unsupported authorized_benign claim was downgraded to benign/monitor",
        )

    def test_real_helpers_preserve_original_and_guarded_verdicts(self) -> None:
        calls = []
        response = {
            "detection_outcome": "true_positive_authorized_benign",
            "activity_disposition": "authorized_benign",
            "handling": "no_action",
            "tuning_recommendation": "drop",
            "recommended_tuning_actions": ["drop"],
        }
        authorization.apply_authorized_benign(
            response,
            {"prompt": 1},
            dependencies(calls),
        )
        audit = response["_authorization_evidence_guard"]
        self.assertEqual(audit["original_verdict"]["activity_disposition"], "authorized_benign")
        self.assertEqual(audit["original_verdict"]["handling"], "no_action")
        self.assertEqual(audit["guarded_verdict"]["activity_disposition"], "benign")
        self.assertEqual(audit["guarded_verdict"]["handling"], "monitor")
        self.assertEqual(response["tuning_recommendation"], "needs_more_data")
        self.assertEqual(response["recommended_tuning_actions"], [])
        self.assertEqual(response["detection_outcome"], "derived-outcome")

    def test_dependency_exceptions_propagate_without_guard_synthesis(self) -> None:
        response = {"activity_disposition": "authorized_benign"}
        deps = authorization.Dependencies(
            is_incident_responder=lambda _package: True,
            has_authorization_evidence=lambda _package: (_ for _ in ()).throw(
                RuntimeError("authorization failure")
            ),
            has_trusted_endpoint_evidence=lambda _package: False,
            derive_legacy_outcome=lambda _value: "unused",
            control_tuning_values=frozenset(),
            factored_verdict_keys=frozenset(),
        )
        with self.assertRaisesRegex(RuntimeError, "authorization failure"):
            authorization.apply_authorized_benign(response, {}, deps)
        self.assertNotIn("_authorization_evidence_guard", response)


if __name__ == "__main__":
    unittest.main()
