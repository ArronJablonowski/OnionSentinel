"""Characterize the policy-sensitive deterministic conclusion guard."""
from __future__ import annotations

import copy
import unittest
from unittest.mock import patch

from n8n.onion_sentinel.analysis.conclusions import authorization


def dependencies(
    trace: list[object],
    *,
    incident: bool,
    authorized: bool = False,
    endpoint: bool = False,
    endpoint_error: Exception | None = None,
) -> authorization.Dependencies:
    def is_incident(package):
        trace.append(("incident", package))
        return incident

    def has_authorization(package):
        trace.append(("authorization", package))
        return authorized

    def has_endpoint(package):
        trace.append(("endpoint", package))
        if endpoint_error is not None:
            raise endpoint_error
        return endpoint

    def derive(values):
        trace.append(("derive", values))
        return f"legacy:{values.get('activity_disposition')}:{values.get('handling')}"

    return authorization.Dependencies(
        is_incident_responder=is_incident,
        has_authorization_evidence=has_authorization,
        has_trusted_endpoint_evidence=has_endpoint,
        derive_legacy_outcome=derive,
        control_tuning_values=frozenset({"suppress", "drop"}),
        factored_verdict_keys=frozenset({"activity_disposition", "handling"}),
    )


class TrackingResponse(dict):
    def __init__(self, *args: object, trace: list[object], **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self.trace = trace

    def get(self, key: object, default: object = None) -> object:
        self.trace.append(("get", key, default))
        return super().get(key, default)

    def __setitem__(self, key: object, value: object) -> None:
        self.trace.append(("set", key, value))
        super().__setitem__(key, value)


class AuthorizationPolicySensitiveTests(unittest.TestCase):
    def test_non_incident_and_invalid_prompt_admission_order_are_exact(self) -> None:
        trace: list[object] = []
        response = TrackingResponse(
            {"activity_disposition": "benign"},
            trace=trace,
        )
        snapshot = dict(response)
        deps = dependencies(trace, incident=False)
        with patch.object(authorization, "_policy_class") as policy_class:
            result = authorization.apply_policy_sensitive(response, None, deps)
        self.assertIs(result, response)
        self.assertEqual(dict(response), snapshot)
        self.assertEqual(trace, [("incident", None)])
        policy_class.assert_not_called()

        trace.clear()
        deps = dependencies(trace, incident=True)
        with patch.object(authorization, "_policy_class") as policy_class:
            with self.assertRaises(AssertionError):
                authorization.apply_policy_sensitive(response, None, deps)
        self.assertEqual(trace, [("incident", None)])
        policy_class.assert_not_called()

    def test_policy_class_and_benign_admission_precede_evidence_dependencies(self) -> None:
        trace: list[object] = []
        prompt = {"alert": {"rule_name": "ordinary"}}
        response = TrackingResponse(
            {"activity_disposition": "benign"},
            trace=trace,
        )
        deps = dependencies(trace, incident=True)

        def classify(package):
            trace.append(("classify", package))
            return ""

        with patch.object(authorization, "_policy_class", classify):
            self.assertIs(
                authorization.apply_policy_sensitive(response, prompt, deps),
                response,
            )
        self.assertEqual(trace, [("incident", prompt), ("classify", prompt)])

        trace.clear()
        response["activity_disposition"] = "malicious"
        trace.clear()
        with patch.object(
            authorization,
            "_policy_class",
            side_effect=lambda package: trace.append(("classify", package)) or "discord",
        ):
            self.assertIs(
                authorization.apply_policy_sensitive(response, prompt, deps),
                response,
            )
        self.assertEqual(trace, [
            ("incident", prompt),
            ("classify", prompt),
            ("get", "activity_disposition", None),
        ])

    def test_authorized_path_still_checks_endpoint_and_writes_exact_audit(self) -> None:
        trace: list[object] = []
        prompt = {"alert": {"rule_name": "Discord application traffic"}}
        response = TrackingResponse(
            {"activity_disposition": "benign", "handling": "no_action"},
            trace=trace,
        )
        deps = dependencies(
            trace,
            incident=True,
            authorized=True,
            endpoint=False,
        )
        result = authorization.apply_policy_sensitive(response, prompt, deps)
        self.assertIs(result, response)
        self.assertEqual(trace[-3:-1], [
            ("authorization", prompt),
            ("endpoint", prompt),
        ])
        self.assertEqual(
            response["_policy_sensitive_activity_guard"],
            {
                "version": 1,
                "policy_class": "discord",
                "authorization_supported": True,
                "endpoint_attribution_supported": False,
                "override_applied": False,
            },
        )
        self.assertEqual(response["activity_disposition"], "benign")
        self.assertEqual(response["handling"], "no_action")

        trace.clear()
        failing = {"activity_disposition": "benign"}
        snapshot = copy.deepcopy(failing)
        with self.assertRaisesRegex(RuntimeError, "endpoint lookup failed"):
            authorization.apply_policy_sensitive(
                failing,
                prompt,
                dependencies(
                    trace,
                    incident=True,
                    authorized=True,
                    endpoint_error=RuntimeError("endpoint lookup failed"),
                ),
            )
        self.assertEqual(failing, snapshot)
        self.assertEqual(trace[-2:], [
            ("authorization", prompt),
            ("endpoint", prompt),
        ])

    def test_unsupported_mutation_order_and_endpoint_specific_gaps_are_exact(self) -> None:
        for endpoint, expected_disposition, expected_gap in (
            (
                False,
                "unknown",
                "Policy-sensitive application activity lacks trusted endpoint "
                "attribution and structured local authorization evidence; "
                "benign/no-action is not established.",
            ),
            (
                True,
                "benign",
                "Policy-sensitive application activity has endpoint attribution "
                "but no structured local authorization evidence; no-action is not established.",
            ),
        ):
            with self.subTest(endpoint=endpoint):
                trace: list[object] = []
                prompt = {"alert": {"rule_name": "Possible DNS over HTTPS"}}
                response = {
                    "detection_outcome": "informational_no_action",
                    "activity_disposition": "benign",
                    "handling": "no_action",
                    "tuning_recommendation": "suppress",
                    "recommended_tuning_actions": ["suppress it"],
                    "evidence_gaps": ["existing gap"],
                    "_verdict_validation": {"warnings": ["existing warning"]},
                }
                original_snapshot = authorization._verdict_snapshot
                original_downgrade = authorization._downgrade_tuning
                original_derive = authorization._derive_outcome
                original_gap = authorization._append_gap
                original_warning = authorization._append_warning

                def snapshot(actual):
                    trace.append(("snapshot", dict(actual)))
                    return original_snapshot(actual)

                def downgrade(actual, reason, deps):
                    trace.append(("downgrade", actual, reason, deps))
                    return original_downgrade(actual, reason, deps)

                def derive(actual, deps):
                    trace.append(("derive_helper", actual, deps))
                    return original_derive(actual, deps)

                def append_gap(actual, gap):
                    trace.append(("gap", actual, gap))
                    return original_gap(actual, gap)

                def append_warning(actual, warning):
                    trace.append(("warning", actual, warning))
                    return original_warning(actual, warning)

                deps = dependencies(
                    trace,
                    incident=True,
                    authorized=False,
                    endpoint=endpoint,
                )
                with (
                    patch.object(authorization, "_verdict_snapshot", snapshot),
                    patch.object(authorization, "_downgrade_tuning", downgrade),
                    patch.object(authorization, "_derive_outcome", derive),
                    patch.object(authorization, "_append_gap", append_gap),
                    patch.object(authorization, "_append_warning", append_warning),
                ):
                    result = authorization.apply_policy_sensitive(
                        response,
                        prompt,
                        deps,
                    )

                self.assertIs(result, response)
                helper_order = [item[0] for item in trace if item[0] in {
                    "snapshot", "downgrade", "derive_helper", "gap", "warning"
                }]
                self.assertEqual(helper_order, [
                    "snapshot", "downgrade", "derive_helper", "gap", "warning", "snapshot"
                ])
                self.assertEqual(response["activity_disposition"], expected_disposition)
                self.assertEqual(response["handling"], "monitor")
                self.assertEqual(response["tuning_recommendation"], "needs_more_data")
                self.assertEqual(response["recommended_tuning_actions"], [])
                self.assertEqual(response["evidence_gaps"], ["existing gap", expected_gap])
                self.assertEqual(
                    response["_verdict_validation"]["warnings"],
                    [
                        "existing warning",
                        "unsupported policy-sensitive benign/no_action claim was downgraded",
                    ],
                )
                audit = response["_policy_sensitive_activity_guard"]
                self.assertTrue(audit["override_applied"])
                self.assertEqual(audit["policy_class"], "dns over https")
                self.assertEqual(audit["endpoint_attribution_supported"], endpoint)
                self.assertEqual(audit["original_verdict"]["activity_disposition"], "benign")
                self.assertEqual(
                    audit["guarded_verdict"]["activity_disposition"],
                    expected_disposition,
                )


if __name__ == "__main__":
    unittest.main()
