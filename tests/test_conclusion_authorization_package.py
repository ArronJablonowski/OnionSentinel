"""Direct contracts for authorization-sensitive conclusion guards."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.analysis.conclusions import authorization  # noqa: E402


def dependencies(*, authorized=False, endpoint=False) -> authorization.Dependencies:
    return authorization.Dependencies(
        is_incident_responder=lambda package: bool(package and package.get("ir")),
        has_authorization_evidence=lambda _package: authorized,
        has_trusted_endpoint_evidence=lambda _package: endpoint,
        derive_legacy_outcome=lambda value: f"legacy:{value.get('activity_disposition')}",
        control_tuning_values=frozenset({"suppress", "drop"}),
        factored_verdict_keys=frozenset({"activity_disposition"}),
    )


class ConclusionAuthorizationPackageTests(unittest.TestCase):
    def test_unsupported_authorized_benign_downgrades_controls(self) -> None:
        response = {
            "activity_disposition": "authorized_benign", "handling": "no_action",
            "tuning_recommendation": "suppress", "evidence_gaps": [],
        }
        result = authorization.apply_authorized_benign(
            response, {"ir": True}, dependencies()
        )
        self.assertEqual(result["activity_disposition"], "benign")
        self.assertEqual(result["handling"], "monitor")
        self.assertEqual(result["tuning_recommendation"], "needs_more_data")
        self.assertTrue(result["_authorization_evidence_guard"]["override_applied"])

    def test_structured_authorization_preserves_claim(self) -> None:
        response = {"activity_disposition": "authorized_benign"}
        result = authorization.apply_authorized_benign(
            response, {"ir": True}, dependencies(authorized=True)
        )
        self.assertEqual(result["activity_disposition"], "authorized_benign")
        self.assertFalse(result["_authorization_evidence_guard"]["override_applied"])

    def test_unattributed_policy_sensitive_activity_stays_unknown(self) -> None:
        response = {"activity_disposition": "benign", "handling": "no_action"}
        result = authorization.apply_policy_sensitive(
            response,
            {"ir": True, "alert": {"rule_name": "Possible DNS over HTTPS"}},
            dependencies(),
        )
        self.assertEqual(result["activity_disposition"], "unknown")
        self.assertEqual(result["handling"], "monitor")

    def test_non_policy_rule_is_unchanged(self) -> None:
        response = {"activity_disposition": "benign", "handling": "no_action"}
        result = authorization.apply_policy_sensitive(
            response, {"ir": True, "alert": {"rule_name": "APT traffic"}},
            dependencies(),
        )
        self.assertIs(result, response)
        self.assertNotIn("_policy_sensitive_activity_guard", result)


if __name__ == "__main__":
    unittest.main()
