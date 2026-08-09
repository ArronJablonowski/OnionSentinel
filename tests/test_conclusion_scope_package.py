"""Direct contracts for selected-event and grouped-history dispositions."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.analysis.conclusions import scope  # noqa: E402


POLICY = scope.Policy(
    disposition_values=frozenset({
        "authorized_benign", "malicious", "suspicious", "unknown",
    }),
    handling_values=frozenset({
        "contain", "escalate", "investigate", "monitor", "no_action",
    }),
)
DEPENDENCIES = scope.Dependencies(
    bounded_text_list=lambda value, limit, item_limit: [
        str(item or "")[:item_limit]
        for item in (value if isinstance(value, list) else [])[:limit]
    ],
)


class ConclusionScopePackageTests(unittest.TestCase):
    def test_multi_observation_group_defaults_to_unresolved(self) -> None:
        response = {
            "activity_disposition": "authorized_benign",
            "handling": "no_action",
            "scope_dispositions": {
                "selected_event": {"evidence_basis": ["authorized tuple"]},
            },
        }
        result = scope.normalize(
            response,
            {"grouped_alert_context": {"total_observations": 560}},
            policy=POLICY,
            dependencies=DEPENDENCIES,
        )
        self.assertIs(result, response)
        self.assertEqual(result["scope_dispositions"], {
            "selected_event": {
                "activity_disposition": "authorized_benign",
                "handling": "no_action",
                "evidence_basis": ["authorized tuple"],
            },
            "group_history": {
                "activity_disposition": "unknown",
                "handling": "monitor",
                "evidence_basis": [],
            },
        })
        validation = result["_scope_disposition_validation"]
        self.assertEqual(validation["group_observation_count"], 560)
        self.assertFalse(validation["group_history_model_supplied"])
        self.assertTrue(validation["group_history_defaulted_to_unresolved"])
        self.assertEqual(validation["invalid_fields"], [])

    def test_single_observation_group_inherits_selected_verdict(self) -> None:
        response = {
            "activity_disposition": "suspicious",
            "handling": "investigate",
        }
        result = scope.normalize(
            response,
            {"grouped_alert_context": {"total_observations": "invalid"}},
            policy=POLICY,
            dependencies=DEPENDENCIES,
        )
        group = result["scope_dispositions"]["group_history"]
        self.assertEqual(group["activity_disposition"], "suspicious")
        self.assertEqual(group["handling"], "investigate")
        self.assertEqual(
            result["_scope_disposition_validation"]["group_observation_count"],
            1,
        )

    def test_invalid_supplied_group_is_audited_and_does_not_widen_scope(self) -> None:
        response = {
            "activity_disposition": "authorized_benign",
            "handling": "no_action",
            "scope_dispositions": {
                "group_history": {
                    "activity_disposition": "Definitely Evil",
                    "handling": "Destroy Everything",
                    "evidence_basis": ["x" * 1100] * 25,
                },
            },
        }
        result = scope.normalize(
            response,
            {"grouped_alert_context": {"total_observations": 3}},
            policy=POLICY,
            dependencies=DEPENDENCIES,
        )
        group = result["scope_dispositions"]["group_history"]
        self.assertEqual(group["activity_disposition"], "unknown")
        self.assertEqual(group["handling"], "monitor")
        self.assertEqual(len(group["evidence_basis"]), 20)
        self.assertTrue(all(len(item) == 1000 for item in group["evidence_basis"]))
        self.assertEqual(
            result["_scope_disposition_validation"]["invalid_fields"],
            [
                "scope_dispositions.group_history.activity_disposition",
                "scope_dispositions.group_history.handling",
            ],
        )
        self.assertTrue(
            result["_scope_disposition_validation"]
            ["group_history_model_supplied"]
        )


if __name__ == "__main__":
    unittest.main()
