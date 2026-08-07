"""Direct contracts for page-scoped SOC AI artifact correlation."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_soc_ai_artifact_context import (  # noqa: E402
    AiArtifactContextDependencies,
    compose_page_ai_artifact_context,
)


class SocAiArtifactContextTests(unittest.TestCase):
    def dependencies(self, members: list[tuple[str, str]] | None = None,
                     calls: list[list[str]] | None = None) -> AiArtifactContextDependencies:
        def group_members(group_keys: list[str]) -> list[tuple[str, str]]:
            if calls is not None:
                calls.append(group_keys)
            return members or []

        return AiArtifactContextDependencies(
            dashboard_group_id=lambda key: f"dashboard:{key}",
            group_members=group_members,
        )

    def test_representative_artifact_marks_group_and_projects_outcome(self) -> None:
        index = {
            "analysis_mtime_by_alert": {"alert-1": 10.0},
            "detection_outcome_by_alert": {"alert-1": "true_positive_suspicious"},
            "retained_index_field": {"value"},
        }
        result = compose_page_ai_artifact_context(
            [{"group_key": "group-a", "alert_id": "alert-1"}],
            index,
            self.dependencies(),
        )

        self.assertEqual(result["analysis_group_ids"], {"dashboard:group-a"})
        self.assertEqual(
            result["detection_outcome_by_group_id"],
            {"dashboard:group-a": "true_positive_suspicious"},
        )
        self.assertEqual(result["retained_index_field"], {"value"})

    def test_newest_member_artifact_overrides_representative_outcome(self) -> None:
        calls: list[list[str]] = []
        index = {
            "analysis_mtime_by_alert": {"representative": 4.0, "member": 8.0},
            "detection_outcome_by_alert": {
                "representative": "inconclusive",
                "member": "true_positive_benign",
            },
        }
        result = compose_page_ai_artifact_context(
            [{"group_key": "group-a", "representative_alert_id": "representative"}],
            index,
            self.dependencies([("group-a", "member")], calls),
        )

        self.assertEqual(calls, [["group-a"]])
        self.assertEqual(result["analysis_group_ids"], {"dashboard:group-a"})
        self.assertEqual(
            result["detection_outcome_by_group_id"],
            {"dashboard:group-a": "true_positive_benign"},
        )

    def test_malformed_index_is_empty_and_does_not_load_members(self) -> None:
        calls: list[list[str]] = []
        result = compose_page_ai_artifact_context(
            [{"group_key": "group-a", "alert_id": "alert-1"}],
            {"analysis_mtime_by_alert": "invalid"},
            self.dependencies(calls=calls),
        )

        self.assertEqual(calls, [])
        self.assertEqual(result["analysis_group_ids"], set())
        self.assertEqual(result["detection_outcome_by_group_id"], {})

    def test_malformed_timestamp_cannot_displace_newer_outcome(self) -> None:
        index = {
            "analysis_mtime_by_alert": {"representative": 5.0, "member": "invalid"},
            "detection_outcome_by_alert": {
                "representative": "inconclusive",
                "member": "false_positive",
            },
        }
        result = compose_page_ai_artifact_context(
            [{"group_key": "group-a", "alert_id": "representative"}],
            index,
            self.dependencies([("group-a", "member")]),
        )

        self.assertEqual(
            result["detection_outcome_by_group_id"],
            {"dashboard:group-a": "inconclusive"},
        )


if __name__ == "__main__":
    unittest.main()
