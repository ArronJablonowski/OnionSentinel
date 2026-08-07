"""Direct contracts for SOC AI artifact indexing."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_soc_ai_artifacts import (  # noqa: E402
    AiArtifactSources,
    AiGroupArtifactDependencies,
    build_ai_artifact_index,
    group_has_analysis_artifact,
    latest_analysis_mtime,
    latest_prompt_mtime,
)


class SocAiArtifactTests(unittest.TestCase):
    def sources(self, prompts: dict[str, object], analyses: dict[str, object],
                mtimes: dict[str, object]) -> AiArtifactSources:
        records = {**prompts, **analyses}

        def read(path: Path) -> object:
            value = records[str(path)]
            if isinstance(value, Exception):
                raise value
            return value

        def modified(path: Path) -> float:
            value = mtimes[str(path)]
            if isinstance(value, Exception):
                raise value
            return float(value)

        return AiArtifactSources(
            prompt_paths=lambda: [Path(name) for name in prompts],
            analysis_paths=lambda: [Path(name) for name in analyses],
            read_record=read,
            modified_time=modified,
        )

    def test_prompt_index_accepts_nested_and_top_level_identity(self) -> None:
        sources = self.sources(
            {
                "old.json": {"alert": {"alert_id": "alert-a"}},
                "new.json": {"alert_id": "alert-a"},
            },
            {},
            {"old.json": 2, "new.json": 5},
        )

        result = build_ai_artifact_index(sources, include_prompts=True)

        self.assertEqual(result["prompt_mtime_by_alert"], {"alert-a": 5.0})

    def test_newest_analysis_selects_response_or_top_level_outcome(self) -> None:
        sources = self.sources(
            {},
            {
                "old.json": {"alert_id": "alert-a", "detection_outcome": "inconclusive"},
                "new.json": {
                    "alert_id": "alert-a",
                    "response": {"detection_outcome": "true_positive_suspicious"},
                },
            },
            {"old.json": 2, "new.json": 5},
        )

        result = build_ai_artifact_index(sources, include_prompts=True)

        self.assertEqual(result["analysis_mtime_by_alert"], {"alert-a": 5.0})
        self.assertEqual(
            result["detection_outcome_by_alert"],
            {"alert-a": "true_positive_suspicious"},
        )

    def test_newer_analysis_without_outcome_preserves_last_known_outcome(self) -> None:
        sources = self.sources(
            {},
            {
                "old.json": {"alert_id": "alert-a", "detection_outcome": "inconclusive"},
                "new.json": {"alert_id": "alert-a"},
            },
            {"old.json": 2, "new.json": 5},
        )

        result = build_ai_artifact_index(sources, include_prompts=True)

        self.assertEqual(result["analysis_mtime_by_alert"], {"alert-a": 5.0})
        self.assertEqual(result["detection_outcome_by_alert"], {"alert-a": "inconclusive"})

    def test_disabled_prompts_and_malformed_artifacts_degrade_safely(self) -> None:
        sources = self.sources(
            {"prompt.json": {"alert_id": "ignored"}},
            {
                "broken.json": ValueError("broken"),
                "missing-stat.json": {"alert_id": "alert-a"},
            },
            {
                "prompt.json": 3,
                "broken.json": 1,
                "missing-stat.json": OSError("missing"),
            },
        )

        result = build_ai_artifact_index(sources, include_prompts=False)

        self.assertEqual(result["prompt_mtime_by_alert"], {})
        self.assertEqual(result["analysis_mtime_by_alert"], {})
        self.assertEqual(result["detection_outcome_by_alert"], {})

    def test_single_alert_lookup_selects_newest_matching_artifact(self) -> None:
        sources = self.sources(
            {
                "old-prompt.json": {"alert": {"alert_id": "alert-a"}},
                "new-prompt.json": {"alert_id": "alert-a"},
                "other-prompt.json": {"alert_id": "alert-b"},
            },
            {
                "old-analysis.json": {"alert_id": "alert-a"},
                "new-analysis.json": {"alert_id": "alert-a"},
            },
            {
                "old-prompt.json": 2,
                "new-prompt.json": 7,
                "other-prompt.json": 9,
                "old-analysis.json": 3,
                "new-analysis.json": 8,
            },
        )

        self.assertEqual(latest_prompt_mtime("alert-a", sources), 7.0)
        self.assertEqual(latest_analysis_mtime("alert-a", sources), 8.0)
        self.assertEqual(latest_analysis_mtime("missing", sources), 0.0)
        self.assertEqual(latest_prompt_mtime("", sources), 0.0)

    def test_single_alert_lookup_ignores_unreadable_and_unstatable_matches(self) -> None:
        sources = self.sources(
            {
                "broken-prompt.json": ValueError("broken"),
                "missing-stat-prompt.json": {"alert_id": "alert-a"},
            },
            {"missing-stat-analysis.json": {"alert_id": "alert-a"}},
            {
                "broken-prompt.json": 3,
                "missing-stat-prompt.json": OSError("missing"),
                "missing-stat-analysis.json": OSError("missing"),
            },
        )

        self.assertEqual(latest_prompt_mtime("alert-a", sources), 0.0)
        self.assertEqual(latest_analysis_mtime("alert-a", sources), 0.0)

    def test_group_lookup_checks_representative_and_all_members(self) -> None:
        checked: list[str] = []

        def latest(alert_id: str) -> float:
            checked.append(alert_id)
            return 4.0 if alert_id == "member-with-analysis" else 0.0

        dependencies = AiGroupArtifactDependencies(
            group_members=lambda group_key: (
                ["member-without-analysis", "member-with-analysis"]
                if group_key == "group-a" else []
            ),
            latest_analysis_mtime=latest,
        )

        self.assertTrue(group_has_analysis_artifact(
            {"group_key": "group-a", "alert_id": "representative"},
            dependencies,
        ))
        self.assertEqual(
            checked,
            ["representative", "member-without-analysis", "member-with-analysis"],
        )

    def test_group_lookup_handles_representative_only_and_empty_rows(self) -> None:
        dependencies = AiGroupArtifactDependencies(
            group_members=lambda _group_key: [],
            latest_analysis_mtime=lambda alert_id: 1.0 if alert_id == "representative" else 0.0,
        )

        self.assertTrue(group_has_analysis_artifact(
            {"alert_id": "representative"}, dependencies,
        ))
        self.assertFalse(group_has_analysis_artifact({}, dependencies))


if __name__ == "__main__":
    unittest.main()
