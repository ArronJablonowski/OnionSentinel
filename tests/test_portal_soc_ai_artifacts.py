"""Direct contracts for SOC AI artifact indexing."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_soc_ai_artifacts import (  # noqa: E402
    AiArtifactSources,
    build_ai_artifact_index,
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


if __name__ == "__main__":
    unittest.main()
