#!/usr/bin/env python3
"""Direct contracts for bounded prior-analysis prompt context."""
from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))

from prompt_prior_analysis import (  # noqa: E402
    PriorAnalysisRequest,
    PriorAnalysisSources,
    build_prior_analysis_context,
)


def source_bundle(query=None, loader=None) -> PriorAnalysisSources:
    return PriorAnalysisSources(
        row_value=lambda row, key: row.get(key),
        query_rows=query or mock.Mock(return_value=[]),
        load_json_bounded=loader
        or (lambda path: json.loads(path.read_text(encoding="utf-8"))),
    )


def request(root: Path, **changes) -> PriorAnalysisRequest:
    values = {
        "connection": "connection",
        "analysis_dir": root,
        "selected": {"alert_id": "alert-1", "stable_group_id": "group-1"},
        "result_limit": 3,
        "legacy_scan_limit": 10,
    }
    values.update(changes)
    return PriorAnalysisRequest(**values)


class PromptPriorAnalysisTests(unittest.TestCase):
    def test_indexed_context_is_authoritative_and_skips_legacy_files(self):
        indexed = {
            "analysis_id": "analysis-1",
            "artifact_path": "/runtime/analysis-1.json",
            "generated_at": "2026-08-08T12:00:00Z",
            "model": "gpt-5.5",
            "model_path": "codex-cli",
            "detection_outcome": "true_positive_suspicious",
            "bluf": "Indexed conclusion",
            "summary": "Indexed summary",
            "confidence": "high",
        }
        query = mock.Mock(return_value=[indexed])
        loader = mock.Mock(side_effect=AssertionError("legacy path must not load"))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "z-local-ai-analysis.json").write_text("{}", encoding="utf-8")
            result = build_prior_analysis_context(
                source_bundle(query=query, loader=loader), request(root)
            )

        self.assertEqual(
            result,
            [
                {
                    "analysis_id": "analysis-1",
                    "artifact": "/runtime/analysis-1.json",
                    "generated_at": "2026-08-08T12:00:00Z",
                    "model": "gpt-5.5",
                    "model_path": "codex-cli",
                    "detection_outcome": "true_positive_suspicious",
                    "bluf": "Indexed conclusion",
                    "summary": "Indexed summary",
                    "confidence": "high",
                }
            ],
        )
        self.assertEqual(
            query.call_args.args[2],
            ["alert-1", "group-1", "group-1", 3],
        )
        self.assertIn("ORDER BY generated_at DESC", query.call_args.args[1])
        loader.assert_not_called()

    def test_missing_index_schema_falls_back_to_matching_legacy_artifact(self):
        query = mock.Mock(side_effect=sqlite3.OperationalError("missing table"))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "z-local-ai-analysis.json").write_text(
                json.dumps({"alert_id": "other-alert"}), encoding="utf-8"
            )
            matching = root / "y-local-ai-analysis.json"
            matching.write_text(
                json.dumps(
                    {
                        "alert_id": "alert-1",
                        "generated_at": "2026-08-08T12:00:00Z",
                        "analysis_model": "legacy-model",
                        "analysis": {
                            "detection_outcome": "false_positive",
                            "bluf": "Legacy conclusion",
                            "summary": "Legacy summary",
                            "confidence": "medium",
                            "tuning_recommendation": "Review rule threshold",
                        },
                    }
                ),
                encoding="utf-8",
            )
            result = build_prior_analysis_context(source_bundle(query=query), request(root))

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["artifact"], str(matching))
        self.assertEqual(result[0]["model"], "legacy-model")
        self.assertEqual(result[0]["detection_outcome"], "false_positive")
        self.assertEqual(result[0]["tuning_recommendation"], "Review rule threshold")

    def test_legacy_scan_limit_prevents_unbounded_corpus_reads(self):
        loader = mock.Mock(side_effect=lambda path: json.loads(path.read_text()))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("z", "y"):
                (root / f"{name}-local-ai-analysis.json").write_text(
                    json.dumps({"alert_id": "other-alert"}), encoding="utf-8"
                )
            (root / "x-local-ai-analysis.json").write_text(
                json.dumps({"alert_id": "alert-1", "bluf": "outside bound"}),
                encoding="utf-8",
            )
            result = build_prior_analysis_context(
                source_bundle(loader=loader),
                request(root, legacy_scan_limit=2),
            )

        self.assertEqual(result, [])
        self.assertEqual(loader.call_count, 2)

    def test_result_limit_stops_loading_after_first_matching_legacy_artifact(self):
        loader = mock.Mock(side_effect=lambda path: json.loads(path.read_text()))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("z", "y"):
                (root / f"{name}-local-ai-analysis.json").write_text(
                    json.dumps({"alert_id": "alert-1", "bluf": name}),
                    encoding="utf-8",
                )
            result = build_prior_analysis_context(
                source_bundle(loader=loader), request(root, result_limit=1)
            )

        self.assertEqual([item["bluf"] for item in result], ["z"])
        self.assertEqual(loader.call_count, 1)

    def test_invalid_legacy_artifact_is_skipped_within_scan_bound(self):
        loader = mock.Mock(
            side_effect=[ValueError("oversize artifact"), {"alert_id": "alert-1"}]
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("z", "y"):
                (root / f"{name}-local-ai-analysis.json").write_text(
                    "fixture", encoding="utf-8"
                )
            result = build_prior_analysis_context(source_bundle(loader=loader), request(root))

        self.assertEqual(len(result), 1)
        self.assertTrue(result[0]["artifact"].endswith("y-local-ai-analysis.json"))
        self.assertEqual(loader.call_count, 2)

    def test_missing_legacy_directory_returns_empty_context(self):
        query = mock.Mock(return_value=[])
        loader = mock.Mock(side_effect=AssertionError("missing directory must not scan"))
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing"
            result = build_prior_analysis_context(
                source_bundle(query=query, loader=loader), request(missing)
            )

        self.assertEqual(result, [])
        loader.assert_not_called()


if __name__ == "__main__":
    unittest.main()
