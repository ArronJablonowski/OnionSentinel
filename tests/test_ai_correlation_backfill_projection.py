"""Characterization for historical AI correlation artifact projection."""
from __future__ import annotations

import hashlib
import importlib.util
import inspect
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "n8n" / "bin" / "backfill-ai-correlation-context.py"


def load_module():
    spec = importlib.util.spec_from_file_location("correlation_backfill_projection", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class AiCorrelationBackfillProjectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()

    def test_surface_and_signature_are_exact(self) -> None:
        names = sorted(name for name in dir(self.module) if not name.startswith("__"))
        encoded = json.dumps(names, separators=(",", ":"), sort_keys=True).encode()
        self.assertEqual(
            (len(names), hashlib.sha256(encoded).hexdigest()),
            (24, "a2bad24058a87ca14dce22748b79cb374dcf02116655886a96c044fa37f05a24"),
        )
        self.assertEqual(
            str(inspect.signature(self.module.artifact_payload)),
            "(path: 'Path') -> 'dict[str, Any] | None'",
        )

    def test_projection_fallbacks_precedence_and_provenance_are_exact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prompt = root / "prompt.json"
            prompt.write_text(
                json.dumps(
                    {
                        "correlated_alert_context": {
                            "candidates": [{"group_id": "b" * 20, "score": 80}]
                        },
                        "private": "excluded",
                    }
                ),
                encoding="utf-8",
            )
            artifact = root / "example-local-ai-analysis.json"
            artifact.write_text(
                json.dumps(
                    {
                        "alert_id": " alert-1 ",
                        "generated_at": " 2026-08-12T01:02:03Z ",
                        "prompt_package": str(prompt),
                        "analysis_model": "artifact-model",
                        "analysis_type": "artifact-path",
                        "response": {
                            "summary": "synthetic",
                            "_analysis_model": "response-model",
                            "_analysis_model_path": "response-path",
                        },
                    }
                ),
                encoding="utf-8",
            )
            projected = self.module.artifact_payload(artifact)
            self.assertEqual(
                projected,
                {
                    "analysis_id": "9a5e0ba7b482751356e068c8",
                    "alert_id": "alert-1",
                    "generated_at": "2026-08-12T01:02:03Z",
                    "model": "response-model",
                    "model_path": "response-path",
                    "artifact_path": str(artifact),
                    "evidence_hash": "89fab15ad5e020d7c4b0724a51ea63a8be296d7493f0d2885ed5bfd916906d82",
                    "response": {
                        "summary": "synthetic",
                        "_analysis_model": "response-model",
                        "_analysis_model_path": "response-path",
                    },
                    "correlation_candidates": [{"group_id": "b" * 20, "score": 80}],
                },
            )

            explicit = json.loads(artifact.read_text(encoding="utf-8"))
            explicit["analysis_id"] = "explicit-id"
            explicit["response"] = {"summary": "synthetic"}
            artifact.write_text(json.dumps(explicit), encoding="utf-8")
            projected = self.module.artifact_payload(artifact)
            self.assertEqual(projected["analysis_id"], "explicit-id")
            self.assertEqual(projected["model"], "artifact-model")
            self.assertEqual(projected["model_path"], "artifact-path")

    def test_invalid_shapes_fail_closed_without_projection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid-local-ai-analysis.json"
            for value in (
                [],
                {},
                {"alert_id": "alert", "response": []},
                {"response": {"summary": "missing alert"}},
            ):
                with self.subTest(value=value):
                    path.write_text(json.dumps(value), encoding="utf-8")
                    self.assertIsNone(self.module.artifact_payload(path))


if __name__ == "__main__":
    unittest.main()
