"""Regression coverage for queue-consistency prompt cleanup failures."""
from __future__ import annotations

import argparse
from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "n8n" / "bin" / "check-ai-queue-consistency.py"
DELETE_ERROR = "x" * 300
BOUNDED_DELETE_ERROR = "x" * 240


def load_module():
    spec = importlib.util.spec_from_file_location(
        "ai_queue_consistency_cleanup_errors",
        SCRIPT_PATH,
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


queue_check = load_module()


class AiQueueConsistencyCleanupErrorTests(unittest.TestCase):
    def run_cleanup_failure(
        self,
        root: Path,
        *,
        json_mode: bool,
    ) -> tuple[int, str, str, Path, Path]:
        database = root / "alerts.sqlite3"
        database.touch()
        prompt_dir = root / "prompts"
        analysis_dir = root / "analysis"
        prompt_dir.mkdir()
        analysis_dir.mkdir()
        resolved = prompt_dir / "resolved-ai-prompt.json"
        orphan = prompt_dir / "orphan-ai-prompt.json"
        resolved.write_text("{}", encoding="utf-8")
        orphan.write_text("{}", encoding="utf-8")
        os.utime(resolved, (100, 100))
        os.utime(orphan, (100, 100))
        args = argparse.Namespace(
            db=database,
            prompt_dir=prompt_dir,
            analysis_dir=analysis_dir,
            json=json_mode,
            fail_on_issue=True,
            delete_resolved_prompts=True,
            delete_orphan_prompts=True,
        )
        state = {
            "quick_check": "ok",
            "alert_rows": 1,
            "alert_groups": 1,
            "summary_groups": 1,
            "bad_alert_filters": 0,
            "bad_summary_filters": 0,
            "orphan_summaries": 0,
            "missing_summaries": 0,
        }
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.object(
            queue_check,
            "parse_args",
            return_value=args,
        ), mock.patch.object(
            queue_check,
            "db_state",
            return_value=(state, {"known-alert": "group-1"}, {"group-1": {"known-alert"}}),
        ), mock.patch.object(
            queue_check,
            "artifact_index",
            side_effect=[
                ({"known-alert": 200.0}, {}),
                (
                    {"known-alert": 100.0, "missing-alert": 100.0},
                    {
                        resolved: {"known-alert"},
                        orphan: {"missing-alert"},
                    },
                ),
            ],
        ), mock.patch.object(
            Path,
            "unlink",
            side_effect=OSError(DELETE_ERROR),
        ), redirect_stdout(stdout), redirect_stderr(stderr):
            return_code = queue_check.main()
        return return_code, stdout.getvalue(), stderr.getvalue(), resolved, orphan

    def test_text_mode_reports_bounded_resolved_and_orphan_delete_errors(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            return_code, stdout, stderr, resolved, orphan = self.run_cleanup_failure(
                Path(tmp),
                json_mode=False,
            )

        self.assertEqual(return_code, 1)
        self.assertEqual(stderr, "")
        self.assertIn(
            f"DELETE_ERROR {resolved} error={BOUNDED_DELETE_ERROR}\n",
            stdout,
        )
        self.assertIn(
            f"DELETE_ERROR {orphan} error={BOUNDED_DELETE_ERROR}\n",
            stdout,
        )
        self.assertNotIn(DELETE_ERROR, stdout)

    def test_json_mode_preserves_schema_and_bounds_cleanup_errors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            return_code, stdout, stderr, resolved, orphan = self.run_cleanup_failure(
                Path(tmp),
                json_mode=True,
            )

        self.assertEqual(return_code, 1)
        self.assertEqual(stderr, "")
        result = json.loads(stdout)
        self.assertEqual(
            result["stale_prompts"],
            [
                {"path": str(resolved), "delete_error": BOUNDED_DELETE_ERROR},
                {"path": str(orphan), "delete_error": BOUNDED_DELETE_ERROR},
            ],
        )
        self.assertEqual(result["orphan_prompts"], [str(orphan)])
        self.assertEqual(result["deleted_resolved_prompts"], [])
        self.assertEqual(
            result["artifacts"],
            {
                "prompt_packages": 2,
                "analysis_alert_ids": 1,
                "stale_prompts": 2,
                "resolved_prompts": 1,
                "orphan_prompts": 1,
                "deleted_resolved_prompts": 0,
            },
        )


if __name__ == "__main__":
    unittest.main()
