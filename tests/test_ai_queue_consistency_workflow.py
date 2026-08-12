"""Characterization for AI queue-consistency workflow composition."""
from __future__ import annotations

import argparse
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import importlib.util
import inspect
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


def load_module():
    spec = importlib.util.spec_from_file_location(
        "ai_queue_consistency_workflow",
        SCRIPT_PATH,
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


queue_check = load_module()


class AiQueueConsistencyWorkflowTests(unittest.TestCase):
    def test_surface_and_main_signature_are_exact(self) -> None:
        names = sorted(
            name for name in dir(queue_check) if not name.startswith("__")
        )
        encoded = json.dumps(names, separators=(",", ":"), sort_keys=True).encode()
        self.assertEqual(
            (len(names), hashlib.sha256(encoded).hexdigest()),
            (21, "c0d6cfdf5e6ce1a3af0928a019d00b6abc9e2b92883c76b8411137ff2a6ab568"),
        )
        self.assertEqual(str(inspect.signature(queue_check.main)), "() -> 'int'")

    def test_missing_database_stderr_and_exit_are_exact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "missing.sqlite3"
            args = argparse.Namespace(
                db=missing,
                prompt_dir=Path(tmp) / "prompts",
                analysis_dir=Path(tmp) / "analysis",
                json=False,
                fail_on_issue=False,
                delete_resolved_prompts=False,
                delete_orphan_prompts=False,
            )
            stdout = io.StringIO()
            stderr = io.StringIO()
            with mock.patch.object(
                queue_check,
                "parse_args",
                return_value=args,
            ), mock.patch.object(
                queue_check.sqlite3,
                "connect",
            ) as connect, redirect_stdout(stdout), redirect_stderr(stderr):
                return_code = queue_check.main()

        self.assertEqual(return_code, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), f"ERROR db not found: {missing}\n")
        connect.assert_not_called()

    def run_representative(
        self,
        root: Path,
        *,
        json_mode: bool,
        fail_on_issue: bool,
    ) -> tuple[int, str, str, dict[str, object]]:
        database = root / "alerts.sqlite3"
        database.touch()
        prompt_dir = root / "prompts"
        analysis_dir = root / "analysis"
        prompt_dir.mkdir()
        analysis_dir.mkdir()
        resolved = prompt_dir / "resolved-ai-prompt.json"
        stale = prompt_dir / "stale-ai-prompt.json"
        orphan = prompt_dir / "orphan-ai-prompt.json"
        for path, mtime in ((resolved, 100), (stale, 150), (orphan, 160)):
            path.write_text("{}", encoding="utf-8")
            os.utime(path, (mtime, mtime))
        args = argparse.Namespace(
            db=database,
            prompt_dir=prompt_dir,
            analysis_dir=analysis_dir,
            json=json_mode,
            fail_on_issue=fail_on_issue,
            delete_resolved_prompts=False,
            delete_orphan_prompts=False,
        )
        state = {
            "quick_check": "ok",
            "alert_rows": 3,
            "alert_groups": 2,
            "summary_groups": 2,
            "bad_alert_filters": 0,
            "bad_summary_filters": 0,
            "orphan_summaries": 0,
            "missing_summaries": 0,
        }
        prompt_paths = {
            resolved: {"known-a"},
            stale: {"known-c"},
            orphan: {"missing"},
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
            return_value=(
                state,
                {"known-a": "group-1", "known-b": "group-1", "known-c": "group-2"},
                {"group-1": {"known-a", "known-b"}, "group-2": {"known-c"}},
            ),
        ), mock.patch.object(
            queue_check,
            "artifact_index",
            side_effect=[
                ({"known-b": 200.0}, {}),
                (
                    {"known-a": 100.0, "known-c": 150.0, "missing": 160.0},
                    prompt_paths,
                ),
            ],
        ), redirect_stdout(stdout), redirect_stderr(stderr):
            return_code = queue_check.main()
        expected = {
            "db": state,
            "artifacts": {
                "prompt_packages": 3,
                "analysis_alert_ids": 1,
                "stale_prompts": 1,
                "resolved_prompts": 1,
                "orphan_prompts": 1,
                "deleted_resolved_prompts": 0,
            },
            "stale_prompts": [
                {
                    "path": str(stale),
                    "alert_ids": ["known-c"],
                    "group_size": 1,
                    "prompt_mtime": 150.0,
                    "latest_group_analysis_mtime": 0,
                }
            ],
            "orphan_prompts": [str(orphan)],
            "deleted_resolved_prompts": [],
        }
        return return_code, stdout.getvalue(), stderr.getvalue(), expected

    def test_json_result_and_fail_on_issue_exit_are_exact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            return_code, stdout, stderr, expected = self.run_representative(
                Path(tmp),
                json_mode=True,
                fail_on_issue=True,
            )

        self.assertEqual(return_code, 1)
        self.assertEqual(stderr, "")
        self.assertEqual(json.loads(stdout), expected)
        self.assertEqual(
            stdout,
            json.dumps(expected, indent=2, sort_keys=True) + "\n",
        )

    def test_text_result_and_default_zero_exit_are_exact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            return_code, stdout, stderr, expected = self.run_representative(
                Path(tmp),
                json_mode=False,
                fail_on_issue=False,
            )

        stale = expected["stale_prompts"][0]
        orphan = expected["orphan_prompts"][0]
        self.assertEqual(return_code, 0)
        self.assertEqual(stderr, "")
        self.assertEqual(
            stdout,
            "quick_check: ok\n"
            "groups: alerts=2 summary=2 missing=0 orphan=0\n"
            "filters: bad_alert_filters=0 bad_summary_filters=0\n"
            "ai prompts: prompt_packages=3 stale=1 resolved=1 orphan=1\n"
            f"STALE {stale['path']} alert_ids=known-c\n"
            f"ORPHAN {orphan}\n",
        )


if __name__ == "__main__":
    unittest.main()
