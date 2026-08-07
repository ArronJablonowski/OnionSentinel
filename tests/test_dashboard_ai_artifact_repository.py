#!/usr/bin/env python3
"""Contracts for dashboard AI prompt/result artifact state."""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "onion-sentinel-dashboard" / "scripts"
MODULE_PATH = SCRIPTS / "dashboard_ai_artifact_repository.py"
BUILDER_PATH = SCRIPTS / "build_soc_alerts_dashboard.py"
INSTALLER_PATH = ROOT / "n8n" / "bin" / "install-macstudio-stack.zsh"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class DashboardAiArtifactRepositoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.repository = load_module("dashboard_ai_artifact_repository", MODULE_PATH)
        cls.builder = load_module("dashboard_ai_artifact_repository_test_builder", BUILDER_PATH)

    def config(self, root: Path):
        return self.repository.AiArtifactRepositoryConfig(
            analysis_dir=root / "analysis",
            prompt_dir=root / "prompts",
        )

    def test_analysis_index_uses_newest_valid_object_per_alert(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = self.config(root)
            config.analysis_dir.mkdir()
            old = config.analysis_dir / "old.json"
            new = config.analysis_dir / "new.json"
            malformed = config.analysis_dir / "malformed.json"
            non_object = config.analysis_dir / "list.json"
            old.write_text(json.dumps({"alert_id": "same", "model": "old"}), encoding="utf-8")
            new.write_text(json.dumps({"alert_id": "same", "model": "new"}), encoding="utf-8")
            malformed.write_text("{broken", encoding="utf-8")
            non_object.write_text("[]", encoding="utf-8")
            os.utime(old, (1, 1))
            os.utime(new, (2, 2))
            indexed = self.repository.index_ai_analysis_by_alert_id(config)
            newest_first = self.repository.load_ai_analysis_records(config, newest_first=True)

        self.assertEqual(indexed["same"]["model"], "new")
        self.assertEqual(indexed["same"]["_analysis_filename"], "new.json")
        self.assertEqual([record["model"] for record in newest_first], ["new", "old"])

    def test_prompt_index_supports_nested_and_legacy_alert_ids_with_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = self.config(root)
            config.prompt_dir.mkdir()
            nested = config.prompt_dir / "nested.json"
            legacy = config.prompt_dir / "legacy.json"
            nested.write_text(json.dumps({"alert": {"alert_id": "nested-id"}}), encoding="utf-8")
            legacy.write_text(json.dumps({"alert_id": "legacy-id"}), encoding="utf-8")
            indexed = self.repository.index_ai_prompts_by_alert_id(config)

        self.assertEqual(set(indexed), {"nested-id", "legacy-id"})
        self.assertEqual(indexed["nested-id"]["_prompt_filename"], "nested.json")
        self.assertGreaterEqual(indexed["nested-id"]["_prompt_mtime"], 0)
        self.assertTrue(indexed["legacy-id"]["_prompt_path"].endswith("legacy.json"))

    def test_process_correlation_requires_runner_marker_and_exact_prompt_path(self) -> None:
        prompts = {
            "running": {"_prompt_path": "/safe/prompts/running.json"},
            "idle": {"_prompt_path": "/safe/prompts/idle.json"},
            "missing": {},
        }
        commands = [
            "python run-local-ai-analysis.py --prompt-package /safe/prompts/running.json",
            "python unrelated.py /safe/prompts/idle.json",
        ]
        self.assertEqual(
            self.repository.running_prompt_alert_ids(
                prompts, commands, runner_marker="run-local-ai-analysis.py"
            ),
            {"running"},
        )
        self.assertEqual(
            self.repository.running_prompt_alert_ids(
                prompts, "not-a-list", runner_marker="run-local-ai-analysis.py"
            ),
            set(),
        )

    def test_process_inspection_is_bounded_and_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = self.config(Path(directory))
            prompts = {"a": {"_prompt_path": "/tmp/a.json"}}
            completed = SimpleNamespace(
                stdout="python run-local-ai-analysis.py --prompt-package /tmp/a.json\n"
            )
            with mock.patch.object(self.repository.subprocess, "run", return_value=completed) as run:
                self.assertEqual(
                    self.repository.inspect_running_prompt_alert_ids(config, prompts), {"a"}
                )
            self.assertEqual(run.call_args.kwargs["timeout"], 3.0)
            self.assertFalse(run.call_args.kwargs["check"])
            for error in (OSError("blocked"), subprocess.TimeoutExpired("ps", 3)):
                with mock.patch.object(self.repository.subprocess, "run", side_effect=error):
                    self.assertEqual(
                        self.repository.inspect_running_prompt_alert_ids(config, prompts), set()
                    )

    def test_missing_directories_are_read_only_and_empty(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = self.config(Path(directory))
            self.assertEqual(self.repository.index_ai_analysis_by_alert_id(config), {})
            self.assertEqual(self.repository.index_ai_prompts_by_alert_id(config), {})
            self.assertFalse(config.analysis_dir.exists())
            self.assertFalse(config.prompt_dir.exists())

    def test_builder_wrappers_honor_runtime_directory_overrides(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            analysis, prompts = root / "analysis", root / "prompts"
            analysis.mkdir()
            prompts.mkdir()
            (analysis / "result.json").write_text(
                json.dumps({"alert_id": "result-id"}), encoding="utf-8"
            )
            (prompts / "prompt.json").write_text(
                json.dumps({"alert_id": "prompt-id"}), encoding="utf-8"
            )
            with (
                mock.patch.object(self.builder, "AI_ANALYSIS_DIR", analysis),
                mock.patch.object(self.builder, "AI_PROMPT_DIR", prompts),
            ):
                results = self.builder.load_ai_analysis_by_alert_id()
                queued = self.builder.load_ai_prompts_by_alert_id()
        self.assertEqual(set(results), {"result-id"})
        self.assertEqual(set(queued), {"prompt-id"})

    def test_module_is_bounded_read_only_and_deployed(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertLessEqual(len(source.splitlines()), 160)
        for forbidden in ("sqlite3", "urllib", "mkdir(", "write_text("):
            self.assertNotIn(forbidden, source)
        installer = INSTALLER_PATH.read_text(encoding="utf-8")
        self.assertEqual(installer.count("dashboard_ai_artifact_repository.py"), 2)
        self.assertLess(
            installer.index("dashboard_report_repository.py"),
            installer.index("dashboard_ai_artifact_repository.py"),
        )
        self.assertLess(
            installer.index("dashboard_ai_artifact_repository.py"),
            installer.index("dashboard_alert_ai_workflow.py"),
        )


if __name__ == "__main__":
    unittest.main()
