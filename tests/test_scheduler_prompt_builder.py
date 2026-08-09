from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
BIN_DIR = REPO_ROOT / "n8n" / "bin"
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))

from scheduler_prompt_builder import (  # noqa: E402
    PromptBuilderDefaults,
    PromptBuilderSources,
    build_prompt_package,
)


class SchedulerPromptBuilderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="onion-sentinel-prompt-builder-"
        )
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.prompt_dir = self.root / "prompts"
        self.prompt_dir.mkdir()
        self.output = self.prompt_dir / "prompt.json"
        self.output.write_text("{}", encoding="utf-8")
        self.defaults = PromptBuilderDefaults(
            builder_path=self.root / "build-ai-investigation-prompt.py",
            python_executable="/usr/bin/python-test",
            database=self.root / "default-alerts.sqlite3",
            rollup_dir=self.root / "default-rollups",
            agent_memory_dir=self.root / "default-memory",
            shared_memory_file=self.root / "default-shared.md",
            pcap_analysis_dir=self.root / "default-pcap",
            prior_analysis_dir=self.root / "default-analysis",
            asset_inventory_file=self.root / "default-assets.json",
            detection_playbooks=self.root / "default-playbooks.json",
            investigation_skills=self.root / "default-skills.json",
            timeout_seconds=180,
            max_stdout_bytes=1024,
            max_stderr_bytes=2048,
        )
        self.process = SimpleNamespace(
            returncode=0,
            stdout=f"builder detail\n{self.output}\n",
            stderr="",
        )
        self.sources = PromptBuilderSources(
            initial_prompt_limit=mock.Mock(return_value=4096),
            role_prompt_file=lambda root, role: root / f"{role}-primary.md",
            role_second_opinion_prompt_file=(
                lambda root, role: root / f"{role}-review.md"
            ),
            role_memory_file=lambda root, role: root / f"{role}-memory.md",
            run_command=mock.Mock(return_value=self.process),
            emit_stderr=mock.Mock(),
        )
        self.args = SimpleNamespace(
            db=self.root / "alerts.sqlite3",
            prompt_dir=self.prompt_dir,
            rollup_dir=self.root / "rollups",
            related_limit=8,
            correlation_limit=12,
            correlation_min_score=20,
            ai_settings_file=self.root / "config" / "settings.json",
            agent_memory_dir=self.root / "memory",
            shared_memory_file=self.root / "shared.md",
            pcap_analysis_dir=self.root / "pcap",
            prior_analysis_dir=self.root / "prior-analysis",
            asset_inventory_file=self.root / "assets.json",
            detection_playbooks=self.root / "playbooks.json",
            investigation_skills=self.root / "skills.json",
            include_tests=True,
        )

    @staticmethod
    def value(command: list[str], flag: str) -> str:
        return command[command.index(flag) + 1]

    def build(
        self,
        *,
        payload: dict[str, object] | None = None,
        evidence: Path | None = None,
    ) -> Path:
        return build_prompt_package(
            self.defaults,
            self.sources,
            "alert-1",
            self.args,
            payload,
            evidence,
        )

    def test_command_projects_paths_limits_role_and_manual_flags(self) -> None:
        evidence = self.root / "incident-evidence.json"
        result = self.build(
            payload={
                "agent_role": "incident-responder",
                "related_limit": 999,
                "pcap_analysis_limit": -7,
                "manual_reanalysis": True,
            },
            evidence=evidence,
        )
        self.assertEqual(result, self.output)
        command = self.sources.run_command.call_args.args[0]
        self.assertEqual(command[:2], ["/usr/bin/python-test", str(self.defaults.builder_path)])
        expected = {
            "--db": self.args.db,
            "--out-dir": self.prompt_dir,
            "--rollup-dir": self.args.rollup_dir,
            "--related-limit": "500",
            "--correlation-limit": "12",
            "--correlation-min-score": "20",
            "--pcap-analysis-limit": "1",
            "--max-package-bytes": "4096",
            "--agent-role": "incident-responder",
            "--system-prompt-file": self.root / "config" / "incident-responder-primary.md",
            "--second-opinion-prompt-file": self.root / "config" / "incident-responder-review.md",
            "--agent-memory-file": self.root / "memory" / "incident-responder-memory.md",
            "--shared-memory-file": self.args.shared_memory_file,
            "--pcap-analysis-dir": self.args.pcap_analysis_dir,
            "--analysis-dir": self.args.prior_analysis_dir,
            "--asset-inventory-file": self.args.asset_inventory_file,
            "--detection-playbooks": self.args.detection_playbooks,
            "--investigation-skills": self.args.investigation_skills,
            "--incident-evidence-file": evidence,
        }
        for flag, expected_value in expected.items():
            with self.subTest(flag=flag):
                self.assertEqual(self.value(command, flag), str(expected_value))
        self.assertIn("--blind-reanalysis", command)
        self.assertIn("--include-tests", command)
        self.sources.initial_prompt_limit.assert_called_once_with(
            self.args, agent_role="incident-responder"
        )
        self.assertEqual(
            self.sources.run_command.call_args.kwargs,
            {
                "timeout_seconds": 180,
                "max_stdout_bytes": 1024,
                "max_stderr_bytes": 2048,
            },
        )

    def test_missing_optional_paths_use_defaults_and_default_role(self) -> None:
        args = SimpleNamespace(
            prompt_dir=self.prompt_dir,
            related_limit=9,
            correlation_limit=4,
            correlation_min_score=5,
            ai_settings_file=self.root / "settings.json",
            include_tests=False,
        )
        result = build_prompt_package(
            self.defaults, self.sources, "alert-2", args
        )
        self.assertEqual(result, self.output)
        command = self.sources.run_command.call_args.args[0]
        self.assertEqual(self.value(command, "--agent-role"), "soc-analyst")
        self.assertEqual(self.value(command, "--db"), str(self.defaults.database))
        self.assertEqual(
            self.value(command, "--investigation-skills"),
            str(self.defaults.investigation_skills),
        )
        self.assertNotIn("--blind-reanalysis", command)
        self.assertNotIn("--include-tests", command)

    def test_nonzero_builder_preserves_bounded_terminal_diagnostic(self) -> None:
        terminal = "x" * 900
        self.process.returncode = 7
        self.process.stderr = f"earlier detail\n{terminal}\n"
        with self.assertRaisesRegex(
            RuntimeError, r"prompt builder failed rc=7: " + ("x" * 700)
        ):
            self.build()
        self.sources.emit_stderr.assert_called_once_with(self.process.stderr)

    def test_output_must_exist_inside_directory_and_fit_limit(self) -> None:
        outside = self.root / "outside.json"
        outside.write_text("{}", encoding="utf-8")
        missing = self.prompt_dir / "missing.json"
        cases = (
            ("", "no output path"),
            (str(missing), "did not create"),
            (str(outside), "outside the configured"),
        )
        for stdout, message in cases:
            with self.subTest(message=message):
                self.process.stdout = stdout
                with self.assertRaisesRegex(RuntimeError, message):
                    self.build()

        self.process.stdout = str(self.output)
        self.output.write_bytes(b"x" * 4097)
        with self.assertRaisesRegex(RuntimeError, "exceeded the 4096-byte"):
            self.build()


if __name__ == "__main__":
    unittest.main()
