#!/usr/bin/env python3
"""Direct contracts for the prompt-builder command line."""
from __future__ import annotations

from pathlib import Path
import contextlib
import io
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))

from prompt_builder_cli import (  # noqa: E402
    PromptBuilderCliDefaults,
    PromptBuilderCliSources,
    parse_prompt_builder_args,
)


class PromptBuilderCliTests(unittest.TestCase):
    def setUp(self) -> None:
        root = Path("/runtime")
        self.defaults = PromptBuilderCliDefaults(
            db=root / "alerts.sqlite3",
            rollup_dir=root / "rollups",
            out_dir=root / "prompts",
            system_prompt_file=root / "config" / "soc.md",
            second_opinion_prompt_file=root / "config" / "soc-review.md",
            agent_memory_dir=root / "memory",
            agent_memory_file=root / "memory" / "soc.md",
            shared_memory_file=root / "memory" / "shared.md",
            pcap_analysis_dir=root / "pcap",
            analysis_dir=root / "analysis",
            detection_playbooks=root / "config" / "playbooks.json",
            investigation_skills=root / "config" / "skills.json",
            asset_inventory_file=root / "config" / "assets.json",
            max_package_bytes=4 * 1024 * 1024,
        )
        self.sources = PromptBuilderCliSources(
            memory_roles=frozenset({"soc-analyst", "incident-responder"}),
            role_prompt_file=lambda root, role: root / f"{role}.md",
            role_second_opinion_prompt_file=(
                lambda root, role: root / f"{role}-review.md"
            ),
            role_memory_file=lambda root, role: root / f"{role}.md",
        )

    def test_defaults_preserve_soc_analyst_paths_and_limits(self) -> None:
        args = parse_prompt_builder_args(self.defaults, self.sources, [])

        self.assertEqual(args.db, self.defaults.db)
        self.assertEqual(args.system_prompt_file, self.defaults.system_prompt_file)
        self.assertEqual(args.agent_memory_file, self.defaults.agent_memory_file)
        self.assertEqual(args.max_package_bytes, self.defaults.max_package_bytes)
        self.assertFalse(args.blind_reanalysis)

    def test_non_soc_role_derives_role_specific_default_paths(self) -> None:
        args = parse_prompt_builder_args(
            self.defaults,
            self.sources,
            ["--agent-role", "incident-responder"],
        )

        self.assertEqual(
            args.system_prompt_file,
            Path("/runtime/config/incident-responder.md"),
        )
        self.assertEqual(
            args.second_opinion_prompt_file,
            Path("/runtime/config/incident-responder-review.md"),
        )
        self.assertEqual(
            args.agent_memory_file,
            Path("/runtime/memory/incident-responder.md"),
        )

    def test_explicit_role_paths_are_not_rewritten(self) -> None:
        args = parse_prompt_builder_args(
            self.defaults,
            self.sources,
            [
                "--agent-role",
                "incident-responder",
                "--system-prompt-file",
                "/custom/system.md",
                "--agent-memory-file",
                "/custom/memory.md",
            ],
        )

        self.assertEqual(args.system_prompt_file, Path("/custom/system.md"))
        self.assertEqual(args.agent_memory_file, Path("/custom/memory.md"))

    def test_invalid_numeric_policy_and_role_fail_closed(self) -> None:
        invalid_argv = (
            ["--hours", "0"],
            ["--correlation-min-score", "101"],
            ["--max-package-bytes", "262143"],
            ["--agent-role", "unknown-role"],
        )
        for argv in invalid_argv:
            with (
                self.subTest(argv=argv),
                contextlib.redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit),
            ):
                parse_prompt_builder_args(self.defaults, self.sources, argv)


if __name__ == "__main__":
    unittest.main()
