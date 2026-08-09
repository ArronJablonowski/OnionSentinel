#!/usr/bin/env python3
"""Command-line schema for the investigation prompt builder."""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence


@dataclass(frozen=True)
class PromptBuilderCliDefaults:
    db: Path
    rollup_dir: Path
    out_dir: Path
    system_prompt_file: Path
    second_opinion_prompt_file: Path
    agent_memory_dir: Path
    agent_memory_file: Path
    shared_memory_file: Path
    pcap_analysis_dir: Path
    analysis_dir: Path
    detection_playbooks: Path
    investigation_skills: Path
    asset_inventory_file: Path
    max_package_bytes: int


@dataclass(frozen=True)
class PromptBuilderCliSources:
    memory_roles: frozenset[str]
    role_prompt_file: Callable[[Path, str], Path]
    role_second_opinion_prompt_file: Callable[[Path, str], Path]
    role_memory_file: Callable[[Path, str], Path]


def _add_selection_arguments(parser: argparse.ArgumentParser, defaults) -> None:
    parser.add_argument("--db", type=Path, default=defaults.db)
    parser.add_argument("--rollup-dir", type=Path, default=defaults.rollup_dir)
    parser.add_argument("--out-dir", type=Path, default=defaults.out_dir)
    parser.add_argument("--alert-id", help="Exact alert_id to package")
    parser.add_argument("--levels", default="critical,high,medium")
    parser.add_argument("--hours", type=int, default=24)
    parser.add_argument("--related-limit", type=int, default=15)
    parser.add_argument("--correlation-limit", type=int, default=8)
    parser.add_argument("--correlation-min-score", type=int, default=15)
    parser.add_argument("--rollup-bytes", type=int, default=12000)


def _add_context_arguments(parser: argparse.ArgumentParser, defaults) -> None:
    parser.add_argument(
        "--system-prompt-file",
        type=Path,
        default=defaults.system_prompt_file,
    )
    parser.add_argument(
        "--second-opinion-prompt-file",
        type=Path,
        default=defaults.second_opinion_prompt_file,
    )
    parser.add_argument(
        "--agent-memory-file",
        type=Path,
        default=defaults.agent_memory_file,
    )
    parser.add_argument(
        "--shared-memory-file",
        type=Path,
        default=defaults.shared_memory_file,
    )
    parser.add_argument(
        "--pcap-analysis-dir",
        type=Path,
        default=defaults.pcap_analysis_dir,
    )
    parser.add_argument("--analysis-dir", type=Path, default=defaults.analysis_dir)
    parser.add_argument(
        "--detection-playbooks",
        type=Path,
        default=defaults.detection_playbooks,
    )
    parser.add_argument(
        "--investigation-skills",
        type=Path,
        default=defaults.investigation_skills,
    )
    parser.add_argument(
        "--asset-inventory-file",
        type=Path,
        default=defaults.asset_inventory_file,
    )
    parser.add_argument("--incident-evidence-file", type=Path)


def _add_policy_arguments(parser, defaults, sources) -> None:
    parser.add_argument(
        "--agent-role",
        choices=sorted(sources.memory_roles),
        default="soc-analyst",
    )
    parser.add_argument("--memory-bytes", type=int, default=8000)
    parser.add_argument("--pcap-analysis-limit", type=int, default=3)
    parser.add_argument(
        "--max-package-bytes",
        type=int,
        default=defaults.max_package_bytes,
    )
    parser.add_argument("--include-tests", action="store_true")
    parser.add_argument("--blind-reanalysis", action="store_true")
    parser.add_argument("--stdout", action="store_true")


def _validate_arguments(parser: argparse.ArgumentParser, args) -> None:
    positive = (
        (args.hours, "--hours"),
        (args.related_limit, "--related-limit"),
        (args.correlation_limit, "--correlation-limit"),
        (args.rollup_bytes, "--rollup-bytes"),
        (args.memory_bytes, "--memory-bytes"),
        (args.pcap_analysis_limit, "--pcap-analysis-limit"),
    )
    for value, option in positive:
        if value <= 0:
            parser.error(f"{option} must be positive")
    if not 0 <= args.correlation_min_score <= 100:
        parser.error("--correlation-min-score must be between 0 and 100")
    if args.max_package_bytes < 256 * 1024:
        parser.error("--max-package-bytes must be at least 262144")


def _apply_role_defaults(args, defaults, sources) -> None:
    if args.agent_role == "soc-analyst":
        return
    config_dir = defaults.system_prompt_file.parent
    if args.system_prompt_file == defaults.system_prompt_file:
        args.system_prompt_file = sources.role_prompt_file(
            config_dir,
            args.agent_role,
        )
    if args.second_opinion_prompt_file == defaults.second_opinion_prompt_file:
        args.second_opinion_prompt_file = sources.role_second_opinion_prompt_file(
            config_dir,
            args.agent_role,
        )
    if args.agent_memory_file == defaults.agent_memory_file:
        args.agent_memory_file = sources.role_memory_file(
            defaults.agent_memory_dir,
            args.agent_role,
        )


def parse_prompt_builder_args(
    defaults: PromptBuilderCliDefaults,
    sources: PromptBuilderCliSources,
    argv: Sequence[str] | None = None,
) -> argparse.Namespace:
    """Parse and validate the stable prompt-builder command line."""
    parser = argparse.ArgumentParser(
        description="Build an AI investigation prompt package"
    )
    _add_selection_arguments(parser, defaults)
    _add_context_arguments(parser, defaults)
    _add_policy_arguments(parser, defaults, sources)
    args = parser.parse_args(argv)
    _validate_arguments(parser, args)
    _apply_role_defaults(args, defaults, sources)
    return args
