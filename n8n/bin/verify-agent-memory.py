#!/usr/bin/env python3
"""Verify every Onion Sentinel agent's prompt and durable memory contract."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

from agent_memory import (
    MANAGED_END,
    MANAGED_START,
    MEMORY_ROLES,
    build_agent_execution_context,
    build_agent_memory_context,
    initialize_memory_file,
    role_memory_file,
    role_prompt_file,
    role_second_opinion_prompt_file,
)


HOME = Path.home()
DEFAULT_CONFIG_DIR = HOME / "n8n-local" / "config"
DEFAULT_MEMORY_DIR = HOME / "n8n-local" / "soc-alerts" / "agent-memory"


def _managed_memory_issues(text: str) -> list[str]:
    if text.count(MANAGED_START) != 1 or text.count(MANAGED_END) != 1:
        return ["invalid-managed-section"]
    return []


def _prompt_issues(text: str) -> list[str]:
    lowered = text.lower()
    return [
        f"prompt-missing-{term}"
        for term in ("memory", "shared", "memory_candidates")
        if term not in lowered
    ]


def _file_contract(path: Path, *, managed_memory: bool = False) -> list[str]:
    issues: list[str] = []
    if not path.is_file():
        return ["missing"]
    if not os.access(path, os.R_OK):
        issues.append("not-readable")
    if managed_memory and not os.access(path, os.W_OK):
        issues.append("not-writable")
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return issues + ["read-failed"]
    content_issues = (
        _managed_memory_issues(text)
        if managed_memory
        else _prompt_issues(text)
    )
    return issues + content_issues


def _agent_paths(
    config_dir: Path,
    memory_dir: Path,
    role: str,
) -> tuple[Path, Path, Path, Path]:
    return (
        role_prompt_file(config_dir, role),
        role_second_opinion_prompt_file(config_dir, role),
        role_memory_file(memory_dir, role),
        memory_dir / "shared-agent-memory.md",
    )


def _agent_file_issues(
    prompt_file: Path,
    second_opinion_prompt_file: Path,
    memory_file: Path,
    shared_issues: list[str],
) -> list[str]:
    return [
        *(f"prompt:{item}" for item in _file_contract(prompt_file)),
        *(
            f"second-opinion-prompt:{item}"
            for item in _file_contract(second_opinion_prompt_file)
        ),
        *(
            f"memory:{item}"
            for item in _file_contract(memory_file, managed_memory=True)
        ),
        *(f"shared:{item}" for item in shared_issues),
    ]


def _memory_context_matches(
    context: dict[str, Any],
    memory_file: Path,
    shared_file: Path,
) -> bool:
    return bool(
        context["role_memory"]["exists"]
        and context["shared_memory"]["exists"]
        and context["role_memory"]["path"] == str(memory_file)
        and context["shared_memory"]["path"] == str(shared_file)
    )


def _execution_context_matches(
    context: dict[str, Any],
    paths: tuple[Path, Path, Path, Path],
) -> bool:
    prompt_file, second_opinion_prompt_file, memory_file, shared_file = paths
    return bool(
        context["system_prompt_file"] == str(prompt_file)
        and context["second_opinion_system_prompt_file"]
        == str(second_opinion_prompt_file)
        and context["agent_memory_file"] == str(memory_file)
        and context["shared_memory_file"] == str(shared_file)
        and context["memory_writeback_contract"]["response_field"]
        == "memory_candidates"
    )


def _agent_context_readiness(
    role: str,
    config_dir: Path,
    memory_dir: Path,
    paths: tuple[Path, Path, Path, Path],
) -> tuple[bool, bool, list[str]]:
    prompt_file, second_opinion_prompt_file, memory_file, shared_file = paths
    context_ok = False
    execution_context_ok = False
    issues: list[str] = []
    try:
        context = build_agent_memory_context(
            agent_role=role,
            role_memory_file=memory_file,
            shared_memory_file=shared_file,
            evidence={"verification": "agent memory contract", "agent_role": role},
            limit_bytes=1024,
        )
        context_ok = _memory_context_matches(
            context,
            memory_file,
            shared_file,
        )
        execution_context = build_agent_execution_context(
            agent_role=role,
            config_dir=config_dir,
            memory_dir=memory_dir,
            evidence={"verification": "agent execution contract", "agent_role": role},
            limit_bytes=1024,
        )
        execution_context_ok = _execution_context_matches(
            execution_context,
            paths,
        )
    except (OSError, ValueError, KeyError) as exc:
        issues.append(f"query:{type(exc).__name__}")
    if not context_ok and not issues:
        issues.append("query:contract-mismatch")
    if not execution_context_ok and not issues:
        issues.append("execution:contract-mismatch")
    return context_ok, execution_context_ok, issues


def _agent_result(
    paths: tuple[Path, Path, Path, Path],
    context_ok: bool,
    execution_context_ok: bool,
    issues: list[str],
) -> dict[str, Any]:
    prompt_file, second_opinion_prompt_file, memory_file, shared_file = paths
    return {
        "ok": not issues,
        "prompt_file": str(prompt_file),
        "second_opinion_prompt_file": str(second_opinion_prompt_file),
        "memory_file": str(memory_file),
        "shared_memory_file": str(shared_file),
        "read_context_ready": context_ok,
        "execution_context_ready": execution_context_ok,
        "writeback_ready": not issues,
        "issues": issues,
    }


def _verify_agent(
    role: str,
    config_dir: Path,
    memory_dir: Path,
    shared_issues: list[str],
) -> dict[str, Any]:
    paths = _agent_paths(config_dir, memory_dir, role)
    issues = _agent_file_issues(*paths[:3], shared_issues)
    context_ok = False
    execution_context_ok = False
    if not issues:
        context_ok, execution_context_ok, issues = _agent_context_readiness(
            role,
            config_dir,
            memory_dir,
            paths,
        )
    return _agent_result(paths, context_ok, execution_context_ok, issues)


def verify_setup(config_dir: Path, memory_dir: Path) -> dict[str, Any]:
    shared_file = memory_dir / "shared-agent-memory.md"
    shared_issues = _file_contract(shared_file, managed_memory=True)
    agents = {
        role: _verify_agent(role, config_dir, memory_dir, shared_issues)
        for role in sorted(MEMORY_ROLES)
    }
    return {
        "ok": all(item["ok"] for item in agents.values()),
        "agent_count": len(agents),
        "agents": agents,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify all Onion Sentinel agent memory contracts")
    parser.add_argument("--config-dir", type=Path, default=DEFAULT_CONFIG_DIR)
    parser.add_argument("--memory-dir", type=Path, default=DEFAULT_MEMORY_DIR)
    parser.add_argument(
        "--initialize",
        action="store_true",
        help="Idempotently add missing files/managed sections while preserving operator notes",
    )
    args = parser.parse_args()
    initialized: list[dict[str, Any]] = []
    if args.initialize:
        for role in sorted(MEMORY_ROLES):
            initialized.append(
                initialize_memory_file(
                    role_memory_file(args.memory_dir, role),
                    f"{role.replace('-', ' ').title()} Memory",
                )
            )
        initialized.append(
            initialize_memory_file(args.memory_dir / "shared-agent-memory.md", "Shared Cyber Security Agent Memory")
        )
    result = verify_setup(args.config_dir, args.memory_dir)
    result["initialization"] = initialized
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
