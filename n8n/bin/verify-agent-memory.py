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
)


HOME = Path.home()
DEFAULT_CONFIG_DIR = HOME / "n8n-local" / "config"
DEFAULT_MEMORY_DIR = HOME / "n8n-local" / "soc-alerts" / "agent-memory"


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
    if managed_memory:
        if text.count(MANAGED_START) != 1 or text.count(MANAGED_END) != 1:
            issues.append("invalid-managed-section")
    else:
        lowered = text.lower()
        for term in ("memory", "shared", "memory_candidates"):
            if term not in lowered:
                issues.append(f"prompt-missing-{term}")
    return issues


def verify_setup(config_dir: Path, memory_dir: Path) -> dict[str, Any]:
    shared_file = memory_dir / "shared-agent-memory.md"
    shared_issues = _file_contract(shared_file, managed_memory=True)
    agents: dict[str, Any] = {}
    for role in sorted(MEMORY_ROLES):
        prompt_file = role_prompt_file(config_dir, role)
        memory_file = role_memory_file(memory_dir, role)
        issues = [
            *(f"prompt:{item}" for item in _file_contract(prompt_file)),
            *(f"memory:{item}" for item in _file_contract(memory_file, managed_memory=True)),
            *(f"shared:{item}" for item in shared_issues),
        ]
        context_ok = False
        execution_context_ok = False
        if not issues:
            try:
                context = build_agent_memory_context(
                    agent_role=role,
                    role_memory_file=memory_file,
                    shared_memory_file=shared_file,
                    evidence={"verification": "agent memory contract", "agent_role": role},
                    limit_bytes=1024,
                )
                context_ok = (
                    context["role_memory"]["exists"]
                    and context["shared_memory"]["exists"]
                    and context["role_memory"]["path"] == str(memory_file)
                    and context["shared_memory"]["path"] == str(shared_file)
                )
                execution_context = build_agent_execution_context(
                    agent_role=role,
                    config_dir=config_dir,
                    memory_dir=memory_dir,
                    evidence={"verification": "agent execution contract", "agent_role": role},
                    limit_bytes=1024,
                )
                execution_context_ok = (
                    execution_context["system_prompt_file"] == str(prompt_file)
                    and execution_context["agent_memory_file"] == str(memory_file)
                    and execution_context["shared_memory_file"] == str(shared_file)
                    and execution_context["memory_writeback_contract"]["response_field"] == "memory_candidates"
                )
            except (OSError, ValueError, KeyError) as exc:
                issues.append(f"query:{type(exc).__name__}")
        if not context_ok and not issues:
            issues.append("query:contract-mismatch")
        if not execution_context_ok and not issues:
            issues.append("execution:contract-mismatch")
        agents[role] = {
            "ok": not issues,
            "prompt_file": str(prompt_file),
            "memory_file": str(memory_file),
            "shared_memory_file": str(shared_file),
            "read_context_ready": context_ok,
            "execution_context_ready": execution_context_ok,
            "writeback_ready": not issues,
            "issues": issues,
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
