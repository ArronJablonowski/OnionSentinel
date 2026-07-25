#!/usr/bin/env python3
"""Query or write Onion Sentinel memory for any Cyber Security Agent role."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from agent_memory import (
    MEMORY_ROLES,
    build_agent_execution_context,
    build_agent_memory_context,
    persist_memory_candidates,
    quarantine_bpfdoor_code_zero_memory,
    role_memory_file,
)


HOME = Path.home()
DEFAULT_MEMORY_DIR = HOME / "n8n-local" / "soc-alerts" / "agent-memory"
DEFAULT_CONFIG_DIR = HOME / "n8n-local" / "config"
def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description="Query or update role-aware Onion Sentinel agent memory")
    parser.add_argument("--agent", choices=sorted(MEMORY_ROLES), required=True)
    parser.add_argument("--memory-dir", type=Path, default=DEFAULT_MEMORY_DIR)
    parser.add_argument("--config-dir", type=Path, default=DEFAULT_CONFIG_DIR)
    subparsers = parser.add_subparsers(dest="command", required=True)

    query = subparsers.add_parser("query", help="Return bounded relevant role and shared memory")
    query.add_argument("--evidence-json", type=Path, required=True)
    query.add_argument("--memory-bytes", type=int, default=8000)

    prepare = subparsers.add_parser(
        "prepare",
        help="Return the system prompt and bounded role/shared memory as one execution context",
    )
    prepare.add_argument("--evidence-json", type=Path, required=True)
    prepare.add_argument("--memory-bytes", type=int, default=8000)

    writeback = subparsers.add_parser("writeback", help="Persist validated memory_candidates from an agent response")
    writeback.add_argument("--response-json", type=Path, required=True)
    writeback.add_argument("--analysis-id", required=True)
    writeback.add_argument("--source-artifact", default="")
    quarantine = subparsers.add_parser(
        "quarantine-bpfdoor-code-zero",
        help=(
            "Preview model-only BPFDoor memories that incorrectly treat ICMP "
            "code 0 as a decisive SID 2069174 false-positive predicate"
        ),
    )
    quarantine.add_argument(
        "--scope",
        choices=("role", "shared", "both"),
        default="shared",
    )
    quarantine.add_argument(
        "--apply",
        action="store_true",
        help="Apply the quarantine; without this flag the command is read-only",
    )
    quarantine.add_argument(
        "--record-id",
        action="append",
        default=[],
        help=(
            "Also select one exact audit-identified BPFDoor model-observed record "
            "ID; may be repeated"
        ),
    )
    args = parser.parse_args()

    role_file = role_memory_file(args.memory_dir, args.agent)
    shared_file = args.memory_dir / "shared-agent-memory.md"
    if args.command == "query":
        result = build_agent_memory_context(
            agent_role=args.agent,
            role_memory_file=role_file,
            shared_memory_file=shared_file,
            evidence=load_json(args.evidence_json),
            limit_bytes=args.memory_bytes,
        )
    elif args.command == "prepare":
        result = build_agent_execution_context(
            agent_role=args.agent,
            config_dir=args.config_dir,
            memory_dir=args.memory_dir,
            evidence=load_json(args.evidence_json),
            limit_bytes=args.memory_bytes,
        )
    elif args.command == "writeback":
        payload = load_json(args.response_json)
        response = payload.get("response") if isinstance(payload, dict) and isinstance(payload.get("response"), dict) else payload
        candidates = response.get("memory_candidates", []) if isinstance(response, dict) else []
        result = persist_memory_candidates(
            agent_role=args.agent,
            role_memory_file=role_file,
            shared_memory_file=shared_file,
            candidates=candidates,
            analysis_id=args.analysis_id,
            source_artifact=args.source_artifact or str(args.response_json),
        )
    else:
        paths = []
        if args.scope in {"role", "both"}:
            paths.append(role_file)
        if args.scope in {"shared", "both"}:
            paths.append(shared_file)
        results = [
            quarantine_bpfdoor_code_zero_memory(
                path,
                apply=args.apply,
                record_ids=args.record_id,
            )
            for path in paths
        ]
        result = {
            "dry_run": not args.apply,
            "matched": sum(int(item.get("matched") or 0) for item in results),
            "applied": sum(int(item.get("applied") or 0) for item in results),
            "files": results,
        }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
