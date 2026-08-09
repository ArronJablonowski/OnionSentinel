#!/usr/bin/env python3
"""Argument parsing and command dispatch for the cohort runner CLI."""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import sys
from typing import Any, Callable, Mapping, Sequence


@dataclass(frozen=True)
class CohortCliOperations:
    freeze_cohort: Callable[..., dict[str, Any]]
    freeze_cohort_from_rows: Callable[..., dict[str, Any]]
    queue_cohort: Callable[..., dict[str, Any]]
    monitor_cohort: Callable[..., tuple[dict[str, Any], bool]]
    export_cohort: Callable[..., dict[str, Any]]
    handled_errors: tuple[type[BaseException], ...]


def _add_execution_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--expected-release-id", required=True)
    parser.add_argument("--expected-assigned-route", required=True)
    parser.add_argument("--expected-reviewer-route", required=True)
    parser.add_argument(
        "--evaluation-profile",
        default="",
        help=(
            "optional exact controlled campaign profile; the named profile "
            "pins its approved primary and reviewer routes"
        ),
    )


def _add_freeze_command(commands: Any) -> None:
    freeze = commands.add_parser("freeze", help="freeze the newest stable cohort")
    freeze.add_argument("--db", required=True, type=Path)
    freeze.add_argument("--manifest", required=True, type=Path)
    freeze.add_argument("--cohort-id", required=True)
    freeze.add_argument("--reason", required=True)
    freeze.add_argument("--count", required=True, type=int)
    _add_execution_arguments(freeze)
    freeze.add_argument(
        "--dry-run",
        action="store_true",
        help="validate and print the frozen plan without writing a manifest",
    )


def _add_import_command(commands: Any, agent_roles: Sequence[str]) -> None:
    imported = commands.add_parser(
        "freeze-from-rows",
        help="freeze an already-selected owner-only JSON array without reselection",
    )
    imported.add_argument("--db", required=True, type=Path)
    imported.add_argument("--source-rows", required=True, type=Path)
    imported.add_argument("--manifest", required=True, type=Path)
    imported.add_argument("--cohort-id", required=True)
    imported.add_argument("--reason", required=True)
    imported.add_argument("--expected-count", required=True, type=int)
    _add_execution_arguments(imported)
    imported.add_argument(
        "--agent-role",
        choices=sorted(agent_roles),
        default="incident-responder",
        help="agent queue to exercise; defaults to incident-responder",
    )
    imported.add_argument(
        "--dry-run",
        action="store_true",
        help="validate exact source rows without writing a manifest",
    )


def _add_queue_command(commands: Any) -> None:
    queue = commands.add_parser("queue", help="queue each frozen member once")
    queue.add_argument("--db", required=True, type=Path)
    queue.add_argument("--manifest", required=True, type=Path)
    queue.add_argument(
        "--base-url",
        default="http://127.0.0.1:8766",
        help="loopback dashboard origin",
    )
    queue.add_argument("--http-timeout", type=float, default=15.0)
    queue.add_argument(
        "--evaluation-token-file",
        type=Path,
        help=(
            "owner-only file containing the 64-character evaluation token; "
            "the token is sent only as an evaluation POST header"
        ),
    )
    queue.add_argument(
        "--dry-run",
        action="store_true",
        help="validate all identities without sending any HTTP request",
    )


def _add_monitor_command(commands: Any) -> None:
    monitor = commands.add_parser("monitor", help="monitor exact accepted identities")
    monitor.add_argument("--db", required=True, type=Path)
    monitor.add_argument("--manifest", required=True, type=Path)
    monitor.add_argument(
        "--timeout",
        type=float,
        default=0.0,
        help="seconds to wait; zero performs one snapshot",
    )
    monitor.add_argument("--poll-interval", type=float, default=5.0)


def _add_export_command(commands: Any) -> None:
    export = commands.add_parser("export", help="export terminal result metadata")
    export.add_argument("--db", required=True, type=Path)
    export.add_argument("--manifest", required=True, type=Path)
    export.add_argument("--output", required=True, type=Path)
    export.add_argument(
        "--harness-db",
        required=True,
        type=Path,
        help="read-only harness ledger used to attest every exact analysis",
    )


def build_parser(description: str, agent_roles: Sequence[str]) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=description)
    commands = parser.add_subparsers(dest="command", required=True)
    _add_freeze_command(commands)
    _add_import_command(commands, agent_roles)
    _add_queue_command(commands)
    _add_monitor_command(commands)
    _add_export_command(commands)
    return parser


def print_summary(document: Mapping[str, Any]) -> None:
    print(
        json.dumps(
            {
                "schema": document.get("schema"),
                "cohort_id": document.get("cohort_id"),
                "agent_role": document.get("agent_role"),
                "state": document.get("state"),
                "count": document.get("count"),
                "manifest_sha256": document.get("manifest_sha256"),
                "export_sha256": document.get("export_sha256"),
            },
            indent=2,
            sort_keys=True,
        )
    )


def _freeze(args: argparse.Namespace, operations: CohortCliOperations) -> dict[str, Any]:
    return operations.freeze_cohort(
        args.db,
        args.manifest,
        cohort_id=args.cohort_id,
        reason=args.reason,
        count=args.count,
        expected_release_id=args.expected_release_id,
        expected_assigned_route=args.expected_assigned_route,
        expected_reviewer_route=args.expected_reviewer_route,
        evaluation_profile=args.evaluation_profile,
        dry_run=args.dry_run,
    )


def _freeze_from_rows(
    args: argparse.Namespace,
    operations: CohortCliOperations,
) -> dict[str, Any]:
    return operations.freeze_cohort_from_rows(
        args.db,
        args.source_rows,
        args.manifest,
        cohort_id=args.cohort_id,
        reason=args.reason,
        expected_count=args.expected_count,
        expected_release_id=args.expected_release_id,
        agent_role=args.agent_role,
        expected_assigned_route=args.expected_assigned_route,
        expected_reviewer_route=args.expected_reviewer_route,
        evaluation_profile=args.evaluation_profile,
        dry_run=args.dry_run,
    )


def _run_command(
    args: argparse.Namespace,
    operations: CohortCliOperations,
) -> tuple[dict[str, Any], int]:
    if args.command == "freeze":
        return _freeze(args, operations), 0
    if args.command == "freeze-from-rows":
        return _freeze_from_rows(args, operations), 0
    if args.command == "queue":
        result = operations.queue_cohort(
            args.db,
            args.manifest,
            base_url=args.base_url,
            timeout=args.http_timeout,
            dry_run=args.dry_run,
            evaluation_token_file=args.evaluation_token_file,
        )
        return result, 0
    if args.command == "monitor":
        result, terminal = operations.monitor_cohort(
            args.db,
            args.manifest,
            timeout=args.timeout,
            poll_interval=args.poll_interval,
        )
        return result, 0 if terminal else 3
    if args.command == "export":
        result = operations.export_cohort(
            args.db,
            args.manifest,
            args.output,
            harness_database_path=args.harness_db,
        )
        return result, 0
    raise AssertionError(f"unhandled command: {args.command}")


def main(
    argv: list[str] | None,
    *,
    parser: argparse.ArgumentParser,
    operations: CohortCliOperations,
) -> int:
    args = parser.parse_args(argv)
    try:
        result, status = _run_command(args, operations)
        print_summary(result)
        return status
    except operations.handled_errors as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
