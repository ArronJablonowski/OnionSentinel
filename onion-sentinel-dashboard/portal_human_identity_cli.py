"""Secret-safe CLI for owner-managed Viewer and Analyst identities."""
from __future__ import annotations

import argparse
import getpass
import json
from pathlib import Path
import sys
from typing import Callable, Sequence, TextIO

from portal_human_identity_management import (
    HumanIdentityManagementError,
    remove_human_identity,
    set_human_identity,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Manage trusted Viewer and Analyst identities while the Onion "
            "Sentinel web service is stopped."
        )
    )
    parser.add_argument(
        "--stack-dir", type=Path, default=Path.home() / "n8n-local"
    )
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--set", dest="set_username", metavar="USERNAME")
    action.add_argument("--remove", dest="remove_username", metavar="USERNAME")
    parser.add_argument("--principal-id")
    parser.add_argument("--role", choices=("viewer", "analyst"))
    parser.add_argument("--confirm-service-stopped", action="store_true")
    return parser


def _password(read_password: Callable[[str], str]) -> str:
    first = read_password("New identity password: ")
    second = read_password("Confirm identity password: ")
    if first != second:
        raise HumanIdentityManagementError(
            "identity password confirmation does not match"
        )
    return first


def _result_payload(result: object) -> dict[str, object]:
    return {
        "action": getattr(result, "action"),
        "generation": getattr(result, "generation"),
        "identity_count": getattr(result, "identity_count"),
        "ok": True,
        "principal_id": getattr(result, "principal_id"),
        "role": getattr(result, "role"),
        "username": getattr(result, "username"),
    }


def main(
    argv: Sequence[str] | None = None,
    *,
    read_password: Callable[[str], str] = getpass.getpass,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    args = _parser().parse_args(argv)
    if not args.confirm_service_stopped:
        print(
            "Human identity update refused: the web service must be stopped "
            "and explicitly confirmed.",
            file=stderr,
        )
        return 2
    path = args.stack_dir / "config/onion-sentinel-human-identities.json"
    try:
        if args.set_username is not None:
            if not args.principal_id or not args.role:
                print(
                    "Human identity update refused: --set requires "
                    "--principal-id and --role.",
                    file=stderr,
                )
                return 2
            result = set_human_identity(
                path,
                username=args.set_username,
                principal_id=args.principal_id,
                role=args.role,
                password=_password(read_password),
            )
        else:
            result = remove_human_identity(
                path, username=args.remove_username
            )
    except (HumanIdentityManagementError, EOFError, KeyboardInterrupt) as exc:
        message = (
            str(exc)
            if isinstance(exc, HumanIdentityManagementError)
            else "identity password input was interrupted"
        )
        print(f"Human identity update failed: {message}", file=stderr)
        return 1
    print(json.dumps(_result_payload(result), sort_keys=True), file=stdout)
    return 0


__all__ = ("main",)
