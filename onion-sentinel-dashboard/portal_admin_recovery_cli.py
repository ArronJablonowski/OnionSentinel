"""Bounded command-line adapter for local administrator recovery."""
from __future__ import annotations

import argparse
import getpass
import json
from pathlib import Path
import sys
from typing import Callable, Sequence, TextIO

from portal_admin_recovery import AdminRecoveryError, recover_admin_access


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Reset the local dashboard administrator password and/or revoke "
            "all browser sessions while the dashboard service is stopped."
        )
    )
    parser.add_argument(
        "--stack-dir",
        type=Path,
        default=Path.home() / "n8n-local",
    )
    parser.add_argument("--reset-password", action="store_true")
    parser.add_argument("--revoke-sessions", action="store_true")
    parser.add_argument("--confirm-service-stopped", action="store_true")
    return parser


def _password(
    read_password: Callable[[str], str],
) -> str:
    first = read_password("New dashboard administrator password: ")
    second = read_password("Confirm dashboard administrator password: ")
    if first != second:
        raise AdminRecoveryError(
            "administrator password confirmation does not match"
        )
    return first


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
            "Administrator recovery refused: the dashboard write service "
            "must be stopped and explicitly confirmed.",
            file=stderr,
        )
        return 2
    if not args.reset_password and not args.revoke_sessions:
        print(
            "Administrator recovery refused: select --reset-password and/or "
            "--revoke-sessions.",
            file=stderr,
        )
        return 2
    try:
        password = _password(read_password) if args.reset_password else None
        result = recover_admin_access(
            args.stack_dir,
            new_password=password,
            revoke_sessions=args.revoke_sessions,
        )
    except (AdminRecoveryError, EOFError, KeyboardInterrupt) as exc:
        message = (
            str(exc)
            if isinstance(exc, AdminRecoveryError)
            else "administrator password input was interrupted"
        )
        print(f"Administrator recovery failed: {message}", file=stderr)
        return 1
    print(
        json.dumps(
            {
                "human_sessions_revoked": result.human_sessions_revoked,
                "legacy_sessions_revoked": result.legacy_sessions_revoked,
                "ok": True,
                "password_reset": result.password_reset,
            },
            sort_keys=True,
        ),
        file=stdout,
    )
    return 0


__all__ = ("main",)
