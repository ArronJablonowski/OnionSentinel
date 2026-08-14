#!/usr/bin/env python3
"""Validate, activate, inspect, or roll back a signed v2 skill registry."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any

import investigation_skill_lifecycle_v2 as lifecycle
import investigation_skill_registry_v2 as registry
import investigation_skill_signing_v2 as signing


MAX_SNAPSHOT_BYTES = 4 * 1024 * 1024


def _snapshot(path: Path) -> dict[str, Any]:
    try:
        details = path.lstat()
    except (FileNotFoundError, OSError) as exc:
        raise ValueError("registry snapshot file is unavailable") from exc
    if path.is_symlink() or not stat.S_ISREG(details.st_mode):
        raise ValueError("registry snapshot must be a regular non-symlink")
    if details.st_uid != os.getuid() or details.st_size > MAX_SNAPSHOT_BYTES:
        raise ValueError("registry snapshot ownership or size is invalid")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        raw = os.read(descriptor, MAX_SNAPSHOT_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(raw) > MAX_SNAPSHOT_BYTES:
        raise ValueError("registry snapshot exceeds its byte limit")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("registry snapshot JSON is invalid") from exc
    if not isinstance(value, dict):
        raise ValueError("registry snapshot must contain an object")
    return value


def _status(value: dict[str, Any], *, action: str) -> dict[str, Any]:
    return {
        "schema": "onion-sentinel-investigation-skill-lifecycle-receipt-v1",
        "action": action,
        "registry_version": value["revision"],
        "registry_digest": value["registry_digest"],
        "previous_registry_digest": value["previous_registry_digest"],
        "mode": value["mode"],
        "record_count": len(value["records"]),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--openssl", type=Path)
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser("validate")
    validate.add_argument("--snapshot", type=Path, required=True)

    activate = subparsers.add_parser("activate")
    activate.add_argument("--snapshot", type=Path, required=True)
    activate.add_argument("--expected-current-digest", required=True)

    rollback = subparsers.add_parser("rollback")
    rollback.add_argument("--expected-current-digest", required=True)

    subparsers.add_parser("status")
    return parser


def _execute(args: argparse.Namespace) -> dict[str, Any]:
    verifier = signing.openssl_ed25519_verifier(
        {args.key_id: args.public_key},
        openssl=args.openssl,
    )
    if args.command == "validate":
        value = registry.validate_registry(
            _snapshot(args.snapshot),
            verifier=verifier,
        )
        return _status(value, action="validate")
    if args.command == "activate":
        return lifecycle.activate_snapshot(
            args.root,
            _snapshot(args.snapshot),
            expected_current_digest=args.expected_current_digest,
            verifier=verifier,
        )
    if args.command == "rollback":
        return lifecycle.rollback_active(
            args.root,
            expected_current_digest=args.expected_current_digest,
            verifier=verifier,
        )
    return _status(
        lifecycle.load_current(args.root, verifier=verifier),
        action="status",
    )


def main() -> int:
    try:
        result = _execute(_parser().parse_args())
    except (OSError, TypeError, ValueError) as exc:
        print(f"registry operation rejected: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
