#!/usr/bin/env python3
"""Validate a secret-free cross-host handoff and emit its safe apply decision."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any

from cross_host_handoff_contract import HandoffError, build_handoff_plan


MAX_HANDOFF_BYTES = 1024 * 1024
PASS_DECISIONS = {"apply_authorized", "noop_already_applied", "noop_current_match"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--handoff", type=Path, required=True)
    parser.add_argument(
        "--prior-handoff",
        type=Path,
        help="Prior document for idempotent replay or identity-collision detection.",
    )
    return parser.parse_args()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise HandoffError("handoff JSON contains a duplicate field")
        value[key] = item
    return value


def _read_bounded_file(path: Path) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path.absolute(), flags)
    except OSError as exc:
        raise HandoffError("handoff path must be a safe regular file") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_HANDOFF_BYTES:
            raise HandoffError("handoff path must be a safe regular file")
        chunks = []
        consumed = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, MAX_HANDOFF_BYTES + 1 - consumed))
            if not chunk:
                break
            chunks.append(chunk)
            consumed += len(chunk)
            if consumed > MAX_HANDOFF_BYTES:
                raise HandoffError("handoff path must be a safe regular file")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def read_handoff(path: Path) -> Any:
    try:
        return json.loads(
            _read_bounded_file(path).decode("utf-8", "strict"),
            object_pairs_hook=_unique_object,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HandoffError("handoff JSON is invalid") from exc


def main() -> int:
    args = parse_args()
    try:
        repo_root = args.repo_root.absolute()
        if repo_root.is_symlink() or not repo_root.is_dir():
            raise HandoffError("repository root must be a safe directory")
        document = read_handoff(args.handoff)
        prior = read_handoff(args.prior_handoff) if args.prior_handoff else None
        report = build_handoff_plan(repo_root, document, prior_document=prior)
    except (OSError, HandoffError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["decision"] in PASS_DECISIONS else 1


if __name__ == "__main__":
    sys.exit(main())
