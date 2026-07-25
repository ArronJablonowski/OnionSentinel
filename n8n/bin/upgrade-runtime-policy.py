#!/usr/bin/env python3
"""Upgrade a runtime policy file only from an exact reviewed baseline."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from pathlib import Path


MAX_POLICY_BYTES = 1024 * 1024


class PolicyUpgradeError(RuntimeError):
    """A policy path or reviewed hash failed its safety contract."""


def _regular_bytes(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise PolicyUpgradeError(f"policy must be a regular file: {path}")
    data = path.read_bytes()
    if len(data) > MAX_POLICY_BYTES:
        raise PolicyUpgradeError(f"policy exceeds its byte limit: {path}")
    return data


def upgrade_runtime_policy(
    *,
    source: Path,
    destination: Path,
    accepted_prior_hashes: set[str],
) -> dict[str, str]:
    source_data = _regular_bytes(source)
    source_digest = hashlib.sha256(source_data).hexdigest()
    if any(
        len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
        for digest in accepted_prior_hashes
    ):
        raise PolicyUpgradeError("accepted prior policy hash is invalid")

    if not destination.exists():
        raise PolicyUpgradeError("runtime policy must be seeded before upgrade")
    destination_data = _regular_bytes(destination)
    destination_digest = hashlib.sha256(destination_data).hexdigest()
    if destination_digest == source_digest:
        return {"action": "already_current", "sha256": source_digest}
    if destination_digest not in accepted_prior_hashes:
        return {
            "action": "preserved_operator_policy",
            "sha256": destination_digest,
        }

    mode = destination.stat().st_mode & 0o777
    with tempfile.NamedTemporaryFile(
        "wb",
        dir=destination.parent,
        prefix=f".{destination.name}.",
        delete=False,
    ) as handle:
        handle.write(source_data)
        handle.flush()
        os.fsync(handle.fileno())
        temporary = Path(handle.name)
    try:
        os.chmod(temporary, mode or 0o600)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)
    return {"action": "upgraded_reviewed_baseline", "sha256": source_digest}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument(
        "--accepted-prior-sha256",
        action="append",
        default=[],
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        result = upgrade_runtime_policy(
            source=args.source,
            destination=args.destination,
            accepted_prior_hashes=set(args.accepted_prior_sha256),
        )
    except (OSError, PolicyUpgradeError) as exc:
        raise SystemExit(f"runtime policy upgrade refused: {exc}") from exc
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
