#!/usr/bin/env python3
"""Persist the exact deployed Onion Sentinel release without exposing .env data."""
from __future__ import annotations

import argparse
import os
import re
import tempfile
from pathlib import Path


RELEASE_KEY = "ONION_SENTINEL_RELEASE_ID"
RELEASE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{6,99}$")
MAX_ENV_BYTES = 1024 * 1024


class ReleaseIdError(RuntimeError):
    """The requested release marker or runtime environment file is unsafe."""


def validate_release_id(release_id: str) -> str:
    release_id = str(release_id or "").strip()
    if not RELEASE_ID_RE.fullmatch(release_id):
        raise ReleaseIdError(
            "release id must be 7..100 characters using letters, digits, dot, "
            "underscore, or hyphen"
        )
    return release_id


def set_runtime_release_id(env_path: Path, release_id: str) -> None:
    release_id = validate_release_id(release_id)
    if env_path.is_symlink():
        raise ReleaseIdError("runtime .env must not be a symbolic link")
    try:
        raw = env_path.read_bytes()
    except OSError as exc:
        raise ReleaseIdError(f"could not read runtime .env: {exc}") from exc
    if len(raw) > MAX_ENV_BYTES:
        raise ReleaseIdError("runtime .env exceeds its byte limit")
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ReleaseIdError("runtime .env is not valid UTF-8") from exc

    replacement = f"{RELEASE_KEY}={release_id}"
    output: list[str] = []
    replaced = False
    for line in lines:
        key = line.split("=", 1)[0].strip() if "=" in line else ""
        if key != RELEASE_KEY:
            output.append(line)
            continue
        if not replaced:
            output.append(replacement)
            replaced = True
    if not replaced:
        if output and output[-1]:
            output.append("")
        output.append(replacement)

    env_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=env_path.parent,
        prefix=f".{env_path.name}.",
        delete=False,
    ) as handle:
        handle.write("\n".join(output) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
        temporary = Path(handle.name)
    try:
        os.chmod(temporary, 0o600)
        os.replace(temporary, env_path)
    finally:
        temporary.unlink(missing_ok=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--env-file", type=Path)
    parser.add_argument("--release-id", required=True)
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Validate the release marker without reading or writing an env file",
    )
    args = parser.parse_args()
    if not args.validate_only and args.env_file is None:
        parser.error("--env-file is required unless --validate-only is used")
    return args


def main() -> int:
    args = parse_args()
    try:
        release_id = validate_release_id(args.release_id)
        if not args.validate_only:
            set_runtime_release_id(args.env_file, release_id)
    except ReleaseIdError as exc:
        raise SystemExit(f"release id update refused: {exc}") from exc
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
