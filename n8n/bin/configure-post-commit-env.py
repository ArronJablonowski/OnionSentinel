#!/usr/bin/env python3
"""Atomically configure the Mac-only alert-store to n8n handoff.

The token is accepted only on stdin so it never appears in process arguments,
repository files, or normal command output. Existing comments and unrelated
runtime settings are preserved.
"""
from __future__ import annotations

import argparse
import os
import tempfile
from pathlib import Path


DEFAULT_URL = "http://127.0.0.1:5678/webhook/onion-sentinel-committed-alert"
SETTINGS = {
    "N8N_POST_COMMIT_INTERVAL_MS": "5000",
    "N8N_POST_COMMIT_TIMEOUT_MS": "30000",
    "N8N_POST_COMMIT_MAX_ATTEMPTS": "12",
    "N8N_POST_COMMIT_BASE_RETRY_SECONDS": "15",
}


def read_token() -> str:
    raw = os.read(0, 65537)
    if len(raw) > 65536:
        raise SystemExit("post-commit token exceeds the input limit")
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SystemExit("post-commit token must be UTF-8") from exc
    token = decoded.rstrip("\r\n")
    if "\n" in token or "\r" in token or "\0" in token:
        raise SystemExit("post-commit token contains an unsupported character")
    if len(token) < 20:
        raise SystemExit("post-commit token is missing or too short")
    return token


def _literal_newline_block(line: str, updates: dict[str, str]) -> bool:
    if "\\n" not in line:
        return False
    fragments = [fragment for fragment in line.split("\\n") if fragment]
    fragment_keys = {
        fragment.split("=", 1)[0].strip()
        for fragment in fragments
        if "=" in fragment
    }
    if fragment_keys and fragment_keys.issubset(updates):
        # Repair an older deployment bug that appended a whole block with
        # literal backslash-n separators. Fresh values replace every
        # secret-bearing fragment without echoing it.
        return True
    raise SystemExit("environment file contains an unsupported literal \\\\n sequence")


def _existing_env_lines(
    existing: str,
    updates: dict[str, str],
) -> tuple[list[str], set[str]]:
    output: list[str] = []
    written: set[str] = set()
    for line in existing.splitlines():
        if _literal_newline_block(line, updates):
            continue
        key = line.split("=", 1)[0].strip() if "=" in line else ""
        if key in updates:
            if key not in written:
                output.append(f"{key}={updates[key]}")
                written.add(key)
            continue
        output.append(line)
    return output, written


def _append_missing_settings(
    output: list[str],
    written: set[str],
    updates: dict[str, str],
) -> None:
    if output and output[-1] != "":
        output.append("")
    for key, value in updates.items():
        if key not in written:
            output.append(f"{key}={value}")


def render_env(existing: str, updates: dict[str, str]) -> str:
    output, written = _existing_env_lines(existing, updates)
    _append_missing_settings(output, written, updates)
    return "\n".join(output).rstrip("\n") + "\n"


def atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--env-file", type=Path, required=True)
    parser.add_argument("--url", default=DEFAULT_URL)
    args = parser.parse_args()

    token = read_token()
    path = args.env_file.expanduser()
    existing = path.read_text(encoding="utf-8") if path.exists() else ""
    updates = {
        "N8N_POST_COMMIT_URL": args.url,
        "N8N_POST_COMMIT_TOKEN": token,
        **SETTINGS,
    }
    atomic_write(path, render_env(existing, updates))
    print("post_commit_env=updated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
