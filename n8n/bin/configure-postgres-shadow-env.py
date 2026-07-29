#!/usr/bin/env python3
"""Atomically configure the disabled-by-default PostgreSQL queue shadow."""
from __future__ import annotations

import argparse
import os
import tempfile
from pathlib import Path


SETTINGS = {
    "ALERT_STORE_POSTGRES_SHADOW_ENABLED": "0",
    "ALERT_STORE_POSTGRES_HOST": "127.0.0.1",
    "ALERT_STORE_POSTGRES_PORT": "5433",
    "ALERT_STORE_POSTGRES_DATABASE": "onion_sentinel",
    "ALERT_STORE_POSTGRES_USER": "onion_sentinel",
    "ALERT_STORE_POSTGRES_SHADOW_INTERVAL_MS": "5000",
    "ALERT_STORE_POSTGRES_SHADOW_BATCH_SIZE": "250",
}


def read_password() -> str:
    raw = os.read(0, 4097)
    if len(raw) > 4096:
        raise SystemExit("PostgreSQL password exceeds the input limit")
    try:
        password = raw.decode("utf-8").rstrip("\r\n")
    except UnicodeDecodeError as exc:
        raise SystemExit("PostgreSQL password must be UTF-8") from exc
    if (
        len(password) < 32
        or any(character in password for character in "\r\n\0")
        or password.startswith("replace-with-")
    ):
        raise SystemExit("PostgreSQL password is missing, unsafe, or too short")
    return password


def render_env(existing: str, updates: dict[str, str]) -> str:
    output: list[str] = []
    written: set[str] = set()
    for line in existing.splitlines():
        key = line.split("=", 1)[0].strip() if "=" in line else ""
        if key in updates:
            if key not in written:
                output.append(f"{key}={updates[key]}")
                written.add(key)
            continue
        output.append(line)
    if output and output[-1] != "":
        output.append("")
    for key, value in updates.items():
        if key not in written:
            output.append(f"{key}={value}")
    return "\n".join(output).rstrip("\n") + "\n"


def atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        dir=path.parent,
    )
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--env-file", type=Path, required=True)
    args = parser.parse_args()

    password = read_password()
    path = args.env_file.expanduser()
    existing = path.read_text(encoding="utf-8") if path.exists() else ""
    updates = {
        **SETTINGS,
        "ALERT_STORE_POSTGRES_PASSWORD": password,
    }
    atomic_write(path, render_env(existing, updates))
    print("postgres_shadow_env=configured_disabled")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
