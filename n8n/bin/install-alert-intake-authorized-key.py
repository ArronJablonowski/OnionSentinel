#!/usr/bin/env python3
"""Install the relay alert-intake key without corrupting authorized_keys.

The public key is accepted only on stdin. Existing authorizations are retained,
the managed forced-command entry is replaced idempotently, and the resulting
file is always newline-delimited and atomically written with mode 0600.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import ipaddress
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path


MARKER = "onion-sentinel-alert-intake@relay"
MAX_INPUT_BYTES = 16 * 1024


def read_public_key() -> tuple[str, str]:
    raw = os.read(0, MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise SystemExit("public key input exceeds the size limit")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise SystemExit("public key must be ASCII") from exc
    if "\\n" in text:
        raise SystemExit("public key contains a literal \\\\n sequence")
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if len(lines) != 1:
        raise SystemExit("provide exactly one public key on stdin")
    fields = lines[0].split()
    if len(fields) < 2 or fields[0] != "ssh-ed25519":
        raise SystemExit("the alert-intake identity must be one ssh-ed25519 public key")
    try:
        decoded = base64.b64decode(fields[1], validate=True)
    except (binascii.Error, ValueError) as exc:
        raise SystemExit("public key payload is not valid base64") from exc
    if not decoded:
        raise SystemExit("public key payload is empty")
    return fields[0], fields[1]


def load_existing(path: Path) -> list[str]:
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8")
    if "\\n" in text:
        raise SystemExit(
            "authorized_keys contains a literal \\\\n sequence; "
            "restore or normalize it before installing"
        )
    return [line.rstrip("\r") for line in text.splitlines() if line.strip()]


def forced_entry(source_ip: str, wrapper: Path, key_type: str, key_data: str) -> str:
    ipaddress.ip_address(source_ip)
    wrapper_text = str(wrapper)
    if any(character in wrapper_text for character in ('"', "\r", "\n")):
        raise SystemExit("wrapper path contains an unsupported character")
    return (
        f'from="{source_ip}",command="{wrapper_text}",'
        "no-agent-forwarding,no-X11-forwarding,no-port-forwarding,no-pty,no-user-rc "
        f"{key_type} {key_data} {MARKER}"
    )


def atomic_write(path: Path, lines: list[str]) -> Path | None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    backup = None
    if path.exists():
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        backup = path.with_name(f"{path.name}.pre-alert-intake.{stamp}")
        backup.write_bytes(path.read_bytes())
        os.chmod(backup, 0o600)
    content = "\n".join(lines).rstrip("\n") + "\n"
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
        directory = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
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
    return backup


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--authorized-keys",
        type=Path,
        default=Path.home() / ".ssh" / "authorized_keys",
    )
    parser.add_argument("--source-ip", default="10.88.8.8")
    parser.add_argument(
        "--wrapper",
        type=Path,
        default=Path.home() / "n8n-local" / "bin" / "onion-sentinel-alert-intake.py",
    )
    args = parser.parse_args()

    wrapper = args.wrapper.expanduser().resolve()
    if not wrapper.is_file() or not os.access(wrapper, os.X_OK):
        raise SystemExit("alert-intake wrapper is missing or not executable")
    key_type, key_data = read_public_key()
    path = args.authorized_keys.expanduser()
    existing = [line for line in load_existing(path) if MARKER not in line]
    existing.append(forced_entry(args.source_ip, wrapper, key_type, key_data))
    backup = atomic_write(path, existing)
    print(
        f"alert_intake_authorized_key=installed records={len(existing)} "
        f"backup_created={str(backup is not None).lower()}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
