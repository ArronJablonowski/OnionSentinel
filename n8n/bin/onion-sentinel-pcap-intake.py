#!/usr/bin/env python3
"""Forced-command intake for relay-to-Mac PCAP transfers.

The dedicated relay key may prepare one request directory, run inbound rsync
server mode, or verify one completed tar. It cannot obtain a shell or address
paths outside the runtime PCAP intake root.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
import sys
from pathlib import Path


REQUEST_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
ROOT = Path(os.environ.get(
    "ONION_SENTINEL_PCAP_INTAKE_ROOT",
    str(Path.home() / "n8n-local" / "pcap-evidence" / "artifacts"),
))


def reject(reason: str) -> None:
    print(json.dumps({"ok": False, "status": "rejected", "error": reason}, sort_keys=True), file=sys.stderr)
    raise SystemExit(1)


def safe_request_id(value: str) -> str:
    if not REQUEST_ID.fullmatch(value or ""):
        reject("invalid request id")
    return value


def request_dir(request_id: str) -> Path:
    request_id = safe_request_id(request_id)
    root = ROOT.resolve(strict=False)
    path = (root / request_id).resolve(strict=False)
    if path.parent != root:
        reject("request directory escaped intake root")
    return path


def prepare(request_id: str) -> int:
    path = request_dir(request_id)
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o700)
    print(json.dumps({"ok": True, "status": "prepared", "request_id": request_id}, sort_keys=True))
    return 0


def verify(request_id: str, filename: str, expected_size: str, expected_sha256: str) -> int:
    request_id = safe_request_id(request_id)
    expected_name = f"{request_id}.tar"
    if filename != expected_name:
        reject("artifact name does not match request id")
    if not expected_size.isdigit() or int(expected_size) <= 0:
        reject("invalid expected artifact size")
    if not re.fullmatch(r"[a-fA-F0-9]{64}", expected_sha256 or ""):
        reject("invalid expected artifact sha256")
    path = request_dir(request_id) / filename
    if path.is_symlink() or not path.is_file():
        reject("artifact is missing or not a regular file")
    actual_size = path.stat().st_size
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    actual_sha256 = digest.hexdigest()
    if actual_size != int(expected_size) or actual_sha256 != expected_sha256.lower():
        reject("artifact size or sha256 did not match")
    print(json.dumps({"ok": True, "status": "verified", "size": actual_size, "sha256": actual_sha256}, sort_keys=True))
    return 0


def validate_rsync(args: list[str]) -> list[str]:
    if not args or Path(args[0]).name != "rsync" or "--server" not in args:
        reject("only rsync server mode is permitted")
    if "--sender" in args or "--daemon" in args:
        reject("only inbound rsync receiver mode is permitted")
    if any(arg in {"--delete", "--remove-source-files", "--rsync-path"} for arg in args):
        reject("destructive or command-changing rsync options are not permitted")
    raw_target = args[-1].rstrip("/")
    target = Path(raw_target)
    if target.is_absolute():
        resolved = target.resolve(strict=False)
    else:
        resolved = (Path.home() / target).resolve(strict=False)
    root = ROOT.resolve(strict=False)
    if resolved.parent != root or not REQUEST_ID.fullmatch(resolved.name):
        reject("rsync target is outside a single request directory")
    return args


def main() -> int:
    original = os.environ.get("SSH_ORIGINAL_COMMAND", "")
    if not original:
        reject("interactive sessions are not permitted")
    try:
        args = shlex.split(original)
    except ValueError as exc:
        reject(f"invalid command: {exc}")
    if args[:1] == ["onion-sentinel-pcap-intake"]:
        if len(args) == 3 and args[1] == "prepare":
            return prepare(args[2])
        if len(args) == 6 and args[1] == "verify":
            return verify(args[2], args[3], args[4], args[5])
        reject("unsupported intake control command")
    validated = validate_rsync(args)
    rsync = next((path for path in ("/opt/homebrew/bin/rsync", "/usr/local/bin/rsync", "/usr/bin/rsync") if Path(path).is_file()), None)
    if not rsync:
        rsync = shutil.which("rsync")
    if not rsync:
        reject("rsync is unavailable")
    os.execv(rsync, [rsync, *validated[1:]])
    return 127


if __name__ == "__main__":
    raise SystemExit(main())
