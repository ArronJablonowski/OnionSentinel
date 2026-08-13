#!/usr/bin/env python3
"""Forced-command intake for relay-to-Mac PCAP transfers.

The dedicated relay key may prepare or clean one request directory, run inbound
rsync server mode, or verify one completed tar. It cannot obtain a shell or
address paths outside the runtime PCAP intake root.
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

BIN_DIR = Path(__file__).resolve().parent
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))
from disk_capacity import DiskCapacityError, require_runtime_capacity


REQUEST_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
ROOT = Path(os.environ.get(
    "ONION_SENTINEL_PCAP_INTAKE_ROOT", str(Path.home() / "n8n-local" / "pcap-evidence" / "artifacts"),
))
RESERVATION_NAME = ".onion-sentinel-reservation.json"
MAX_ARTIFACT_BYTES = max(1, int(os.environ.get(
    "ONION_SENTINEL_PCAP_INTAKE_MAX_ARTIFACT_BYTES",
    str(128 * 1024**3),
)))


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


def parse_size(value: str) -> int:
    if not str(value or "").isdigit() or int(value) <= 0:
        reject("invalid expected artifact size")
    size = int(value)
    if size > MAX_ARTIFACT_BYTES:
        reject("artifact exceeds Mac intake size limit")
    return size


def reservation_path(request_id: str) -> Path:
    return request_dir(request_id) / RESERVATION_NAME


def load_reservation(request_id: str) -> dict:
    path = reservation_path(request_id)
    if path.is_symlink() or not path.is_file():
        reject("PCAP intake reservation is missing")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        reject("PCAP intake reservation is invalid")
    if payload.get("request_id") != request_id or int(payload.get("expected_size") or 0) <= 0:
        reject("PCAP intake reservation does not match request")
    return payload


def write_reservation(request_id: str, expected_size: int, verified: bool = False) -> None:
    path = reservation_path(request_id)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps({
        "request_id": request_id,
        "expected_size": expected_size,
        "verified": bool(verified),
    }, sort_keys=True) + "\n", encoding="utf-8")
    temporary.chmod(0o600)
    temporary.replace(path)


def admit_capacity(path: Path, additional_bytes: int, label: str) -> None:
    try:
        require_runtime_capacity(path, additional_bytes, label=label)
    except DiskCapacityError as exc:
        reject(str(exc))


def prepare(request_id: str, expected_size: str) -> int:
    request_id = safe_request_id(request_id)
    size = parse_size(expected_size)
    path = request_dir(request_id)
    expected_artifact = path / f"{request_id}.tar"
    existing_size = expected_artifact.stat().st_size if expected_artifact.is_file() else 0
    admit_capacity(
        path,
        max(0, size - existing_size),
        f"PCAP intake {request_id}",
    )
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o700)
    unexpected = [item.name for item in path.iterdir() if item.name not in {f"{request_id}.tar", RESERVATION_NAME}]
    if unexpected:
        reject("request directory contains unexpected files")
    if reservation_path(request_id).exists():
        prior = load_reservation(request_id)
        if int(prior["expected_size"]) != size:
            reject("existing reservation size does not match request")
    write_reservation(request_id, size)
    print(json.dumps({"ok": True, "status": "prepared", "request_id": request_id, "expected_size": size}, sort_keys=True))
    return 0


def verify(request_id: str, filename: str, expected_size: str, expected_sha256: str) -> int:
    request_id = safe_request_id(request_id)
    expected_name = f"{request_id}.tar"
    if filename != expected_name:
        reject("artifact name does not match request id")
    size = parse_size(expected_size)
    if not re.fullmatch(r"[a-fA-F0-9]{64}", expected_sha256 or ""):
        reject("invalid expected artifact sha256")
    reservation = load_reservation(request_id)
    if int(reservation["expected_size"]) != size:
        reject("artifact size does not match intake reservation")
    path = request_dir(request_id) / filename
    if path.is_symlink() or not path.is_file():
        reject("artifact is missing or not a regular file")
    actual_size = path.stat().st_size
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    actual_sha256 = digest.hexdigest()
    if actual_size != size or actual_sha256 != expected_sha256.lower():
        reject("artifact size or sha256 did not match")
    write_reservation(request_id, size, verified=True)
    print(json.dumps({"ok": True, "status": "verified", "size": actual_size, "sha256": actual_sha256}, sort_keys=True))
    return 0


def cleanup(request_id: str) -> int:
    """Remove one failed or superseded request without exposing arbitrary paths."""
    request_id = safe_request_id(request_id)
    path = request_dir(request_id)
    if path.is_symlink():
        reject("request directory cannot be a symlink")
    if path.exists():
        if not path.is_dir():
            reject("request path is not a directory")
        shutil.rmtree(path)
    print(json.dumps({"ok": True, "status": "cleaned", "request_id": request_id}, sort_keys=True))
    return 0


def _admit_rsync_mode(args: list[str]) -> None:
    if not args or Path(args[0]).name != "rsync" or "--server" not in args:
        reject("only rsync server mode is permitted")
    if "--sender" in args or "--daemon" in args:
        reject("only inbound rsync receiver mode is permitted")
    if any(arg in {"--delete", "--remove-source-files", "--rsync-path"} for arg in args):
        reject("destructive or command-changing rsync options are not permitted")


def _resolve_rsync_target(raw_target: str) -> Path:
    raw_target = raw_target.rstrip("/")
    target = Path(raw_target)
    resolved = target.resolve(strict=False) if target.is_absolute() else (Path.home() / target).resolve(strict=False)
    root = ROOT.resolve(strict=False)
    if resolved.parent != root or not REQUEST_ID.fullmatch(resolved.name):
        reject("rsync target is outside a single request directory")
    return resolved


def _admit_rsync_capacity(args: list[str], resolved: Path) -> None:
    request_id = resolved.name
    reservation = load_reservation(request_id)
    expected_size = int(reservation["expected_size"])
    artifact = resolved / f"{request_id}.tar"
    current_size = artifact.stat().st_size if artifact.is_file() else 0
    admit_capacity(
        resolved,
        max(0, expected_size - current_size),
        f"PCAP rsync {request_id}",
    )
    if not any(arg.startswith("--max-size=") for arg in args):
        args.insert(-2, f"--max-size={expected_size}")


def validate_rsync(args: list[str]) -> list[str]:
    _admit_rsync_mode(args)
    _admit_rsync_capacity(args, _resolve_rsync_target(args[-1]))
    return args


def _original_command() -> list[str]:
    original = os.environ.get("SSH_ORIGINAL_COMMAND", "")
    if not original:
        reject("interactive sessions are not permitted")
    try:
        return shlex.split(original)
    except ValueError as exc:
        reject(f"invalid command: {exc}")


def _dispatch_control(args: list[str]) -> int:
    if len(args) == 4 and args[1] == "prepare":
        return prepare(args[2], args[3])
    if len(args) == 6 and args[1] == "verify":
        return verify(args[2], args[3], args[4], args[5])
    if len(args) == 3 and args[1] == "cleanup":
        return cleanup(args[2])
    reject("unsupported intake control command")


def _rsync_executable() -> str:
    rsync = next((path for path in ("/opt/homebrew/bin/rsync", "/usr/local/bin/rsync", "/usr/bin/rsync") if Path(path).is_file()), None)
    if not rsync:
        rsync = shutil.which("rsync")
    if not rsync:
        reject("rsync is unavailable")
    return rsync


def _exec_rsync(validated: list[str]) -> int:
    rsync = _rsync_executable()
    os.execv(rsync, [rsync, *validated[1:]])
    return 127


def main() -> int:
    args = _original_command()
    if args[:1] == ["onion-sentinel-pcap-intake"]:
        return _dispatch_control(args)
    return _exec_rsync(validate_rsync(args))


if __name__ == "__main__":
    raise SystemExit(main())
