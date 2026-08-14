#!/usr/bin/env python3
"""External OpenSSL Ed25519 adapters for v2 registry governance."""

from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
from typing import Callable, Mapping


MAX_KEY_BYTES = 64 * 1024
OPENSSL_TIMEOUT_SECONDS = 10
_KEY_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{2,127}")
_SIGNATURE_RE = re.compile(r"[a-f0-9]{128}")


def _openssl_path(value: str | Path | None) -> str:
    candidate = str(value or shutil.which("openssl") or "")
    path = Path(candidate)
    try:
        details = path.stat()
    except (FileNotFoundError, OSError) as exc:
        raise ValueError("OpenSSL executable is unavailable") from exc
    if not path.is_absolute() or not stat.S_ISREG(details.st_mode):
        raise ValueError("OpenSSL executable is invalid")
    if not os.access(path, os.X_OK):
        raise ValueError("OpenSSL executable is not executable")
    return str(path)


def _key_path(value: str | Path, *, private: bool) -> Path:
    path = Path(value)
    try:
        details = path.lstat()
    except (FileNotFoundError, OSError) as exc:
        raise ValueError("Ed25519 key file is unavailable") from exc
    if path.is_symlink() or not stat.S_ISREG(details.st_mode):
        raise ValueError("Ed25519 key file must be a regular non-symlink")
    if details.st_uid != os.getuid() or details.st_size > MAX_KEY_BYTES:
        raise ValueError("Ed25519 key file ownership or size is invalid")
    if details.st_mode & 0o077:
        label = "private" if private else "trusted public"
        raise ValueError(f"Ed25519 {label} key must be owner-only")
    return path


def _key_id(value: str) -> str:
    if not isinstance(value, str) or not _KEY_ID_RE.fullmatch(value):
        raise ValueError("Ed25519 key id is invalid")
    return value


def _run_sign(openssl: str, key: Path, payload: bytes) -> bytes:
    with tempfile.NamedTemporaryFile(prefix="onion-sentinel-ed25519-payload-") as handle:
        os.fchmod(handle.fileno(), 0o600)
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
        completed = subprocess.run(
            [
                openssl, "pkeyutl", "-sign", "-rawin", "-inkey", str(key),
                "-in", handle.name,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=OPENSSL_TIMEOUT_SECONDS,
        )
    if completed.returncode != 0 or len(completed.stdout) != 64:
        raise ValueError("external Ed25519 signing failed")
    return completed.stdout


def openssl_ed25519_signer(
    private_key: str | Path,
    *,
    key_id: str,
    openssl: str | Path | None = None,
) -> Callable[[bytes], dict[str, str]]:
    """Return a signer that never exports the protected private-key bytes."""
    key = _key_path(private_key, private=True)
    identity = _key_id(key_id)
    executable = _openssl_path(openssl)

    def sign(payload: bytes) -> dict[str, str]:
        if not isinstance(payload, bytes) or not payload:
            raise ValueError("Ed25519 signing payload is invalid")
        signature = _run_sign(executable, key, payload)
        return {
            "algorithm": "external-ed25519",
            "key_id": identity,
            "value": signature.hex(),
        }

    return sign


def _verify_signature(
    openssl: str, key: Path, payload: bytes, signature: bytes,
) -> bool:
    try:
        with tempfile.TemporaryDirectory(prefix="onion-sentinel-ed25519-") as root:
            payload_path = Path(root) / "payload"
            signature_path = Path(root) / "signature"
            _write_private_temporary(payload_path, payload)
            _write_private_temporary(signature_path, signature)
            completed = subprocess.run(
                [
                    openssl, "pkeyutl", "-verify", "-pubin", "-rawin",
                    "-inkey", str(key), "-in", str(payload_path),
                    "-sigfile", str(signature_path),
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=OPENSSL_TIMEOUT_SECONDS,
            )
        return completed.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _write_private_temporary(path: Path, payload: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def openssl_ed25519_verifier(
    trusted_keys: Mapping[str, str | Path],
    *,
    openssl: str | Path | None = None,
) -> Callable[[bytes, dict[str, str]], bool]:
    """Return a verifier bound to an exact owner-controlled key-id map."""
    if not isinstance(trusted_keys, Mapping) or not trusted_keys:
        raise ValueError("trusted Ed25519 key map is invalid")
    keys = {
        _key_id(key_id): _key_path(path, private=False)
        for key_id, path in trusted_keys.items()
    }
    executable = _openssl_path(openssl)

    def verify(payload: bytes, metadata: dict[str, str]) -> bool:
        if not isinstance(payload, bytes) or not isinstance(metadata, dict):
            return False
        if metadata.get("algorithm") != "external-ed25519":
            return False
        key = keys.get(str(metadata.get("key_id") or ""))
        encoded = metadata.get("value")
        if key is None or not isinstance(encoded, str) or not _SIGNATURE_RE.fullmatch(encoded):
            return False
        return _verify_signature(executable, key, payload, bytes.fromhex(encoded))

    return verify
