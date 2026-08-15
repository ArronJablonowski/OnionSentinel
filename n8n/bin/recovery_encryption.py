#!/usr/bin/env python3
"""Authenticated, streaming encryption for local recovery artifacts."""
from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile


ENCRYPTION_SCHEME = (
    "openssl-aes-256-cbc-pbkdf2-sha256+hmac-sha256-etm-v1"
)
ENVELOPE_MAGIC = b"ONION-SENTINEL-RECOVERY-ENCRYPTION-V1\n"
HMAC_SALT_BYTES = 32
HMAC_TAG_BYTES = 32
PBKDF2_ITERATIONS = 600_000
MIN_SECRET_BYTES = 32
MAX_SECRET_BYTES = 1024
CHUNK_BYTES = 1024 * 1024


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _owner_only_directory(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return False
    return (
        not path.is_symlink()
        and stat.S_ISDIR(metadata.st_mode)
        and metadata.st_uid == os.getuid()
        and not stat.S_IMODE(metadata.st_mode) & 0o077
    )


def _trusted_executable(path: str) -> Path:
    executable = Path(path)
    try:
        metadata = executable.lstat()
    except OSError:
        raise ValueError("recovery encryption executable path is invalid") from None
    if (
        not executable.is_absolute()
        or executable.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or bool(stat.S_IMODE(metadata.st_mode) & 0o022)
        or not os.access(executable, os.X_OK)
    ):
        raise ValueError("recovery encryption executable path is invalid")
    return executable


def _regular_source(path: Path, *, owner_only: bool) -> None:
    try:
        metadata = path.lstat()
    except OSError:
        raise RuntimeError(
            "recovery encryption source must be a regular owner-only file"
        ) from None
    unsafe_mode = owner_only and bool(stat.S_IMODE(metadata.st_mode) & 0o077)
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or unsafe_mode
        or not _owner_only_directory(path.parent)
    ):
        raise RuntimeError(
            "recovery encryption source must be a regular owner-only file"
        )


def _destination_parent(path: Path) -> None:
    if not _owner_only_directory(path.parent):
        raise RuntimeError(
            "recovery encryption destination must use an owner-only directory"
        )
    if path.exists() or path.is_symlink():
        raise RuntimeError("recovery encryption destination already exists")


def _temporary_path(destination: Path, label: str) -> tuple[int, Path]:
    descriptor, raw = tempfile.mkstemp(
        prefix=f".{destination.name}.{label}.",
        suffix=".tmp",
        dir=destination.parent,
    )
    os.fchmod(descriptor, 0o600)
    return descriptor, Path(raw)


def _remove(path: Path | None) -> None:
    if path is None:
        return
    try:
        path.unlink()
    except FileNotFoundError:
        pass


class RecoveryEncryption:
    """One secret-bearing encryption owner; its secret is never projected."""

    def __init__(
        self,
        secret: bytes,
        *,
        openssl: str = "/usr/bin/openssl",
        key_source: str = "injected",
        key_id: str = "injected",
    ):
        if (
            not isinstance(secret, bytes)
            or not MIN_SECRET_BYTES <= len(secret) <= MAX_SECRET_BYTES
            or any(marker in secret for marker in (b"\x00", b"\r", b"\n"))
        ):
            raise ValueError("recovery encryption secret must be at least 32 bytes")
        if key_source not in {"injected", "macos-keychain"}:
            raise ValueError("recovery encryption key source is invalid")
        if re.fullmatch(r"[A-Za-z0-9._-]{1,128}", key_id) is None:
            raise ValueError("recovery encryption key identifier is invalid")
        executable = _trusted_executable(openssl)
        self.__secret = bytes(secret)
        self.__openssl = str(executable)
        self.__key_source = key_source
        self.__key_id = key_id

    @classmethod
    def from_keychain(
        cls,
        *,
        service: str,
        account: str,
        security: str = "/usr/bin/security",
        openssl: str = "/usr/bin/openssl",
    ) -> "RecoveryEncryption":
        if not service.strip() or not account.strip():
            raise ValueError("recovery encryption keychain identity is required")
        security_path = _trusted_executable(security)
        result = subprocess.run(
            [
                str(security_path),
                "find-generic-password",
                "-w",
                "-s",
                service,
                "-a",
                account,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
            check=False,
        )
        secret = result.stdout.rstrip(b"\r\n")
        if result.returncode != 0 or not MIN_SECRET_BYTES <= len(secret) <= MAX_SECRET_BYTES:
            raise RuntimeError("recovery encryption key is unavailable")
        return cls(
            secret,
            openssl=openssl,
            key_source="macos-keychain",
            key_id=service,
        )

    @property
    def descriptor(self) -> dict[str, object]:
        return {
            "scheme": ENCRYPTION_SCHEME,
            "pbkdf2_iterations": PBKDF2_ITERATIONS,
            "authenticated": True,
            "key_source": self.__key_source,
            "key_id": self.__key_id,
        }

    def __run_openssl(self, arguments: list[str]) -> None:
        result = subprocess.run(
            [self.__openssl, *arguments],
            input=self.__secret + b"\n",
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=3600,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError("recovery encryption OpenSSL operation failed")

    def __hmac_key(self, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac(
            "sha256",
            self.__secret,
            salt + b"onion-sentinel-recovery-hmac-v1",
            PBKDF2_ITERATIONS,
            dklen=32,
        )

    def encrypt_file(self, source: Path, destination: Path) -> dict[str, object]:
        source = Path(source)
        destination = Path(destination)
        _regular_source(source, owner_only=False)
        _destination_parent(destination)
        plaintext_bytes = source.stat().st_size
        plaintext_sha256 = sha256_file(source)
        raw_fd, raw_path = _temporary_path(destination, "cipher")
        os.close(raw_fd)
        envelope_path: Path | None = None
        try:
            self.__run_openssl([
                "enc", "-aes-256-cbc", "-pbkdf2", "-iter",
                str(PBKDF2_ITERATIONS), "-md", "sha256", "-salt",
                "-in", str(source), "-out", str(raw_path), "-pass", "stdin",
            ])
            envelope_fd, envelope_path = _temporary_path(destination, "envelope")
            salt = os.urandom(HMAC_SALT_BYTES)
            prefix = ENVELOPE_MAGIC + salt
            digest = hmac.new(self.__hmac_key(salt), digestmod=hashlib.sha256)
            digest.update(prefix)
            with os.fdopen(envelope_fd, "wb") as output, raw_path.open("rb") as ciphertext:
                output.write(prefix)
                for chunk in iter(lambda: ciphertext.read(CHUNK_BYTES), b""):
                    digest.update(chunk)
                    output.write(chunk)
                output.write(digest.digest())
                output.flush()
                os.fsync(output.fileno())
            envelope_path.replace(destination)
            envelope_path = None
            os.chmod(destination, 0o600)
            return {
                **self.descriptor,
                "bytes": destination.stat().st_size,
                "sha256": sha256_file(destination),
                "plaintext_bytes": plaintext_bytes,
                "plaintext_sha256": plaintext_sha256,
            }
        finally:
            _remove(raw_path)
            _remove(envelope_path)

    def __authenticated_ciphertext(self, source: Path, raw_path: Path) -> None:
        total = source.stat().st_size
        prefix_bytes = len(ENVELOPE_MAGIC) + HMAC_SALT_BYTES
        ciphertext_bytes = total - prefix_bytes - HMAC_TAG_BYTES
        if ciphertext_bytes < 32:
            raise RuntimeError("recovery artifact authentication failed")
        with source.open("rb") as encrypted:
            magic = encrypted.read(len(ENVELOPE_MAGIC))
            salt = encrypted.read(HMAC_SALT_BYTES)
            if magic != ENVELOPE_MAGIC or len(salt) != HMAC_SALT_BYTES:
                raise RuntimeError("recovery artifact authentication failed")
            prefix = magic + salt
            digest = hmac.new(self.__hmac_key(salt), digestmod=hashlib.sha256)
            digest.update(prefix)
            remaining = ciphertext_bytes
            with raw_path.open("wb") as ciphertext:
                while remaining:
                    chunk = encrypted.read(min(CHUNK_BYTES, remaining))
                    if not chunk:
                        raise RuntimeError("recovery artifact authentication failed")
                    remaining -= len(chunk)
                    digest.update(chunk)
                    ciphertext.write(chunk)
                tag = encrypted.read(HMAC_TAG_BYTES)
                if len(tag) != HMAC_TAG_BYTES or encrypted.read(1):
                    raise RuntimeError("recovery artifact authentication failed")
            if not hmac.compare_digest(digest.digest(), tag):
                raise RuntimeError("recovery artifact authentication failed")

    def decrypt_file(
        self,
        source: Path,
        destination: Path,
        *,
        expected_plaintext_sha256: str,
    ) -> dict[str, object]:
        source = Path(source)
        destination = Path(destination)
        _regular_source(source, owner_only=True)
        _destination_parent(destination)
        if (
            not isinstance(expected_plaintext_sha256, str)
            or re.fullmatch(r"[a-f0-9]{64}", expected_plaintext_sha256) is None
        ):
            raise RuntimeError("recovery plaintext digest is invalid")
        raw_fd, raw_path = _temporary_path(destination, "cipher")
        os.close(raw_fd)
        plaintext_fd, plaintext_path = _temporary_path(destination, "plaintext")
        os.close(plaintext_fd)
        try:
            self.__authenticated_ciphertext(source, raw_path)
            self.__run_openssl([
                "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-iter",
                str(PBKDF2_ITERATIONS), "-md", "sha256",
                "-in", str(raw_path), "-out", str(plaintext_path),
                "-pass", "stdin",
            ])
            plaintext_sha256 = sha256_file(plaintext_path)
            if not hmac.compare_digest(plaintext_sha256, expected_plaintext_sha256):
                raise RuntimeError("recovery plaintext digest validation failed")
            plaintext_path.replace(destination)
            os.chmod(destination, 0o600)
            return {
                "scheme": ENCRYPTION_SCHEME,
                "plaintext_bytes": destination.stat().st_size,
                "plaintext_sha256": plaintext_sha256,
            }
        finally:
            _remove(raw_path)
            _remove(plaintext_path)
