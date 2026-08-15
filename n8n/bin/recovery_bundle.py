"""Fail-closed contract for encrypted Onion Sentinel recovery bundles."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat

from recovery_encryption import (
    ENCRYPTION_SCHEME,
    PBKDF2_ITERATIONS,
    RecoveryEncryption,
)


BUNDLE_PAYLOADS = {
    "alerts.sqlite3.enc": "alerts.sqlite3",
    "investigation-harness.sqlite3.enc": "investigation-harness.sqlite3",
    "n8n-postgres.dump.enc": "n8n-postgres.dump",
    "alert-store-postgres.dump.enc": "alert-store-postgres.dump",
    "runtime-secrets.tar.gz.enc": "runtime-secrets.tar.gz",
}
ALLOWED_BUNDLE_FILES = frozenset(BUNDLE_PAYLOADS)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def newest_bundle(root: Path) -> Path:
    bundles = sorted(
        path
        for path in root.iterdir()
        if (
            not path.name.startswith(".")
            and not path.is_symlink()
            and path.is_dir()
            and (path / "manifest.json").is_file()
            and not (path / "manifest.json").is_symlink()
        )
    )
    if not bundles:
        raise RuntimeError("no eligible recovery bundle exists")
    return bundles[-1]


def _require_owner_only_bundle(bundle: Path) -> None:
    metadata = bundle.lstat()
    if (
        bundle.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) & 0o077
        or metadata.st_uid != os.getuid()
    ):
        raise RuntimeError("recovery bundle directory must be owner-only")


def _load_owner_only_manifest(bundle: Path) -> dict[str, object]:
    path = bundle / "manifest.json"
    metadata = path.lstat()
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) & 0o077
        or metadata.st_uid != os.getuid()
    ):
        raise RuntimeError("recovery bundle manifest must be owner-only")
    manifest = json.loads(path.read_text())
    if not isinstance(manifest, dict):
        raise RuntimeError("recovery bundle manifest must be an object")
    return manifest


def _validated_manifest_path(bundle: Path, name: object) -> Path:
    pure_name = PurePosixPath(str(name))
    if (
        pure_name.is_absolute()
        or len(pure_name.parts) != 1
        or str(name) not in ALLOWED_BUNDLE_FILES
    ):
        raise RuntimeError("recovery bundle manifest contains an unsafe file")
    return bundle / str(name)


def _verify_manifest_file(
    path: Path,
    name: object,
    metadata: dict[str, object],
) -> None:
    try:
        path_metadata = path.lstat()
    except FileNotFoundError:
        raise RuntimeError(f"bundle hash validation failed for {name}") from None
    if (
        path.is_symlink()
        or not stat.S_ISREG(path_metadata.st_mode)
        or stat.S_IMODE(path_metadata.st_mode) & 0o077
        or path_metadata.st_uid != os.getuid()
        or metadata.get("bytes") != path_metadata.st_size
        or sha256_file(path) != metadata.get("sha256")
    ):
        raise RuntimeError(f"bundle hash validation failed for {name}")


def _valid_file_encryption_metadata(
    name: str,
    metadata: object,
) -> bool:
    if not isinstance(metadata, dict):
        return False
    plaintext_bytes = metadata.get("plaintext_bytes")
    plaintext_sha256 = metadata.get("plaintext_sha256")
    return (
        metadata.get("scheme") == ENCRYPTION_SCHEME
        and metadata.get("plaintext_name") == BUNDLE_PAYLOADS[name]
        and isinstance(plaintext_bytes, int)
        and plaintext_bytes >= 0
        and isinstance(plaintext_sha256, str)
        and re.fullmatch(r"[a-f0-9]{64}", plaintext_sha256) is not None
    )


def _verify_manifest_files(bundle: Path, files: dict[str, object]) -> None:
    for name, metadata in files.items():
        path = _validated_manifest_path(bundle, name)
        if not _valid_file_encryption_metadata(str(name), metadata):
            raise RuntimeError("recovery bundle encryption metadata is invalid")
        _verify_manifest_file(path, name, metadata)
    actual = {
        path.name for path in bundle.iterdir() if path.name != "manifest.json"
    }
    if actual != set(files):
        raise RuntimeError("recovery bundle contains undeclared files")


def _validate_encryption_descriptor(manifest: dict[str, object]) -> None:
    encryption = manifest.get("encryption")
    if not isinstance(encryption, dict):
        raise RuntimeError("recovery bundle encryption descriptor is invalid")
    expected = {
        "scheme": ENCRYPTION_SCHEME,
        "pbkdf2_iterations": PBKDF2_ITERATIONS,
        "authenticated": True,
        "key_source": encryption.get("key_source"),
        "key_id": encryption.get("key_id"),
    }
    if (
        encryption != expected
        or encryption.get("key_source") not in {"injected", "macos-keychain"}
        or not isinstance(encryption.get("key_id"), str)
        or re.fullmatch(r"[A-Za-z0-9._-]{1,128}", encryption["key_id"])
        is None
    ):
        raise RuntimeError("recovery bundle encryption descriptor is invalid")


def _require_optional_manifest_match(
    bundle: Path,
    manifest: dict[str, object],
    files: dict[str, object],
    *,
    section: str,
    name: str,
    message: str,
) -> None:
    key = (
        "investigation_harness"
        if section == "sqlite"
        else "alert_store_shadow"
    )
    metadata = dict(dict(manifest.get(section) or {}).get(key) or {})
    present = (bundle / name).is_file()
    if bool(metadata.get("present")) != present or present != (name in files):
        raise RuntimeError(message)


def verify_bundle(bundle: Path) -> dict[str, object]:
    _require_owner_only_bundle(bundle)
    manifest = _load_owner_only_manifest(bundle)
    _validate_encryption_descriptor(manifest)
    raw_files = manifest.get("files")
    if not isinstance(raw_files, dict):
        raise RuntimeError("recovery bundle encryption metadata is invalid")
    files = dict(raw_files)
    for name in files:
        _validated_manifest_path(bundle, name)
    required = {
        "alerts.sqlite3.enc",
        "n8n-postgres.dump.enc",
        "runtime-secrets.tar.gz.enc",
    }
    if not required.issubset(set(files)):
        raise RuntimeError("recovery bundle is missing required files")
    _verify_manifest_files(bundle, files)
    _require_optional_manifest_match(
        bundle,
        manifest,
        files,
        section="sqlite",
        name="investigation-harness.sqlite3.enc",
        message="recovery bundle harness manifest does not match its files",
    )
    _require_optional_manifest_match(
        bundle,
        manifest,
        files,
        section="postgres",
        name="alert-store-postgres.dump.enc",
        message=(
            "recovery bundle alert-store PostgreSQL manifest does not match "
            "its files"
        ),
    )
    return manifest


def decrypt_bundle_files(
    bundle: Path,
    manifest: dict[str, object],
    destination: Path,
    encryption: RecoveryEncryption,
) -> dict[str, Path]:
    metadata = destination.lstat()
    if (
        destination.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) & 0o077
        or metadata.st_uid != os.getuid()
    ):
        raise RuntimeError("recovery plaintext directory must be owner-only")
    files = dict(manifest["files"])
    decrypted: dict[str, Path] = {}
    for encrypted_name in sorted(files):
        file_metadata = dict(files[encrypted_name])
        plaintext_name = BUNDLE_PAYLOADS[encrypted_name]
        plaintext = destination / plaintext_name
        result = encryption.decrypt_file(
            bundle / encrypted_name,
            plaintext,
            expected_plaintext_sha256=file_metadata["plaintext_sha256"],
        )
        if (
            result.get("plaintext_bytes") != file_metadata["plaintext_bytes"]
            or result.get("plaintext_sha256")
            != file_metadata["plaintext_sha256"]
        ):
            try:
                plaintext.unlink()
            except FileNotFoundError:
                pass
            raise RuntimeError("recovery plaintext metadata validation failed")
        decrypted[plaintext_name] = plaintext
    return decrypted
