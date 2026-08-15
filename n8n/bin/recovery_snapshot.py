#!/usr/bin/env python3
"""Create and restore authenticated single-file recovery snapshots."""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import pwd
import re
import stat
import sys
import tempfile


BIN_DIR = Path(__file__).resolve().parent
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))
from recovery_encryption import (
    ENCRYPTION_SCHEME,
    PBKDF2_ITERATIONS,
    RecoveryEncryption,
    sha256_file,
)


SNAPSHOT_FORMAT = "onion-sentinel-repair-snapshot-v1"
DEFAULT_KEYCHAIN_SERVICE = "com.arron.onion-sentinel.runtime-backup.v1"
MAX_METADATA_BYTES = 32 * 1024
SHA256_PATTERN = re.compile(r"[a-f0-9]{64}")
KEY_ID_PATTERN = re.compile(r"[A-Za-z0-9._-]{1,128}")


def _owner_only_directory(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError:
        raise RuntimeError("snapshot directory is unavailable") from None
    if (
        path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise RuntimeError("snapshot directory must be owner-only")


def _owner_only_file(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except OSError:
        raise RuntimeError(f"snapshot {label} is unavailable") from None
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise RuntimeError(f"snapshot {label} must be owner-only")


def _created_at(value: str | None, source_mtime: float) -> str:
    if value is None:
        parsed = dt.datetime.fromtimestamp(source_mtime, tz=dt.timezone.utc)
    else:
        try:
            parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            raise RuntimeError("snapshot creation timestamp is invalid") from None
        if parsed.tzinfo is None:
            raise RuntimeError("snapshot creation timestamp is invalid")
    return parsed.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _atomic_json(path: Path, payload: dict[str, object], mtime: float) -> None:
    _owner_only_directory(path.parent)
    if path.exists() or path.is_symlink():
        raise RuntimeError("snapshot metadata already exists")
    descriptor, raw = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(raw)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        temporary.replace(path)
        os.chmod(path, 0o600)
        os.utime(path, (mtime, mtime), follow_symlinks=False)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def create_snapshot(
    source: Path,
    artifact: Path,
    metadata_path: Path,
    *,
    encryption: RecoveryEncryption,
    created_at: str | None = None,
) -> dict[str, object]:
    """Encrypt one verified caller-owned snapshot and publish its commit metadata."""
    source = Path(source)
    artifact = Path(artifact)
    metadata_path = Path(metadata_path)
    _owner_only_file(source, "source")
    _owner_only_directory(artifact.parent)
    _owner_only_directory(metadata_path.parent)
    if metadata_path.exists() or metadata_path.is_symlink():
        raise RuntimeError("snapshot metadata already exists")
    source_mtime = source.stat().st_mtime
    encryption_metadata = encryption.encrypt_file(source, artifact)
    try:
        os.utime(artifact, (source_mtime, source_mtime), follow_symlinks=False)
        payload = {
            "format": SNAPSHOT_FORMAT,
            "created_at": _created_at(created_at, source_mtime),
            "artifact": artifact.name,
            "ciphertext_bytes": encryption_metadata["bytes"],
            "ciphertext_sha256": encryption_metadata["sha256"],
            "plaintext_bytes": encryption_metadata["plaintext_bytes"],
            "plaintext_sha256": encryption_metadata["plaintext_sha256"],
            "encryption": encryption.descriptor,
        }
        _atomic_json(metadata_path, payload, source_mtime)
        return payload
    except BaseException:
        try:
            artifact.unlink()
        except FileNotFoundError:
            pass
        try:
            metadata_path.unlink()
        except FileNotFoundError:
            pass
        raise


def _load_metadata(path: Path) -> dict[str, object]:
    _owner_only_file(path, "metadata")
    if path.stat().st_size > MAX_METADATA_BYTES:
        raise RuntimeError("snapshot metadata exceeds its byte budget")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise RuntimeError("snapshot metadata is invalid") from None
    if not isinstance(value, dict):
        raise RuntimeError("snapshot metadata is invalid")
    return value


def _valid_metadata_timestamp(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _valid_encryption_metadata(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    return all(
        (
            value.get("scheme") == ENCRYPTION_SCHEME,
            value.get("pbkdf2_iterations") == PBKDF2_ITERATIONS,
            value.get("authenticated") is True,
            value.get("key_source") in {"injected", "macos-keychain"},
            KEY_ID_PATTERN.fullmatch(str(value.get("key_id", ""))) is not None,
        )
    )


def _valid_nonnegative_int(value: object) -> bool:
    return type(value) is int and value >= 0


def _valid_payload_metadata(value: dict[str, object]) -> bool:
    ciphertext_digest = str(value.get("ciphertext_sha256", ""))
    plaintext_digest = str(value.get("plaintext_sha256", ""))
    return all(
        (
            value.get("format") == SNAPSHOT_FORMAT,
            _valid_metadata_timestamp(value.get("created_at")),
            _valid_nonnegative_int(value.get("ciphertext_bytes")),
            _valid_nonnegative_int(value.get("plaintext_bytes")),
            SHA256_PATTERN.fullmatch(ciphertext_digest) is not None,
            SHA256_PATTERN.fullmatch(plaintext_digest) is not None,
            _valid_encryption_metadata(value.get("encryption")),
        )
    )


def _validated_metadata(
    artifact: Path, metadata_path: Path
) -> dict[str, object]:
    value = _load_metadata(metadata_path)
    if value.get("artifact") != artifact.name:
        raise RuntimeError("snapshot metadata artifact does not match")
    if not _valid_payload_metadata(value):
        raise RuntimeError("snapshot metadata contract is invalid")
    _owner_only_file(artifact, "artifact")
    if (
        artifact.stat().st_size != value["ciphertext_bytes"]
        or sha256_file(artifact) != value["ciphertext_sha256"]
    ):
        raise RuntimeError("snapshot ciphertext validation failed")
    return value


def restore_snapshot(
    artifact: Path,
    metadata_path: Path,
    destination: Path,
    *,
    encryption: RecoveryEncryption,
) -> dict[str, object]:
    """Authenticate metadata and ciphertext before publishing plaintext."""
    artifact = Path(artifact)
    metadata = _validated_metadata(artifact, Path(metadata_path))
    expected_key = dict(metadata["encryption"])["key_id"]
    if encryption.descriptor["key_id"] != expected_key:
        raise RuntimeError("snapshot key generation does not match")
    return encryption.decrypt_file(
        artifact,
        Path(destination),
        expected_plaintext_sha256=str(metadata["plaintext_sha256"]),
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "action", choices=("create", "restore"),
        help="encrypt a snapshot or authenticate and restore one",
    )
    parser.add_argument("--artifact", required=True, type=Path)
    parser.add_argument("--metadata", required=True, type=Path)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--destination", type=Path)
    parser.add_argument("--keychain-service", default=DEFAULT_KEYCHAIN_SERVICE)
    parser.add_argument(
        "--keychain-account",
        default=pwd.getpwuid(os.getuid()).pw_name,
    )
    parser.add_argument("--security", default="/usr/bin/security")
    parser.add_argument("--openssl", default="/usr/bin/openssl")
    return parser


def main() -> int:
    args = _parser().parse_args()
    if (args.action == "create") != (args.source is not None):
        _parser().error("create requires --source and restore does not accept it")
    if (args.action == "restore") != (args.destination is not None):
        _parser().error(
            "restore requires --destination and create does not accept it"
        )
    try:
        encryption = RecoveryEncryption.from_keychain(
            service=args.keychain_service,
            account=args.keychain_account,
            security=args.security,
            openssl=args.openssl,
        )
        if args.action == "create":
            create_snapshot(
                args.source,
                args.artifact,
                args.metadata,
                encryption=encryption,
            )
        else:
            restore_snapshot(
                args.artifact,
                args.metadata,
                args.destination,
                encryption=encryption,
            )
    except Exception as exc:
        print(f"recovery snapshot {args.action} failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"ok": True, "operation": args.action}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
