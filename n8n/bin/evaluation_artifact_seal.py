"""Owner-only digest seals for terminal evaluation outputs."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import tempfile
from typing import Any, Iterable

from evaluation_artifact_contract import (
    MAX_SEAL_BYTES,
    MAX_SEALED_OUTPUTS,
    SEAL_NAME,
    SEAL_SCHEMA,
    TEMPORARY_ENTRY_NAMES,
)


def _timestamp(value: dt.datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("evaluation completion time must include a timezone")
    return value.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def _parse_timestamp(value: object) -> dt.datetime:
    text = str(value or "").strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError("evaluation seal completion time is invalid") from exc
    if parsed.tzinfo is None:
        raise ValueError("evaluation seal completion time is invalid")
    return parsed.astimezone(dt.timezone.utc)


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _digest(document: dict[str, Any]) -> str:
    unsigned = dict(document)
    unsigned.pop("seal_sha256", None)
    return hashlib.sha256(_canonical(unsigned)).hexdigest()


def _owner_private_directory(path: Path) -> Path:
    candidate = path.expanduser()
    try:
        metadata = candidate.lstat()
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise ValueError("evaluation run directory is unavailable") from exc
    if (
        not candidate.is_absolute()
        or candidate != resolved
        or stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise ValueError("evaluation run directory must be canonical and owner-only")
    return resolved


def _admit_output(run_dir: Path, path: Path) -> tuple[Path, os.stat_result]:
    candidate = path.expanduser()
    try:
        metadata = candidate.lstat()
        resolved = candidate.resolve(strict=True)
        relative = resolved.relative_to(run_dir)
    except (OSError, ValueError) as exc:
        raise ValueError("sealed output must stay inside the evaluation run") from exc
    if (
        candidate != resolved
        or stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
        or relative == Path(SEAL_NAME)
        or any(part in TEMPORARY_ENTRY_NAMES for part in relative.parts)
    ):
        raise ValueError(
            "sealed output must be an owner-only non-temporary regular file"
        )
    return relative, metadata


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_seal(
    run_dir: Path,
    *,
    outputs: Iterable[Path],
    completed_at: dt.datetime,
) -> dict[str, Any]:
    root = _owner_private_directory(run_dir)
    paths = tuple(outputs)
    if not paths or len(paths) > MAX_SEALED_OUTPUTS:
        raise ValueError("evaluation seal output count is invalid")
    records = []
    for output in paths:
        relative, metadata = _admit_output(root, output)
        records.append(
            {
                "path": relative.as_posix(),
                "bytes": int(metadata.st_size),
                "sha256": _sha256_file(output),
            }
        )
    records.sort(key=lambda item: item["path"])
    if len({item["path"] for item in records}) != len(records):
        raise ValueError("evaluation seal contains duplicate output paths")
    document = {
        "schema": SEAL_SCHEMA,
        "completed_at": _timestamp(completed_at),
        "outputs": records,
    }
    document["seal_sha256"] = _digest(document)
    return document


def write_seal(
    run_dir: Path,
    *,
    outputs: Iterable[Path],
    completed_at: dt.datetime,
) -> Path:
    root = _owner_private_directory(run_dir)
    target = root / SEAL_NAME
    if target.exists() or target.is_symlink():
        raise ValueError("evaluation artifact seal already exists")
    payload = json.dumps(
        build_seal(root, outputs=outputs, completed_at=completed_at),
        indent=2,
        sort_keys=True,
    ).encode("utf-8") + b"\n"
    if len(payload) > MAX_SEAL_BYTES:
        raise ValueError("evaluation artifact seal exceeds its size bound")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{SEAL_NAME}.", suffix=".tmp", dir=root
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
        os.chmod(target, 0o600)
    finally:
        temporary.unlink(missing_ok=True)
    return target


def _relative_output(value: object) -> Path:
    text = str(value or "")
    pure = PurePosixPath(text)
    if not text or pure.is_absolute() or ".." in pure.parts or "\\" in text:
        raise ValueError("evaluation seal output path is invalid")
    return Path(*pure.parts)


def _read_seal(root: Path) -> dict[str, Any]:
    path = root / SEAL_NAME
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ValueError("evaluation artifact seal is missing") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_size > MAX_SEAL_BYTES
    ):
        raise ValueError("evaluation artifact seal must be owner-only and bounded")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("evaluation artifact seal is invalid JSON") from exc
    if not isinstance(document, dict) or document.get("schema") != SEAL_SCHEMA:
        raise ValueError("evaluation artifact seal schema is invalid")
    return document


def _verify_document(document: dict[str, Any]) -> dt.datetime:
    if set(document) != {"schema", "completed_at", "outputs", "seal_sha256"}:
        raise ValueError("evaluation artifact seal fields are invalid")
    if str(document.get("seal_sha256") or "") != _digest(document):
        raise ValueError("evaluation artifact seal digest is invalid")
    return _parse_timestamp(document.get("completed_at"))


def _verify_output_record(
    root: Path, record: object, seen: set[str],
) -> None:
    if not isinstance(record, dict) or set(record) != {"path", "bytes", "sha256"}:
        raise ValueError("evaluation artifact seal output record is invalid")
    relative = _relative_output(record["path"])
    if relative.as_posix() in seen:
        raise ValueError("evaluation artifact seal output path is duplicated")
    seen.add(relative.as_posix())
    output = root / relative
    _, output_metadata = _admit_output(root, output)
    if int(record.get("bytes") or -1) != output_metadata.st_size:
        raise ValueError("sealed output byte count changed")
    if str(record.get("sha256") or "") != _sha256_file(output):
        raise ValueError("sealed output digest changed")


def _verify_outputs(root: Path, outputs: object) -> int:
    if not isinstance(outputs, list) or not outputs or len(outputs) > MAX_SEALED_OUTPUTS:
        raise ValueError("evaluation artifact seal output list is invalid")
    seen: set[str] = set()
    for record in outputs:
        _verify_output_record(root, record, seen)
    return len(outputs)


def verify_seal(run_dir: Path) -> dict[str, Any]:
    root = _owner_private_directory(run_dir)
    document = _read_seal(root)
    completed = _verify_document(document)
    output_count = _verify_outputs(root, document.get("outputs"))
    return {
        "completed_at": completed,
        "output_count": output_count,
        "seal_sha256": document["seal_sha256"],
    }


__all__ = ["build_seal", "verify_seal", "write_seal"]
