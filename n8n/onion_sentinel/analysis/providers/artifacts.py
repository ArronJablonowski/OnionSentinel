"""Bounded, descriptor-verified provider runtime artifact readers."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat
from typing import Any


ErrorType = type[Exception]


def _validate_metadata(
    metadata: os.stat_result,
    *,
    label: str,
    max_bytes: int,
    required_mode: int | None,
    error_type: ErrorType,
) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise error_type(f"{label} must be a regular file")
    if required_mode is not None and stat.S_IMODE(metadata.st_mode) != required_mode:
        raise error_type(f"{label} must have mode {required_mode:04o}")
    if metadata.st_size > max_bytes:
        raise error_type(f"{label} exceeds its size limit")


def _admit(
    path: Path,
    *,
    label: str,
    max_bytes: int,
    required_mode: int | None,
    error_type: ErrorType,
) -> os.stat_result:
    try:
        admitted = path.lstat()
    except OSError as exc:
        raise error_type(f"{label} is missing") from exc
    if stat.S_ISLNK(admitted.st_mode):
        raise error_type(f"{label} must be a regular file")
    _validate_metadata(
        admitted,
        label=label,
        max_bytes=max_bytes,
        required_mode=required_mode,
        error_type=error_type,
    )
    return admitted


def _read_descriptor(descriptor: int, max_bytes: int) -> bytes:
    chunks: list[bytes] = []
    remaining = max_bytes + 1
    while remaining:
        chunk = os.read(descriptor, min(64 * 1024, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_regular_bytes(
    path: Path,
    *,
    max_bytes: int,
    label: str,
    error_type: ErrorType,
    required_mode: int | None = None,
) -> bytes:
    """Read a bounded regular file without symlink or replacement traversal."""
    admitted = _admit(
        path,
        label=label,
        max_bytes=max_bytes,
        required_mode=required_mode,
        error_type=error_type,
    )
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (admitted.st_dev, admitted.st_ino):
            raise error_type(f"{label} changed during admission")
        _validate_metadata(
            opened,
            label=label,
            max_bytes=max_bytes,
            required_mode=required_mode,
            error_type=error_type,
        )
        raw = _read_descriptor(descriptor, max_bytes)
        if len(raw) > max_bytes:
            raise error_type(f"{label} exceeds its size limit")
        return raw
    except OSError as exc:
        raise error_type(f"{label} is not safely readable") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def read_json_object(
    path: Path,
    *,
    max_bytes: int,
    label: str,
    error_type: ErrorType,
    required_mode: int | None = None,
) -> dict[str, Any]:
    """Read one verified UTF-8 JSON artifact whose root is an object."""
    raw = read_regular_bytes(
        path,
        max_bytes=max_bytes,
        label=label,
        error_type=error_type,
        required_mode=required_mode,
    )
    try:
        value = json.loads(raw.decode("utf-8", errors="strict"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise error_type(f"{label} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise error_type(f"{label} JSON root must be an object")
    return value


def parse_model_output_object(text: str) -> dict[str, Any]:
    """Return the first complete JSON object without repairing malformed data.

    Providers may wrap an object in a Markdown fence or append bounded prose or
    another value. The first independently decodable object is admitted; an
    array root and malformed object fragments are never coerced into evidence.
    """
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = re.sub(
            r"^```(?:json)?\s*", "", stripped, flags=re.IGNORECASE
        )
        stripped = re.sub(r"\s*```$", "", stripped)
    try:
        parsed = json.loads(stripped)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass

    decoder = json.JSONDecoder()
    for match in re.finditer(r"\{", stripped):
        try:
            parsed, _ = decoder.raw_decode(stripped, match.start())
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            continue
    raise SystemExit("model output did not contain a valid JSON object")
