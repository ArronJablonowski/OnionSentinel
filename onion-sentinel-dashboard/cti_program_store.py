"""Owner-controlled atomic persistence and public projection for CTI data."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import stat
from pathlib import Path

from scripts.atomic_io import atomic_write_json

from cti_program_validation import *  # noqa: F403


def _now() -> str:
    return (
        dt.datetime.now(dt.timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def _safe_metadata(path: Path) -> os.stat_result:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise CTIProgramError(  # noqa: F405
            "CTI workspace path is not a regular file."
        )
    if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
        raise CTIProgramError(  # noqa: F405
            "CTI workspace is not owned by the service account."
        )
    if metadata.st_size > MAX_FILE_BYTES:  # noqa: F405
        raise CTIProgramError(  # noqa: F405
            f"CTI workspace exceeds {MAX_FILE_BYTES} bytes."  # noqa: F405
        )
    return metadata


def load_program(path: Path | None = None) -> dict[str, object]:
    destination = DEFAULT_PROGRAM_FILE if path is None else Path(path)  # noqa: F405
    with PROGRAM_LOCK:  # noqa: F405
        if not destination.exists():
            return _default_program()  # noqa: F405
        _safe_metadata(destination)
        try:
            raw = destination.read_bytes()
            if len(raw) > MAX_FILE_BYTES:  # noqa: F405
                raise CTIProgramError(  # noqa: F405
                    f"CTI workspace exceeds {MAX_FILE_BYTES} bytes."  # noqa: F405
                )
            parsed = json.loads(raw.decode("utf-8"))
        except UnicodeDecodeError as exc:
            raise CTIProgramError("CTI workspace is not valid UTF-8.") from exc  # noqa: F405
        except json.JSONDecodeError as exc:
            raise CTIProgramError("CTI workspace is not valid JSON.") from exc  # noqa: F405
        return normalize_program(parsed, stored=True)  # noqa: F405


def save_program(payload: object, path: Path | None = None) -> dict[str, object]:
    if not isinstance(payload, dict):
        raise CTIProgramError("Request body must be a JSON object.")  # noqa: F405
    allowed = {"expected_revision", "sources", "technologies"}
    unknown = set(payload) - allowed
    if unknown:
        raise CTIProgramError(  # noqa: F405
            f"Request contains unsupported fields: {', '.join(sorted(unknown))}."
        )
    expected_revision = payload.get("expected_revision")
    if (
        not isinstance(expected_revision, int)
        or isinstance(expected_revision, bool)
        or expected_revision < 0
    ):
        raise CTIProgramError(  # noqa: F405
            "expected_revision must be a non-negative integer."
        )
    destination = DEFAULT_PROGRAM_FILE if path is None else Path(path)  # noqa: F405
    with PROGRAM_LOCK:  # noqa: F405
        current = load_program(destination)
        if int(current["revision"]) != expected_revision:
            raise CTIProgramConflict(  # noqa: F405
                "The CTI workspace changed in another session. Reload it before saving."
            )
        candidate = normalize_program(  # noqa: F405
            {
                "schema_version": SCHEMA_VERSION,  # noqa: F405
                "revision": expected_revision,
                "updated_at": "",
                "sources": payload.get("sources", []),
                "technologies": payload.get("technologies", []),
            }
        )
        candidate["revision"] = expected_revision + 1
        candidate["updated_at"] = _now()
        rendered = json.dumps(candidate, indent=2, sort_keys=True).encode("utf-8")
        if len(rendered) > MAX_FILE_BYTES:  # noqa: F405
            raise CTIProgramError(  # noqa: F405
                f"CTI workspace exceeds {MAX_FILE_BYTES} bytes."  # noqa: F405
            )
        atomic_write_json(destination, candidate, mode=0o600)
        return candidate


def program_digest(program: dict[str, object]) -> str:
    """Return a content digest suitable for metadata-only mutation logging."""
    payload = json.dumps(
        program, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def public_response(program: dict[str, object]) -> dict[str, object]:
    return {
        "ok": True,
        "program": program,
        "editing": {
            "requires_admin": True,
            "credentials_are_references_only": True,
        },
        "limits": {
            "sources": MAX_SOURCES,  # noqa: F405
            "technologies": MAX_TECHNOLOGIES,  # noqa: F405
            "bytes": MAX_FILE_BYTES,  # noqa: F405
        },
    }


for __compat_function__ in (
    _now,
    _safe_metadata,
    load_program,
    save_program,
    program_digest,
    public_response,
):
    __compat_function__.__module__ = "cti_program"
del __compat_function__

__all__ = tuple(
    name for name in globals()
    if not (name.startswith("__") and name.endswith("__"))
)
