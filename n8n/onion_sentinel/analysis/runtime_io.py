"""Bounded runtime artifact I/O for local AI analysis."""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any, TypeVar


ErrorT = TypeVar("ErrorT", bound=Exception)


def atomic_write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(data, indent=2, sort_keys=True) + "\n")
        tmp.replace(path)
    finally:
        tmp.unlink(missing_ok=True)


def atomic_write_private_json(path: Path, data: dict[str, Any]) -> None:
    """Atomically persist owner-only state and sync its directory entry."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, stat.S_IRWXU)
    fd, tmp_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    tmp = Path(tmp_name)
    try:
        os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(data, indent=2, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        tmp.replace(path)
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        tmp.unlink(missing_ok=True)


def canonical_payload_digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            default=str,
        ).encode("utf-8")
    ).hexdigest()


def active_analysis_record_path(run_id: object, active_dir: Path) -> Path:
    safe_run_id = re.sub(
        r"[^A-Za-z0-9_-]+", "-", str(run_id or "analysis")
    ).strip("-_")
    return active_dir / f"{(safe_run_id or 'analysis')[:120]}.json"


def append_jsonl(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(data, sort_keys=True) + "\n")


def best_effort_warning(message: str) -> None:
    """Report supplemental failures without risking a committed job result."""
    try:
        sys.stderr.write(f"warning: {message}\n")
        sys.stderr.flush()
    except Exception:
        pass


def read_bytes_bounded(
    path: Path,
    max_bytes: int,
    *,
    error_type: type[ErrorT],
) -> bytes:
    """Read a regular runtime artifact only inside its admission limit."""
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise error_type(f"cannot stat {path}: {exc}") from exc
    if size > max_bytes:
        raise error_type(
            f"runtime artifact exceeds {max_bytes} byte limit: {path}"
        )
    try:
        with path.open("rb") as handle:
            data = handle.read(max_bytes + 1)
    except OSError as exc:
        raise error_type(f"cannot read {path}: {exc}") from exc
    if len(data) > max_bytes:
        raise error_type(
            f"runtime artifact grew beyond {max_bytes} byte limit: {path}"
        )
    return data


def load_json(
    path: Path,
    max_bytes: int,
    *,
    error_type: type[ErrorT],
) -> dict[str, Any]:
    try:
        value = json.loads(
            read_bytes_bounded(
                path, max_bytes, error_type=error_type
            ).decode("utf-8", errors="strict")
        )
    except (error_type, UnicodeError, json.JSONDecodeError) as exc:
        raise error_type(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise error_type(f"JSON root must be an object: {path}")
    return value


def load_system_prompt(
    path: Path,
    *,
    max_bytes: int,
    default_prompt: str,
    error_type: type[ErrorT],
) -> str:
    if not path.exists():
        return default_prompt
    prompt = read_bytes_bounded(
        path, max_bytes, error_type=error_type
    ).decode("utf-8", errors="replace").strip()
    return prompt or default_prompt
