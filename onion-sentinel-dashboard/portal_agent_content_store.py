"""Allowlisted prompt persistence and read-only agent-memory viewing."""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from http import HTTPStatus
from pathlib import Path


@dataclass(frozen=True)
class AgentMemorySources:
    directory: Path
    files: dict[str, tuple[str, Path]]
    max_bytes: int


def read_prompt_file(path: Path, label: str) -> dict:
    """Read one trusted prompt path without accepting arbitrary path input."""
    try:
        prompt = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        prompt = ""
    except Exception as exc:
        return {
            "ok": False,
            "error": f"Could not read {label} prompt: {exc}",
            "path": str(path),
        }
    return {"ok": True, "prompt": prompt, "path": str(path)}


def read_allowlisted_prompt(
    route: str,
    prompt_files: dict[str, tuple[str, Path]],
) -> dict:
    entry = prompt_files.get(route)
    if entry is None:
        return {"ok": False, "error": "Unknown SOC settings prompt route."}
    label, path = entry
    return read_prompt_file(path, label)


def save_prompt_file(
    prompt: object,
    path: Path,
    label: str,
    *,
    max_bytes: int,
) -> tuple[bool, dict]:
    """Normalize and atomically save one trusted editable prompt."""
    normalized = (
        str(prompt or "")
        .replace("\r\n", "\n")
        .replace("\r", "\n")
        .strip()
    )
    if not normalized:
        return False, {
            "ok": False,
            "error": f"{label} prompt cannot be empty.",
            "path": str(path),
        }
    encoded = normalized.encode("utf-8")
    if len(encoded) > max_bytes:
        return False, {
            "ok": False,
            "error": f"{label} prompt exceeds {max_bytes} bytes.",
            "path": str(path),
        }
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(normalized + "\n", encoding="utf-8")
        try:
            tmp.chmod(0o600)
        except Exception:
            pass
        tmp.replace(path)
    except Exception as exc:
        return False, {
            "ok": False,
            "error": f"Could not save {label} prompt: {exc}",
            "path": str(path),
        }
    return True, {
        "ok": True,
        "message": f"{label} prompt saved.",
        "path": str(path),
        "bytes": len((normalized + "\n").encode("utf-8")),
    }


def save_allowlisted_prompt(
    route: str,
    prompt: object,
    prompt_files: dict[str, tuple[str, Path]],
    *,
    max_bytes: int,
) -> tuple[bool, dict]:
    entry = prompt_files.get(route)
    if entry is None:
        return False, {
            "ok": False,
            "error": "Unknown SOC settings prompt route.",
        }
    label, path = entry
    return save_prompt_file(prompt, path, label, max_bytes=max_bytes)


def _memory_error(status: int, message: str) -> tuple[int, dict]:
    return status, {"ok": False, "error": message}


def read_agent_memory(
    sources: AgentMemorySources,
    memory_key: object,
) -> tuple[int, dict]:
    """Read one allowlisted bounded Markdown file beneath the memory root."""
    key = str(memory_key or "").strip().lower()
    entry = sources.files.get(key)
    if entry is None:
        return _memory_error(
            HTTPStatus.BAD_REQUEST, "Unknown agent memory key."
        )
    label, path = entry
    try:
        resolved_dir = sources.directory.resolve(strict=True)
        resolved_path = path.resolve(strict=True)
        resolved_path.relative_to(resolved_dir)
        metadata = resolved_path.stat()
        if not resolved_path.is_file():
            raise FileNotFoundError(str(resolved_path))
        if metadata.st_size > sources.max_bytes:
            return HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {
                "ok": False,
                "key": key,
                "label": label,
                "path": str(path),
                "bytes": metadata.st_size,
                "read_only": True,
                "error": (
                    f"{label} exceeds the {sources.max_bytes}-byte viewer limit."
                ),
            }
        content = resolved_path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return _memory_error(HTTPStatus.NOT_FOUND, f"{label} does not exist.")
    except ValueError:
        return _memory_error(
            HTTPStatus.FORBIDDEN,
            "Agent memory path escaped the configured memory directory.",
        )
    except Exception as exc:
        return _memory_error(
            HTTPStatus.INTERNAL_SERVER_ERROR,
            f"Could not read {label}: {exc}",
        )
    modified_at = (
        dt.datetime.fromtimestamp(metadata.st_mtime)
        .astimezone()
        .isoformat(timespec="seconds")
        .replace("T", "  ")
    )
    return HTTPStatus.OK, {
        "ok": True,
        "key": key,
        "label": label,
        "path": str(path),
        "content": content,
        "bytes": metadata.st_size,
        "modified_at": modified_at,
        "read_only": True,
    }
