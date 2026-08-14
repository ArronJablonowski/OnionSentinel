"""Filesystem-safe readiness checks for optional CLI analysis providers."""
from __future__ import annotations

import json
import os
import stat
from collections.abc import Callable
from pathlib import Path


def resolve_cli_harness(
    configured: object,
    basename: str,
    *,
    home: Path,
    discover: Callable[[str], str | None],
) -> Path | None:
    """Resolve one executable without running it, in the fixed runner order."""
    executable = str(configured or basename).strip()
    path = Path(executable)
    if path.is_absolute():
        candidates = [path]
    else:
        candidates = []
        discovered = discover(basename)
        if discovered:
            candidates.append(Path(discovered))
        candidates.extend([
            home / ".local" / "bin" / basename,
            Path("/opt/homebrew/bin") / basename,
            Path("/usr/local/bin") / basename,
        ])
    seen = set()
    for candidate in candidates:
        candidate_text = str(candidate)
        if candidate_text in seen:
            continue
        seen.add(candidate_text)
        if (
            candidate.name == basename
            and candidate.is_file()
            and os.access(candidate, os.X_OK)
        ):
            return candidate
    return None


def _owner_private_metadata_error(path: Path, max_bytes: int) -> str:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return "missing"
    except OSError:
        return "inspection_failed"
    mode = stat.S_IMODE(metadata.st_mode)
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        return "not_regular"
    if mode != 0o600:
        return "unsafe_mode"
    if metadata.st_size <= 0 or metadata.st_size > max_bytes:
        return "unsafe_size"
    return ""


def _read_owner_private_bytes(path: Path, max_bytes: int) -> tuple[bytes, str]:
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or stat.S_IMODE(opened.st_mode) != 0o600
        ):
            return b"", "changed_after_check"
        remaining = max_bytes + 1
        chunks = []
        while remaining > 0:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
    except OSError:
        return b"", "read_failed"
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not raw or len(raw) > max_bytes:
        return b"", "unsafe_size"
    return raw, ""


def _read_owner_private_json(path: Path, max_bytes: int) -> tuple[object, str]:
    if error := _owner_private_metadata_error(path, max_bytes):
        return None, error
    raw, error = _read_owner_private_bytes(path, max_bytes)
    if error:
        return None, error
    try:
        return json.loads(raw.decode("utf-8", errors="strict")), ""
    except (UnicodeError, json.JSONDecodeError):
        return None, "invalid_json"


def hermes_auth_readiness_error(path: Path, max_bytes: int) -> str:
    """Return a safe operator-facing error for the dedicated Hermes credential."""
    auth_store, error = _read_owner_private_json(path, max_bytes)
    if error:
        return _hermes_auth_file_error(error)
    return _hermes_auth_store_error(auth_store)


def _hermes_auth_file_error(error: str) -> str:
    return {
        "missing": (
            "Hermes Agent authentication is unavailable at "
            "~/n8n-local/private/hermes-agent/auth.json."
        ),
        "inspection_failed": "Hermes Agent authentication file could not be inspected.",
        "not_regular": "Hermes Agent authentication must be a regular, non-symlink file.",
        "unsafe_mode": (
            "Hermes Agent authentication permissions are unsafe; "
            "set the file mode to 0600."
        ),
        "unsafe_size": "Hermes Agent authentication file is empty or exceeds 2 MiB.",
        "changed_after_check": (
            "Hermes Agent authentication must remain a regular owner-only file."
        ),
        "read_failed": "Hermes Agent authentication file is not safely readable.",
        "invalid_json": "Hermes Agent authentication file is not valid bounded JSON.",
    }[error]


def _hermes_auth_store_error(auth_store: object) -> str:
    if not isinstance(auth_store, dict):
        return "Hermes Agent authentication JSON root must be an object."
    providers = auth_store.get("providers")
    provider_state = (
        providers.get("openai-codex") if isinstance(providers, dict) else None
    )
    credential_pool = auth_store.get("credential_pool")
    pool_entries = (
        credential_pool.get("openai-codex")
        if isinstance(credential_pool, dict)
        else None
    )
    pool_is_valid = _hermes_pool_is_valid(pool_entries)
    if isinstance(pool_entries, list) and not pool_is_valid:
        return "Hermes Agent openai-codex credential pool is invalid."
    has_provider = isinstance(provider_state, dict) and bool(provider_state)
    has_pool = pool_is_valid and bool(pool_entries)
    if not (has_provider or has_pool):
        return (
            "Hermes Agent authentication does not contain dedicated "
            "openai-codex credentials."
        )
    return ""


def _hermes_pool_is_valid(pool_entries: object) -> bool:
    return isinstance(pool_entries, list) and not any(
        not isinstance(entry, dict)
        or (
            entry.get("provider") is not None
            and str(entry.get("provider")).strip() != "openai-codex"
        )
        for entry in pool_entries
    )


def enabled_cli_harnesses_ready(
    settings: dict,
    *,
    boolean_setting: Callable[[object], bool],
    resolve: Callable[[object, str], Path | None],
    hermes_auth_error: Callable[[], str],
) -> tuple[bool, str]:
    """Fail a settings save when an enabled harness cannot safely start."""
    for enabled_key, path_key, basename, label in (
        ("hermes_agent_enabled", "hermes_agent_path", "hermes", "Hermes Agent"),
        ("openclaw_enabled", "openclaw_path", "openclaw", "OpenClaw"),
    ):
        if not boolean_setting(settings.get(enabled_key)):
            continue
        if resolve(settings.get(path_key), basename) is None:
            return False, (
                f"{label} is enabled but its executable is unavailable. "
                f"Install {basename} or configure an executable absolute path."
            )
        if basename == "hermes" and (auth_error := hermes_auth_error()):
            return False, auth_error
    return True, ""
