"""Secure member resolution, bounded reads, and redaction for application logs."""
from __future__ import annotations

import os
from pathlib import Path

from application_log_catalog import _family_members
from application_log_contract import (
    AUTHORIZATION_RE,
    BEARER_RE,
    COOKIE_RE,
    ENSURE_STACK_RE,
    LOG_SPECS_BY_ID,
    MAX_TAIL_BYTES,
    MAX_TAIL_LINES,
    PRIVATE_KEY_RE,
    SECRET_ASSIGNMENT_RE,
    ApplicationLogError,
    LogSpec,
    is_application_log_id,
)
from application_log_filesystem import (
    _alert_store_policy,
    _iso_timestamp,
    _open_regular,
    _roots,
)


def _resolve_member(spec: LogSpec, root: Path, requested: str, home: Path) -> tuple[str, str]:
    if spec.family:
        return _resolve_family_member(root, requested)
    return _resolve_fixed_member(spec, requested, home)


def _resolve_family_member(root: Path, requested: str) -> tuple[str, str]:
    members, _count, _size = _family_members(root)
    if not members:
        raise ApplicationLogError(404, "Log file does not exist")
    member = requested or str(members[0]["id"])
    if not ENSURE_STACK_RE.fullmatch(member):
        raise ApplicationLogError(404, "Unknown log member")
    if not any(item["id"] == member for item in members):
        raise ApplicationLogError(404, "Unknown or unavailable log member")
    return member, member


def _resolve_fixed_member(
    spec: LogSpec, requested: str, home: Path
) -> tuple[str, str]:
    backups = spec.backups
    if spec.id == "alert-store-application":
        _size, backups = _alert_store_policy(home)
    allowed = {"current": spec.basename}
    allowed.update({str(index): f"{spec.basename}.{index}" for index in range(1, backups + 1)})
    member = requested or "current"
    basename = allowed.get(member)
    if basename is None:
        raise ApplicationLogError(404, "Unknown log member")
    return member, basename


def _redact(content: str) -> str:
    content = PRIVATE_KEY_RE.sub("[REDACTED PRIVATE KEY]", content)
    content = COOKIE_RE.sub(r"\1[REDACTED]", content)
    content = AUTHORIZATION_RE.sub(r"\1[REDACTED]", content)
    content = BEARER_RE.sub(r"\1[REDACTED]", content)
    return SECRET_ASSIGNMENT_RE.sub(r"\1[REDACTED]", content)


def _utf8_tail(content: str, maximum_bytes: int) -> tuple[str, int, bool]:
    """Trim text to a valid UTF-8 suffix without re-expanding replacement bytes."""
    encoded = content.encode("utf-8")
    if len(encoded) <= maximum_bytes:
        return content, len(encoded), False
    suffix = encoded[-maximum_bytes:]
    while suffix and suffix[0] & 0xC0 == 0x80:
        suffix = suffix[1:]
    while suffix:
        try:
            decoded = suffix.decode("utf-8", errors="strict")
            return decoded, len(suffix), True
        except UnicodeDecodeError:
            suffix = suffix[1:]
    return "", 0, True


def _bounded_tail(root: Path, basename: str, line_limit: int) -> dict[str, object]:
    descriptor, metadata = _open_regular(root, basename)
    try:
        size = int(metadata.st_size)
        read_size = min(size, MAX_TAIL_BYTES)
        start = max(0, size - read_size)
        os.lseek(descriptor, start, os.SEEK_SET)
        data = os.read(descriptor, read_size)
    finally:
        os.close(descriptor)
    text = data.decode("utf-8", errors="replace")
    lines = text.splitlines()
    truncated = start > 0 or len(lines) > line_limit
    selected = lines[-line_limit:]
    content = _redact("\n".join(selected))
    content, returned_bytes, byte_truncated = _utf8_tail(content, MAX_TAIL_BYTES)
    if byte_truncated:
        truncated = True
    return {
        "content": content,
        "line_count": len(selected),
        "returned_bytes": returned_bytes,
        "file_size_bytes": size,
        "modified_at": _iso_timestamp(metadata.st_mtime),
        "truncated": truncated,
        "redacted": True,
    }


def content_response(
    log_id: str,
    member: str = "",
    lines: int = 200,
    home: Path | None = None,
) -> dict[str, object]:
    if not is_application_log_id(log_id):
        raise ApplicationLogError(404, "Unknown application log")
    selected_home = Path.home() if home is None else Path(home)
    spec = LOG_SPECS_BY_ID[log_id]
    root = _roots(selected_home)[spec.root]
    selected_member, basename = _resolve_member(spec, root, member, selected_home)
    line_limit = max(1, min(MAX_TAIL_LINES, int(lines)))
    tail = _bounded_tail(root, basename, line_limit)
    return {
        "ok": True,
        "id": spec.id,
        "label": spec.label,
        "path": str(root / basename),
        "member": selected_member,
        **tail,
    }
