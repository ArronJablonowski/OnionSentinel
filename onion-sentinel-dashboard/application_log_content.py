"""Secure member resolution, bounded reads, and redaction for application logs."""
from __future__ import annotations

import gzip
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
    suffix = ".gz" if spec.compression == "gzip" else ""
    allowed.update(
        {
            str(index): f"{spec.basename}.{index}{suffix}"
            for index in range(1, backups + 1)
        }
    )
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
    return _bounded_regular_page(root, basename, line_limit, before=None)


def _page_content(
    data: bytes,
    *,
    window_start: int,
    page_end: int,
    total_size: int,
    line_limit: int,
) -> dict[str, object]:
    segments = data.splitlines(keepends=True)
    selected = segments[-line_limit:]
    omitted_bytes = sum(len(segment) for segment in segments[:-line_limit])
    page_start = window_start + omitted_bytes
    raw = b"".join(selected)
    text = raw.decode("utf-8", errors="replace")
    content = _redact("\n".join(text.splitlines()))
    content, returned_bytes, byte_truncated = _utf8_tail(content, MAX_TAIL_BYTES)
    return {
        "content": content,
        "line_count": len(selected),
        "returned_bytes": returned_bytes,
        "file_size_bytes": total_size,
        "truncated": page_start > 0 or page_end < total_size or byte_truncated,
        "has_older": page_start > 0,
        "has_newer": page_end < total_size,
        "next_before": page_start if page_start > 0 else None,
        "page_start": page_start,
        "page_end": page_end,
        "redacted": True,
    }


def _bounded_regular_page(
    root: Path,
    basename: str,
    line_limit: int,
    before: int | None,
) -> dict[str, object]:
    descriptor, metadata = _open_regular(root, basename)
    try:
        size = int(metadata.st_size)
        end = size if before is None else min(size, before)
        start = max(0, end - MAX_TAIL_BYTES)
        os.lseek(descriptor, start, os.SEEK_SET)
        data = os.read(descriptor, end - start)
    finally:
        os.close(descriptor)
    return {
        **_page_content(
            data,
            window_start=start,
            page_end=end,
            total_size=size,
            line_limit=line_limit,
        ),
        "modified_at": _iso_timestamp(metadata.st_mtime),
    }


def _bounded_gzip_page(
    root: Path,
    basename: str,
    line_limit: int,
    before: int | None,
    maximum_expanded_bytes: int,
) -> dict[str, object]:
    descriptor, metadata = _open_regular(root, basename)
    try:
        total = 0
        window = bytearray()
        with os.fdopen(descriptor, "rb", closefd=False) as raw:
            with gzip.GzipFile(fileobj=raw, mode="rb") as archive:
                while True:
                    chunk = archive.read(min(1024 * 1024, maximum_expanded_bytes + 1 - total))
                    if not chunk:
                        break
                    chunk_start = total
                    total += len(chunk)
                    if total > maximum_expanded_bytes:
                        raise ApplicationLogError(413, "Compressed log member exceeds its expansion bound")
                    target_end = total if before is None else min(total, before)
                    admitted = max(0, target_end - chunk_start)
                    if admitted:
                        window.extend(chunk[:admitted])
                        if len(window) > MAX_TAIL_BYTES:
                            del window[:-MAX_TAIL_BYTES]
    except (OSError, EOFError) as exc:
        raise ApplicationLogError(422, "Compressed log member is invalid") from exc
    finally:
        os.close(descriptor)
    end = total if before is None else min(total, before)
    start = max(0, end - len(window))
    return {
        **_page_content(
            bytes(window),
            window_start=start,
            page_end=end,
            total_size=total,
            line_limit=line_limit,
        ),
        "compressed_size_bytes": int(metadata.st_size),
        "modified_at": _iso_timestamp(metadata.st_mtime),
    }


def content_response(
    log_id: str,
    member: str = "",
    lines: int = 200,
    home: Path | None = None,
    before: int | None = None,
) -> dict[str, object]:
    if not is_application_log_id(log_id):
        raise ApplicationLogError(404, "Unknown application log")
    selected_home = Path.home() if home is None else Path(home)
    spec = LOG_SPECS_BY_ID[log_id]
    root = _roots(selected_home)[spec.root]
    selected_member, basename = _resolve_member(spec, root, member, selected_home)
    line_limit = max(1, min(MAX_TAIL_LINES, int(lines)))
    if before is not None and int(before) < 0:
        raise ApplicationLogError(400, "before must be a non-negative integer")
    if basename.endswith(".gz"):
        tail = _bounded_gzip_page(
            root,
            basename,
            line_limit,
            None if before is None else int(before),
            max(spec.maximum_size_bytes, MAX_TAIL_BYTES),
        )
    else:
        tail = _bounded_regular_page(
            root,
            basename,
            line_limit,
            None if before is None else int(before),
        )
    return {
        "ok": True,
        "id": spec.id,
        "label": spec.label,
        "path": str(root / basename),
        "member": selected_member,
        **tail,
    }
