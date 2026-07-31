#!/usr/bin/env python3
"""Secure, bounded access to Onion Sentinel's local application logs.

The web API exposes immutable logical identifiers rather than filesystem
paths.  Every read is constrained to an owner-controlled runtime directory,
uses descriptor-relative ``O_NOFOLLOW`` opens, and returns only a bounded tail
with likely credentials redacted.
"""
from __future__ import annotations

import datetime as dt
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Final


DEFAULT_TAIL_LINES: Final = 200
MAX_TAIL_LINES: Final = 500
MAX_TAIL_BYTES: Final = 512 * 1024
MAX_ENV_BYTES: Final = 1024 * 1024
DEFAULT_ROTATION_BYTES: Final = 10 * 1024 * 1024
DEFAULT_ROTATION_BACKUPS: Final = 5
MAX_FAMILY_MEMBERS: Final = 50

LOG_ID_RE: Final = re.compile(r"[a-z0-9][a-z0-9-]{0,79}")
ENSURE_STACK_RE: Final = re.compile(
    r"ensure-n8n-stack-\d{8}-\d{6}Z\.log"
)
SECRET_ASSIGNMENT_RE: Final = re.compile(
    r"(?i)(\b(?:authorization|proxy-authorization|password|passwd|secret|"
    r"token|access[_-]?token|refresh[_-]?token|api[_-]?key|credential|"
    r"client[_-]?secret)\b\"?\s*[=:]\s*\"?)([^\"\s,;]+)"
)
BEARER_RE: Final = re.compile(r"(?i)(\bBearer\s+)[A-Za-z0-9._~+/=-]+")
COOKIE_RE: Final = re.compile(
    r"(?im)^(\s*(?:Cookie|Set-Cookie)\s*:\s*).*$"
)
AUTHORIZATION_RE: Final = re.compile(
    r"(?im)^(\s*(?:Authorization|Proxy-Authorization)\s*:\s*).*$"
)
PRIVATE_KEY_RE: Final = re.compile(
    r"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----.*?"
    r"-----END(?: [A-Z0-9]+)? PRIVATE KEY-----",
    re.DOTALL,
)


class ApplicationLogError(Exception):
    """A safe client-facing application-log error."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = int(status)
        self.message = str(message)


@dataclass(frozen=True)
class LogSpec:
    id: str
    label: str
    category: str
    root: str
    basename: str
    description: str
    format: str = "text"
    rotation: str = "Not automatically rotated"
    retention: str = "Unbounded; review and archive manually"
    backups: int = 0
    bounded: bool = False
    family: bool = False


STRUCTURED_SPECS: Final = (
    LogSpec(
        "onion-sentinel-application",
        "Onion Sentinel web application",
        "Application",
        "runtime",
        "onion-sentinel-application.jsonl",
        "HTTP requests and audited application events from the dedicated web service.",
        "JSON Lines",
        "At 10 MiB; 5 numbered backups",
        "Current file plus 5 backups (about 60 MiB maximum)",
        DEFAULT_ROTATION_BACKUPS,
        True,
    ),
    LogSpec(
        "alert-store-application",
        "Alert Store application",
        "Application",
        "runtime",
        "alert-store-application.jsonl",
        "Structured Alert Store lifecycle, API, and persistence events.",
        "JSON Lines",
        "At the configured size; numbered backups",
        "Controlled by ALERT_STORE_APPLICATION_LOG_* settings",
        DEFAULT_ROTATION_BACKUPS,
        True,
    ),
    LogSpec(
        "investigation-harness",
        "Investigation harness",
        "Investigation",
        "runtime",
        "investigation-harness.jsonl",
        "Structured harness execution, evidence, reviewer, and outcome events.",
        "JSON Lines",
        "At 10 MiB; 5 numbered backups",
        "Current file plus 5 backups (about 60 MiB maximum)",
        DEFAULT_ROTATION_BACKUPS,
        True,
    ),
    LogSpec(
        "software-inventory",
        "Software Inventory collector",
        "Inventory",
        "runtime",
        "software-inventory.jsonl",
        "Structured Software Inventory collection and normalization events.",
        "JSON Lines",
        "At 10 MiB; 5 numbered backups",
        "Current file plus 5 backups (about 60 MiB maximum)",
        DEFAULT_ROTATION_BACKUPS,
        True,
    ),
    LogSpec(
        "dhcp-asset-discovery",
        "DHCP asset discovery",
        "Inventory",
        "runtime",
        "dhcp-asset-discovery.jsonl",
        "Structured DHCP and asset-observation collection events.",
        "JSON Lines",
        "At 10 MiB; 5 numbered backups",
        "Current file plus 5 backups (about 60 MiB maximum)",
        DEFAULT_ROTATION_BACKUPS,
        True,
    ),
    LogSpec(
        "dhcp-asset-review",
        "DHCP asset review",
        "Inventory",
        "runtime",
        "dhcp-asset-review.jsonl",
        "Structured operator review and asset-promotion events, when used.",
        "JSON Lines",
        "At 10 MiB; 5 numbered backups",
        "Current file plus 5 backups (about 60 MiB maximum)",
        DEFAULT_ROTATION_BACKUPS,
        True,
    ),
    LogSpec(
        "security-onion-query",
        "Security Onion query client",
        "Investigation",
        "runtime",
        "security-onion-query.jsonl",
        "Structured relay query lifecycle and result-summary events.",
        "JSON Lines",
        "At 10 MiB; 5 numbered backups",
        "Current file plus 5 backups (about 60 MiB maximum)",
        DEFAULT_ROTATION_BACKUPS,
        True,
    ),
    LogSpec(
        "operational-slo-history",
        "Operational SLO history",
        "Health",
        "runtime",
        "operational-slo-history.jsonl",
        "Periodic production health and service-level objective snapshots.",
        "JSON Lines",
        "Rewritten as a bounded record history",
        "Latest 4,032 samples (about 14 days at five-minute intervals)",
        0,
        True,
    ),
    LogSpec(
        "llm-analysis",
        "LLM analysis transcript audit",
        "Investigation",
        "analysis",
        "llm-analysis-log.jsonl",
        "AI analysis execution records retained outside the general log directory.",
        "JSON Lines",
        "Not automatically rotated",
        "Unbounded; monitor disk use and archive according to policy",
    ),
)

LAUNCHD_STEMS: Final = (
    ("launchd-ensure-stack", "Stack ensure scheduler"),
    ("launchd-monitor-stack", "Stack monitor"),
    ("harness-maintenance", "Harness maintenance"),
    ("runtime-backup", "Runtime backup"),
    ("onion-sentinel-web-guard", "Onion Sentinel web guard"),
    ("onion-sentinel-web", "Onion Sentinel web service"),
    ("ac-hunter", "AC Hunter collector"),
    ("ai-analysis-cli", "AI analysis CLI worker"),
    ("ai-analysis", "AI analysis worker"),
    ("alert-store-maintenance", "Alert Store maintenance"),
    ("alert-store-host", "Alert Store service"),
    ("daily-rollup", "Daily rollup"),
    ("dashboard-refresh", "Dashboard refresh"),
    ("dhcp-asset-discovery", "DHCP asset discovery service"),
    ("pcap-analysis", "PCAP analysis worker"),
    ("pcap-retention", "PCAP retention"),
    ("software-inventory", "Software Inventory service"),
)


def _launchd_specs() -> tuple[LogSpec, ...]:
    specs: list[LogSpec] = []
    for stem, label in LAUNCHD_STEMS:
        for stream, stream_label in (("out", "standard output"), ("err", "standard error")):
            specs.append(
                LogSpec(
                    f"{stem}-{stream}",
                    f"{label} — {stream_label}",
                    "Service output",
                    "runtime",
                    f"{stem}.{stream}.log",
                    f"Raw launchd {stream_label} for the {label} job.",
                )
            )
    return tuple(specs)


OTHER_SPECS: Final = (
    LogSpec(
        "alert-store-sqlite-maintenance",
        "Alert Store SQLite maintenance",
        "Maintenance",
        "runtime",
        "alert-store-sqlite-maintenance.log",
        "SQLite integrity, optimization, and maintenance output.",
    ),
    LogSpec(
        "ensure-stack-runs",
        "Stack ensure run logs",
        "Maintenance",
        "runtime",
        "ensure-n8n-stack-*.log",
        "One timestamped file per stack-health reconciliation run.",
        "Text",
        "A new timestamped file is created for each run",
        "Files older than 30 days are deleted by ensure-n8n-stack",
        0,
        True,
        True,
    ),
)

LOG_SPECS: Final = STRUCTURED_SPECS + _launchd_specs() + OTHER_SPECS
LOG_SPECS_BY_ID: Final = {spec.id: spec for spec in LOG_SPECS}


def is_application_log_id(value: str) -> bool:
    return bool(LOG_ID_RE.fullmatch(value) and value in LOG_SPECS_BY_ID)


def _roots(home: Path) -> dict[str, Path]:
    base = home.expanduser() / "n8n-local"
    return {
        "runtime": base / "logs",
        "analysis": base / "soc-alerts" / "llm-analysis-logs",
    }


def _root_descriptor(root: Path) -> int:
    try:
        metadata = root.lstat()
    except FileNotFoundError as exc:
        raise ApplicationLogError(404, "Log directory does not exist") from exc
    except OSError as exc:
        raise ApplicationLogError(503, "Log directory is unavailable") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise ApplicationLogError(403, "Log directory failed security validation")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        return os.open(root, flags)
    except OSError as exc:
        raise ApplicationLogError(503, "Log directory is unavailable") from exc


def _validate_basename(value: str) -> None:
    if not value or value in {".", ".."} or Path(value).name != value or "/" in value or "\\" in value:
        raise ApplicationLogError(404, "Unknown log member")


def _member_metadata(root: Path, basename: str) -> dict[str, object] | None:
    _validate_basename(basename)
    try:
        root_fd = _root_descriptor(root)
    except ApplicationLogError as exc:
        if exc.status == 404:
            return None
        raise
    try:
        try:
            metadata = os.stat(basename, dir_fd=root_fd, follow_symlinks=False)
        except FileNotFoundError:
            return None
        except OSError:
            return None
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            return None
        return {
            "path": str(root / basename),
            "size_bytes": int(metadata.st_size),
            "modified_at": _iso_timestamp(metadata.st_mtime),
        }
    finally:
        os.close(root_fd)


def _iso_timestamp(epoch: float) -> str:
    return dt.datetime.fromtimestamp(epoch, dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _safe_env_values(home: Path) -> dict[str, str]:
    path = home.expanduser() / "n8n-local" / ".env"
    try:
        metadata = path.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
            or metadata.st_size > MAX_ENV_BYTES
        ):
            return {}
        raw = path.read_bytes()
    except OSError:
        return {}
    if len(raw) > MAX_ENV_BYTES:
        return {}
    allowed = {
        "ALERT_STORE_APPLICATION_LOG_MAX_BYTES",
        "ALERT_STORE_APPLICATION_LOG_BACKUPS",
    }
    result: dict[str, str] = {}
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        return {}
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key.strip() in allowed:
            result[key.strip()] = value.strip()
    return result


def _bounded_int(value: str | None, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value or "")
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, parsed))


def _alert_store_policy(home: Path) -> tuple[int, int]:
    values = _safe_env_values(home)
    size = _bounded_int(
        values.get("ALERT_STORE_APPLICATION_LOG_MAX_BYTES"),
        DEFAULT_ROTATION_BYTES,
        1024 * 1024,
        1024 * 1024 * 1024,
    )
    backups = _bounded_int(
        values.get("ALERT_STORE_APPLICATION_LOG_BACKUPS"),
        DEFAULT_ROTATION_BACKUPS,
        1,
        20,
    )
    return size, backups


def _fixed_members(spec: LogSpec, root: Path, backups: int) -> list[dict[str, object]]:
    candidates = [("current", "Current", spec.basename)]
    candidates.extend(
        (str(index), f"Backup {index}", f"{spec.basename}.{index}")
        for index in range(1, backups + 1)
    )
    members: list[dict[str, object]] = []
    for member_id, label, basename in candidates:
        metadata = _member_metadata(root, basename)
        if metadata is None:
            continue
        members.append({"id": member_id, "label": label, **metadata})
    return members


def _family_members(root: Path) -> tuple[list[dict[str, object]], int, int]:
    try:
        root_fd = _root_descriptor(root)
    except ApplicationLogError as exc:
        if exc.status == 404:
            return [], 0, 0
        raise
    names: list[str] = []
    retained_size = 0
    try:
        try:
            with os.scandir(root_fd) as entries:
                for entry in entries:
                    if not ENSURE_STACK_RE.fullmatch(entry.name):
                        continue
                    try:
                        metadata = entry.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    if (
                        not stat.S_ISREG(metadata.st_mode)
                        or metadata.st_uid != os.getuid()
                        or stat.S_IMODE(metadata.st_mode) & 0o022
                    ):
                        continue
                    names.append(entry.name)
                    retained_size += int(metadata.st_size)
        except OSError as exc:
            raise ApplicationLogError(503, "Log directory is unavailable") from exc
    finally:
        os.close(root_fd)
    names.sort(reverse=True)
    members: list[dict[str, object]] = []
    for name in names[:MAX_FAMILY_MEMBERS]:
        metadata = _member_metadata(root, name)
        if metadata is None:
            continue
        members.append({"id": name, "label": name, **metadata})
    return members, len(names), retained_size


def _spec_catalog_item(spec: LogSpec, home: Path) -> dict[str, object]:
    root = _roots(home)[spec.root]
    backups = spec.backups
    rotation = spec.rotation
    retention = spec.retention
    if spec.id == "alert-store-application":
        size, backups = _alert_store_policy(home)
        rotation = f"At {size:,} bytes; {backups} numbered backup(s)"
        retention = f"Current file plus {backups} configured backup(s)"

    omitted = 0
    if spec.family:
        members, member_count, retained_size = _family_members(root)
        omitted = max(0, member_count - len(members))
    else:
        members = _fixed_members(spec, root, backups)
        member_count = len(members)
        retained_size = sum(int(member["size_bytes"]) for member in members)
    current = next((member for member in members if member["id"] == "current"), None)
    if spec.family and members:
        current = members[0]
    return {
        "id": spec.id,
        "label": spec.label,
        "category": spec.category,
        "description": spec.description,
        "path": str(root / spec.basename),
        "exists": bool(members),
        "size_bytes": int(current["size_bytes"]) if current else 0,
        "retained_size_bytes": retained_size,
        "modified_at": str(current["modified_at"]) if current else "",
        "format": spec.format,
        "rotation": rotation,
        "retention": retention,
        "bounded": spec.bounded,
        "member_count": member_count,
        "omitted_member_count": omitted,
        "members": members,
    }


def catalog_response(home: Path | None = None) -> dict[str, object]:
    selected_home = Path.home() if home is None else Path(home)
    logs = [_spec_catalog_item(spec, selected_home) for spec in LOG_SPECS]
    return {
        "ok": True,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "logs": logs,
    }


def _resolve_member(spec: LogSpec, root: Path, requested: str, home: Path) -> tuple[str, str]:
    if spec.family:
        members, _count, _size = _family_members(root)
        if not members:
            raise ApplicationLogError(404, "Log file does not exist")
        member = requested or str(members[0]["id"])
        if not ENSURE_STACK_RE.fullmatch(member):
            raise ApplicationLogError(404, "Unknown log member")
        if not any(item["id"] == member for item in members):
            raise ApplicationLogError(404, "Unknown or unavailable log member")
        return member, member

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


def _open_regular(root: Path, basename: str) -> tuple[int, os.stat_result]:
    _validate_basename(basename)
    root_fd = _root_descriptor(root)
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        try:
            descriptor = os.open(basename, flags, dir_fd=root_fd)
        except FileNotFoundError as exc:
            raise ApplicationLogError(404, "Log file does not exist") from exc
        except OSError as exc:
            raise ApplicationLogError(403, "Log file failed security validation") from exc
    finally:
        os.close(root_fd)
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        os.close(descriptor)
        raise ApplicationLogError(403, "Log file failed security validation")
    return descriptor, metadata


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
    content, returned_bytes, byte_truncated = _utf8_tail(
        content,
        MAX_TAIL_BYTES,
    )
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
    lines: int = DEFAULT_TAIL_LINES,
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


__all__ = [
    "ApplicationLogError",
    "DEFAULT_TAIL_LINES",
    "LOG_SPECS",
    "MAX_TAIL_BYTES",
    "MAX_TAIL_LINES",
    "catalog_response",
    "content_response",
    "is_application_log_id",
]
