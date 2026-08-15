"""Bounded catalog enumeration and projection for application logs."""
from __future__ import annotations

import datetime as dt
import os
import stat
from pathlib import Path

from application_log_contract import (
    ENSURE_STACK_RE,
    LOG_SPECS,
    MAX_FAMILY_MEMBERS,
    ApplicationLogError,
    LogSpec,
)
from application_log_filesystem import (
    _alert_store_policy,
    _member_metadata,
    _root_descriptor,
    _roots,
)


def _fixed_members(spec: LogSpec, root: Path, backups: int) -> list[dict[str, object]]:
    candidates = [("current", "Current", spec.basename)]
    suffix = ".gz" if spec.compression == "gzip" else ""
    candidates.extend(
        (str(index), f"Backup {index}", f"{spec.basename}.{index}{suffix}")
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
        names, retained_size = _admitted_family_names(root_fd)
    finally:
        os.close(root_fd)
    names.sort(reverse=True)
    members = _family_member_metadata(root, names)
    return members, len(names), retained_size


def _admitted_family_names(root_fd: int) -> tuple[list[str], int]:
    names: list[str] = []
    retained_size = 0
    try:
        with os.scandir(root_fd) as entries:
            for entry in entries:
                metadata = _admitted_family_metadata(entry)
                if metadata is None:
                    continue
                names.append(entry.name)
                retained_size += int(metadata.st_size)
    except OSError as exc:
        raise ApplicationLogError(503, "Log directory is unavailable") from exc
    return names, retained_size


def _admitted_family_metadata(entry: os.DirEntry[str]) -> os.stat_result | None:
    if not ENSURE_STACK_RE.fullmatch(entry.name):
        return None
    try:
        metadata = entry.stat(follow_symlinks=False)
    except OSError:
        return None
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        return None
    return metadata


def _family_member_metadata(
    root: Path, names: list[str]
) -> list[dict[str, object]]:
    members: list[dict[str, object]] = []
    for name in names[:MAX_FAMILY_MEMBERS]:
        metadata = _member_metadata(root, name)
        if metadata is None:
            continue
        members.append({"id": name, "label": name, **metadata})
    return members


def _spec_catalog_item(spec: LogSpec, home: Path) -> dict[str, object]:
    root = _roots(home)[spec.root]
    backups = spec.backups
    rotation = spec.rotation
    retention = spec.retention
    maximum_size_bytes = spec.maximum_size_bytes
    if spec.id == "alert-store-application":
        size, backups = _alert_store_policy(home)
        maximum_size_bytes = size
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
        "path_class": spec.path_class,
        "owner": spec.owner,
        "exists": bool(members),
        "size_bytes": int(current["size_bytes"]) if current else 0,
        "retained_size_bytes": retained_size,
        "modified_at": str(current["modified_at"]) if current else "",
        "format": spec.format,
        "rotation": rotation,
        "retention": retention,
        "retention_days": spec.retention_days,
        "maximum_size_bytes": maximum_size_bytes,
        "compression": spec.compression,
        "disk_pressure": spec.disk_pressure,
        "maintenance": spec.maintenance,
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
