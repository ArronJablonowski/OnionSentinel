#!/usr/bin/env python3
"""Shared disk admission control for Mac Studio runtime jobs.

Disk-heavy work stops at the start threshold, before the hard ceiling is
reached.  The gap is intentional headroom for SQLite, PostgreSQL, logs, and
macOS itself while an operator clears space.
"""
from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Any


GIB = 1024**3
DEFAULT_START_MAX_USED_PERCENT = 75.0
DEFAULT_HARD_MAX_USED_PERCENT = 80.0
DEFAULT_MIN_FREE_BYTES = 50 * GIB


class DiskCapacityError(RuntimeError):
    """Raised when new work would violate the runtime disk reserve."""


def env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default


def env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default


def existing_anchor(path: Path) -> Path:
    """Return the nearest existing parent so pre-create checks are reliable."""
    candidate = path.expanduser().resolve(strict=False)
    while not candidate.exists() and candidate != candidate.parent:
        candidate = candidate.parent
    return candidate


def capacity_snapshot(path: Path, additional_bytes: int = 0) -> dict[str, Any]:
    additional = max(0, int(additional_bytes))
    anchor = existing_anchor(path)
    usage = shutil.disk_usage(anchor)
    used_percent = (usage.used / usage.total * 100) if usage.total else 100.0
    projected_percent = ((usage.used + additional) / usage.total * 100) if usage.total else 100.0
    return {
        "path": str(path),
        "filesystem_anchor": str(anchor),
        "total_bytes": usage.total,
        "used_bytes": usage.used,
        "free_bytes": usage.free,
        "additional_bytes": additional,
        "free_after_bytes": usage.free - additional,
        "used_percent": round(used_percent, 2),
        "projected_used_percent": round(projected_percent, 2),
    }


def runtime_policy() -> tuple[float, float, int]:
    hard = min(DEFAULT_HARD_MAX_USED_PERCENT, max(2.0, env_float(
        "ONION_SENTINEL_DISK_HARD_MAX_USED_PERCENT",
        DEFAULT_HARD_MAX_USED_PERCENT,
    )))
    start = min(hard - 0.1, max(1.0, env_float(
        "ONION_SENTINEL_DISK_START_MAX_USED_PERCENT",
        DEFAULT_START_MAX_USED_PERCENT,
    )))
    minimum_free = max(0, env_int(
        "ONION_SENTINEL_DISK_MIN_FREE_BYTES",
        DEFAULT_MIN_FREE_BYTES,
    ))
    return start, hard, minimum_free


def require_runtime_capacity(
    path: Path,
    additional_bytes: int = 0,
    *,
    label: str = "runtime work",
    start_max_used_percent: float | None = None,
    hard_max_used_percent: float | None = None,
    min_free_bytes: int | None = None,
) -> dict[str, Any]:
    """Reject new work before it can consume the protected disk reserve."""
    policy_start, policy_hard, policy_free = runtime_policy()
    start = policy_start if start_max_used_percent is None else float(start_max_used_percent)
    hard = policy_hard if hard_max_used_percent is None else float(hard_max_used_percent)
    minimum_free = policy_free if min_free_bytes is None else max(0, int(min_free_bytes))
    if start >= hard:
        raise ValueError("disk start threshold must be below the hard threshold")

    snapshot = capacity_snapshot(path, additional_bytes)
    if snapshot["used_percent"] >= hard:
        raise DiskCapacityError(
            f"{label} refused: disk is {snapshot['used_percent']:.2f}% used; hard limit is {hard:.2f}%"
        )
    if snapshot["used_percent"] >= start:
        raise DiskCapacityError(
            f"{label} refused: disk is {snapshot['used_percent']:.2f}% used; new-work limit is {start:.2f}%"
        )
    if snapshot["projected_used_percent"] >= start:
        raise DiskCapacityError(
            f"{label} refused: projected disk use is {snapshot['projected_used_percent']:.2f}%; "
            f"new-work limit is {start:.2f}%"
        )
    if snapshot["free_after_bytes"] < minimum_free:
        raise DiskCapacityError(
            f"{label} refused: projected free space is {snapshot['free_after_bytes']} bytes; "
            f"reserve is {minimum_free} bytes"
        )
    snapshot.update({
        "start_max_used_percent": start,
        "hard_max_used_percent": hard,
        "min_free_bytes": minimum_free,
    })
    return snapshot
