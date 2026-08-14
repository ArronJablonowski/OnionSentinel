#!/usr/bin/env python3
"""Relay PCAP spool admission, retention, and checkpoint primitives."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import time
from pathlib import Path


__all__ = [
    "atomic_json_write",
    "cleanup_stale_spool_artifacts",
    "cleanup_stale_spool_partials",
    "load_json_file",
    "pcap_spool_dir",
    "require_spool_capacity",
    "sha256_file",
    "spool_mount_ready",
    "spool_usage",
]


def pcap_spool_dir(config: dict) -> Path:
    broker = config.get("pcap_broker", {})
    raw_path = str(
        broker.get("artifact_spool_dir")
        or "/mnt/onion-sentinel-pcap-spool/pcap"
    )
    path = Path(raw_path)
    if not path.is_absolute():
        raise RuntimeError("pcap_broker.artifact_spool_dir must be an absolute path")
    return path


def spool_mount_ready(config: dict) -> bool:
    broker = config.get("pcap_broker", {})
    if not bool(broker.get("artifact_spool_require_mount", False)):
        return True
    spool_dir = pcap_spool_dir(config)
    # The configured directory is intentionally one level below the filesystem
    # root. Requiring that parent to be a mount prevents an absent USB disk from
    # silently redirecting multi-gigabyte writes onto the Pi SD card.
    return os.path.ismount(spool_dir.parent)


def _spool_capacity_limits(broker: dict) -> tuple[int, int, float]:
    max_bytes = int(
        broker.get("artifact_spool_max_bytes", 32 * 1024 * 1024 * 1024) or 0
    )
    min_free_bytes = int(
        broker.get("artifact_spool_min_free_bytes", 100 * 1024 * 1024 * 1024)
        or 0
    )
    max_used_percent = max(
        1.0,
        min(
            75.0,
            float(broker.get("artifact_spool_max_used_percent", 75) or 75),
        ),
    )
    return max_bytes, min_free_bytes, max_used_percent


def _require_spool_location(config: dict) -> Path:
    spool_dir = pcap_spool_dir(config)
    if not spool_dir.exists() or not spool_dir.is_dir():
        raise RuntimeError(f"relay PCAP spool directory is unavailable: {spool_dir}")
    if not spool_mount_ready(config):
        raise RuntimeError(
            f"relay PCAP spool filesystem is not mounted: {spool_dir.parent}"
        )
    return spool_dir


def _require_available_capacity(
    usage: shutil._ntuple_diskusage,
    artifact_size: int,
    min_free_bytes: int,
    max_used_percent: float,
) -> None:
    required = artifact_size + max(0, min_free_bytes)
    if usage.free < required:
        raise RuntimeError(
            "relay PCAP spool has insufficient free space: "
            f"free={usage.free} required={required}"
        )
    projected_percent = (
        ((usage.used + artifact_size) / usage.total) * 100
        if usage.total
        else 100.0
    )
    if projected_percent > max_used_percent:
        raise RuntimeError(
            "relay PCAP spool high watermark exceeded: "
            f"projected={projected_percent:.1f}% "
            f"limit={max_used_percent:.1f}%"
        )


def require_spool_capacity(config: dict, artifact_size: int) -> None:
    broker = config.get("pcap_broker", {})
    max_bytes, min_free_bytes, max_used_percent = _spool_capacity_limits(broker)
    if max_bytes > 0 and artifact_size > max_bytes:
        raise RuntimeError(
            f"PCAP artifact exceeds relay spool limit: {artifact_size} > {max_bytes}"
        )
    spool_dir = _require_spool_location(config)
    _require_available_capacity(
        shutil.disk_usage(spool_dir),
        artifact_size,
        min_free_bytes,
        max_used_percent,
    )


def spool_usage(config: dict) -> dict:
    spool_dir = pcap_spool_dir(config)
    if not spool_dir.exists():
        return {"available": False, "path": str(spool_dir)}
    if not spool_mount_ready(config):
        return {
            "available": False,
            "path": str(spool_dir),
            "reason": "spool filesystem is not mounted",
        }
    usage = shutil.disk_usage(spool_dir)
    return {
        "available": True,
        "total_bytes": usage.total,
        "used_bytes": usage.used,
        "free_bytes": usage.free,
        "used_percent": (
            round((usage.used / usage.total) * 100, 1) if usage.total else 100.0
        ),
    }


def cleanup_stale_spool_partials(config: dict) -> int:
    """Remove interrupted relay-spool transfer fragments older than the configured TTL."""
    broker = config.get("pcap_broker", {})
    ttl_seconds = int(broker.get("artifact_spool_partial_ttl_seconds", 0) or 0)
    if ttl_seconds < 0:
        return 0
    try:
        spool_dir = pcap_spool_dir(config)
    except Exception:
        return 0
    if not spool_dir.exists() or not spool_dir.is_dir():
        return 0
    cutoff = time.time() - ttl_seconds
    removed = 0
    for path in spool_dir.rglob("*.part"):
        try:
            if path.is_file() and path.stat().st_mtime < cutoff:
                path.unlink()
                removed += 1
        except OSError:
            continue
    return removed


def _remove_stale_completed_tar(path: Path, cutoff: float) -> int:
    try:
        if not path.is_file() or path.stat().st_mtime >= cutoff:
            return 0
        path.unlink()
        path.with_suffix(".stream.json").unlink(missing_ok=True)
    except OSError:
        return 0
    return 1


def _remove_stale_request_dir(path: Path, cutoff: float) -> int:
    try:
        if not path.is_dir() or path.stat().st_mtime >= cutoff:
            return 0
        shutil.rmtree(path)
    except OSError:
        return 0
    return 1


def cleanup_stale_spool_artifacts(config: dict) -> int:
    """Remove completed relay artifacts after their bounded retry window.

    This runs while the broker lock is held, so a matching rsync upload cannot
    be active. Security Onion keeps its independently retained export as the
    recovery source if a request is retried after this relay-side TTL.
    """
    broker = config.get("pcap_broker", {})
    ttl_seconds = int(
        broker.get("artifact_spool_completed_ttl_seconds", 3600) or 0
    )
    if ttl_seconds < 0:
        return 0
    try:
        spool_dir = pcap_spool_dir(config)
    except Exception:
        return 0
    if not spool_dir.exists() or not spool_dir.is_dir():
        return 0
    cutoff = time.time() - ttl_seconds
    removed = sum(
        _remove_stale_completed_tar(path, cutoff)
        for path in spool_dir.glob("*.tar")
    )
    removed += sum(
        _remove_stale_request_dir(path, cutoff) for path in spool_dir.iterdir()
    )
    return removed


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_json_write(path: Path, payload: dict) -> None:
    """Persist a relay checkpoint without exposing a partially-written file."""
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    temporary.replace(path)


def load_json_file(path: Path) -> dict:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}
