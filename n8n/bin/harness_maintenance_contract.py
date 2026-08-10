"""Shared policy, time, and runtime-loading contracts for harness maintenance."""

from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from typing import Any


DEFAULT_RETENTION_DAYS = 30
DEFAULT_MAX_TERMINAL_RUNS = 10_000
DEFAULT_MIN_TERMINAL_RUNS = 1_000
DEFAULT_MAX_DELETE_RUNS = 1_000
DEFAULT_MAX_LIVE_BYTES = 2 * 1024**3
DEFAULT_INCREMENTAL_VACUUM_PAGES = 4_096
DEFAULT_MAX_BACKUP_AGE_SECONDS = 26 * 60 * 60
DEFAULT_STALE_RUNNING_SECONDS = 60 * 60
DEFAULT_MAX_RECONCILE_RUNS = 100
TERMINAL_STATUSES = ("succeeded", "failed", "cancelled")
REQUIRED_TABLES = frozenset(
    {
        "harness_metadata",
        "harness_runs",
        "harness_events",
        "harness_evidence",
        "harness_hypotheses",
        "harness_decisions",
        "harness_model_calls",
        "harness_tool_calls",
        "harness_budget_reservations",
    }
)
MAX_BACKUP_MANIFEST_BYTES = 1024 * 1024
RECONCILABLE_JOB_TYPES = {
    "soc-analyst": "ai_analysis",
    "incident-responder": "incident_response_analysis",
}


class MaintenanceError(RuntimeError):
    """A safe, concise maintenance failure."""


def load_harness_runtime():
    """Load the sibling harness API without depending on the caller's cwd."""
    module_name = "onion_sentinel_harness_maintenance_runtime"
    existing = sys.modules.get(module_name)
    if existing is not None:
        return existing
    module_path = Path(__file__).with_name("onion_sentinel_harness.py")
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise MaintenanceError("could not load the harness runtime API")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    script_dir = str(module_path.parent)
    inserted = script_dir not in sys.path
    if inserted:
        sys.path.insert(0, script_dir)
    try:
        spec.loader.exec_module(module)
    except Exception:
        sys.modules.pop(module_name, None)
        raise
    finally:
        if inserted:
            sys.path.remove(script_dir)
    return module


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def timestamp_text(value: dt.datetime) -> str:
    return (
        value.astimezone(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def parse_timestamp(value: object) -> dt.datetime | None:
    text = str(value or "").strip().replace("  ", "T", 1)
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    )


def digest_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def bounded_int(
    value: int,
    *,
    name: str,
    minimum: int,
    maximum: int,
) -> int:
    if value < minimum or value > maximum:
        raise MaintenanceError(
            f"{name} must be between {minimum} and {maximum}"
        )
    return value
