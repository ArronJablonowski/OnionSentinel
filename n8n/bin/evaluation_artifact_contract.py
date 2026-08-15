"""Bounded policy and path classes for evaluation artifact retention."""

from __future__ import annotations

from typing import NamedTuple


SEAL_NAME = "evaluation-artifact-seal.json"
SEAL_SCHEMA = "onion-sentinel-evaluation-artifact-seal-v1"
REPORT_SCHEMA = "onion-sentinel-evaluation-artifact-maintenance-v1"
MAX_SEAL_BYTES = 1024 * 1024
MAX_SEALED_OUTPUTS = 1024
TEMPORARY_ENTRY_NAMES = frozenset({"tmp", "__pycache__", ".pytest_cache"})


class RetentionPolicy(NamedTuple):
    run_retention_days: int
    max_run_directories: int
    max_run_bytes: int
    preserve_newest_runs: int
    max_run_deletions_per_pass: int
    soak_report_retention_days: int
    soak_report_max_count: int
    restore_report_retention_days: int
    restore_report_max_count: int
    max_report_deletions_per_pass: int
    local_warning_percent: float
    local_failure_percent: float
    encrypted_warning_percent: float
    encrypted_failure_percent: float


_DEFAULTS = {
    "run_retention_days": 30,
    "max_run_directories": 40,
    "max_run_bytes": 200 * 1024**3,
    "preserve_newest_runs": 5,
    "max_run_deletions_per_pass": 2,
    "soak_report_retention_days": 14,
    "soak_report_max_count": 4032,
    "restore_report_retention_days": 30,
    "restore_report_max_count": 90,
    "max_report_deletions_per_pass": 256,
    "local_warning_percent": 65.0,
    "local_failure_percent": 75.0,
    "encrypted_warning_percent": 70.0,
    "encrypted_failure_percent": 85.0,
}


def default_policy(**overrides: int | float) -> RetentionPolicy:
    """Return the reviewed default policy with narrow test/operator overrides."""
    unknown = set(overrides).difference(_DEFAULTS)
    if unknown:
        raise ValueError("unknown evaluation retention policy field")
    values = {**_DEFAULTS, **overrides}
    _validate(values)
    return RetentionPolicy(**values)


def _validate(values: dict[str, int | float]) -> None:
    positive = (
        "run_retention_days", "max_run_directories", "max_run_bytes",
        "max_run_deletions_per_pass", "soak_report_retention_days",
        "soak_report_max_count", "restore_report_retention_days",
        "restore_report_max_count", "max_report_deletions_per_pass",
    )
    if any(int(values[name]) < 1 for name in positive):
        raise ValueError("evaluation retention bounds must be positive")
    preserve = int(values["preserve_newest_runs"])
    if preserve < 1 or preserve > int(values["max_run_directories"]):
        raise ValueError("preserved evaluation run count is invalid")
    for prefix in ("local", "encrypted"):
        warning = float(values[f"{prefix}_warning_percent"])
        failure = float(values[f"{prefix}_failure_percent"])
        if not 0 < warning < failure <= 100:
            raise ValueError(f"{prefix} storage thresholds are invalid")


__all__ = [
    "MAX_SEAL_BYTES", "MAX_SEALED_OUTPUTS", "REPORT_SCHEMA", "SEAL_NAME",
    "SEAL_SCHEMA", "TEMPORARY_ENTRY_NAMES", "RetentionPolicy",
    "default_policy",
]
