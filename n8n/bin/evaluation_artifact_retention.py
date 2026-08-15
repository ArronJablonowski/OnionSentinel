"""Metadata-only inventory, alerting, and seal-gated evaluation cleanup."""

from __future__ import annotations

import datetime as dt
import hashlib
import os
from pathlib import Path
import shutil
import stat
from typing import Any, Callable, Iterable

from evaluation_artifact_contract import RetentionPolicy, TEMPORARY_ENTRY_NAMES
from evaluation_artifact_seal import verify_seal


def _alert(code: str, severity: str, detail: str) -> dict[str, str]:
    return {"code": code, "severity": severity, "detail": detail}


def _opaque_identity(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def storage_alerts(
    *,
    local_used_percent: float,
    encrypted_used_percent: float | None,
    policy: RetentionPolicy,
) -> list[dict[str, str]]:
    alerts: list[dict[str, str]] = []
    for label, value, warning, failure in (
        (
            "local_evaluation_storage_capacity", local_used_percent,
            policy.local_warning_percent, policy.local_failure_percent,
        ),
        (
            "encrypted_evaluation_storage_capacity", encrypted_used_percent,
            policy.encrypted_warning_percent, policy.encrypted_failure_percent,
        ),
    ):
        if value is None:
            continue
        severity = "failure" if value >= failure else "warning" if value >= warning else ""
        if severity:
            alerts.append(
                _alert(label, severity, f"{value:.2f}% used (warn {warning:g}%, fail {failure:g}%)")
            )
    return alerts


def _used_percent(path: Path) -> float:
    usage = shutil.disk_usage(path)
    return usage.used / usage.total * 100 if usage.total else 100.0


def _safe_directory(path: Path, *, label: str) -> Path:
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ValueError(f"{label} is unavailable") from exc
    if (
        path != resolved
        or stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise ValueError(f"{label} must be canonical and owner-only")
    return resolved


def _tree_bytes(path: Path) -> tuple[int, bool]:
    total = 0
    unsafe = False
    for root, directories, files in os.walk(path, followlinks=False):
        parent = Path(root)
        kept = []
        for name in directories:
            candidate = parent / name
            try:
                metadata = candidate.lstat()
            except OSError:
                unsafe = True
                continue
            if stat.S_ISLNK(metadata.st_mode):
                unsafe = True
            else:
                kept.append(name)
        directories[:] = kept
        for name in files:
            candidate = parent / name
            try:
                metadata = candidate.lstat()
            except OSError:
                unsafe = True
                continue
            if stat.S_ISREG(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode):
                total += int(metadata.st_size)
            else:
                unsafe = True
    return total, unsafe


def _admit_run(path: Path) -> os.stat_result:
    metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise ValueError("evaluation entry is not an owner-only directory")
    return metadata


def _seal_state(
    path: Path, fallback: dt.datetime,
) -> tuple[dict[str, Any] | None, dt.datetime, list[dict[str, str]]]:
    try:
        seal = verify_seal(path)
        return seal, seal["completed_at"], []
    except ValueError as exc:
        if not (path / "evaluation-artifact-seal.json").exists():
            return None, fallback, []
        return None, fallback, [
            _alert(
                "invalid_evaluation_seal",
                "failure",
                f"{_opaque_identity(path.name)}: {exc}",
            )
        ]


def _run_record(
    path: Path,
    metadata: os.stat_result,
    *,
    now: dt.datetime,
    policy: RetentionPolicy,
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    size, unsafe_tree = _tree_bytes(path)
    fallback = dt.datetime.fromtimestamp(metadata.st_mtime, dt.timezone.utc)
    seal, completed, alerts = _seal_state(path, fallback)
    age_days = max(0.0, (now - completed).total_seconds() / 86400)
    temporary = [
        child.name for child in path.iterdir()
        if child.name in TEMPORARY_ENTRY_NAMES and not child.is_symlink()
    ]
    if unsafe_tree:
        alerts.append(
            _alert("unsafe_evaluation_tree", "failure", _opaque_identity(path.name))
        )
    if seal is None and age_days >= policy.run_retention_days:
        alerts.append(
            _alert("unsealed_expired_run", "failure", _opaque_identity(path.name))
        )
    return {
        "path": path,
        "name": path.name,
        "completed_at": completed,
        "age_days": age_days,
        "bytes": size,
        "sealed": seal is not None,
        "safe_tree": not unsafe_tree,
        "temporary_entries": temporary,
    }, alerts


def _run_inventory(
    root: Path, *, now: dt.datetime, policy: RetentionPolicy,
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    if not root.exists():
        return [], []
    root = _safe_directory(root, label="evaluation artifact root")
    runs: list[dict[str, Any]] = []
    alerts: list[dict[str, str]] = []
    for path in sorted(root.iterdir(), key=lambda item: item.name):
        try:
            record, record_alerts = _run_record(
                path, _admit_run(path), now=now, policy=policy
            )
        except (OSError, ValueError):
            alerts.append(
                _alert("unsafe_evaluation_entry", "failure", _opaque_identity(path.name))
            )
            continue
        runs.append(record)
        alerts.extend(record_alerts)
    return runs, alerts


def _select_run(
    item: dict[str, Any],
    selected: list[dict[str, Any]],
    selected_names: set[str],
    protected: set[str],
    limit: int,
) -> bool:
    eligible = bool(
        len(selected) < limit
        and item["sealed"]
        and item["safe_tree"]
        and item["name"] not in protected
        and item["name"] not in selected_names
    )
    if eligible:
        selected.append(item)
        selected_names.add(item["name"])
    return eligible


def _run_deletion_plan(
    runs: list[dict[str, Any]], policy: RetentionPolicy,
) -> list[dict[str, Any]]:
    oldest = sorted(runs, key=lambda item: (item["completed_at"], item["name"]))
    newest = sorted(oldest, key=lambda item: (item["completed_at"], item["name"]), reverse=True)
    protected = {item["name"] for item in newest[: policy.preserve_newest_runs]}
    selected: list[dict[str, Any]] = []
    selected_names: set[str] = set()

    def add(item: dict[str, Any]) -> bool:
        return _select_run(
            item, selected, selected_names, protected,
            policy.max_run_deletions_per_pass,
        )

    for item in oldest:
        if item["age_days"] >= policy.run_retention_days:
            add(item)
    _select_count_pressure(
        oldest, selected, add,
        max(0, len(runs) - policy.max_run_directories),
    )
    _select_byte_pressure(oldest, selected, add, policy.max_run_bytes)
    return selected


def _select_count_pressure(
    oldest: list[dict[str, Any]],
    selected: list[dict[str, Any]],
    add: Callable[[dict[str, Any]], bool],
    overflow: int,
) -> None:
    count_selected = min(overflow, len(selected))
    for item in oldest:
        if count_selected >= overflow:
            return
        if add(item):
            count_selected += 1


def _select_byte_pressure(
    oldest: list[dict[str, Any]],
    selected: list[dict[str, Any]],
    add: Callable[[dict[str, Any]], bool],
    max_bytes: int,
) -> None:
    projected = sum(int(item["bytes"]) for item in oldest)
    projected -= sum(int(item["bytes"]) for item in selected)
    for item in oldest:
        if projected <= max_bytes:
            return
        if add(item):
            projected -= int(item["bytes"])


def _safe_remove_run(root: Path, item: dict[str, Any]) -> None:
    path = Path(item["path"])
    if path.parent != root or path.name != item["name"]:
        raise ValueError("evaluation cleanup candidate escaped its root")
    verify_seal(path)
    shutil.rmtree(path)


def _cleanup_temporary(run: dict[str, Any]) -> int:
    path = Path(run["path"])
    verify_seal(path)
    removed = 0
    for name in run["temporary_entries"]:
        candidate = path / name
        try:
            metadata = candidate.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError("temporary evaluation entry became a symlink")
        if stat.S_ISDIR(metadata.st_mode):
            shutil.rmtree(candidate)
        elif stat.S_ISREG(metadata.st_mode):
            candidate.unlink()
        else:
            raise ValueError("temporary evaluation entry is unsafe")
        removed += 1
    return removed


def _report_plan(
    directory: Path,
    *,
    now: dt.datetime,
    retention_days: int,
    max_count: int,
    limit: int,
) -> tuple[list[Path], list[dict[str, str]]]:
    if not directory.exists():
        return [], []
    directory = _safe_directory(directory, label="evaluation report directory")
    files, alerts = _report_inventory(directory)
    cutoff = (now - dt.timedelta(days=retention_days)).timestamp()
    selected = {
        path: modified for path, modified in files
        if modified < cutoff
    }
    selected.update({path: modified for path, modified in files[max_count:]})
    oldest = sorted(selected.items(), key=lambda item: (item[1], item[0].name))
    return [path for path, _ in oldest[:limit]], alerts


def _report_inventory(
    directory: Path,
) -> tuple[list[tuple[Path, float]], list[dict[str, str]]]:
    files: list[tuple[Path, float]] = []
    alerts: list[dict[str, str]] = []
    for path in directory.iterdir():
        metadata = path.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            alerts.append(
                _alert("unsafe_evaluation_report", "failure", _opaque_identity(path.name))
            )
            continue
        files.append((path, metadata.st_mtime))
    files.sort(key=lambda item: (item[1], item[0].name), reverse=True)
    return files, alerts


def _storage_state(path: Path | None, warning: float, failure: float) -> dict[str, Any]:
    if path is None:
        return {"configured": False, "used_percent": None, "warning_percent": warning, "failure_percent": failure}
    root = _safe_directory(path.expanduser(), label="encrypted evaluation storage root")
    return {
        "configured": True,
        "used_percent": round(_used_percent(root), 2),
        "warning_percent": warning,
        "failure_percent": failure,
    }


def _pressure_alerts(
    runs: list[dict[str, Any]], policy: RetentionPolicy,
) -> tuple[int, list[dict[str, str]]]:
    alerts: list[dict[str, str]] = []
    if len(runs) > policy.max_run_directories:
        alerts.append(
            _alert(
                "evaluation_run_count_pressure",
                "failure",
                f"{len(runs)} run directories exceed the {policy.max_run_directories} limit",
            )
        )
    run_bytes = sum(int(item["bytes"]) for item in runs)
    if run_bytes > policy.max_run_bytes:
        alerts.append(
            _alert(
                "evaluation_run_byte_pressure",
                "failure",
                f"{run_bytes} bytes exceed the {policy.max_run_bytes} limit",
            )
        )
    return run_bytes, alerts


def _cleanup_plan(
    stack: Path, *, now: dt.datetime, policy: RetentionPolicy,
) -> dict[str, Any]:
    runs, alerts = _run_inventory(
        stack / "harness-evaluations", now=now, policy=policy
    )
    run_plan = _run_deletion_plan(runs, policy)
    run_bytes, pressure = _pressure_alerts(runs, policy)
    alerts.extend(pressure)
    run_names = {item["name"] for item in run_plan}
    temporary = [
        item for item in runs
        if item["sealed"] and item["safe_tree"] and item["temporary_entries"]
        and item["name"] not in run_names
    ]
    soak_plan, soak_alerts = _report_plan(
        stack / "logs/soak-reports", now=now,
        retention_days=policy.soak_report_retention_days,
        max_count=policy.soak_report_max_count,
        limit=policy.max_report_deletions_per_pass,
    )
    restore_plan, restore_alerts = _report_plan(
        stack / "logs/restore-drills", now=now,
        retention_days=policy.restore_report_retention_days,
        max_count=policy.restore_report_max_count,
        limit=policy.max_report_deletions_per_pass,
    )
    alerts.extend(soak_alerts + restore_alerts)
    return {
        "runs": runs,
        "run_bytes": run_bytes,
        "run_plan": run_plan,
        "temporary": temporary,
        "soak_plan": soak_plan,
        "restore_plan": restore_plan,
        "alerts": alerts,
    }


def _storage_projection(
    stack: Path,
    encrypted_storage_root: Path | None,
    policy: RetentionPolicy,
) -> tuple[float, dict[str, Any], list[dict[str, str]]]:
    local_used = _used_percent(stack)
    encrypted = _storage_state(
        encrypted_storage_root,
        policy.encrypted_warning_percent,
        policy.encrypted_failure_percent,
    )
    alerts = storage_alerts(
        local_used_percent=local_used,
        encrypted_used_percent=encrypted["used_percent"],
        policy=policy,
    )
    return local_used, encrypted, alerts


def _apply_cleanup(stack: Path, plan: dict[str, Any]) -> tuple[int, int, int]:
    removed_runs = removed_temp = removed_reports = 0
    root = (stack / "harness-evaluations").resolve(strict=False)
    for item in plan["run_plan"]:
        _safe_remove_run(root, item)
        removed_runs += 1
    for item in plan["temporary"]:
        removed_temp += _cleanup_temporary(item)
    for path in [*plan["soak_plan"], *plan["restore_plan"]]:
        path.unlink()
        removed_reports += 1
    return removed_runs, removed_temp, removed_reports


def _status(alerts: list[dict[str, str]]) -> str:
    severity = {item["severity"] for item in alerts}
    return "failure" if "failure" in severity else "warning" if severity else "ok"


def _result(
    *,
    plan: dict[str, Any],
    policy: RetentionPolicy,
    apply: bool,
    local_used: float,
    encrypted: dict[str, Any],
    removed: tuple[int, int, int],
) -> dict[str, Any]:
    runs = plan["runs"]
    removed_runs, removed_temp, removed_reports = removed
    return {
        "status": _status(plan["alerts"]),
        "applied": apply,
        "policy": policy._asdict(),
        "inventory": {
            "run_directories": len(runs),
            "run_bytes": plan["run_bytes"],
            "sealed_runs": sum(bool(item["sealed"]) for item in runs),
            "unsealed_runs": sum(not item["sealed"] for item in runs),
        },
        "storage": {
            "local": {
                "used_percent": round(local_used, 2),
                "warning_percent": policy.local_warning_percent,
                "failure_percent": policy.local_failure_percent,
            },
            "encrypted": encrypted,
        },
        "cleanup": {
            "temporary_candidates": len(plan["temporary"]),
            "temporary_removed": removed_temp,
            "run_directory_candidates": len(plan["run_plan"]),
            "run_directories_removed": removed_runs,
            "report_file_candidates": len(plan["soak_plan"]) + len(plan["restore_plan"]),
            "report_files_removed": removed_reports,
        },
        "alerts": plan["alerts"],
    }


def maintain(
    stack_dir: Path,
    *,
    now: dt.datetime,
    policy: RetentionPolicy,
    apply: bool,
    encrypted_storage_root: Path | None = None,
) -> dict[str, Any]:
    stack = stack_dir.expanduser().resolve(strict=True)
    plan = _cleanup_plan(stack, now=now, policy=policy)
    local_used, encrypted, storage = _storage_projection(
        stack, encrypted_storage_root, policy
    )
    plan["alerts"].extend(storage)
    removed = _apply_cleanup(stack, plan) if apply else (0, 0, 0)
    return _result(
        plan=plan,
        policy=policy,
        apply=apply,
        local_used=local_used,
        encrypted=encrypted,
        removed=removed,
    )


__all__ = ["maintain", "storage_alerts"]
