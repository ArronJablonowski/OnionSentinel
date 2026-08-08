"""Durable Administration action status and singleton-lock ownership."""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import datetime as dt
import json
import os
from pathlib import Path


@dataclass(frozen=True)
class AdminActionStateSources:
    state_dir: Path
    lock_file: Path
    actions: Mapping[str, Mapping[str, object]]
    process_running: Callable[[int | None], bool]
    now_iso: Callable[[], str]
    parse_timestamp: Callable[[object], dt.datetime]
    format_timestamp: Callable[[dt.datetime], str]


def action_status_path(action_id: str, sources: AdminActionStateSources) -> Path:
    return sources.state_dir / f"{action_id}.json"


def action_log_path(action_id: str, sources: AdminActionStateSources) -> Path:
    return sources.state_dir / f"{action_id}.log"


def _default_status(action_id: str, sources: AdminActionStateSources) -> dict:
    action = sources.actions.get(action_id, {})
    command = " ".join(str(part) for part in action.get("command", []))
    return {
        "id": action_id,
        "label": action.get("label", action_id),
        "summary": action.get("summary", ""),
        "command": command,
        "started_at": None,
        "pid": None,
        "state": "idle",
        "returncode": None,
        "message": "Not run yet.",
        "updated_at": None,
    }


def _loaded_status(path: Path) -> tuple[dict, bool, str]:
    try:
        if not path.exists():
            return {}, False, ""
        loaded = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(loaded, dict):
            raise ValueError("status document must be an object")
        return loaded, "command" in loaded, ""
    except Exception as exc:
        return {}, False, f"Could not read status: {exc}"


def _apply_reboot_command_migration(
    action_id: str, status: dict, loaded_has_command: bool, current_command: str
) -> None:
    if (
        action_id == "reboot"
        and status.get("started_at")
        and (not loaded_has_command or status.get("command") != current_command)
    ):
        status.update(
            {
                "command": current_command,
                "message": (
                    "Last reboot run was recorded before the current reboot command path "
                    "changed; the timestamp is retained for audit history."
                ),
            }
        )


def read_action_status(action_id: str, sources: AdminActionStateSources) -> dict:
    """Read one status with stable defaults and stale-process projection."""
    status = _default_status(action_id, sources)
    current_command = str(status.get("command") or "")
    loaded, loaded_has_command, error = _loaded_status(
        action_status_path(action_id, sources)
    )
    status.update(loaded)
    if error:
        status.update({"state": "error", "message": error})
    _apply_reboot_command_migration(
        action_id, status, loaded_has_command, current_command
    )
    if status.get("state") == "running" and not sources.process_running(
        status.get("pid")
    ):
        status["state"] = "unknown"
        status["message"] = (
            "Process is no longer visible; check the log for completion details."
        )
    return status


def write_action_status(
    action_id: str, status: dict, sources: AdminActionStateSources
) -> None:
    sources.state_dir.mkdir(parents=True, exist_ok=True)
    status["updated_at"] = sources.now_iso()
    action_status_path(action_id, sources).write_text(
        json.dumps(status, indent=2), encoding="utf-8"
    )


def _status_time(status: dict, sources: AdminActionStateSources) -> dt.datetime | None:
    for key in ("finished_at", "updated_at", "started_at"):
        value = status.get(key)
        if not value:
            continue
        try:
            return sources.parse_timestamp(value)
        except Exception:
            continue
    return None


def latest_action_outcome(sources: AdminActionStateSources) -> dict | None:
    """Return the newest non-running outcome for Administration banner rendering."""
    candidates = []
    for action_id, action in sources.actions.items():
        status = read_action_status(action_id, sources)
        state = str(status.get("state") or "idle")
        when = None if state in {"idle", "running"} else _status_time(status, sources)
        if when is not None:
            candidates.append((when, action_id, action, status, state))
    if not candidates:
        return None
    when, action_id, action, status, state = max(candidates, key=lambda row: row[0])
    return {
        "id": action_id,
        "label": status.get("label") or action.get("label", action_id),
        "state": state,
        "returncode": status.get("returncode"),
        "message": status.get("message") or "No completion message recorded.",
        "when": sources.format_timestamp(when),
    }


def read_action_lock(sources: AdminActionStateSources) -> dict | None:
    try:
        lock = json.loads(sources.lock_file.read_text(encoding="utf-8"))
        return lock if isinstance(lock, dict) else None
    except Exception:
        return None


def _remove_stale_lock(sources: AdminActionStateSources) -> bool:
    try:
        sources.lock_file.unlink()
        return True
    except FileNotFoundError:
        return True
    except Exception:
        return False


def running_action(sources: AdminActionStateSources) -> dict | None:
    """Return a running action and clear a stale lock only when removal is safe."""
    lock = read_action_lock(sources)
    if lock and sources.process_running(lock.get("pid")):
        return lock
    if lock and not _remove_stale_lock(sources):
        return lock
    for action_id in sources.actions:
        status = read_action_status(action_id, sources)
        if status.get("state") == "running" and sources.process_running(
            status.get("pid")
        ):
            return {
                "id": action_id,
                "label": status.get("label")
                or sources.actions[action_id]["label"],
                "pid": status.get("pid"),
                "started_at": status.get("started_at"),
            }
    return None


def _running_message(running: dict) -> str:
    return (
        f"{running.get('label', 'Another admin action')} is still running as PID "
        f"{running.get('pid', 'unknown')}. Wait for it to complete before starting "
        "another update or reboot."
    )


def _write_exclusive_lock(payload: dict, sources: AdminActionStateSources) -> None:
    descriptor = os.open(
        str(sources.lock_file), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
    )
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)


def claim_action_lock(
    action_id: str,
    label: str,
    started_at: str,
    sources: AdminActionStateSources,
) -> tuple[bool, str]:
    """Atomically claim the singleton action lock after stale-state reconciliation."""
    sources.state_dir.mkdir(parents=True, exist_ok=True)
    running = running_action(sources)
    if running:
        return False, _running_message(running)
    payload = {"id": action_id, "label": label, "pid": None, "started_at": started_at}
    try:
        _write_exclusive_lock(payload, sources)
        return True, "Lock acquired."
    except FileExistsError:
        running = running_action(sources)
        if running:
            return False, _running_message(running)
        return claim_action_lock(action_id, label, started_at, sources)
    except Exception as exc:
        return False, f"Could not acquire admin action lock: {exc}"


def update_action_lock_pid(
    action_id: str, pid: int, sources: AdminActionStateSources
) -> None:
    lock = read_action_lock(sources) or {}
    if lock.get("id") == action_id:
        lock["pid"] = pid
        sources.lock_file.write_text(json.dumps(lock, indent=2), encoding="utf-8")


def release_action_lock(action_id: str, sources: AdminActionStateSources) -> None:
    lock = read_action_lock(sources) or {}
    if not lock or lock.get("id") == action_id:
        try:
            sources.lock_file.unlink()
        except FileNotFoundError:
            pass
