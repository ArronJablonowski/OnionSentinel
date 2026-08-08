"""Validated Administration action preparation and detached launch orchestration."""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO


@dataclass(frozen=True)
class AdminActionRunnerSources:
    actions: Mapping[str, Mapping[str, object]]
    state_dir: Path
    lock_file: Path
    macos_update_checker: Path
    now_iso: Callable[[], str]
    running_action: Callable[[], dict | None]
    read_status: Callable[[str], dict]
    process_running: Callable[[int | None], bool]
    check_available: Callable[[str], tuple[bool, str]]
    claim_lock: Callable[[str, str, str], tuple[bool, str]]
    release_lock: Callable[[str], None]
    update_lock_pid: Callable[[str, int], None]
    write_status: Callable[[str, dict], None]
    status_path: Callable[[str], Path]
    log_path: Callable[[str], Path]
    quote: Callable[[str], str]
    spawn: Callable[[str, BinaryIO], int]


def _running_message(running: dict) -> str:
    return (
        f"{running.get('label', 'Another admin action')} is still running as PID "
        f"{running.get('pid', 'unknown')}. Wait for it to complete before starting "
        "another update or reboot."
    )


def _completion_script(
    action_id: str,
    status_path: Path,
    lock_path: Path,
    macos_update_checker: Path,
) -> str:
    return (
        "import datetime,json,pathlib,subprocess,sys; "
        f"p=pathlib.Path({str(status_path)!r}); "
        f"lp=pathlib.Path({str(lock_path)!r}); "
        f"aid={action_id!r}; "
        "d=json.loads(p.read_text()); "
        "rc=int(sys.argv[1]); "
        "label=d.get('label') or aid; "
        "d.update({'state':'ok' if rc == 0 else 'failed', 'returncode':rc, "
        "'message':(f'{label} completed successfully.' if rc == 0 else f'{label} failed with exit code {rc}.'), "
        "'finished_at':datetime.datetime.now().astimezone().isoformat(timespec='seconds').replace('T','  '), "
        "'updated_at':datetime.datetime.now().astimezone().isoformat(timespec='seconds').replace('T','  ')}); "
        "p.write_text(json.dumps(d, indent=2)); "
        f"checker=pathlib.Path({str(macos_update_checker)!r}); "
        "\ntry:\n subprocess.run([str(checker)], timeout=300) if (rc == 0 and aid == 'macos-update' and checker.exists()) else None\n"
        "except Exception: pass\n"
        "try:\n l=json.loads(lp.read_text()) if lp.exists() else {};\n"
        " lp.unlink() if (not l or l.get('id') == aid) else None\n"
        "except Exception: pass"
    )


def build_admin_wrapped_command(
    action_id: str,
    label: str,
    command: list[str],
    status_path: Path,
    lock_path: Path,
    macos_update_checker: Path,
    quote: Callable[[str], str],
) -> str:
    """Build the bounded shell wrapper used by the detached host adapter."""
    finish = _completion_script(
        action_id, status_path, lock_path, macos_update_checker
    )
    shell_command = " ".join(quote(part) for part in command)
    return (
        f"{shell_command}; rc=$?; "
        f"printf '\\n===== %s END {quote(label)} rc=%s =====\\n' "
        '"$(date -u \'+%Y-%m-%d  %H:%M:%SZ\')" "$rc"; '
        f"/usr/bin/python3 -c {quote(finish)} \"$rc\"; exit $rc"
    )


def _initial_status(
    action_id: str,
    action: Mapping[str, object],
    command: list[str],
    started_at: str,
) -> dict:
    label = str(action["label"])
    return {
        "id": action_id,
        "label": label,
        "summary": action.get("summary", ""),
        "command": " ".join(command),
        "started_at": started_at,
        "pid": None,
        "state": "running",
        "returncode": None,
        "message": f"Starting {label}.",
    }


def _write_start_log(
    path: Path, started_at: str, label: str, command: list[str]
) -> None:
    with path.open("ab") as log:
        log.write(f"\n===== {started_at} START {label} =====\n".encode("utf-8"))
        log.write(("Command: " + " ".join(command) + "\n").encode("utf-8"))
        log.flush()


def _validate_request(
    action_id: str, confirmation: str, sources: AdminActionRunnerSources
) -> tuple[Mapping[str, object] | None, str]:
    action = sources.actions.get(action_id)
    if not action:
        return None, "Unknown admin action."
    required = action.get("requires_confirmation")
    if required and confirmation != required:
        return None, f"Confirmation failed. Type {required!r} to run this action."
    running = sources.running_action()
    if running:
        return None, _running_message(running)
    current = sources.read_status(action_id)
    if current.get("state") == "running" and sources.process_running(
        current.get("pid")
    ):
        return None, f"{action['label']} is already running."
    available, message = sources.check_available(action_id)
    return (action, "") if available else (None, message)


def start_admin_action(
    action_id: str,
    confirmation: str,
    sources: AdminActionRunnerSources,
) -> tuple[bool, str]:
    """Validate, journal, lock, and launch one approved Administration action."""
    action, error = _validate_request(action_id, confirmation, sources)
    if action is None:
        return False, error
    sources.state_dir.mkdir(parents=True, exist_ok=True)
    label = str(action["label"])
    started_at = sources.now_iso()
    lock_ok, lock_message = sources.claim_lock(action_id, label, started_at)
    if not lock_ok:
        return False, lock_message
    command = [str(part) for part in action["command"]]
    log_path = sources.log_path(action_id)
    _write_start_log(log_path, started_at, label, command)
    status = _initial_status(action_id, action, command, started_at)
    sources.write_status(action_id, status)
    wrapped = build_admin_wrapped_command(
        action_id,
        label,
        command,
        sources.status_path(action_id),
        sources.lock_file,
        sources.macos_update_checker,
        sources.quote,
    )
    try:
        with log_path.open("ab") as log:
            pid = sources.spawn(wrapped, log)
    except Exception as exc:
        sources.release_lock(action_id)
        failed = {
            **status,
            "state": "failed",
            "returncode": None,
            "message": f"Failed to start {label}: {exc}",
        }
        sources.write_status(action_id, failed)
        return False, f"Failed to start {label}: {exc}"
    status["pid"] = pid
    status["message"] = f"Started {label} as PID {pid}."
    sources.update_lock_pid(action_id, pid)
    sources.write_status(action_id, status)
    return True, f"Started {label}."
