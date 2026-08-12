#!/usr/bin/env python3
"""Verify and narrowly recover the dedicated Onion Sentinel web listener.

The dashboard port is a security boundary. This guard may restart the expected
LaunchAgent or terminate the exact Python ``http.server`` command that once
served the Mac user's home directory on that port. It deliberately refuses to
kill any other listener because an unknown process requires operator review.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from typing import Optional, Tuple

BIN_DIR = Path(__file__).resolve().parent
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))
from bounded_http import BoundedHttpError, read_bounded_json


DEFAULT_PORT = 8766
DEFAULT_LABEL = "com.arron.onion-sentinel.web"
DEFAULT_HEALTH_URL = "http://127.0.0.1:8766/healthz"
DEFAULT_HOLD_MAX_AGE_SECONDS = 15 * 60
DEFAULT_RESTART_WINDOW_SECONDS = 15 * 60
DEFAULT_MAX_RESTARTS = 3
MAX_HEALTH_RESPONSE_BYTES = 64 * 1024


def command_kind(command: str, port: int) -> str:
    """Classify only the expected server and the known unsafe collision."""

    try:
        parts = shlex.split(command)
    except ValueError:
        return "unknown"
    if "onion_sentinel_server.py" in " ".join(parts) and str(port) in parts:
        return "onion-sentinel"
    for index in range(len(parts) - 2):
        if parts[index : index + 2] == ["-m", "http.server"]:
            return "unsafe-simple-http" if str(port) in parts[index + 2 :] else "unknown"
    return "unknown"


def probe_health(url: str, timeout: float = 3.0) -> Tuple[bool, str]:
    """Require the versioned service identity, not merely an HTTP 200."""

    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            payload = read_bounded_json(response, max_bytes=MAX_HEALTH_RESPONSE_BYTES)
    except (BoundedHttpError, OSError, ValueError, urllib.error.URLError) as exc:
        return False, type(exc).__name__
    if payload.get("ok") is True and payload.get("service") == "onion-sentinel":
        return True, "onion-sentinel"
    return False, "identity-mismatch"


def listener_pids(port: int) -> list[int]:
    result = subprocess.run(
        ["/usr/sbin/lsof", "-nP", "-t", f"-iTCP:{port}", "-sTCP:LISTEN"],
        capture_output=True,
        check=False,
        text=True,
    )
    return sorted({int(value) for value in result.stdout.split() if value.isdigit()})


def process_details(pid: int) -> Tuple[Optional[int], str]:
    result = subprocess.run(
        ["/bin/ps", "-p", str(pid), "-o", "uid=", "-o", "command="],
        capture_output=True,
        check=False,
        text=True,
    )
    line = result.stdout.strip()
    if not line:
        return None, ""
    uid_text, _, command = line.partition(" ")
    try:
        uid = int(uid_text)
    except ValueError:
        return None, command.strip()
    return uid, command.strip()


def terminate_known_simple_server(pid: int) -> None:
    os.kill(pid, signal.SIGTERM)
    for _ in range(30):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.1)
    raise RuntimeError("known unsafe listener did not exit after SIGTERM")


def launchd_domain(label: str) -> str:
    return f"gui/{os.getuid()}/{label}"


def service_registered(label: str) -> bool:
    result = subprocess.run(
        ["/bin/launchctl", "print", launchd_domain(label)],
        capture_output=True,
        check=False,
        text=True,
    )
    return result.returncode == 0


def validate_plist(plist_path: Path, label: str) -> Path:
    """Accept only this user's expected LaunchAgent plist, never an arbitrary job."""

    path = plist_path.expanduser()
    expected_dir = Path.home() / "Library" / "LaunchAgents"
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("expected web LaunchAgent plist is missing or unsafe")
    if path.parent.resolve() != expected_dir.resolve() or path.name != f"{label}.plist":
        raise RuntimeError("web LaunchAgent plist path is outside the allowlisted location")
    if path.stat().st_uid != os.getuid():
        raise RuntimeError("web LaunchAgent plist is not owned by the current user")
    result = subprocess.run(
        ["/usr/bin/plutil", "-extract", "Label", "raw", "-o", "-", str(path)],
        capture_output=True,
        check=False,
        text=True,
    )
    if result.returncode != 0 or result.stdout.strip() != label:
        raise RuntimeError("web LaunchAgent plist label does not match the expected service")
    return path


def maintenance_hold_active(
    hold_path: Path,
    max_age_seconds: int = DEFAULT_HOLD_MAX_AGE_SECONDS,
) -> bool:
    """Honor only a recent, regular hold file owned by the current user."""

    path = hold_path.expanduser()
    try:
        stat_result = path.lstat()
    except OSError:
        return False
    if path.is_symlink() or not path.is_file() or stat_result.st_uid != os.getuid():
        return False
    return 0 <= time.time() - stat_result.st_mtime <= max_age_seconds


def ensure_started(label: str, plist_path: Path) -> bool:
    """Start the service and bootstrap its exact plist when launchd lost the job."""

    registered = service_registered(label)
    if not registered:
        path = validate_plist(plist_path, label)
        subprocess.run(
            ["/bin/launchctl", "bootstrap", f"gui/{os.getuid()}", str(path)],
            capture_output=True,
            check=True,
            text=True,
        )
    subprocess.run(
        ["/bin/launchctl", "kickstart", "-k", launchd_domain(label)],
        capture_output=True,
        check=True,
        text=True,
    )
    return not registered


def __load_restart_state(path: Path) -> dict[str, object]:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return {}
    if path.is_symlink() or not path.is_file() or metadata.st_uid != os.getuid():
        raise RuntimeError("restart state file is unsafe")
    if metadata.st_mode & 0o077:
        raise RuntimeError("restart state file permissions are too open")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise RuntimeError("restart state file is invalid") from exc
    if not isinstance(value, dict):
        raise RuntimeError("restart state file is invalid")
    return value


def __recent_restart_attempts(
    value: dict[str, object], current: float, window_seconds: int,
) -> list[float]:
    return [
        float(item)
        for item in value.get("attempts", [])
        if isinstance(item, (int, float))
        and 0 <= current - float(item) <= window_seconds
    ]


def __publish_restart_state(path: Path, state: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=path.parent,
        prefix=f".{path.name}.", delete=False,
    ) as handle:
        json.dump(state, handle, sort_keys=True, separators=(",", ":"))
        handle.write("\n")
        temporary = Path(handle.name)
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def authorize_restart(
    state_path: Path,
    *,
    now: float | None = None,
    window_seconds: int = DEFAULT_RESTART_WINDOW_SECONDS,
    max_restarts: int = DEFAULT_MAX_RESTARTS,
) -> tuple[bool, dict[str, object]]:
    """Persist a bounded restart attempt or fail closed into quarantine."""

    current = time.time() if now is None else now
    path = state_path.expanduser()
    if window_seconds < 1 or max_restarts < 1:
        raise RuntimeError("restart budget is invalid")
    attempts = __recent_restart_attempts(__load_restart_state(path), current, window_seconds)
    allowed = len(attempts) < max_restarts
    if allowed:
        attempts.append(current)
    state = {
        "schema": "onion-sentinel-web-restart-budget-v1",
        "attempts": attempts,
        "window_seconds": window_seconds,
        "max_restarts": max_restarts,
        "quarantined": not allowed,
        "updated_at": current,
    }
    __publish_restart_state(path, state)
    return allowed, state


def __listener_admission(port: int, pids: list[int]) -> tuple[list[str], dict[str, object] | None]:
    kinds: list[str] = []
    for pid in pids:
        uid, command = process_details(pid)
        kind = command_kind(command, port)
        kinds.append(kind)
        if uid != os.getuid() or kind == "unknown":
            return kinds, {
                "ok": False,
                "state": "refused",
                "recovered": False,
                "detail": "unknown listener requires operator review",
                "listener_pid": pid,
            }
    if len(pids) > 1:
        return kinds, {
            "ok": False,
            "state": "refused",
            "recovered": False,
            "detail": "multiple listeners require operator review",
        }
    return kinds, None


def __restart_budget_refusal(
    restart_state_path: Path | None,
    restart_window_seconds: int,
    max_restarts: int,
) -> dict[str, object] | None:
    if restart_state_path is None:
        return None
    allowed, budget = authorize_restart(
        restart_state_path,
        window_seconds=restart_window_seconds,
        max_restarts=max_restarts,
    )
    if allowed:
        return None
    return {
        "ok": False,
        "state": "quarantined",
        "recovered": False,
        "detail": "automatic restart budget exhausted",
        "restart_attempts": len(budget["attempts"]),
        "restart_window_seconds": budget["window_seconds"],
    }


def __await_recovery(health_url: str, bootstrapped: bool) -> dict[str, object]:
    last_detail = "not-ready"
    for _ in range(24):
        healthy, last_detail = probe_health(health_url, timeout=1.0)
        if healthy:
            return {
                "ok": True,
                "state": "recovered",
                "recovered": True,
                "bootstrapped": bootstrapped,
                "detail": last_detail,
            }
        time.sleep(0.5)
    return {"ok": False, "state": "failed", "recovered": False, "detail": last_detail}


def recover(
    port: int,
    label: str,
    health_url: str,
    plist_path: Path,
    restart_state_path: Path | None = None,
    restart_window_seconds: int = DEFAULT_RESTART_WINDOW_SECONDS,
    max_restarts: int = DEFAULT_MAX_RESTARTS,
) -> dict[str, object]:
    healthy, detail = probe_health(health_url)
    if healthy:
        return {"ok": True, "state": "healthy", "recovered": False, "detail": detail}

    pids = listener_pids(port)
    kinds, refusal = __listener_admission(port, pids)
    if refusal is not None:
        return refusal
    refusal = __restart_budget_refusal(restart_state_path, restart_window_seconds, max_restarts)
    if refusal is not None:
        return refusal

    if pids and kinds == ["unsafe-simple-http"]:
        terminate_known_simple_server(pids[0])

    # No listener and an unhealthy expected listener are both safely handled by
    # launchd. The -k operation is scoped to Onion Sentinel's own service label.
    bootstrapped = ensure_started(label, plist_path)
    return __await_recovery(health_url, bootstrapped)


def __parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--label", default=DEFAULT_LABEL)
    parser.add_argument("--health-url", default=DEFAULT_HEALTH_URL)
    parser.add_argument("--plist")
    parser.add_argument("--maintenance-hold")
    parser.add_argument("--restart-state")
    parser.add_argument(
        "--restart-window-seconds",
        type=int,
        default=DEFAULT_RESTART_WINDOW_SECONDS,
    )
    parser.add_argument("--max-restarts", type=int, default=DEFAULT_MAX_RESTARTS)
    parser.add_argument("--check-only", action="store_true")
    return parser.parse_args()


def __runtime_paths(args: argparse.Namespace) -> tuple[Path, Path, Path]:
    plist_path = (
        Path(args.plist)
        if args.plist
        else Path.home() / "Library" / "LaunchAgents" / f"{args.label}.plist"
    )
    hold_path = (
        Path(args.maintenance_hold)
        if args.maintenance_hold
        else Path.home() / "n8n-local" / "logs" / "onion-sentinel-web-maintenance.hold"
    )
    restart_state_path = (
        Path(args.restart_state)
        if args.restart_state
        else Path.home() / "n8n-local" / "logs" / "onion-sentinel-web-restart-budget.json"
    )
    return plist_path, hold_path, restart_state_path


def __maintenance_result() -> dict[str, object]:
    return {
        "ok": True,
        "state": "maintenance",
        "recovered": False,
        "detail": "planned maintenance hold",
    }


def __check_only_result(health_url: str) -> dict[str, object]:
    healthy, detail = probe_health(health_url)
    return {"ok": healthy, "state": "healthy" if healthy else "failed", "detail": detail}


def __safe_recovery(
    args: argparse.Namespace, plist_path: Path, restart_state_path: Path,
) -> dict[str, object]:
    try:
        return recover(
            args.port,
            args.label,
            args.health_url,
            plist_path,
            restart_state_path,
            args.restart_window_seconds,
            args.max_restarts,
        )
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        return {"ok": False, "state": "failed", "recovered": False, "detail": str(exc)}


def main() -> int:
    args = __parse_args()
    plist_path, hold_path, restart_state_path = __runtime_paths(args)

    if maintenance_hold_active(hold_path):
        result = __maintenance_result()
    elif args.check_only:
        result = __check_only_result(args.health_url)
    else:
        result = __safe_recovery(args, plist_path, restart_state_path)
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("ok") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
