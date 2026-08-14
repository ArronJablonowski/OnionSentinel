"""Update-source health checks and homepage precedence policy."""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import datetime as dt
import json
from pathlib import Path


UPDATE_ACTION_IDS = ("macos-update", "brew-update", "hermes-update")


@dataclass(frozen=True)
class UpdateCommandOutcome:
    returncode: int
    stdout: str = ""
    stderr: str = ""


@dataclass(frozen=True)
class UpdateHealthSources:
    macos_status_file: Path
    run_brew_check: Callable[[], UpdateCommandOutcome]
    run_hermes_check: Callable[[], UpdateCommandOutcome]
    read_action_status: Callable[[str], dict]
    process_running: Callable[[object], bool]
    action_labels: Mapping[str, str]
    parse_timestamp: Callable[[object], dt.datetime]
    format_timestamp: Callable[[dt.datetime], str]


def read_macos_update_status(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception as exc:
        return {
            "status": "Not checked",
            "count": -1,
            "updates": [],
            "error": str(exc),
        }


def compose_macos_update_metric(path: Path) -> tuple[str, str, int]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return "Not checked", "macOS update status has not been checked yet.", -1
    status = str(data.get("status") or "Unknown")
    checked_at = str(data.get("checked_at") or "unknown time")
    updates = data.get("updates") or []
    try:
        count = int(data.get("count", -1))
    except (TypeError, ValueError):
        count = -1
    details = [f"Checked {checked_at}"]
    if isinstance(updates, list) and updates:
        details.append("Updates: " + "; ".join(str(item) for item in updates[:5]))
    if data.get("error"):
        details.append("Error: " + str(data["error"]))
    return status, " · ".join(details), count


def compose_brew_update_source_metric(
    run_check: Callable[[], UpdateCommandOutcome],
) -> tuple[int, str, list[str]]:
    try:
        outcome = run_check()
    except Exception as exc:
        return -1, f"Could not determine Homebrew updates: {exc}", []
    outdated = [line.strip() for line in outcome.stdout.splitlines() if line.strip()]
    if outdated:
        preview = ", ".join(outdated[:8])
        suffix = "" if len(outdated) <= 8 else f" and {len(outdated) - 8} more"
        detail = f"{len(outdated)} Homebrew package(s) outdated: {preview}{suffix}."
        return len(outdated), detail, outdated
    if outcome.returncode == 0:
        return 0, "No Homebrew updates available.", []
    error = outcome.stderr.strip() or "brew outdated failed"
    return -1, f"Could not determine Homebrew updates: {error}.", []


def compose_hermes_update_source_metric(
    run_check: Callable[[], UpdateCommandOutcome],
) -> tuple[bool, str]:
    try:
        outcome = run_check()
    except Exception as exc:
        return False, f"Could not determine Hermes Agent update availability: {exc}"
    output = outcome.stdout.strip()
    lower = output.lower()
    available_markers = ("update available", "commits behind", "run 'hermes update'")
    if any(marker in lower for marker in available_markers):
        first_line = output.splitlines()[0] if output.splitlines() else "Hermes Agent update is available."
        return True, f"Hermes Agent update available: {first_line}"
    current_markers = ("up to date", "already up", "no update")
    if any(marker in lower for marker in current_markers) or outcome.returncode == 0:
        return False, "No Hermes Agent update available."
    error = output[-240:] or "hermes update --check failed"
    return False, f"Could not determine Hermes Agent update availability: {error}."


def _short_action_label(label: str, suffix: str) -> str:
    for marker, short in (
        ("Homebrew", "brew"),
        ("macOS", "macOS"),
        ("Hermes", "Hermes"),
    ):
        if marker in label:
            return f"{short} {suffix}"
    return "Update running" if suffix == "running" else "Failed"


def compose_latest_running_update_action(
    sources: UpdateHealthSources,
) -> tuple[str, str] | None:
    for action_id in UPDATE_ACTION_IDS:
        status = sources.read_action_status(action_id)
        running = _running_update_action(sources, action_id, status)
        if running is not None:
            return running
    return None


def _running_update_action(
    sources: UpdateHealthSources,
    action_id: str,
    status: dict,
) -> tuple[str, str] | None:
    if status.get("state") != "running":
        return None
    pid = status.get("pid")
    try:
        running = sources.process_running(pid)
    except Exception:
        running = False
    if not running:
        return None
    label = str(
        status.get("label") or sources.action_labels.get(action_id) or action_id
    )
    exact = _running_update_timestamp(sources, status)
    detail = (
        f"{label} is currently running as PID {pid or 'unknown'}; started at "
        f"{exact}. The Updates metric will refresh availability after the action completes."
    )
    return _short_action_label(label, "running"), detail


def _running_update_timestamp(
    sources: UpdateHealthSources,
    status: dict,
) -> str:
    timestamp = status.get("started_at") or status.get("updated_at")
    try:
        parsed = (
            sources.parse_timestamp(timestamp).astimezone()
            if timestamp
            else None
        )
    except Exception:
        parsed = None
    return sources.format_timestamp(parsed) if parsed else "unknown time"


def _failure_record(
    action_id: str, status: dict, sources: UpdateHealthSources
) -> tuple[dt.datetime, str, str]:
    timestamp = (
        status.get("finished_at")
        or status.get("updated_at")
        or status.get("started_at")
    )
    try:
        parsed = (
            sources.parse_timestamp(timestamp).astimezone()
            if timestamp
            else dt.datetime.fromtimestamp(0).astimezone()
        )
    except Exception:
        parsed = dt.datetime.fromtimestamp(0).astimezone()
    label = str(sources.action_labels.get(action_id) or action_id)
    exact = sources.format_timestamp(parsed) if timestamp else "unknown time"
    message = str(status.get("message") or "No failure message recorded.")
    return parsed, label, f"WARNING: {label} last failed at {exact}. {message}"


def compose_latest_update_action_failure(
    sources: UpdateHealthSources,
) -> tuple[str, str] | None:
    failures = []
    for action_id in UPDATE_ACTION_IDS:
        status = sources.read_action_status(action_id)
        if str(status.get("state") or "idle") in {"failed", "error", "unknown"}:
            failures.append(_failure_record(action_id, status, sources))
    if not failures:
        return None
    _parsed, label, detail = max(failures, key=lambda item: item[0])
    return _short_action_label(label, "failed"), detail


def compose_prioritized_updates_metric(
    sources: UpdateHealthSources,
) -> tuple[str, str, int, str]:
    running = compose_latest_running_update_action(sources)
    if running:
        label, detail = running
        return f"⏳ {label}", detail, 2, "running"
    failure = compose_latest_update_action_failure(sources)
    if failure:
        label, detail = failure
        return f"⚠ {label}", detail, -2, "failed"
    _mac_value, mac_detail, mac_count = compose_macos_update_metric(
        sources.macos_status_file
    )
    details = ["Priority order: macOS > Homebrew > Hermes Agent.", f"macOS: {mac_detail}"]
    if mac_count > 0:
        return f"{mac_count} macOS", " · ".join(details), mac_count, "macos"
    brew_count, brew_detail, _items = compose_brew_update_source_metric(
        sources.run_brew_check
    )
    details.append(f"Homebrew: {brew_detail}")
    if brew_count > 0:
        return f"{brew_count} brew", " · ".join(details), brew_count, "brew"
    hermes_available, hermes_detail = compose_hermes_update_source_metric(
        sources.run_hermes_check
    )
    details.append(f"Hermes: {hermes_detail}")
    if hermes_available:
        return "Hermes", " · ".join(details), 1, "hermes"
    if mac_count < 0 or brew_count < 0:
        return "Unknown", " · ".join(details), -1, "unknown"
    return "Current", " · ".join(details), 0, "none"
