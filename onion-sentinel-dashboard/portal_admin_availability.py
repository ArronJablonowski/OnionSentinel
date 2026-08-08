"""Update-availability policy for Administration actions."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class AdminCommandOutcome:
    """Bounded process result projected by the portal's host adapter."""

    returncode: int | None
    stdout: str = ""
    stderr: str = ""
    error: str = ""


@dataclass(frozen=True)
class AdminAvailabilitySources:
    """Explicit cached-state and process sources used by availability policy."""

    read_macos_update_status: Callable[[], dict]
    run_command: Callable[[list[str], int, bool], AdminCommandOutcome]
    hermes_bin: str


def _integer(value: object, fallback: int = -1) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return fallback


def _macos_availability(status: dict) -> tuple[bool, str]:
    count = _integer(status.get("count"))
    checked_at = str(status.get("checked_at") or "unknown time")
    if count > 0:
        return True, f"{count} macOS update(s) available. Last checked {checked_at}."
    if count == 0:
        return False, f"No macOS updates available. Last checked {checked_at}."
    return (
        False,
        "macOS update availability is unknown. Refresh the update check first. "
        f"Last checked {checked_at}.",
    )


def _command_error(prefix: str, outcome: AdminCommandOutcome, fallback: str) -> str:
    detail = outcome.error or outcome.stderr.strip() or outcome.stdout.strip() or fallback
    return f"{prefix}: {detail}"


def _brew_availability(
    sources: AdminAvailabilitySources,
) -> tuple[bool, str]:
    outcome = sources.run_command(
        ["/opt/homebrew/bin/brew", "outdated", "--quiet"], 20, False
    )
    if outcome.error:
        return (
            False,
            f"Could not determine Homebrew update availability: {outcome.error}",
        )
    outdated = [line.strip() for line in outcome.stdout.splitlines() if line.strip()]
    if outdated:
        preview = ", ".join(outdated[:5])
        suffix = "" if len(outdated) <= 5 else f" and {len(outdated) - 5} more"
        return (
            True,
            f"{len(outdated)} Homebrew package(s) outdated: {preview}{suffix}.",
        )
    if outcome.returncode == 0:
        return False, "No Homebrew updates available."
    return (
        False,
        _command_error(
            "Could not determine Homebrew update availability",
            outcome,
            "brew outdated failed",
        )
        + ".",
    )


def _tail(value: str, limit: int = 240) -> str:
    return value[-limit:] if value else ""


def _hermes_availability(
    sources: AdminAvailabilitySources,
) -> tuple[bool, str]:
    outcome = sources.run_command(
        [sources.hermes_bin, "update", "--check"], 45, True
    )
    if outcome.error:
        return (
            False,
            f"Could not determine Hermes Agent update availability: {outcome.error}",
        )
    output = outcome.stdout.strip()
    lower = output.lower()
    if "update available" in lower or "commit behind" in lower:
        return True, "Hermes Agent update is available."
    if "up to date" in lower or "already up" in lower or "no update" in lower:
        return False, "No Hermes Agent update available."
    detail = _tail(output) or "empty output"
    if outcome.returncode == 0:
        return False, f"No Hermes Agent update detected. Check output: {detail}."
    return (
        False,
        "Could not determine Hermes Agent update availability: "
        f"{detail if output else 'hermes update --check failed'}.",
    )


def compose_admin_action_availability(
    action_id: str,
    skip_expensive: bool,
    sources: AdminAvailabilitySources,
) -> tuple[bool, str]:
    """Return whether one Administration action can currently be started."""
    if action_id == "reboot":
        return (
            True,
            "Reboot is available when no other admin action is running and typed confirmation is provided.",
        )
    if skip_expensive:
        return True, "Availability check skipped while another admin action is running."
    if action_id == "macos-update":
        return _macos_availability(sources.read_macos_update_status())
    if action_id == "brew-update":
        return _brew_availability(sources)
    if action_id == "hermes-update":
        return _hermes_availability(sources)
    return True, "No update availability rule is configured for this action."
