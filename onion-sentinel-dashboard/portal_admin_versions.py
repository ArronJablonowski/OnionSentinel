"""Bounded version discovery for Administration update cards."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import json
from pathlib import Path
import re


@dataclass(frozen=True)
class AdminVersionSources:
    """Explicit process and cached-status sources used by version discovery."""

    run_command: Callable[[list[str], int], tuple[int | None, str]]
    read_macos_update_status: Callable[[], dict]
    hermes_bin: str
    hermes_project: Path


def _shorten(value: str, max_len: int = 96) -> str:
    normalized = " ".join(str(value).split())
    if len(normalized) <= max_len:
        return normalized
    return normalized[: max_len - 1].rstrip() + "…"


def _display_version(value: object, fallback: str) -> str:
    if isinstance(value, list):
        return ", ".join(str(item) for item in value if item) or fallback
    return str(value or fallback)


def _brew_entries(data: object) -> list[dict]:
    entries: list[dict] = []
    if not isinstance(data, dict):
        return entries
    for section, kind in (("formulae", "formula"), ("casks", "cask")):
        raw_items = data.get(section)
        if not isinstance(raw_items, list):
            continue
        for item in raw_items:
            if isinstance(item, dict):
                entries.append({**item, "kind": kind})
    return entries


def _brew_entry_versions(item: dict) -> tuple[str, str, str]:
    name = str(item.get("name") or item.get("token") or item.get("full_name") or "unknown")
    installed = _display_version(
        item.get("installed_versions")
        or item.get("installed_version")
        or item.get("installed"),
        "installed",
    )
    latest = _display_version(
        item.get("current_version")
        or item.get("current_versions")
        or item.get("latest_version")
        or item.get("latest"),
        "available",
    )
    return name, installed, latest


def _colon_fields(output: str) -> dict[str, str]:
    fields = {}
    for line in output.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            fields[key.strip()] = value.strip()
    return fields


def _macos_update_projection(current: str, status: dict) -> dict[str, str]:
    updates = status.get("updates") if isinstance(status.get("updates"), list) else []
    checked_at = status.get("checked_at") or "unknown time"
    if updates:
        return {
            "current": current,
            "latest": _shorten(str(updates[0]), 120),
            "detail": f"{len(updates)} cached macOS update(s) available from softwareupdate check at {checked_at}.",
        }
    if int(status.get("count", 0) or 0) == 0:
        return {
            "current": current,
            "latest": "Current",
            "detail": f"No cached macOS updates available. Last checked {checked_at}.",
        }
    return {
        "current": current,
        "latest": "Unknown",
        "detail": f"macOS update availability is unknown. Last check: {status.get('status') or 'not checked'}.",
    }


def _macos_version_info(sources: AdminVersionSources) -> dict[str, str]:
    _rc, output = sources.run_command(["/usr/bin/sw_vers"], 6)
    fields = _colon_fields(output)
    version = fields.get("ProductVersion") or "Unknown"
    build = fields.get("BuildVersion")
    current = f"macOS {version}" + (f" ({build})" if build else "")
    return _macos_update_projection(current, sources.read_macos_update_status())


def _decode_brew_entries(rc: int | None, output: str) -> list[dict]:
    if rc != 0:
        return []
    try:
        json_start = output.find("{")
        payload = output[json_start:] if json_start >= 0 else output
        return _brew_entries(json.loads(payload))
    except (TypeError, ValueError, json.JSONDecodeError):
        return []


def _brew_outdated_projection(
    current: str, rc: int | None, output: str, entries: list[dict]
) -> dict[str, str]:
    if not entries and rc == 0:
        return {
            "current": current,
            "latest": "Current",
            "detail": "No Homebrew formulae or casks are outdated.",
        }
    if not entries:
        return {
            "current": current,
            "latest": "Unknown",
            "detail": _shorten(
                output or "Could not determine Homebrew outdated versions.", 260
            ),
        }
    versions = [_brew_entry_versions(item) for item in entries[:6]]
    suffix = "" if len(entries) <= 6 else f" +{len(entries) - 6} more"
    latest = _shorten(", ".join(f"{name} {available}" for name, _installed, available in versions) + suffix, 140)
    details = "; ".join(
        f"{name}: {installed} → {available}"
        for name, installed, available in versions
    )
    detail_suffix = "." if len(entries) <= 6 else f"; plus {len(entries) - 6} more."
    return {
        "current": current,
        "latest": latest,
        "detail": f"{len(entries)} Homebrew package(s) outdated: {details}{detail_suffix}",
    }


def _brew_version_info(sources: AdminVersionSources) -> dict[str, str]:
    _rc, version_output = sources.run_command(["/opt/homebrew/bin/brew", "--version"], 8)
    lines = version_output.splitlines()
    current = lines[0].strip() if lines else "Homebrew version unknown"
    rc, outdated_output = sources.run_command(
        ["/opt/homebrew/bin/brew", "outdated", "--json=v2"], 25
    )
    entries = _decode_brew_entries(rc, outdated_output)
    return _brew_outdated_projection(current, rc, outdated_output, entries)


def _hermes_git_metadata(
    sources: AdminVersionSources,
) -> tuple[str, str, str, str]:
    project = str(sources.hermes_project)
    _lrc, local_hash = sources.run_command(
        ["/usr/bin/git", "-C", project, "rev-parse", "--short", "HEAD"], 8
    )
    _orc, origin_hash = sources.run_command(
        ["/usr/bin/git", "-C", project, "rev-parse", "--short", "origin/main"], 8
    )
    _src, subject = sources.run_command(
        ["/usr/bin/git", "-C", project, "log", "origin/main", "-1", "--pretty=%s"], 8
    )
    _vrc, origin_init = sources.run_command(
        ["/usr/bin/git", "-C", project, "show", "origin/main:hermes_cli/__init__.py"], 8
    )
    return local_hash, origin_hash, subject, origin_init


def _hermes_labels(current_line: str, origin_init: str) -> tuple[str, str, str]:
    version_match = re.search(r"Hermes Agent\s+(v\S+)", current_line)
    version_label = version_match.group(1) if version_match else current_line
    origin_version_match = re.search(r"__version__\s*=\s*['\"]([^'\"]+)['\"]", origin_init)
    origin_release_match = re.search(r"__release_date__\s*=\s*['\"]([^'\"]+)['\"]", origin_init)
    origin_version = f"v{origin_version_match.group(1)}" if origin_version_match else "latest"
    origin_release = f" ({origin_release_match.group(1)})" if origin_release_match else ""
    return version_label, origin_version, origin_release


def _hermes_version_info(sources: AdminVersionSources) -> dict[str, str]:
    _rc, version_output = sources.run_command([sources.hermes_bin, "--version"], 25)
    lines = version_output.splitlines()
    current_line = lines[0].strip() if lines else "Hermes Agent version unknown"
    local_hash, origin_hash, subject, origin_init = _hermes_git_metadata(sources)
    version_label, origin_version, origin_release = _hermes_labels(
        current_line, origin_init
    )
    current = _shorten(
        f"Hermes Agent {version_label}" + (f" · {local_hash}" if local_hash else ""), 110
    )
    if local_hash and origin_hash and local_hash != origin_hash:
        return {
            "current": current,
            "latest": _shorten(
                f"Hermes Agent {origin_version}{origin_release} · {origin_hash}", 110
            ),
            "detail": _shorten(
                f"Current Hermes version {version_label} at commit {local_hash}; latest available is Hermes Agent {origin_version}{origin_release} at {origin_hash}. {subject}",
                260,
            ),
        }
    if "Update available" in version_output:
        return {
            "current": current,
            "latest": "Available",
            "detail": _shorten(
                "Hermes reports an update is available: " + " ".join(lines[-2:]), 220
            ),
        }
    return {
        "current": current,
        "latest": "Current",
        "detail": _shorten(
            f"Current commit {local_hash} matches origin/main."
            if local_hash
            else "No Hermes update version detail available.",
            220,
        ),
    }


def compose_admin_action_version_info(
    action_id: str, sources: AdminVersionSources
) -> dict[str, str]:
    """Return current/latest metadata for one supported Administration action."""
    if action_id == "macos-update":
        return _macos_version_info(sources)
    if action_id == "brew-update":
        return _brew_version_info(sources)
    if action_id == "hermes-update":
        return _hermes_version_info(sources)
    return {
        "current": "Not applicable",
        "latest": "Not applicable",
        "detail": "This action does not have update-version metadata.",
    }
