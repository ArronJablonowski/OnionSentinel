"""Administration process and daemon probe policy."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import re


@dataclass(frozen=True)
class ServiceCommandOutcome:
    returncode: int | None
    stdout: str = ""
    stderr: str = ""
    error: str = ""


@dataclass(frozen=True)
class AdminServiceProbeSources:
    process_lines: Callable[[], list[str]]
    docker_info: Callable[[], ServiceCommandOutcome]


def matching_process_lines(
    lines: list[str], matchers: list[str], exclude: list[str] | None = None
) -> list[str]:
    blocked = exclude or []
    return [
        line.strip()
        for line in lines
        if line.strip()
        and any(matcher in line for matcher in matchers)
        and not any(value in line for value in blocked)
    ]


def _process_probe(
    sources: AdminServiceProbeSources,
    matchers: list[str],
    running_prefix: str,
    missing_message: str,
    error_prefix: str,
) -> tuple[bool, str]:
    try:
        matches = matching_process_lines(sources.process_lines(), matchers, ["grep"])
    except Exception as exc:
        return False, f"WARNING: {error_prefix}: {exc}"
    if matches:
        return True, f"{running_prefix}: {' | '.join(matches[:2])}"
    return False, missing_message


def macs_fan_control_status(
    sources: AdminServiceProbeSources,
) -> tuple[bool, str]:
    return _process_probe(
        sources,
        [
            "Macs Fan Control.app/Contents/MacOS/Macs Fan Control",
            "com.crystalidea.macsfancontrol",
            "MacsFanControl",
        ],
        "Macs Fan Control is running",
        "WARNING: Macs Fan Control is not currently running on this system.",
        "Unable to verify Macs Fan Control process state",
    )


def codex_app_status(sources: AdminServiceProbeSources) -> tuple[bool, str]:
    return _process_probe(
        sources,
        [
            "/Applications/Codex.app/Contents/MacOS/Codex",
            "/Applications/Codex.app/Contents/Resources/codex app-server",
        ],
        "Codex app is running",
        "WARNING: Codex app is not currently running on this system.",
        "Unable to verify Codex app process state",
    )


_CODEX_CLI_EXCLUDES = (
    "/Applications/Codex.app/",
    "Codex Computer Use.app/",
    "Codex for Chrome",
    "com.openai.codex",
    "Sparkle/Launcher",
    "browser_crashpad_handler",
    "grep",
)
_CODEX_CLI_PATTERNS = (
    re.compile(r"(^|/)codex(\s|$)", re.IGNORECASE),
    re.compile(
        r"(^|\s)codex\s+(exec|run|login|resume|mcp|sandbox|apply|--)",
        re.IGNORECASE,
    ),
    re.compile(r"openai[-_]codex", re.IGNORECASE),
)


def _codex_cli_matches(lines: list[str]) -> list[str]:
    return [
        line.strip()
        for line in lines
        if line.strip()
        and not any(value in line for value in _CODEX_CLI_EXCLUDES)
        and any(pattern.search(line) for pattern in _CODEX_CLI_PATTERNS)
    ]


def codex_cli_status(sources: AdminServiceProbeSources) -> tuple[bool, str]:
    try:
        matches = _codex_cli_matches(sources.process_lines())
    except Exception as exc:
        return False, f"WARNING: Unable to verify Codex CLI process state: {exc}"
    if not matches:
        return False, "Codex CLI is not currently running."
    preview = " | ".join(matches[:3])
    suffix = "" if len(matches) <= 3 else f" | +{len(matches) - 3} more"
    return True, f"Codex CLI is running: {preview}{suffix}"


def _docker_processes(
    sources: AdminServiceProbeSources,
) -> tuple[list[str], list[str]]:
    lines = sources.process_lines()
    desktop = matching_process_lines(
        lines,
        [
            "/Applications/Docker.app/Contents/MacOS/Docker",
            "com.docker.backend",
            "com.docker.hyperkit",
            "com.docker.virtualization",
            "docker desktop",
        ],
        ["grep"],
    )
    helper = matching_process_lines(lines, ["com.docker.vmnetd"], ["grep"])
    return desktop, helper


def _docker_unavailable_detail(
    outcome: ServiceCommandOutcome, helper: list[str]
) -> str:
    stderr_lines = outcome.stderr.strip().splitlines()
    reason = stderr_lines[-1] if stderr_lines else "docker info did not report a running daemon"
    helper_note = ""
    if helper:
        helper_note = (
            " Docker helper is present but the daemon is unavailable: "
            f"{' | '.join(helper[:1])}."
        )
    return (
        "WARNING: Docker is not currently running or the daemon is unavailable: "
        f"{reason}.{helper_note}"
    )


def docker_status(sources: AdminServiceProbeSources) -> tuple[bool, str]:
    try:
        outcome = sources.docker_info()
        if outcome.error:
            raise RuntimeError(outcome.error)
        if outcome.returncode == 0 and outcome.stdout.strip():
            version = outcome.stdout.strip().splitlines()[0]
            return True, f"Docker daemon is running. Server version: {version}."
        desktop, helper = _docker_processes(sources)
    except Exception as exc:
        return False, f"WARNING: Unable to verify Docker state: {exc}"
    if desktop:
        return (
            True,
            "Docker Desktop process is running, but docker info did not return "
            f"daemon details: {' | '.join(desktop[:2])}",
        )
    return False, _docker_unavailable_detail(outcome, helper)
