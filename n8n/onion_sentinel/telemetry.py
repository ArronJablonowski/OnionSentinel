"""Best-effort terminal telemetry for the AI analysis pipeline."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping


@dataclass(frozen=True)
class FinalizationInputs:
    status: str
    error: str
    has_prompt: bool
    monitor_started: bool
    harness: Any = None


@dataclass(frozen=True)
class FinalizationPorts:
    fail_harness: Callable[[str], None]
    stop_monitor: Callable[[], None]
    build_record: Callable[[], Mapping[str, Any]]
    append_record: Callable[[Mapping[str, Any]], None]
    write_current: Callable[[Mapping[str, Any]], None]
    cleanup_active: Callable[[], None]
    warn: Callable[[str], None]


def finalize(inputs: FinalizationInputs, ports: FinalizationPorts) -> None:
    """Publish terminal telemetry without changing the analysis outcome."""
    try:
        try:
            if inputs.harness is not None and inputs.status != "success":
                ports.fail_harness(inputs.error or "analysis did not complete")
            if inputs.monitor_started:
                ports.stop_monitor()
            if inputs.has_prompt:
                record = ports.build_record()
                ports.append_record(record)
                ports.write_current(record)
        except Exception as exc:
            ports.warn(
                "analysis telemetry finalization failed: "
                f"{type(exc).__name__}"
            )
    finally:
        try:
            ports.cleanup_active()
        except OSError:
            pass
