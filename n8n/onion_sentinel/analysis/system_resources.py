"""Bounded macOS resource sampling and per-analysis maxima monitoring."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
import shlex
import threading
from typing import Any, Callable, Mapping


MetricValues = tuple[
    float | None,
    float | None,
    float | None,
    float | None,
    float | None,
    float | None,
    float | None,
]
Sample = tuple[
    float | None,
    float | None,
    float | None,
    float | None,
    float | None,
    float | None,
    float | None,
    str,
]
RunCommand = Callable[..., Any]
ReadMactop = Callable[..., Sample]
ReadGpu = Callable[..., tuple[float | None, str]]


@dataclass(frozen=True)
class Dependencies:
    environment: Mapping[str, str]
    path_exists: Callable[[Path], bool]
    run_command: RunCommand
    process_error: type[Exception]


class SamplingCancelled(RuntimeError):
    """Raised inside a bounded sampler when its owning monitor is stopping."""


@dataclass(frozen=True)
class CommandAttempt:
    process: Any | None
    error: str = ""
    cancelled: bool = False


def _empty(note: str) -> Sample:
    return None, None, None, None, None, None, None, note


def parse_gpu_temperature(output: str) -> float | None:
    """Extract the greatest GPU temperature from common sensor output."""
    matches = re.findall(
        r"(?im)\bgpu\b[^\n:]*[:=]?\s*([0-9]+(?:\.[0-9]+)?)\s*(?:°\s*)?c\b",
        output,
    )
    if not matches:
        matches = re.findall(
            r"(?im)\bgpu\b.*?([0-9]+(?:\.[0-9]+)?)\s*(?:°\s*)?c\b",
            output,
        )
    values = [float(value) for value in matches]
    return max(values) if values else None


def parse_float(value: Any) -> float | None:
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _memory_percent(sample: dict[str, Any]) -> float | None:
    memory = sample.get("memory")
    values = memory if isinstance(memory, dict) else {}
    used, total = values.get("used"), values.get("total")
    try:
        return (float(used) / float(total)) * 100 if used is not None and total else None
    except (TypeError, ValueError, ZeroDivisionError):
        return None


def parse_mactop_sample(output: str) -> MetricValues:
    """Return max-relevant system metrics from one mactop JSON sample."""
    try:
        payload = json.loads(output)
    except json.JSONDecodeError:
        return (None,) * 7
    sample = payload[0] if isinstance(payload, list) and payload else payload
    if not isinstance(sample, dict):
        return (None,) * 7
    soc_value = sample.get("soc_metrics")
    gpu_value = sample.get("gpu_metrics")
    soc = soc_value if isinstance(soc_value, dict) else {}
    gpu = gpu_value if isinstance(gpu_value, dict) else {}
    gpu_percent = parse_float(gpu.get("active_percent"))
    if gpu_percent is None:
        gpu_percent = parse_float(sample.get("gpu_usage"))
    if gpu_percent is None:
        gpu_percent = parse_float(soc.get("gpu_active"))
    power_watts = parse_float(soc.get("total_power"))
    if power_watts is None:
        power_watts = parse_float(soc.get("system_power"))
    return (
        parse_float(soc.get("gpu_temp")),
        _memory_percent(sample),
        power_watts,
        parse_float(sample.get("cpu_usage")),
        gpu_percent,
        parse_float(soc.get("cpu_temp")),
        parse_float(soc.get("soc_temp")),
    )


def mactop_command(dependencies: Dependencies) -> list[str] | None:
    custom = str(dependencies.environment.get("SOC_MACTOP_COMMAND") or "").strip()
    if custom:
        return shlex.split(custom)
    for name in ("/opt/homebrew/bin/mactop", "/usr/local/bin/mactop", "mactop"):
        if name.startswith("/") and not dependencies.path_exists(Path(name)):
            continue
        return [name]
    return None


def raise_if_cancelled(cancel_event: threading.Event | None) -> None:
    if cancel_event is not None and cancel_event.is_set():
        raise SamplingCancelled("system resource sampling cancelled")


def _progress(cancel_event: threading.Event | None) -> Callable[[], None] | None:
    return (
        lambda: raise_if_cancelled(cancel_event)
        if cancel_event is not None
        else None
    )


def _run_sensor_command(
    command: list[str],
    *,
    dependencies: Dependencies,
    cancel_event: threading.Event | None,
    timeout_seconds: int,
) -> CommandAttempt:
    try:
        process = dependencies.run_command(
            command,
            timeout_seconds=timeout_seconds,
            max_stdout_bytes=2 * 1024 * 1024,
            max_stderr_bytes=256 * 1024,
            progress_callback=_progress(cancel_event),
            progress_interval_seconds=0.1,
        )
        return CommandAttempt(process=process)
    except SamplingCancelled:
        return CommandAttempt(process=None, cancelled=True)
    except FileNotFoundError:
        return CommandAttempt(process=None, error=f"{command[0]} not found")
    except dependencies.process_error as exc:
        return CommandAttempt(
            process=None,
            error=f"{command[0]} unavailable: {exc}",
        )
    except Exception as exc:
        return CommandAttempt(process=None, error=f"{command[0]} failed: {exc}")


def _mactop_process_sample(process: Any, command_name: str) -> Sample:
    if process.returncode != 0 and not process.stdout.strip():
        detail = (process.stderr or "").strip().splitlines()
        suffix = f": {detail[-1][:120]}" if detail else ""
        return _empty(f"{command_name} unavailable{suffix}")
    values = parse_mactop_sample(process.stdout)
    if any(value is not None for value in values):
        return (*values, "mactop sampled")
    return _empty(f"{command_name} returned no parseable mactop metrics")


def read_mactop_system_sample(
    *,
    dependencies: Dependencies,
    cancel_event: threading.Event | None = None,
) -> Sample:
    command = mactop_command(dependencies)
    if not command:
        return _empty("mactop not found")
    if cancel_event is not None and cancel_event.is_set():
        return _empty("mactop sampling cancelled")
    attempt = _run_sensor_command(
        [*command, "--headless", "--format", "json", "--count", "1"],
        dependencies=dependencies,
        cancel_event=cancel_event,
        timeout_seconds=8,
    )
    if attempt.cancelled:
        return _empty("mactop sampling cancelled")
    if attempt.process is None:
        return _empty(attempt.error)
    return _mactop_process_sample(attempt.process, command[0])


def _gpu_commands(dependencies: Dependencies) -> list[list[str]]:
    commands: list[list[str]] = []
    custom = str(dependencies.environment.get("SOC_GPU_TEMP_COMMAND") or "").strip()
    if custom:
        commands.append(shlex.split(custom))
    return commands + [
        ["powermetrics", "--samplers", "smc", "-n", "1", "-i", "500"],
        ["/usr/bin/powermetrics", "--samplers", "smc", "-n", "1", "-i", "500"],
    ]


def _gpu_process_result(
    process: Any, command_name: str,
) -> tuple[float | None, str]:
    output = "\n".join(
        part for part in (process.stdout, process.stderr) if part
    )
    value = parse_gpu_temperature(output)
    if value is not None:
        return value, "GPU temperature sampled"
    detail = (process.stderr or process.stdout or "").strip().splitlines()
    suffix = f": {detail[-1][:120]}" if detail else ""
    return None, f"{command_name} unavailable{suffix}"


def read_gpu_temperature_celsius(
    *,
    dependencies: Dependencies,
    cancel_event: threading.Event | None = None,
) -> tuple[float | None, str]:
    """Read GPU temperature through bounded unprivileged sensor commands."""
    notes: list[str] = []
    for command in _gpu_commands(dependencies):
        if cancel_event is not None and cancel_event.is_set():
            return None, "GPU temperature sampling cancelled"
        attempt = _run_sensor_command(
            command,
            dependencies=dependencies,
            cancel_event=cancel_event,
            timeout_seconds=4,
        )
        if attempt.cancelled:
            return None, "GPU temperature sampling cancelled"
        if attempt.process is None:
            notes.append(attempt.error)
            continue
        value, note = _gpu_process_result(attempt.process, command[0])
        if value is not None:
            return value, note
        notes.append(note)
    return None, "; ".join(notes[:3]) or "GPU temperature unavailable"


class SystemResourceMonitor:
    """Best-effort sampler retaining maximum system metrics per analysis."""

    _ATTRIBUTES = (
        "max_gpu_celsius",
        "max_memory_percent",
        "max_power_watts",
        "max_cpu_percent",
        "max_gpu_percent",
        "max_cpu_celsius",
        "max_soc_celsius",
    )

    def __init__(
        self,
        interval_seconds: float = 5.0,
        *,
        read_mactop: ReadMactop,
        read_gpu: ReadGpu,
    ) -> None:
        self.interval_seconds = interval_seconds
        for attribute in self._ATTRIBUTES:
            setattr(self, attribute, None)
        self.note = "system metrics not sampled"
        self._read_mactop = read_mactop
        self._read_gpu = read_gpu
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None:
            raise RuntimeError("system resource monitor was already started")
        self._stop.clear()
        self._sample_once()
        self._thread = threading.Thread(
            target=self._run,
            name="system-resource-monitor",
            daemon=False,
        )
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            if self._stop.wait(self.interval_seconds):
                break
            self._sample_once()

    def _record_maxima(self, values: MetricValues) -> None:
        for attribute, value in zip(self._ATTRIBUTES, values):
            if value is None:
                continue
            previous = getattr(self, attribute)
            setattr(self, attribute, value if previous is None else max(previous, value))

    def _sample_once(self) -> None:
        if self._stop.is_set():
            return
        *values, note = self._read_mactop(cancel_event=self._stop)
        if self._stop.is_set():
            return
        if values[0] is None:
            gpu_value, fallback_note = self._read_gpu(cancel_event=self._stop)
            if self._stop.is_set():
                return
            if gpu_value is not None:
                values[0] = gpu_value
                note = f"{note}; {fallback_note}"
        self.note = note
        self._record_maxima(tuple(values))

    def stop(self) -> None:
        self._stop.set()
        thread = self._thread
        if thread is None:
            return
        thread.join(timeout=12)
        if thread.is_alive():
            raise RuntimeError(
                "system resource monitor did not terminate after cancellation"
            )
        self._thread = None
