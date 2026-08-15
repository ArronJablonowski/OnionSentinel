#!/usr/bin/env python3
"""Bounded, read-only Raspberry Pi Relay readiness evaluation.

The probe intentionally never opens an SSH or application network connection.
It inspects local kernel, systemd, route, configuration, and credential metadata
so application monitoring can distinguish Relay-node readiness from downstream
availability without reading private keys or exposing host-specific values.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit


APP_DIR = Path(__file__).resolve().parent
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

from process_io import BoundedProcessError, run_bounded_command
from storage_health import evaluate_storage


CHECK_IDS = (
    "power",
    "thermal",
    "filesystem",
    "storage",
    "services",
    "routes",
    "ssh",
    "brokers",
)
MAX_REPORT_BYTES = 16 * 1024
MAX_CONFIG_BYTES = 1024 * 1024
MAX_KERNEL_BYTES = 64 * 1024
DEFAULT_CONFIG = Path("/opt/so-alert-relay/app/config.json")
DEFAULT_THERMAL_PATH = Path("/sys/class/thermal/thermal_zone0/temp")
PROBE_ENVIRONMENT = {
    "HOME": "/opt/so-alert-relay",
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
}


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except ValueError:
        return default


MAX_SOC_TEMPERATURE_C = min(
    90,
    max(40, _env_int("RELAY_SOC_MAX_TEMPERATURE_C", 80)),
)
SYSTEMD_TIMERS = (
    "so-alert-poll.timer",
    "so-pcap-broker.timer",
    "so-storage-health.timer",
)
SYSTEMD_SERVICES = (
    "so-alert-poll.service",
    "so-pcap-broker.service",
    "so-storage-health.service",
)
POWER_COMMAND = (
    "/usr/bin/sudo",
    "-n",
    "/usr/bin/vcgencmd",
    "get_throttled",
)
KERNEL_COMMAND = (
    "/usr/bin/sudo",
    "-n",
    "/usr/bin/journalctl",
    "--dmesg",
    "--boot=0",
    "--priority=warning..alert",
    "--no-pager",
    "--output=cat",
)
KERNEL_FAILURE_PATTERNS = (
    r"ext[234]-fs (?:error|warning)",
    r"buffer i/o error",
    r"blk_update_request: i/o error",
    r"critical medium error",
    r"\bmmc(?:blk)?\S*.*\b(?:error|timeout|failed)\b",
    r"\b(?:error|timeout|failed)\b.*\bmmc(?:blk)?\S*",
    r"uas_eh_abort_handler",
    r"usb disconnect",
    r"reset (?:high-speed|superspeed) usb device",
    r"remounting filesystem read-only",
)


def _check(identifier: str, passed: bool, pass_code: str, fail_code: str) -> dict:
    return {
        "id": identifier,
        "status": "pass" if passed else "fail",
        "code": pass_code if passed else fail_code,
    }


def _decode(value: object, limit: int = MAX_KERNEL_BYTES) -> str:
    if isinstance(value, bytes):
        return value[:limit].decode("utf-8", errors="replace")
    if isinstance(value, str):
        return value[:limit]
    return ""


def _run_local(command: list[str] | tuple[str, ...]) -> subprocess.CompletedProcess:
    result = run_bounded_command(
        list(command),
        timeout_seconds=15,
        max_stdout_bytes=MAX_KERNEL_BYTES,
        max_stderr_bytes=16 * 1024,
        env=PROBE_ENVIRONMENT,
    )
    return subprocess.CompletedProcess(
        list(command),
        result.returncode,
        _decode(result.stdout),
        _decode(result.stderr, 16 * 1024),
    )


def _completed(run_command, command: list[str] | tuple[str, ...]):
    try:
        return run_command(list(command))
    except (OSError, subprocess.SubprocessError, BoundedProcessError):
        return None


def _power_check(run_command) -> dict:
    result = _completed(run_command, POWER_COMMAND)
    if result is None or result.returncode != 0:
        return _check("power", False, "power_ready", "power_probe_failed")
    match = re.fullmatch(r"\s*throttled=0x([0-9a-fA-F]+)\s*", _decode(result.stdout, 128))
    if not match:
        return _check("power", False, "power_ready", "power_probe_failed")
    return _check("power", int(match.group(1), 16) == 0, "power_ready", "power_throttled")


def _thermal_check(thermal_path: Path) -> dict:
    try:
        if thermal_path.is_symlink() or not thermal_path.is_file():
            raise OSError("invalid thermal source")
        with thermal_path.open("rb") as handle:
            raw = handle.read(32)
        temperature_c = int(raw.strip()) / 1000.0
    except (OSError, ValueError, OverflowError):
        return _check("thermal", False, "temperature_ready", "temperature_probe_failed")
    return _check(
        "thermal",
        temperature_c < MAX_SOC_TEMPERATURE_C,
        "temperature_ready",
        "temperature_high",
    )


def _filesystem_check(run_command) -> dict:
    result = _completed(run_command, KERNEL_COMMAND)
    if result is None or result.returncode != 0:
        return _check(
            "filesystem",
            False,
            "filesystem_ready",
            "filesystem_probe_failed",
        )
    output = _decode(result.stdout).lower()
    failed = any(re.search(pattern, output) for pattern in KERNEL_FAILURE_PATTERNS)
    return _check(
        "filesystem",
        not failed,
        "filesystem_ready",
        "filesystem_errors",
    )


def evaluate_platform_health(
    run_command=_run_local,
    thermal_path: Path = DEFAULT_THERMAL_PATH,
) -> list[dict]:
    """Evaluate Pi power, SoC temperature, and current-boot kernel health."""
    return [
        _power_check(run_command),
        _thermal_check(Path(thermal_path)),
        _filesystem_check(run_command),
    ]


def _timers_ready(run_command) -> bool:
    for unit in SYSTEMD_TIMERS:
        active = _completed(run_command, ["/usr/bin/systemctl", "is-active", unit])
        enabled = _completed(run_command, ["/usr/bin/systemctl", "is-enabled", unit])
        if (
            active is None
            or active.returncode != 0
            or enabled is None
            or enabled.returncode != 0
        ):
            return False
    return True


def _service_properties(result) -> dict[str, str]:
    if result is None or result.returncode != 0:
        return {}
    properties = {}
    for line in _decode(result.stdout, 256).splitlines():
        name, separator, value = line.partition("=")
        if separator and name in {"LoadState", "Result"}:
            properties[name] = value
    return properties


def _services_ready(run_command) -> bool:
    for unit in SYSTEMD_SERVICES:
        properties = _service_properties(
            _completed(
                run_command,
                [
                    "/usr/bin/systemctl",
                    "show",
                    "--property=LoadState",
                    "--property=Result",
                    unit,
                ],
            )
        )
        if properties.get("LoadState") != "loaded":
            return False
        # The readiness probe runs inside so-storage-health.service. Its prior
        # failed Result must not make recovery impossible; the wrapper's own
        # debounced state proves failure/recovery for this component.
        if (
            unit != "so-storage-health.service"
            and properties.get("Result", "") not in {"", "success"}
        ):
            return False
    return True


def evaluate_service_health(run_command=_run_local) -> dict:
    """Require enabled/active timers and loaded, nonfailed service units."""
    passed = _timers_ready(run_command) and _services_ready(run_command)
    return _check("services", passed, "services_ready", "services_unavailable")


def _enabled_route_values(config: dict) -> list[object] | None:
    security_onion = config.get("security_onion")
    hosts: list[object] = [
        security_onion.get("host") if isinstance(security_onion, dict) else None
    ]
    for section_name in ("alert_ingest",):
        section = config.get(section_name)
        if isinstance(section, dict) and section.get("enabled") is True:
            hosts.append(section.get("host"))
    pcap = config.get("pcap_broker")
    if isinstance(pcap, dict) and pcap.get("enabled") is True:
        try:
            hosts.append(urlsplit(str(pcap.get("url") or "")).hostname)
        except ValueError:
            return None
        transfer = pcap.get("mac_transfer")
        if isinstance(transfer, dict):
            hosts.append(transfer.get("host"))
    return hosts


def _normalized_ip_hosts(values: list[object] | None) -> list[str] | None:
    if not values:
        return None
    normalized = []
    for value in values:
        try:
            normalized.append(str(ipaddress.ip_address(str(value or "").strip())))
        except ValueError:
            return None
    return list(dict.fromkeys(normalized)) if normalized else None


def _route_hosts(config: dict) -> list[str] | None:
    return _normalized_ip_hosts(_enabled_route_values(config))


def evaluate_route_health(config: dict, run_command=_run_local) -> dict:
    """Ask only the local kernel routing table how configured peers resolve."""
    hosts = _route_hosts(config)
    if hosts is None:
        return _check("routes", False, "routes_ready", "route_config_invalid")
    for host in hosts:
        result = _completed(run_command, ["/usr/sbin/ip", "route", "get", host])
        route = _decode(result.stdout, 4096).lower() if result is not None else ""
        if (
            result is None
            or result.returncode != 0
            or any(marker in route for marker in ("unreachable", "prohibit", "blackhole"))
        ):
            return _check("routes", False, "routes_ready", "routes_unavailable")
    return _check("routes", True, "routes_ready", "routes_unavailable")


def _credential_paths(config: dict) -> list[object]:
    paths: list[object] = []
    security_onion = config.get("security_onion")
    if isinstance(security_onion, dict):
        paths.append(security_onion.get("ssh_key"))
        pcap = config.get("pcap_broker")
        if isinstance(pcap, dict) and pcap.get("enabled") is True:
            paths.append(security_onion.get("pcap_ssh_key") or security_onion.get("ssh_key"))
    alert_ingest = config.get("alert_ingest")
    if isinstance(alert_ingest, dict) and alert_ingest.get("enabled") is True:
        paths.extend((alert_ingest.get("ssh_key"), alert_ingest.get("known_hosts")))
    pcap = config.get("pcap_broker")
    if isinstance(pcap, dict) and pcap.get("enabled") is True:
        transfer = pcap.get("mac_transfer")
        if isinstance(transfer, dict):
            paths.append(transfer.get("ssh_key"))
    return paths


def _secure_regular_metadata(value: object) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    try:
        metadata = Path(value).lstat()
    except OSError:
        return False
    mode = stat.S_IMODE(metadata.st_mode)
    return bool(
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == os.geteuid()
        and mode & stat.S_IRUSR
        and mode & 0o077 == 0
    )


def evaluate_ssh_health(config: dict) -> dict:
    """Check only file metadata; never read a private key or host-pin file."""
    paths = _credential_paths(config)
    passed = bool(paths) and all(_secure_regular_metadata(value) for value in paths)
    return _check("ssh", passed, "ssh_ready", "ssh_metadata_invalid")


def _present_strings(section: dict, fields: tuple[str, ...]) -> bool:
    return all(isinstance(section.get(field), str) and section[field].strip() for field in fields)


def _alert_broker_valid(config: dict) -> bool:
    alert_ingest = config.get("alert_ingest")
    if not isinstance(alert_ingest, dict) or alert_ingest.get("enabled") is not True:
        return True
    return bool(
        alert_ingest.get("mode") == "ssh_batch"
        and _present_strings(
            alert_ingest,
            ("host", "user", "ssh_key", "known_hosts", "remote_command"),
        )
    )


def _pcap_broker_valid(config: dict) -> bool:
    pcap = config.get("pcap_broker")
    if not isinstance(pcap, dict) or pcap.get("enabled") is not True:
        return True
    transfer = pcap.get("mac_transfer")
    try:
        broker_url = urlsplit(str(pcap.get("url") or ""))
    except ValueError:
        return False
    return bool(
        broker_url.scheme in {"http", "https"}
        and broker_url.hostname
        and isinstance(pcap.get("token"), str)
        and pcap["token"].strip()
        and isinstance(transfer, dict)
        and _present_strings(transfer, ("host", "user", "ssh_key"))
    )


def evaluate_broker_health(config: dict) -> dict:
    """Validate configured broker contracts without contacting either broker."""
    security_onion = config.get("security_onion")
    security_onion_valid = bool(
        isinstance(security_onion, dict)
        and _present_strings(security_onion, ("host", "ssh_user", "ssh_key"))
    )
    passed = security_onion_valid and _alert_broker_valid(config) and _pcap_broker_valid(config)
    return _check("brokers", passed, "brokers_ready", "broker_config_invalid")


def load_config(path: Path) -> dict:
    """Load one bounded regular JSON object and reject link-based substitution."""
    candidate = Path(path)
    metadata = candidate.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_CONFIG_BYTES:
        raise ValueError("Relay config is not an admissible regular file")
    with candidate.open("rb") as handle:
        raw = handle.read(MAX_CONFIG_BYTES + 1)
    if len(raw) > MAX_CONFIG_BYTES:
        raise ValueError("Relay config exceeds its byte budget")
    payload = json.loads(raw.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Relay config must be a JSON object")
    return payload


def evaluate_nonstorage_checks(config: dict) -> list[dict]:
    return [
        *evaluate_platform_health(),
        evaluate_service_health(),
        evaluate_route_health(config),
        evaluate_ssh_health(config),
        evaluate_broker_health(config),
    ]


def _storage_check(storage: object) -> dict:
    passed = isinstance(storage, dict) and storage.get("ok") is True
    return _check("storage", passed, "storage_ready", "storage_failed")


def _ordered_report(checks: list[dict]) -> dict:
    by_id = {
        item.get("id"): item
        for item in checks
        if isinstance(item, dict) and item.get("id") in CHECK_IDS
    }
    ordered = [
        by_id.get(identifier, _check(identifier, False, "ready", "probe_missing"))
        for identifier in CHECK_IDS
    ]
    return {
        "schema": "onion-sentinel-relay-readiness-v1",
        "ok": all(item["status"] == "pass" for item in ordered),
        "checks": ordered,
    }


def build_report(config_path: Path = DEFAULT_CONFIG) -> dict:
    """Compose the fixed-schema report from local read-only observations."""
    config = load_config(Path(config_path))
    checks = [
        *evaluate_nonstorage_checks(config),
        _storage_check(evaluate_storage()),
    ]
    report = _ordered_report(checks)
    if len(json.dumps(report, separators=(",", ":")).encode("utf-8")) > MAX_REPORT_BYTES:
        raise RuntimeError("Relay readiness report exceeded its byte budget")
    return report


def _failure_report() -> dict:
    checks = [
        _check(identifier, False, "ready", "probe_failed")
        for identifier in CHECK_IDS
    ]
    return _ordered_report(checks)


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate read-only Relay readiness")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    args = parser.parse_args()
    try:
        report = build_report(args.config)
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError):
        report = _failure_report()
    print(json.dumps(report, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
