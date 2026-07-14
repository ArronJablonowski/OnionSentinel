#!/usr/bin/env python3
"""Read-only relay SSD health check for systemd and Telegram escalation."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


MOUNT = Path(os.environ.get("RELAY_SSD_MOUNT", "/mnt/onion-sentinel-pcap-spool"))
DEVICE = os.environ.get("RELAY_SSD_DEVICE", "/dev/sda")
SMARTCTL = os.environ.get("RELAY_SMARTCTL", "/usr/sbin/smartctl")


def env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except ValueError:
        return default


MIN_FREE_BYTES = max(0, env_int("RELAY_SSD_MIN_FREE_BYTES", 100 * 1024**3))
MAX_USED_PERCENT = min(99, max(1, env_int("RELAY_SSD_MAX_USED_PERCENT", 80)))
MAX_TEMPERATURE_C = min(100, max(20, env_int("RELAY_SSD_MAX_TEMPERATURE_C", 70)))
MAX_UNSAFE_SHUTDOWNS = max(0, env_int("RELAY_SSD_MAX_UNSAFE_SHUTDOWNS", 0))


def run(command: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(command, check=False, capture_output=True, text=True, timeout=30)


def main() -> int:
    failures: list[str] = []
    result: dict = {"ok": False, "mount": str(MOUNT), "device": DEVICE}
    findmnt = run(["/usr/bin/findmnt", "-J", "-T", str(MOUNT)])
    if findmnt.returncode != 0:
        failures.append("relay SSD mount is unavailable")
    else:
        try:
            filesystems = json.loads(findmnt.stdout).get("filesystems") or []
            source = str(filesystems[0].get("source") or "") if filesystems else ""
        except (json.JSONDecodeError, IndexError, AttributeError):
            source = ""
        result["mount_source"] = source
        if not source or source.startswith("/dev/mmc"):
            failures.append("relay SSD mount resolved to the SD card or an unknown source")
        try:
            usage = shutil.disk_usage(MOUNT)
            used_percent = round((usage.used / usage.total) * 100, 2) if usage.total else 100.0
            result["storage"] = {
                "total_bytes": usage.total,
                "used_bytes": usage.used,
                "free_bytes": usage.free,
                "used_percent": used_percent,
            }
            if usage.free < MIN_FREE_BYTES:
                failures.append(f"relay SSD free space is below {MIN_FREE_BYTES} bytes")
            if used_percent >= MAX_USED_PERCENT:
                failures.append(f"relay SSD usage is at or above {MAX_USED_PERCENT} percent")
        except OSError as exc:
            failures.append(f"relay SSD usage check failed: {exc}")

    smart = run(["/usr/bin/sudo", "-n", SMARTCTL, "-a", "-j", DEVICE])
    if smart.returncode not in (0,):
        failures.append(f"SMART query failed with exit {smart.returncode}")
    else:
        try:
            payload = json.loads(smart.stdout)
        except json.JSONDecodeError:
            payload = {}
            failures.append("SMART query returned invalid JSON")
        health = payload.get("smart_status") or {}
        nvme = payload.get("nvme_smart_health_information_log") or {}
        temperature = (payload.get("temperature") or {}).get("current")
        smart_summary = {
            "passed": health.get("passed"),
            "temperature_c": temperature,
            "critical_warning": int(nvme.get("critical_warning") or 0),
            "media_errors": int(nvme.get("media_errors") or 0),
            "unsafe_shutdowns": int(nvme.get("unsafe_shutdowns") or 0),
        }
        result["smart"] = smart_summary
        if health.get("passed") is not True:
            failures.append("SMART overall health did not pass")
        if smart_summary["critical_warning"]:
            failures.append("SMART critical warning is nonzero")
        if smart_summary["media_errors"]:
            failures.append("SMART media errors are nonzero")
        if smart_summary["unsafe_shutdowns"] > MAX_UNSAFE_SHUTDOWNS:
            failures.append(f"SMART unsafe shutdowns exceed {MAX_UNSAFE_SHUTDOWNS}")
        if isinstance(temperature, (int, float)) and temperature >= MAX_TEMPERATURE_C:
            failures.append(f"relay SSD temperature is at or above {MAX_TEMPERATURE_C} C")

    result["failures"] = failures
    result["ok"] = not failures
    print(json.dumps(result, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
