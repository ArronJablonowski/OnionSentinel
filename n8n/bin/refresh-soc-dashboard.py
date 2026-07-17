#!/usr/bin/env python3
"""Build and publish the SOC dashboard outside security processing paths.

Alert ingestion, PCAP parsing, and local inference only touch a wake file. This
worker coalesces those hints behind a non-overlap lock and retains a five-minute
LaunchAgent timer as recovery for a missed filesystem event.
"""
from __future__ import annotations

import argparse
import fcntl
import shutil
import subprocess
import sys
from pathlib import Path


BIN_DIR = Path(__file__).resolve().parent
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))
from disk_capacity import require_runtime_capacity


HOME = Path.home()
DEFAULT_BUILDER = HOME / ".hermes" / "scripts" / "build_soc_alerts_dashboard.py"
DEFAULT_SYNC = HOME / "n8n-local" / "bin" / "sync-soc-alerts-portal.py"
DEFAULT_LOCK = HOME / "n8n-local" / "run" / "dashboard-refresh.lock"
DEFAULT_WAKE = HOME / "n8n-local" / "run" / "dashboard-refresh.wake"
DEFAULT_SOURCE = HOME / "SOC Alerts Web"
DEFAULT_DESTINATION = HOME / "report_portal" / "library" / "Cybersecurity" / "SOC Alerts"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build and publish the Onion Sentinel dashboard")
    parser.add_argument("--builder", type=Path, default=DEFAULT_BUILDER)
    parser.add_argument("--sync", type=Path, default=DEFAULT_SYNC)
    parser.add_argument("--lock-file", type=Path, default=DEFAULT_LOCK)
    parser.add_argument("--wake-file", type=Path, default=DEFAULT_WAKE)
    parser.add_argument("--timeout", type=int, default=240, help="Per-command timeout in seconds")
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    return args


def run_script(path: Path, timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["/usr/bin/python3", str(path)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )


def print_result(result: subprocess.CompletedProcess[str]) -> None:
    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, file=sys.stderr, end="")


def copy_fallback(source: Path = DEFAULT_SOURCE, destination: Path = DEFAULT_DESTINATION) -> bool:
    """Publish a completed build if the narrow sync helper is unavailable."""
    if not source.exists():
        print(f"SOC portal fallback skipped missing source: {source}", file=sys.stderr)
        return False
    destination.mkdir(parents=True, exist_ok=True)
    for item in source.iterdir():
        target = destination / item.name
        if item.is_dir():
            shutil.copytree(item, target, dirs_exist_ok=True)
        elif item.is_file():
            shutil.copy2(item, target)
    print(f"SOC portal fallback copied {source} -> {destination}")
    return True


def main() -> int:
    args = parse_args()
    require_runtime_capacity(DEFAULT_SOURCE, 0, label="dashboard refresh")
    for script in (args.builder, args.sync):
        if not script.exists():
            print(f"dashboard refresh missing script: {script}", file=sys.stderr)
            return 2

    args.lock_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with args.lock_file.open("w") as lock_handle:
        try:
            fcntl.flock(lock_handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print("dashboard refresh already active; wake event coalesced")
            return 0

        try:
            args.wake_file.unlink(missing_ok=True)
        except OSError as error:
            print(f"dashboard wake marker could not be consumed: {error}", file=sys.stderr)

        try:
            built = run_script(args.builder, args.timeout)
        except subprocess.TimeoutExpired:
            print(f"dashboard builder timed out after {args.timeout}s", file=sys.stderr)
            return 1
        print_result(built)
        if built.returncode != 0:
            print(f"dashboard builder failed rc={built.returncode}", file=sys.stderr)
            return 1

        try:
            synced = run_script(args.sync, args.timeout)
        except subprocess.TimeoutExpired:
            print(f"dashboard sync timed out after {args.timeout}s", file=sys.stderr)
            return 0 if copy_fallback() else 1
        print_result(synced)
        if synced.returncode != 0:
            print(f"dashboard sync failed rc={synced.returncode}", file=sys.stderr)
            return 0 if copy_fallback() else 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
