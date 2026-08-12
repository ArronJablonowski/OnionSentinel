#!/usr/bin/env python3
"""Evaluate Onion Sentinel production SLOs from local, read-only endpoints."""

from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path
import shutil
import sys
import time
import urllib.error
import urllib.request

BIN_DIR = Path(__file__).resolve().parent
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))

from bounded_http import BoundedHttpError, read_bounded_json
from operational_slo_policy import (
    CAPTURE_TELEMETRY_UNAVAILABLE_GRACE_SECONDS,
    SOFTWARE_INVENTORY_MAX_AGE_SECONDS,
    age_seconds,
    evaluate,
    parse_timestamp,
)
from operational_slo_state import (
    append_bounded_history,
    load_previous_state,
    update_soak_state,
    write_outputs,
)


MAX_PROBE_RESPONSE_BYTES = 8 * 1024 * 1024
DEFAULT_PROBE_ATTEMPTS = 2
DEFAULT_PROBE_RETRY_DELAY_SECONDS = 0.2


class ProbeError(RuntimeError):
    """A concise, operator-safe failure from a local read-only health probe."""


def newest_file_age(directory: Path, pattern: str, now: dt.datetime) -> int | None:
    matches = [path for path in directory.glob(pattern) if path.is_file()]
    if not matches:
        return None
    newest = max(path.stat().st_mtime for path in matches)
    return max(0, int(now.timestamp() - newest))


def read_json_object(path: Path) -> dict[str, object] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return None
    return value if isinstance(value, dict) else None


def env_flag(path: Path, name: str) -> bool:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return False
    prefix = f"{name}="
    return any(
        line.startswith(prefix)
        and line[len(prefix) :].strip().strip("\"'") == "1"
        for line in lines
    )


def fetch_json(
    url: str,
    name: str,
    *,
    attempts: int = DEFAULT_PROBE_ATTEMPTS,
    retry_delay_seconds: float = DEFAULT_PROBE_RETRY_DELAY_SECONDS,
) -> dict[str, object]:
    """Fetch one bounded local probe, tolerating one transient I/O stall."""
    bounded_attempts = max(1, min(int(attempts), 3))
    delay = max(0.0, min(float(retry_delay_seconds), 1.0))
    last_error: BaseException | None = None
    for attempt in range(bounded_attempts):
        try:
            with urllib.request.urlopen(url, timeout=8) as response:
                return read_bounded_json(
                    response,
                    max_bytes=MAX_PROBE_RESPONSE_BYTES,
                )
        except (BoundedHttpError, ValueError) as exc:
            raise ProbeError(
                f"{name} probe unavailable ({type(exc).__name__})"
            ) from None
        except (OSError, urllib.error.URLError) as exc:
            last_error = exc
            if attempt + 1 < bounded_attempts:
                time.sleep(delay)
    raise ProbeError(
        f"{name} probe unavailable ({type(last_error).__name__})"
    ) from None


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--stack-dir",
        type=Path,
        default=Path.home() / "n8n-local",
    )
    parser.add_argument("--metrics-url", default="http://127.0.0.1:8787/metrics")
    parser.add_argument(
        "--alert-store-health-url",
        default="http://127.0.0.1:8787/health",
    )
    parser.add_argument(
        "--health-url",
        default="http://127.0.0.1:8766/api/system-health/beacons?hours=1",
    )
    return parser.parse_args()


def _evaluation_inputs(
    args: argparse.Namespace,
    previous: dict[str, object],
    now: dt.datetime,
    alert_store_health: dict[str, object],
    runtime_context: dict[str, object],
) -> dict[str, object]:
    return {
        "now": now,
        "disk_used_percent": runtime_context["disk_used_percent"],
        "sqlite_backup_age": newest_file_age(
            args.stack_dir / "alert_store_backups", "*.backup", now
        ),
        "postgres_backup_age": newest_file_age(
            args.stack_dir / "recovery_backups", "*/n8n-postgres.dump", now
        ),
        "previous_ingest_errors": (
            int(previous["ingest_errors"])
            if "ingest_errors" in previous
            else None
        ),
        "previous_pending_job_counts": {
            str(key): int(value)
            for key, value in dict(previous.get("pending_job_counts") or {}).items()
        },
        "harness_database_present": (
            args.stack_dir / "alert_store_data/investigation-harness.sqlite3"
        ).is_file(),
        "harness_maintenance": read_json_object(
            args.stack_dir / "logs/investigation-harness-maintenance.json"
        ),
        "alert_store_postgres_shadow_enabled": runtime_context[
            "alert_store_postgres_shadow_enabled"
        ],
        "alert_store_postgres_backup_age": newest_file_age(
            args.stack_dir / "recovery_backups",
            "*/alert-store-postgres.dump",
            now,
        ),
        "previous_capture_telemetry_unavailable_since": previous.get(
            "capture_telemetry_unavailable_since"
        ),
        "software_inventory_health": dict(
            alert_store_health.get("software_inventory") or {}
        ),
    }


def _runtime_context(stack_dir: Path) -> dict[str, object]:
    shadow_enabled = env_flag(
        stack_dir / ".env",
        "ALERT_STORE_POSTGRES_SHADOW_ENABLED",
    )
    usage = shutil.disk_usage(stack_dir)
    return {
        "alert_store_postgres_shadow_enabled": shadow_enabled,
        "disk_used_percent": (
            usage.used / usage.total * 100 if usage.total else 100.0
        ),
    }


def main() -> int:
    args = _parse_args()
    log_dir = args.stack_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    previous = load_previous_state(
        log_dir / "operational-slo-counter-state.json"
    )
    now = dt.datetime.now(dt.timezone.utc)
    runtime_context = _runtime_context(args.stack_dir)
    try:
        metrics_payload = fetch_json(args.metrics_url, "alert-store metrics")
        alert_store_health = fetch_json(
            args.alert_store_health_url,
            "alert-store health",
        )
        health_payload = fetch_json(args.health_url, "Onion Sentinel health")
    except ProbeError as exc:
        print(str(exc))
        return 2
    failures, snapshot = evaluate(
        metrics_payload,
        health_payload,
        **_evaluation_inputs(
            args,
            previous,
            now,
            alert_store_health,
            runtime_context,
        ),
    )
    write_outputs(log_dir, snapshot, previous, failures, now)
    if failures:
        print("; ".join(failures))
        return 2
    if snapshot.get("advisories"):
        print("operational SLOs degraded: " + "; ".join(snapshot["advisories"]))
        return 0
    print("operational SLOs healthy")
    return 0


if __name__ == "__main__":
    sys.exit(main())
