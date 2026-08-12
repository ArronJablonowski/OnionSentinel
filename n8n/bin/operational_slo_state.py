"""Owner-only persisted state and continuous-soak history for SLO checks."""

from __future__ import annotations

import datetime as dt
import json
import os
from pathlib import Path

from operational_slo_primitives import parse_timestamp


def update_soak_state(
    previous: dict[str, object],
    failures: list[str],
    now: dt.datetime,
) -> dict[str, object]:
    healthy_since = None if failures else parse_timestamp(previous.get("healthy_since"))
    if not failures and healthy_since is None:
        healthy_since = now
    elapsed = (
        int((now - healthy_since.astimezone(dt.timezone.utc)).total_seconds())
        if healthy_since
        else 0
    )
    return {
        "healthy_since": (
            healthy_since.astimezone()
            .replace(microsecond=0)
            .isoformat()
            .replace("T", "  ")
            if healthy_since
            else None
        ),
        "healthy_elapsed_seconds": max(0, elapsed),
        "qualified_48h": bool(healthy_since and elapsed >= 48 * 60 * 60),
    }


def append_bounded_history(
    path: Path,
    snapshot: dict[str, object],
    keep: int = 4032,
) -> None:
    lines: list[str] = []
    try:
        lines = path.read_text().splitlines()
    except OSError:
        pass
    lines.append(json.dumps(snapshot, sort_keys=True, separators=(",", ":")))
    path.write_text("\n".join(lines[-keep:]) + "\n")
    os.chmod(path, 0o600)


def load_previous_state(path: Path) -> dict[str, object]:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError, TypeError):
        return {}


def write_outputs(
    log_dir: Path,
    snapshot: dict[str, object],
    previous: dict[str, object],
    failures: list[str],
    now: dt.datetime,
) -> None:
    snapshot["soak"] = update_soak_state(
        previous,
        failures + list(snapshot.get("advisories") or []),
        now,
    )
    snapshot_path = log_dir / "operational-slo-snapshot.json"
    snapshot_path.write_text(json.dumps(snapshot, indent=2, sort_keys=True) + "\n")
    os.chmod(snapshot_path, 0o600)
    append_bounded_history(log_dir / "operational-slo-history.jsonl", snapshot)
    state_path = log_dir / "operational-slo-counter-state.json"
    state_path.write_text(
        json.dumps(
            {
                "ingest_errors": snapshot["signals"]["ingest_errors"],
                "healthy_since": snapshot["soak"]["healthy_since"],
                "pending_job_counts": {
                    "ai_analysis": snapshot["signals"]["pending_ai_job_count"],
                    "incident_response_analysis": snapshot["signals"][
                        "pending_incident_response_job_count"
                    ],
                },
                "capture_telemetry_unavailable_since": snapshot["signals"].get(
                    "pcap_capture_telemetry_unavailable_since"
                ),
            }
        )
        + "\n"
    )
    os.chmod(state_path, 0o600)
