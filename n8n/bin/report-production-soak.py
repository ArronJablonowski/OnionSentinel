#!/usr/bin/env python3
"""Build a bounded production-soak acceptance report from SLO snapshots."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path


def parse_timestamp(value: object) -> dt.datetime | None:
    text = str(value or "").strip().replace("  ", "T", 1)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)


def load_history(path: Path) -> tuple[list[dict[str, object]], int]:
    samples: list[dict[str, object]] = []
    malformed = 0
    for line in path.read_text().splitlines():
        try:
            value = json.loads(line)
        except (TypeError, ValueError):
            malformed += 1
            continue
        if isinstance(value, dict) and parse_timestamp(value.get("generated_at")):
            samples.append(value)
        else:
            malformed += 1
    samples.sort(key=lambda item: parse_timestamp(item["generated_at"]))
    return samples, malformed


def summarize(samples: list[dict[str, object]], *, required_hours: int = 48) -> dict[str, object]:
    if not samples:
        return {"status": "failed", "qualified": False, "reason": "no valid SLO samples", "sample_count": 0}
    healthy_since = parse_timestamp(dict(samples[-1].get("soak") or {}).get("healthy_since"))
    if healthy_since is None:
        return {"status": "failed", "qualified": False, "reason": "current healthy soak clock is not running", "sample_count": len(samples)}
    window = [item for item in samples if parse_timestamp(item["generated_at"]) >= healthy_since]
    timestamps = [parse_timestamp(item["generated_at"]) for item in window]
    first, last = timestamps[0], timestamps[-1]
    elapsed_seconds = max(0, int((last - healthy_since).total_seconds()))
    expected_samples = max(1, int(elapsed_seconds / 300) + 1)
    coverage = min(1.0, len(window) / expected_samples)
    gaps = [int((right - left).total_seconds()) for left, right in zip(timestamps, timestamps[1:])]
    max_gap = max(gaps, default=0)
    failed = [item for item in window if not item.get("ok")]
    failure_reasons = sorted({str(reason) for item in failed for reason in (item.get("failures") or [])})
    signal_names = sorted({str(key) for item in window for key in dict(item.get("signals") or {})})
    maxima: dict[str, float | int | None] = {}
    for name in signal_names:
        values = [dict(item.get("signals") or {}).get(name) for item in window]
        numbers = [value for value in values if isinstance(value, (int, float))]
        maxima[name] = max(numbers) if numbers else None
    required_seconds = required_hours * 60 * 60
    qualified = elapsed_seconds >= required_seconds and not failed and coverage >= 0.90 and max_gap <= 12 * 60
    status = "passed" if qualified else ("in_progress" if elapsed_seconds < required_seconds and not failed else "failed")
    return {
        "status": status,
        "qualified": qualified,
        "healthy_since": healthy_since.astimezone().replace(microsecond=0).isoformat().replace("T", "  "),
        "first_sample": first.astimezone().replace(microsecond=0).isoformat().replace("T", "  "),
        "last_sample": last.astimezone().replace(microsecond=0).isoformat().replace("T", "  "),
        "required_hours": required_hours,
        "elapsed_seconds": elapsed_seconds,
        "remaining_seconds": max(0, required_seconds - elapsed_seconds),
        "sample_count": len(window),
        "expected_sample_count": expected_samples,
        "sample_coverage_percent": round(coverage * 100, 1),
        "max_sample_gap_seconds": max_gap,
        "failed_sample_count": len(failed),
        "failure_reasons": failure_reasons,
        "signal_maxima": maxima,
    }


def markdown_report(summary: dict[str, object], malformed: int) -> str:
    maxima = dict(summary.get("signal_maxima") or {})
    lines = [
        "# Onion Sentinel Production Soak",
        "",
        f"- Status: **{str(summary.get('status', 'unknown')).upper()}**",
        f"- Qualified: `{str(bool(summary.get('qualified'))).lower()}`",
        f"- Healthy since: `{summary.get('healthy_since', 'n/a')}`",
        f"- Samples: `{summary.get('sample_count', 0)}` ({summary.get('sample_coverage_percent', 0)}% coverage)",
        f"- Maximum sample gap: `{summary.get('max_sample_gap_seconds', 0)}` seconds",
        f"- Remaining: `{summary.get('remaining_seconds', 0)}` seconds",
        f"- Malformed history lines ignored: `{malformed}`",
        "",
        "## Maximum Observed Signals",
        "",
    ]
    lines.extend(f"- {name}: `{value}`" for name, value in maxima.items())
    lines.extend(["", "## Failure Reasons", ""])
    reasons = list(summary.get("failure_reasons") or [])
    lines.extend(f"- {reason}" for reason in reasons)
    if not reasons:
        lines.append("- None")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stack-dir", type=Path, default=Path.home() / "n8n-local")
    parser.add_argument("--required-hours", type=int, default=48)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    history = args.stack_dir / "logs/operational-slo-history.jsonl"
    samples, malformed = load_history(history)
    summary = summarize(samples, required_hours=max(1, args.required_hours))
    summary["malformed_samples"] = malformed
    output_dir = args.output_dir or args.stack_dir / "logs/soak-reports"
    output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    stamp = dt.datetime.now().astimezone().strftime("%Y%m%dT%H%M%S%z")
    json_path = output_dir / f"production-soak-{stamp}.json"
    md_path = output_dir / f"production-soak-{stamp}.md"
    json_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    md_path.write_text(markdown_report(summary, malformed))
    os.chmod(json_path, 0o600)
    os.chmod(md_path, 0o600)
    print(json.dumps({"ok": True, "report": str(json_path), **summary}, sort_keys=True))
    return 0 if summary["status"] in {"passed", "in_progress"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
