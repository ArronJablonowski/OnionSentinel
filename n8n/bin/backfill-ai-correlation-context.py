#!/usr/bin/env python3
"""Index historical local-AI artifacts through alert-store's write API.

The script never opens SQLite for writes. It can be rerun safely because the
analysis endpoint upserts by a deterministic analysis_id.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

BIN_DIR = Path(__file__).resolve().parent
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))
from bounded_http import read_bounded_body, read_bounded_json


HOME = Path.home()
DEFAULT_ANALYSIS_DIR = HOME / "n8n-local" / "soc-alerts" / "ai-analysis"
DEFAULT_ALERT_STORE_URL = os.environ.get("ALERT_STORE_URL", "http://127.0.0.1:8787")
MAX_ALERT_STORE_RESPONSE_BYTES = 1024 * 1024
MAX_ALERT_STORE_ERROR_BYTES = 64 * 1024


class HistoricalAlertMissing(RuntimeError):
    """The artifact is valid, but its source alert is no longer retained."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Backfill AI analysis and correlation context")
    parser.add_argument("--analysis-dir", type=Path, default=DEFAULT_ANALYSIS_DIR)
    parser.add_argument("--alert-store-url", default=DEFAULT_ALERT_STORE_URL)
    parser.add_argument("--limit", type=int, default=0, help="Maximum artifacts to inspect; zero means all")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    if args.limit < 0:
        parser.error("--limit must be zero or positive")
    return args


def load_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def prompt_context(path_value: object) -> tuple[dict[str, Any], str]:
    path = Path(str(path_value or ""))
    if not path.is_file():
        return {}, ""
    package = load_object(path)
    digest = hashlib.sha256(
        json.dumps(package, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return package, digest


def __mapping(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def artifact_payload(path: Path) -> dict[str, Any] | None:
    artifact = load_object(path)
    if not artifact:
        return None
    response = __mapping(artifact.get("response"))
    alert_id = str(artifact.get("alert_id") or "").strip()
    generated_at = str(artifact.get("generated_at") or "").strip()
    if not alert_id or not response:
        return None
    package, evidence_hash = prompt_context(artifact.get("prompt_package"))
    correlation = __mapping(package.get("correlated_alert_context"))
    seed = f"{path.name}\n{alert_id}\n{generated_at}".encode("utf-8")
    analysis_id = str(artifact.get("analysis_id") or hashlib.sha256(seed).hexdigest()[:24])
    return {
        "analysis_id": analysis_id,
        "alert_id": alert_id,
        "generated_at": generated_at,
        "model": response.get("_analysis_model") or artifact.get("analysis_model"),
        "model_path": response.get("_analysis_model_path") or artifact.get("analysis_type"),
        "artifact_path": str(path),
        "evidence_hash": evidence_hash,
        "response": response,
        "correlation_candidates": correlation.get("candidates", []),
    }


def post_payload(url: str, payload: dict[str, Any]) -> None:
    request = urllib.request.Request(
        url.rstrip("/") + "/analysis/result",
        data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": "Onion-Sentinel-Backfill/1.0"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            result = read_bounded_json(
                response,
                max_bytes=MAX_ALERT_STORE_RESPONSE_BYTES,
            )
    except urllib.error.HTTPError as exc:
        body = read_bounded_body(
            exc,
            max_bytes=MAX_ALERT_STORE_ERROR_BYTES,
        ).decode("utf-8", errors="replace")
        try:
            reason = str(json.loads(body).get("reason") or "")
        except json.JSONDecodeError:
            reason = body.strip()
        if exc.code == 400 and reason == "analysis alert_id not found":
            raise HistoricalAlertMissing(reason) from exc
        raise RuntimeError(reason or f"alert-store returned HTTP {exc.code}") from exc
    if not result.get("ok"):
        raise RuntimeError(result.get("reason") or "analysis result rejected")


def main() -> int:
    args = parse_args()
    paths = sorted(args.analysis_dir.glob("*-local-ai-analysis.json"))
    if args.limit:
        paths = paths[-args.limit:]
    inspected = indexed = skipped = failed = 0
    failures: list[str] = []
    for path in paths:
        inspected += 1
        payload = artifact_payload(path)
        if not payload:
            skipped += 1
            continue
        if args.dry_run:
            indexed += 1
            continue
        try:
            post_payload(args.alert_store_url, payload)
            indexed += 1
        except HistoricalAlertMissing:
            # Retention can legitimately outlive the operational alert row.
            # The historical artifact remains on disk but has no safe stable
            # group identity to attach to, so report it as skipped.
            skipped += 1
        except (OSError, RuntimeError, urllib.error.URLError, json.JSONDecodeError) as exc:
            failed += 1
            if len(failures) < 10:
                failures.append(f"{path.name}: {exc}")
    print(json.dumps({
        "ok": failed == 0,
        "dry_run": args.dry_run,
        "inspected": inspected,
        "indexed": indexed,
        "skipped": skipped,
        "failed": failed,
        "failures": failures,
    }, sort_keys=True))
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
