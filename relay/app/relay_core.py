#!/usr/bin/env python3
"""Pull Security Onion alerts over restricted SSH and deliver them durably.

The relay is deliberately small: it pulls a sanitized JSON batch from Security
Onion, deduplicates alert IDs locally for retry safety, saves evidence files,
and sends new alerts to the Mac Studio intake. Rule filtering, suppression,
routing, reporting, and notification policy live in Mac Studio alert-store/n8n.
Troubleshooting usually starts with the final JSON summary printed by this
script.
"""
from __future__ import annotations

import argparse
import importlib.util
import fcntl
import hashlib
import json
import os
import shutil
import socket
import sqlite3
import subprocess
import sys
import tarfile
import threading
import time
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from re import sub
from urllib import request
from urllib.error import HTTPError, URLError

try:
    import alert_outbox
except ModuleNotFoundError:
    # Unit tests and recovery tooling may load relay.py directly without adding
    # its directory to sys.path. Resolve the sibling module explicitly.
    _outbox_spec = importlib.util.spec_from_file_location("alert_outbox", Path(__file__).with_name("alert_outbox.py"))
    if _outbox_spec is None or _outbox_spec.loader is None:
        raise
    alert_outbox = importlib.util.module_from_spec(_outbox_spec)
    _outbox_spec.loader.exec_module(alert_outbox)

try:
    import alert_delivery
except ModuleNotFoundError:
    _delivery_spec = importlib.util.spec_from_file_location(
        "alert_delivery", Path(__file__).with_name("alert_delivery.py")
    )
    if _delivery_spec is None or _delivery_spec.loader is None:
        raise
    alert_delivery = importlib.util.module_from_spec(_delivery_spec)
    _delivery_spec.loader.exec_module(alert_delivery)

try:
    import process_io
except ModuleNotFoundError:
    _process_spec = importlib.util.spec_from_file_location(
        "process_io", Path(__file__).with_name("process_io.py")
    )
    if _process_spec is None or _process_spec.loader is None:
        raise
    process_io = importlib.util.module_from_spec(_process_spec)
    sys.modules.setdefault("process_io", process_io)
    _process_spec.loader.exec_module(process_io)


APP_DIR = Path(__file__).resolve().parent


class WebhookPostError(RuntimeError):
    """Webhook delivery failure with enough context to decide retry behavior."""

    def __init__(self, message: str, *, retryable: bool, status_code: int | None = None):
        super().__init__(message)
        self.retryable = retryable
        self.status_code = status_code


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d  %H:%M:%SZ")


def load_config(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def resolve_path(value: str) -> Path:
    # Production config uses absolute Pi paths. Relative paths are resolved next
    # to this script so the same config shape can be used in a checkout.
    path = Path(value)
    if path.is_absolute():
        return path
    return (APP_DIR / path).resolve()


def run_ssh_pull(config: dict) -> dict:
    # The Security Onion SSH key is restricted to one forced command. The final
    # "poll" argument is only a placeholder; the server ignores it and runs the
    # wrapper configured in authorized_keys.
    so = config["security_onion"]
    relay = config["relay"]
    key_path = resolve_path(so["ssh_key"])
    target = f"{so['ssh_user']}@{so['host']}"

    command = [
        "ssh",
        "-i",
        str(key_path),
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "BatchMode=yes",
        "-o",
        f"ConnectTimeout={relay.get('ssh_timeout_seconds', 20)}",
        "-T",
        target,
        "poll",
    ]

    # BatchMode prevents a broken key or sudo prompt from hanging systemd.
    result = process_io.run_bounded_command(
        command,
        timeout_seconds=relay.get("ssh_timeout_seconds", 20) + 10,
        max_stdout_bytes=int(relay.get("ssh_pull_max_response_bytes", 16 * 1024 * 1024)),
        max_stderr_bytes=int(relay.get("ssh_control_max_stderr_bytes", 256 * 1024)),
    )
    stdout = result.stdout.decode("utf-8", errors="replace")
    stderr = result.stderr.decode("utf-8", errors="replace")
    if result.returncode != 0:
        raise RuntimeError(
            f"SSH pull failed with exit code {result.returncode}: {stderr.strip()}"
        )

    try:
        return json.loads(stdout)
    except json.JSONDecodeError as exc:
        # A short preview makes banner/shell/JSON issues diagnosable in logs.
        preview = stdout[:500]
        raise RuntimeError(f"SSH pull returned invalid JSON: {exc}; preview={preview!r}") from exc


def parse_last_json_object(text: str) -> dict:
    """Return the last JSON object line from command output that may contain banners."""
    for line in reversed((text or "").splitlines()):
        candidate = line.strip()
        if not (candidate.startswith("{") and candidate.endswith("}")):
            continue
        parsed = json.loads(candidate)
        if isinstance(parsed, dict):
            return parsed
    raise json.JSONDecodeError("no JSON object found", text or "", 0)


def safe_transfer_id(value: object) -> str:
    cleaned = sub(r"[^A-Za-z0-9_.-]+", "_", str(value or "").strip()[:100]).strip("._")
    if not cleaned:
        raise RuntimeError("PCAP request_id is required for artifact transfer")
    return cleaned


class PcapExportError(RuntimeError):
    """PCAP export failed after the restricted wrapper returned diagnostics."""

    def __init__(self, message: str, diagnostics: dict | None = None):
        super().__init__(message)
        self.diagnostics = diagnostics if isinstance(diagnostics, dict) else {}


class PcapCaptureProtectionDeferred(RuntimeError):
    """A read was paused to protect Security Onion live packet capture."""

    def __init__(self, message: str, diagnostics: dict | None = None):
        super().__init__(message)
        self.diagnostics = diagnostics if isinstance(diagnostics, dict) else {}


def pcap_ssh_command(config: dict) -> list[str]:
    """Build the forced-command SSH client invocation used for PCAP control/data."""
    so = config["security_onion"]
    relay = config["relay"]
    key_path = resolve_path(so.get("pcap_ssh_key") or so["ssh_key"])
    target = f"{so['ssh_user']}@{so['host']}"
    return [
        "ssh",
        "-i",
        str(key_path),
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "BatchMode=yes",
        "-o",
        f"ConnectTimeout={relay.get('ssh_timeout_seconds', 20)}",
        "-T",
        target,
        "pcap",
    ]


def run_ssh_pcap_export(config: dict, pcap_request: dict) -> dict:
    # PCAP export uses a separate forced-command key when configured. The
    # request JSON is sent over stdin; the Security Onion wrapper validates it
    # again before touching any pcap files.
    command = pcap_ssh_command(config)
    relay = config["relay"]
    result = process_io.run_bounded_command(
        command,
        input_bytes=json.dumps(pcap_request, sort_keys=True).encode("utf-8"),
        timeout_seconds=relay.get("pcap_timeout_seconds", 180),
        max_stdout_bytes=int(relay.get("ssh_control_max_response_bytes", 1024 * 1024)),
        max_stderr_bytes=int(relay.get("ssh_control_max_stderr_bytes", 256 * 1024)),
    )
    stdout = result.stdout.decode("utf-8", errors="replace")
    stderr = result.stderr.decode("utf-8", errors="replace")
    try:
        payload = parse_last_json_object(stdout)
    except json.JSONDecodeError as exc:
        preview = stdout[:500]
        stderr_preview = stderr[:500]
        raise RuntimeError(
            f"PCAP export returned invalid JSON: {exc}; stdout_preview={preview!r}; stderr_preview={stderr_preview!r}"
        ) from exc
    if result.returncode != 0 or not payload.get("ok"):
        raise PcapExportError(
            payload.get("error") or stderr.strip() or f"PCAP export failed with exit code {result.returncode}",
            payload.get("diagnostics"),
        )
    return payload


def save_batch(config: dict, batch: dict) -> Path:
    # Save raw batches before filtering. This is useful when n8n is down or a
    # filter unexpectedly removes an alert you want to inspect.
    batch_dir = resolve_path(config["relay"]["batch_dir"])
    batch_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S%fZ")
    output_path = batch_dir / f"security-onion-alert-batch-{timestamp}.json"
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(batch, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return output_path


def prune_runtime_evidence(config: dict) -> int:
    """Bound relay-owned JSON evidence without touching durable queue state."""
    relay = config.get("relay", {})
    retention_days = max(1, int(relay.get("runtime_evidence_retention_days", 7) or 7))
    cutoff = time.time() - retention_days * 86400
    removed = 0
    for key in ("batch_dir", "alerts_dir"):
        raw_path = relay.get(key)
        if not raw_path:
            continue
        directory = resolve_path(raw_path)
        if not directory.exists() or not directory.is_dir():
            continue
        for path in directory.glob("*.json"):
            try:
                if path.is_file() and not path.is_symlink() and path.stat().st_mtime < cutoff:
                    path.unlink()
                    removed += 1
            except OSError:
                continue
    return removed


def require_relay_root_capacity(config: dict) -> dict:
    """Stop new relay writes at 75 percent, leaving a hard 80 percent ceiling."""
    relay = config.get("relay", {})
    path = resolve_path(relay.get("batch_dir") or "/opt/so-alert-relay/state/batches")
    anchor = path
    while not anchor.exists() and anchor != anchor.parent:
        anchor = anchor.parent
    usage = shutil.disk_usage(anchor)
    used_percent = (usage.used / usage.total * 100) if usage.total else 100.0
    hard_limit = max(2.0, min(80.0, float(relay.get("root_hard_max_used_percent", 80) or 80)))
    start_limit = max(1.0, min(hard_limit - 0.1, float(relay.get("root_start_max_used_percent", 75) or 75)))
    min_free = max(0, int(relay.get("root_min_free_bytes", 2 * 1024**3) or 0))
    if used_percent >= hard_limit:
        raise RuntimeError(f"relay root disk reached hard limit: {used_percent:.1f}% >= {hard_limit:.1f}%")
    if used_percent >= start_limit or usage.free < min_free:
        raise RuntimeError(
            f"relay root disk admission guard active: used={used_percent:.1f}% "
            f"start_limit={start_limit:.1f}% free={usage.free} reserve={min_free}"
        )
    return {"used_percent": round(used_percent, 1), "free_bytes": usage.free}


def connect_db(config: dict) -> sqlite3.Connection:
    # This database is relay-side dedupe only. The long-term alert store lives
    # in the Mac Studio alert-store SQLite database.
    db_path = resolve_path(config["relay"]["db_path"])
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS seen_alerts (
            alert_id TEXT PRIMARY KEY,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            seen_count INTEGER NOT NULL DEFAULT 1
        )
        """
    )
    alert_outbox.initialize(conn)
    conn.commit()
    return conn


def filter_unseen_alerts(conn: sqlite3.Connection, alerts: list[dict]) -> tuple[list[dict], int]:
    # n8n/alert-store also dedupes, but doing it here avoids repeated webhook
    # posts every five minutes for the same Security Onion document ID.
    new_alerts: list[dict] = []
    duplicate_count = 0

    for alert in alerts:
        alert_id = alert.get("alert_id")
        if not alert_id:
            continue
        row = conn.execute(
            "SELECT seen_count FROM seen_alerts WHERE alert_id = ?",
            (alert_id,),
        ).fetchone()
        if row:
            duplicate_count += 1
        else:
            new_alerts.append(alert)

    return new_alerts, duplicate_count


def nested_field(value: dict, dotted_path: str):
    # Minimal dotted-path lookup for config filters such as "source.ip".
    current = value
    for part in dotted_path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def matches_drop_rule(alert: dict, rule: dict) -> bool:
    # Drop rules are intentionally simple exact/substring matches. Keep them for
    # known low-value relay noise, not broad detection tuning.
    source_ip = nested_field(alert, "source.ip")
    destination_ip = nested_field(alert, "destination.ip")
    rule_name = str(alert.get("rule_name") or "")

    if rule.get("source_ip") and rule["source_ip"] != source_ip:
        return False
    if rule.get("destination_ip") and rule["destination_ip"] != destination_ip:
        return False
    if rule.get("rule_contains") and rule["rule_contains"].lower() not in rule_name.lower():
        return False
    return True


def filter_dropped_alerts(config: dict, alerts: list[dict]) -> tuple[list[dict], int]:
    # Normal deployments leave this empty because filtering belongs in
    # alert-store. This emergency brake remains for local containment if a bad
    # upstream rule floods the relay before Mac Studio can receive traffic.
    drop_rules = config.get("filters", {}).get("drop_alerts", [])
    if not drop_rules:
        return alerts, 0

    kept_alerts = []
    dropped_count = 0
    for alert in alerts:
        if any(matches_drop_rule(alert, rule) for rule in drop_rules):
            dropped_count += 1
        else:
            kept_alerts.append(alert)
    return kept_alerts, dropped_count


def mark_seen(conn: sqlite3.Connection, alerts: list[dict]) -> None:
    # Mark as seen only after save/post succeeds. If the webhook fails, the next
    # timer run gets another chance to deliver the alert.
    now = now_utc_iso()
    for alert in alerts:
        alert_id = alert.get("alert_id")
        if not alert_id:
            continue
        conn.execute(
            """
            INSERT INTO seen_alerts (alert_id, first_seen, last_seen, seen_count)
            VALUES (?, ?, ?, 1)
            ON CONFLICT(alert_id) DO UPDATE SET
                last_seen = excluded.last_seen,
                seen_count = seen_alerts.seen_count + 1
            """,
            (alert_id, now, now),
        )
    conn.commit()


def safe_filename(value: str) -> str:
    # Security Onion IDs include punctuation; normalize for portable filenames.
    cleaned = sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._")
    return cleaned[:180] or "alert"


def save_new_alerts(config: dict, alerts: list[dict]) -> list[Path]:
    # Per-alert files are runtime evidence for manual inspection. They are not
    # intended to be committed to the DR repo.
    alerts_dir = resolve_path(config["relay"]["alerts_dir"])
    alerts_dir.mkdir(parents=True, exist_ok=True)
    saved_paths: list[Path] = []

    for alert in alerts:
        timestamp = safe_filename(alert.get("timestamp") or "unknown-time")
        alert_id = safe_filename(alert.get("alert_id") or "unknown-id")
        output_path = alerts_dir / f"{timestamp}-{alert_id}.json"
        counter = 1
        while output_path.exists():
            output_path = alerts_dir / f"{timestamp}-{alert_id}-{counter}.json"
            counter += 1
        with output_path.open("w", encoding="utf-8") as handle:
            json.dump(alert, handle, indent=2, sort_keys=True)
            handle.write("\n")
        saved_paths.append(output_path)

    return saved_paths


def webhook_int(webhook: dict, key: str, default: int) -> int:
    try:
        value = int(webhook.get(key, default))
    except (TypeError, ValueError):
        return default
    return max(value, 0)


def webhook_float(webhook: dict, key: str, default: float) -> float:
    try:
        value = float(webhook.get(key, default))
    except (TypeError, ValueError):
        return default
    return max(value, 0.0)


def read_bounded_http_body(response, max_bytes: int) -> bytes:
    """Read a small control-plane response without trusting the peer.

    Alert and PCAP payloads use dedicated bounded transports. HTTP responses
    here are only acknowledgements/control JSON, so a response above this
    ceiling is a protocol failure rather than useful data. Reading one byte
    beyond the limit detects chunked responses that omit Content-Length while
    keeping memory use deterministic.
    """
    limit = max(1024, min(int(max_bytes or 0), 16 * 1024 * 1024))
    headers = getattr(response, "headers", None)
    declared_value = headers.get("Content-Length") if headers is not None else None
    if declared_value not in (None, ""):
        try:
            declared = int(declared_value)
        except (TypeError, ValueError) as exc:
            raise RuntimeError("HTTP response has invalid Content-Length") from exc
        if declared < 0 or declared > limit:
            raise RuntimeError(f"HTTP response exceeds {limit} byte limit")
    body = response.read(limit + 1)
    if len(body) > limit:
        raise RuntimeError(f"HTTP response exceeds {limit} byte limit")
    return body


def is_retryable_http_status(status_code: int) -> bool:
    return status_code in {408, 409, 425, 429} or status_code >= 500


def parse_webhook_response(body: str) -> dict | list | None:
    """Best-effort parse of n8n's webhook response body.

    n8n returns HTTP 200 for some workflow-level validation failures. The relay
    must inspect the body so an invalid X-Relay-Token or rejected heartbeat
    becomes a failed timer run instead of a silent false positive.
    """
    if not body.strip():
        return None
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return None


def webhook_response_failure(parsed: dict | list | None) -> str | None:
    """Return a sanitized failure reason when the workflow rejected a payload."""
    if parsed is None:
        return None
    candidates = parsed if isinstance(parsed, list) else [parsed]
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        payload = candidate.get("json") if isinstance(candidate.get("json"), dict) else candidate
        status = str(payload.get("status") or "").lower()
        if payload.get("ok") is False or status in {"rejected", "error"}:
            reason = payload.get("reason") or payload.get("error") or status or "workflow rejected payload"
            return str(reason)[:240]
    return None


def post_json_to_webhook_once(config: dict, payload_data: dict) -> None:
    webhook = config.get("webhook", {})
    url = webhook.get("url")
    if not url:
        raise RuntimeError("Webhook is enabled but webhook.url is empty")

    token = webhook.get("token", "")
    timeout = webhook.get("timeout_seconds", 10)
    payload = json.dumps(payload_data, sort_keys=True).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "so-alert-relay-dev/0.1",
    }
    if token:
        # Must match the token configured in the n8n RELAY_WEBHOOK_TOKEN variable.
        headers["X-Relay-Token"] = token

    req = request.Request(url, data=payload, headers=headers, method="POST")
    try:
        with request.urlopen(req, timeout=timeout) as response:
            body = read_bounded_http_body(
                response,
                webhook_int(webhook, "response_max_bytes", 1024 * 1024),
            ).decode("utf-8", errors="replace")
            if response.status < 200 or response.status >= 300:
                raise WebhookPostError(
                    f"Webhook returned HTTP {response.status}",
                    retryable=is_retryable_http_status(response.status),
                    status_code=response.status,
                )
            failure_reason = webhook_response_failure(parse_webhook_response(body))
            if failure_reason:
                raise WebhookPostError(
                    f"Webhook workflow rejected payload: {failure_reason}",
                    retryable=False,
                    status_code=response.status,
                )
    except HTTPError as exc:
        raise WebhookPostError(
            f"Webhook returned HTTP {exc.code}: {exc.reason}",
            retryable=is_retryable_http_status(exc.code),
            status_code=exc.code,
        ) from exc
    except URLError as exc:
        raise WebhookPostError(f"Webhook request failed: {exc.reason}", retryable=True) from exc
    except TimeoutError as exc:
        raise WebhookPostError("Webhook request timed out", retryable=True) from exc


def post_json_to_webhook(config: dict, payload_data: dict) -> None:
    webhook = config.get("webhook", {})
    attempts = max(webhook_int(webhook, "retry_attempts", 3), 1)
    backoff_seconds = webhook_float(webhook, "retry_backoff_seconds", 1.5)
    max_backoff_seconds = webhook_float(webhook, "retry_max_backoff_seconds", 10.0)

    for attempt in range(1, attempts + 1):
        try:
            post_json_to_webhook_once(config, payload_data)
            return
        except WebhookPostError as exc:
            if not exc.retryable or attempt >= attempts:
                raise RuntimeError(str(exc)) from exc
            sleep_seconds = min(backoff_seconds * (2 ** (attempt - 1)), max_backoff_seconds)
            print(
                json.dumps(
                    {
                        "event": "webhook_retry",
                        "attempt": attempt,
                        "max_attempts": attempts,
                        "sleep_seconds": sleep_seconds,
                        "status_code": exc.status_code,
                        "error": str(exc),
                    },
                    sort_keys=True,
                ),
                file=sys.stderr,
            )
            time.sleep(sleep_seconds)


