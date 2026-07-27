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


def broker_headers(config: dict) -> dict:
    token = config.get("pcap_broker", {}).get("token", "")
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "so-alert-relay-dev/0.1",
    }
    if token:
        headers["X-Relay-Token"] = token
    return headers


def broker_request(config: dict, method: str, path: str, payload_data: dict | None = None) -> dict:
    broker = config.get("pcap_broker", {})
    base_url = str(broker.get("url") or "").rstrip("/")
    if not base_url:
        raise RuntimeError("pcap_broker.url is empty")
    timeout = broker.get("timeout_seconds", 20)
    data = None if payload_data is None else json.dumps(payload_data, sort_keys=True).encode("utf-8")
    req = request.Request(
        f"{base_url}{path}",
        data=data,
        headers=broker_headers(config),
        method=method,
    )
    try:
        with request.urlopen(req, timeout=timeout) as response:
            body = read_bounded_http_body(
                response,
                webhook_int(broker, "response_max_bytes", 1024 * 1024),
            ).decode("utf-8")
    except HTTPError as exc:
        raise RuntimeError(f"PCAP broker returned HTTP {exc.code}: {exc.reason}") from exc
    except URLError as exc:
        raise RuntimeError(f"PCAP broker request failed: {exc.reason}") from exc
    try:
        parsed = json.loads(body or "{}")
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"PCAP broker returned invalid JSON: {exc}") from exc
    if not parsed.get("ok"):
        raise RuntimeError(parsed.get("reason") or parsed.get("error") or "PCAP broker rejected request")
    return parsed


class PcapProgressReporter:
    """Renew a PCAP claim while a long export or transfer is demonstrably active.

    Progress reporting is advisory: an unavailable health callback must never
    interrupt resumable evidence transfer. The broker's transfer timeout still
    bounds a process that is alive but no longer useful.
    """

    def __init__(self, config: dict, request_id: str):
        self.config = config
        self.request_id = safe_transfer_id(request_id)
        broker = config.get("pcap_broker", {})
        self.interval = max(10.0, float(broker.get("progress_interval_seconds", 30) or 30))
        self.stage = "claimed"
        self.total_bytes = 0
        self._probe = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def update(self, stage: str, total_bytes: int = 0, probe=None) -> None:
        self.stage = stage
        self.total_bytes = max(0, int(total_bytes or 0))
        self._probe = probe
        self.report()

    def report(self) -> None:
        transferred = 0
        try:
            if self._probe is not None:
                transferred = max(0, int(self._probe() or 0))
            broker_request(
                self.config,
                "POST",
                broker_path(self.config, "progress", "/pcap/progress"),
                {
                    "request_id": self.request_id,
                    "stage": self.stage,
                    "transferred_bytes": transferred,
                    "total_bytes": self.total_bytes,
                },
            )
        except Exception as exc:
            print(
                json.dumps(
                    {"event": "pcap_progress_report_failed", "request_id": self.request_id, "error": str(exc)[:300]},
                    sort_keys=True,
                ),
                file=sys.stderr,
            )

    def _run(self) -> None:
        while not self._stop.wait(self.interval):
            self.report()

    def __enter__(self):
        self.report()
        self._thread = threading.Thread(target=self._run, name=f"pcap-progress-{self.request_id}", daemon=True)
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=min(5.0, self.interval))


def upload_pcap_artifact(
    config: dict,
    pcap_request: dict,
    export_result: dict,
    progress: PcapProgressReporter | None = None,
) -> dict | None:
    broker = config.get("pcap_broker", {})
    upload_mode = str(broker.get("artifact_upload_mode") or "streamed_chunks").strip().lower()
    if upload_mode in {"streamed_chunks", "streaming", "relay_stream"}:
        return upload_pcap_artifact_via_rsync(config, pcap_request, export_result, progress)
    raise RuntimeError(
        f"unsupported PCAP artifact_upload_mode {upload_mode!r}; "
        "Security Onion PCAP transfer must use read-only streamed_chunks"
    )


def completed_artifact_path(export_result: dict, upload_result: dict | None) -> str | None:
    """Prefer Mac-side artifact metadata when the upload path provides it."""
    if upload_result:
        for key in ("path", "artifact_file"):
            value = upload_result.get(key)
            if value:
                return str(value)
    value = export_result.get("artifact_path")
    return str(value) if value else None


def pcap_spool_dir(config: dict) -> Path:
    broker = config.get("pcap_broker", {})
    raw_path = str(broker.get("artifact_spool_dir") or "/mnt/onion-sentinel-pcap-spool/pcap")
    path = Path(raw_path)
    if not path.is_absolute():
        raise RuntimeError("pcap_broker.artifact_spool_dir must be an absolute path")
    return path


def spool_mount_ready(config: dict) -> bool:
    broker = config.get("pcap_broker", {})
    if not bool(broker.get("artifact_spool_require_mount", False)):
        return True
    spool_dir = pcap_spool_dir(config)
    # The configured directory is intentionally one level below the filesystem
    # root. Requiring that parent to be a mount prevents an absent USB disk from
    # silently redirecting multi-gigabyte writes onto the Pi SD card.
    return os.path.ismount(spool_dir.parent)


def require_spool_capacity(config: dict, artifact_size: int) -> None:
    broker = config.get("pcap_broker", {})
    max_bytes = int(broker.get("artifact_spool_max_bytes", 32 * 1024 * 1024 * 1024) or 0)
    min_free_bytes = int(broker.get("artifact_spool_min_free_bytes", 100 * 1024 * 1024 * 1024) or 0)
    max_used_percent = max(1.0, min(75.0, float(broker.get("artifact_spool_max_used_percent", 75) or 75)))
    if max_bytes > 0 and artifact_size > max_bytes:
        raise RuntimeError(f"PCAP artifact exceeds relay spool limit: {artifact_size} > {max_bytes}")
    spool_dir = pcap_spool_dir(config)
    if not spool_dir.exists() or not spool_dir.is_dir():
        raise RuntimeError(f"relay PCAP spool directory is unavailable: {spool_dir}")
    if not spool_mount_ready(config):
        raise RuntimeError(f"relay PCAP spool filesystem is not mounted: {spool_dir.parent}")
    usage = shutil.disk_usage(spool_dir)
    required = artifact_size + max(0, min_free_bytes)
    if usage.free < required:
        raise RuntimeError(f"relay PCAP spool has insufficient free space: free={usage.free} required={required}")
    projected_percent = ((usage.used + artifact_size) / usage.total) * 100 if usage.total else 100.0
    if projected_percent > max_used_percent:
        raise RuntimeError(
            f"relay PCAP spool high watermark exceeded: projected={projected_percent:.1f}% limit={max_used_percent:.1f}%"
        )


def spool_usage(config: dict) -> dict:
    spool_dir = pcap_spool_dir(config)
    if not spool_dir.exists():
        return {"available": False, "path": str(spool_dir)}
    if not spool_mount_ready(config):
        return {"available": False, "path": str(spool_dir), "reason": "spool filesystem is not mounted"}
    usage = shutil.disk_usage(spool_dir)
    return {
        "available": True,
        "total_bytes": usage.total,
        "used_bytes": usage.used,
        "free_bytes": usage.free,
        "used_percent": round((usage.used / usage.total) * 100, 1) if usage.total else 100.0,
    }


def cleanup_stale_spool_partials(config: dict) -> int:
    """Remove interrupted relay-spool transfer fragments older than the configured TTL."""
    broker = config.get("pcap_broker", {})
    ttl_seconds = int(broker.get("artifact_spool_partial_ttl_seconds", 0) or 0)
    if ttl_seconds < 0:
        return 0
    try:
        spool_dir = pcap_spool_dir(config)
    except Exception:
        return 0
    if not spool_dir.exists() or not spool_dir.is_dir():
        return 0
    cutoff = time.time() - ttl_seconds
    removed = 0
    for path in spool_dir.rglob("*.part"):
        try:
            if path.is_file() and path.stat().st_mtime < cutoff:
                path.unlink()
                removed += 1
        except OSError:
            continue
    return removed


def cleanup_stale_spool_artifacts(config: dict) -> int:
    """Remove completed relay artifacts after their bounded retry window.

    This runs while the broker lock is held, so a matching rsync upload cannot
    be active. Security Onion keeps its independently retained export as the
    recovery source if a request is retried after this relay-side TTL.
    """
    broker = config.get("pcap_broker", {})
    ttl_seconds = int(broker.get("artifact_spool_completed_ttl_seconds", 3600) or 0)
    if ttl_seconds < 0:
        return 0
    try:
        spool_dir = pcap_spool_dir(config)
    except Exception:
        return 0
    if not spool_dir.exists() or not spool_dir.is_dir():
        return 0
    cutoff = time.time() - ttl_seconds
    removed = 0
    for path in spool_dir.glob("*.tar"):
        try:
            if path.is_file() and path.stat().st_mtime < cutoff:
                path.unlink()
                path.with_suffix(".stream.json").unlink(missing_ok=True)
                removed += 1
        except OSError:
            continue
    for path in spool_dir.iterdir():
        try:
            if path.is_dir() and path.stat().st_mtime < cutoff:
                shutil.rmtree(path)
                removed += 1
        except OSError:
            continue
    return removed


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_json_write(path: Path, payload: dict) -> None:
    """Persist a relay checkpoint without exposing a partially-written file."""
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    temporary.replace(path)


def load_json_file(path: Path) -> dict:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def streamed_chunk_mode(config: dict) -> bool:
    mode = str(config.get("pcap_broker", {}).get("artifact_upload_mode") or "streamed_chunks").strip().lower()
    if mode not in {"streamed_chunks", "streaming", "relay_stream"}:
        raise RuntimeError(
            "Security Onion PCAP transfer must use read-only streamed_chunks; "
            "Security Onion staging modes have been removed"
        )
    return True


def security_onion_storage_status(config: dict) -> dict:
    """Read non-blocking `/nsm` telemetry through the restricted wrapper."""
    payload = run_ssh_pcap_export(config, {"mode": "storage_status"})
    if payload.get("status") != "storage_status":
        raise RuntimeError("Security Onion PCAP wrapper returned invalid storage status")
    return payload


def capture_protection_decision(config: dict, status: dict | None) -> dict:
    """Decide whether the relay may start another Security Onion PCAP read.

    The restricted wrapper always permits valid read-only requests. Scheduling
    policy lives on the relay so capture telemetry can pause background evidence
    work without changing or blocking Security Onion's native retention logic.
    """
    broker = config.get("pcap_broker", {})
    if not bool(broker.get("capture_protection_enabled", True)):
        return {"deferred": False, "reason": "disabled"}
    require_telemetry = bool(broker.get("capture_protection_require_telemetry", True))
    threshold = max(0.0, min(100.0, float(broker.get("capture_loss_threshold_percent", 1.0) or 1.0)))
    packet_loss_threshold = max(
        0.0,
        min(100.0, float(broker.get("sensor_packet_loss_threshold_percent", 0.1) or 0.1)),
    )
    freshness = max(60, min(3600, int(broker.get("capture_loss_freshness_seconds", 900) or 900)))
    if not isinstance(status, dict) or not status.get("zeek_capture_loss_available"):
        return {
            "deferred": require_telemetry,
            "reason": "Zeek capture-loss telemetry is unavailable",
            "threshold_percent": threshold,
        }
    age = max(0, int(status.get("zeek_capture_loss_age_seconds") or 0))
    maximum = max(0.0, float(status.get("zeek_capture_loss_max_percent") or 0.0))
    if age > freshness:
        return {
            "deferred": require_telemetry,
            "reason": f"Zeek capture-loss telemetry is stale ({age}s)",
            "observed_percent": maximum,
            "threshold_percent": threshold,
            "age_seconds": age,
        }
    for prefix, label in (("zeek", "Zeek"), ("suricata", "Suricata")):
        available = bool(status.get(f"{prefix}_packet_loss_available"))
        packet_age = max(0, int(status.get(f"{prefix}_packet_loss_age_seconds") or 0))
        packet_loss = max(0.0, float(status.get(f"{prefix}_packet_loss_percent") or 0.0))
        if available and packet_age <= freshness and packet_loss > packet_loss_threshold:
            return {
                "deferred": True,
                "reason": (
                    f"{label} packet loss {packet_loss:.4f}% exceeds "
                    f"{packet_loss_threshold:.4f}%"
                ),
                "observed_percent": packet_loss,
                "threshold_percent": packet_loss_threshold,
                "age_seconds": packet_age,
                "metric": f"{prefix}_packet_loss",
            }
    if maximum > threshold:
        return {
            "deferred": True,
            "reason": f"Zeek capture loss {maximum:.4f}% exceeds {threshold:.4f}%",
            "observed_percent": maximum,
            "threshold_percent": threshold,
            "age_seconds": age,
        }
    return {
        "deferred": False,
        "reason": "capture telemetry is healthy",
        "observed_percent": maximum,
        "threshold_percent": threshold,
        "age_seconds": age,
    }


def require_capture_safe(config: dict, status: dict | None = None) -> dict:
    """Raise a retryable deferral when live-capture telemetry is unhealthy."""
    current = status if isinstance(status, dict) else security_onion_storage_status(config)
    decision = capture_protection_decision(config, current)
    if decision.get("deferred"):
        raise PcapCaptureProtectionDeferred(str(decision.get("reason")), decision)
    return current


def stream_chunk_idle_timeout(config: dict) -> int:
    """Return the no-progress timeout without limiting total read duration."""
    broker = config.get("pcap_broker", {})
    configured = int(broker.get("stream_chunk_idle_timeout_seconds", 300) or 300)
    return max(60, min(3600, configured))


def wait_for_stream_progress(proc: subprocess.Popen, temporary: Path, idle_timeout: int) -> bytes:
    """Wait while bytes advance, terminating only a genuinely idle stream.

    A fixed total timeout can truncate a healthy large read. The destination
    file is the authoritative progress signal because stdout is written there
    directly without buffering packet data in relay memory.
    """
    last_size = -1
    last_progress = time.monotonic()
    while proc.poll() is None:
        try:
            current_size = temporary.stat().st_size
        except OSError:
            current_size = 0
        now = time.monotonic()
        if current_size != last_size:
            last_size = current_size
            last_progress = now
        elif now - last_progress >= idle_timeout:
            proc.kill()
            proc.wait()
            raise RuntimeError(
                f"Security Onion PCAP chunk stream made no progress for {idle_timeout} seconds"
            )
        time.sleep(1)
    return proc.stderr.read() if proc.stderr is not None else b""


def transfer_timeout(config: dict, artifact_size: int) -> int:
    transfer = mac_transfer_config(config)
    floor = max(300, int(transfer.get("rsync_timeout_seconds") or 1800))
    minimum_bps = max(256 * 1024, int(transfer.get("minimum_bytes_per_second", 2 * 1024 * 1024) or 1))
    # The relay-to-Mac leg crosses the monitored LAN. Its bandwidth ceiling is
    # deliberately part of timeout sizing so a safe low-rate transfer is not
    # mistaken for a stalled job merely because the artifact is large.
    maximum_bps = rsync_max_bytes_per_second(config)
    estimate_bps = min(minimum_bps, maximum_bps)
    estimate = int(artifact_size / estimate_bps) + 600
    return min(12 * 3600, max(floor, estimate))


def rsync_max_bytes_per_second(config: dict) -> int:
    """Return the enforced relay-to-Mac ceiling for monitored LAN traffic."""
    transfer = mac_transfer_config(config)
    configured = int(transfer.get("max_bytes_per_second", 4 * 1024 * 1024) or 1)
    return max(1024 * 1024, min(8 * 1024 * 1024, configured))


def stream_one_security_onion_chunk(
    config: dict,
    request_payload: dict,
    destination: Path,
    source_size: int,
) -> int:
    """Stream one filtered capture directly from Security Onion to relay SSD."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".part")
    temporary.unlink(missing_ok=True)
    command = pcap_ssh_command(config)
    encoded = json.dumps(request_payload, sort_keys=True).encode("utf-8")
    try:
        with temporary.open("wb") as handle:
            proc = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=handle,
                stderr=subprocess.PIPE,
            )
            if proc.stdin is None:
                proc.kill()
                proc.wait()
                raise RuntimeError("Security Onion PCAP chunk stream stdin is unavailable")
            proc.stdin.write(encoded)
            proc.stdin.close()
            stderr = wait_for_stream_progress(proc, temporary, stream_chunk_idle_timeout(config))
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    if proc.returncode != 0:
        temporary.unlink(missing_ok=True)
        detail = (stderr or b"").decode("utf-8", errors="replace")[-500:].strip()
        raise RuntimeError(detail or f"Security Onion PCAP chunk stream exited {proc.returncode}")
    size = temporary.stat().st_size
    # tcpdump writes a 24-byte global header even when the filter matches no
    # packets. Empty variants are expected because VLAN encapsulation differs.
    if size <= 24:
        temporary.unlink(missing_ok=True)
        return 0
    maximum = source_size + (16 * 1024 * 1024)
    if size > maximum:
        temporary.unlink(missing_ok=True)
        raise RuntimeError(f"Security Onion PCAP chunk exceeded source ceiling: {size} > {maximum}")
    temporary.replace(destination)
    destination.chmod(0o600)
    return size


def streamed_spool_artifact(
    config: dict,
    pcap_request: dict,
    progress: PcapProgressReporter | None = None,
) -> dict:
    """Build a resumable tar on relay SSD from stateless Security Onion streams.

    Security Onion never creates an Onion Sentinel PCAP file in this mode. The
    only durable state is under the externally mounted relay spool.
    """
    request_id = safe_transfer_id(pcap_request.get("request_id"))
    spool_dir = pcap_spool_dir(config)
    spool_dir.mkdir(parents=True, exist_ok=True)
    artifact = spool_dir / f"{request_id}.tar"
    sidecar = spool_dir / f"{request_id}.stream.json"
    prior = load_json_file(sidecar)
    if artifact.is_file() and prior.get("artifact_sha256") and prior.get("artifact_size_bytes") == artifact.stat().st_size:
        if sha256_file(artifact) == str(prior["artifact_sha256"]):
            return {
                "ok": True,
                "status": "relay_stream_artifact",
                "request_id": request_id,
                "relay_spool_path": str(artifact),
                "artifact_path": f"{request_id}.tar",
                "artifact_sha256": prior["artifact_sha256"],
                "artifact_size_bytes": artifact.stat().st_size,
                "part_count": int(prior.get("part_count") or 0),
                "source_mode": "streamed_chunks",
                "security_onion_staging_bytes": 0,
                "reused_existing_artifact": True,
            }

    manifest_request = {**pcap_request, "mode": "stream_manifest"}
    manifest = run_ssh_pcap_export(config, manifest_request)
    require_capture_safe(config, manifest.get("storage_status"))
    chunks = manifest.get("chunks") if isinstance(manifest.get("chunks"), list) else []
    if not chunks:
        raise PcapExportError("no matching packet capture files found", {"candidate_count": 0, "streamed": True})
    request_dir = spool_dir / request_id
    request_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    checkpoint_path = request_dir / "checkpoint.json"
    checkpoint = load_json_file(checkpoint_path)
    if checkpoint.get("manifest_id") != manifest.get("manifest_id"):
        for path in request_dir.glob("part-*.pcap*"):
            if path.is_file():
                path.unlink()
        checkpoint = {"manifest_id": manifest.get("manifest_id"), "completed": {}}
        atomic_json_write(checkpoint_path, checkpoint)
    completed = checkpoint.setdefault("completed", {})
    source_upper_bound = sum(max(0, int(item.get("source_size_bytes") or 0)) for item in chunks)
    if progress:
        progress.update(
            "security_onion_to_relay",
            source_upper_bound,
            lambda: sum(path.stat().st_size for path in request_dir.glob("part-*.pcap") if path.is_file()),
        )

    part_paths: list[Path] = []
    total_bytes = 0
    for chunk_index, item in enumerate(chunks):
        if chunk_index:
            # Re-check between bounded source rotations. A transfer already on
            # the relay SSD is resumable, so pausing here does not discard work.
            require_capture_safe(config)
        chunk_id = safe_transfer_id(item.get("chunk_id"))
        source_size = int(item.get("source_ceiling_bytes") or item.get("source_size_bytes") or 0)
        if source_size <= 0:
            continue
        part = request_dir / f"part-{chunk_id}.pcap"
        recorded = completed.get(chunk_id) if isinstance(completed.get(chunk_id), dict) else {}
        if recorded.get("empty") is True:
            continue
        if part.is_file() and recorded.get("size") == part.stat().st_size and recorded.get("sha256") == sha256_file(part):
            part_paths.append(part)
            total_bytes += part.stat().st_size
            continue
        part.unlink(missing_ok=True)
        require_spool_capacity(config, source_size)
        stream_request = {
            **pcap_request,
            "mode": "stream_chunk",
            "manifest_id": manifest.get("manifest_id"),
            "chunk_id": chunk_id,
            "capture_ref": item.get("capture_ref"),
            "source_size_bytes": item.get("source_size_bytes"),
            "source_device": item.get("source_device"),
            "source_inode": item.get("source_inode"),
            "bpf_variant": item.get("bpf_variant"),
        }
        size = stream_one_security_onion_chunk(config, stream_request, part, source_size)
        if not size:
            completed[chunk_id] = {"empty": True, "size": 0}
        else:
            digest = sha256_file(part)
            completed[chunk_id] = {"size": size, "sha256": digest}
            part_paths.append(part)
            total_bytes += size
        atomic_json_write(checkpoint_path, checkpoint)

    if not part_paths:
        raise PcapExportError(
            "no matching packets found",
            {"candidate_count": len(chunks), "search_strategy": "stateless-streamed-rotation-chunks"},
        )
    require_spool_capacity(config, total_bytes)
    temporary_tar = artifact.with_suffix(".tar.part")
    temporary_tar.unlink(missing_ok=True)
    try:
        with tarfile.open(temporary_tar, "w") as archive:
            for part in sorted(part_paths):
                archive.add(part, arcname=part.name, recursive=False)
        temporary_tar.replace(artifact)
        artifact.chmod(0o600)
    except Exception:
        temporary_tar.unlink(missing_ok=True)
        raise
    digest = sha256_file(artifact)
    metadata = {
        "manifest_id": manifest.get("manifest_id"),
        "artifact_sha256": digest,
        "artifact_size_bytes": artifact.stat().st_size,
        "part_count": len(part_paths),
        "source_chunk_count": len(chunks),
    }
    atomic_json_write(sidecar, metadata)
    shutil.rmtree(request_dir, ignore_errors=True)
    return {
        "ok": True,
        "status": "relay_stream_artifact",
        "request_id": request_id,
        "relay_spool_path": str(artifact),
        "artifact_path": f"{request_id}.tar",
        "artifact_sha256": digest,
        "artifact_size_bytes": artifact.stat().st_size,
        "part_count": len(part_paths),
        "source_mode": "streamed_chunks",
        "security_onion_staging_bytes": 0,
    }


def mac_transfer_config(config: dict) -> dict:
    broker = config.get("pcap_broker", {})
    transfer = broker.get("mac_transfer") if isinstance(broker.get("mac_transfer"), dict) else {}
    return transfer


def remote_shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def remote_artifact_dir(config: dict, request_id: str) -> str:
    transfer = mac_transfer_config(config)
    base_dir = str(transfer.get("artifact_dir") or "n8n-local/pcap-evidence/artifacts").strip().rstrip("/")
    if not base_dir or base_dir.startswith("/") or ".." in Path(base_dir).parts:
        raise RuntimeError("mac_transfer.artifact_dir must be a relative safe path")
    return f"{base_dir}/{safe_transfer_id(request_id)}"


def mac_ssh_base(config: dict) -> list[str]:
    transfer = mac_transfer_config(config)
    host = str(transfer.get("host") or "").strip()
    user = str(transfer.get("user") or "").strip()
    key = str(transfer.get("ssh_key") or "").strip()
    if not host or not user or not key:
        raise RuntimeError("mac_transfer requires host, user, and ssh_key")
    return [
        "ssh",
        "-i",
        str(resolve_path(key)),
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        f"ConnectTimeout={int(transfer.get('connect_timeout_seconds') or 20)}",
        f"{user}@{host}",
    ]


def run_mac_ssh(config: dict, command: str, timeout: int = 60) -> subprocess.CompletedProcess:
    proc = process_io.run_bounded_command(
        [*mac_ssh_base(config), command],
        timeout_seconds=timeout,
        max_stdout_bytes=1024 * 1024,
        max_stderr_bytes=256 * 1024,
    )
    return subprocess.CompletedProcess(
        proc.args,
        proc.returncode,
        proc.stdout.decode("utf-8", errors="replace"),
        proc.stderr.decode("utf-8", errors="replace"),
    )


def verify_remote_artifact(config: dict, remote_path: str, expected_size: int, expected_sha256: str) -> None:
    request_id = safe_transfer_id(Path(remote_path).parent.name)
    filename = Path(remote_path).name
    command = " ".join([
        "onion-sentinel-pcap-intake", "verify", request_id, filename,
        str(expected_size), expected_sha256,
    ])
    proc = run_mac_ssh(config, command, timeout=300)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or f"remote artifact verification exited {proc.returncode}")
    payload = parse_last_json_object(proc.stdout)
    if int(payload.get("size") or -1) != expected_size:
        raise RuntimeError("Mac artifact size did not match Security Onion metadata")
    if str(payload.get("sha256") or "").lower() != expected_sha256:
        raise RuntimeError("Mac artifact sha256 did not match Security Onion metadata")


def cleanup_remote_artifact(config: dict, request_id: str) -> None:
    """Delete exactly one Mac intake request through the restricted SSH wrapper."""
    request_id = safe_transfer_id(request_id)
    proc = run_mac_ssh(
        config,
        f"onion-sentinel-pcap-intake cleanup {request_id}",
        timeout=60,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or f"remote artifact cleanup exited {proc.returncode}")
    payload = parse_last_json_object(proc.stdout)
    if payload.get("status") != "cleaned" or payload.get("request_id") != request_id:
        raise RuntimeError("Mac artifact cleanup returned an invalid response")


def upload_pcap_artifact_via_rsync(
    config: dict,
    pcap_request: dict,
    export_result: dict,
    progress: PcapProgressReporter | None = None,
) -> dict:
    request_id = safe_transfer_id(export_result.get("request_id") or pcap_request.get("request_id"))
    expected_size = int(export_result.get("artifact_size_bytes") or 0)
    expected_sha256 = str(export_result.get("artifact_sha256") or "").lower()
    relay_spool_path = str(export_result.get("relay_spool_path") or "").strip()
    if relay_spool_path:
        artifact_path = Path(relay_spool_path).resolve(strict=False)
        spool_root = pcap_spool_dir(config).resolve(strict=False)
        if artifact_path.parent != spool_root or artifact_path.name != f"{request_id}.tar":
            raise RuntimeError("relay stream artifact escaped the configured spool")
        if not artifact_path.is_file() or artifact_path.stat().st_size != expected_size:
            raise RuntimeError("relay stream artifact is missing or incomplete")
        if sha256_file(artifact_path) != expected_sha256:
            raise RuntimeError("relay stream artifact sha256 did not match its checkpoint")
    else:
        raise RuntimeError("read-only streamed PCAP result is missing its relay spool path")
    transfer = mac_transfer_config(config)
    remote_dir = remote_artifact_dir(config, request_id)
    remote_name = Path(str(export_result.get("artifact_path") or artifact_path.name)).name
    remote_path = f"{remote_dir}/{remote_name}"
    rsync_ssh = " ".join(remote_shell_quote(part) for part in mac_ssh_base(config)[:-1])
    # remote_dir is already restricted to safe relative path segments. Avoid
    # shell quoting inside the rsync target because rsync passes it through to
    # the remote server and some implementations treat quotes as path bytes.
    target = f"{str(transfer.get('user')).strip()}@{str(transfer.get('host')).strip()}:{remote_dir}/"
    maximum_bps = rsync_max_bytes_per_second(config)
    # rsync expresses --bwlimit in KiB/s. Throttle the sending process on the
    # relay so cached artifacts cannot burst at line rate across a mirrored
    # VLAN and oversubscribe Security Onion's capture destination.
    bwlimit_kib = max(1, maximum_bps // 1024)
    command = [
        "rsync",
        "-av",
        "--checksum",
        "--partial",
        "--append-verify",
        f"--bwlimit={bwlimit_kib}",
        "-e",
        rsync_ssh,
        str(artifact_path),
        target,
    ]
    timeout = transfer_timeout(config, expected_size)
    for attempt in range(2):
        mkdir_proc = run_mac_ssh(
            config,
            f"onion-sentinel-pcap-intake prepare {request_id} {expected_size}",
            timeout=60,
        )
        if mkdir_proc.returncode != 0:
            raise RuntimeError(mkdir_proc.stderr.strip() or f"failed to create Mac artifact dir {remote_dir}")
        if progress:
            progress.update("relay_to_mac", expected_size)
        raw_proc = process_io.run_bounded_command(
            command,
            timeout_seconds=timeout,
            max_stdout_bytes=1024 * 1024,
            max_stderr_bytes=1024 * 1024,
        )
        stdout = raw_proc.stdout.decode("utf-8", errors="replace")
        stderr = raw_proc.stderr.decode("utf-8", errors="replace")
        if raw_proc.returncode != 0:
            raise RuntimeError(stderr.strip() or stdout.strip() or f"rsync exited {raw_proc.returncode}")
        if progress:
            progress.update("verifying", expected_size, lambda: expected_size)
        try:
            verify_remote_artifact(config, remote_path, expected_size, expected_sha256)
            break
        except RuntimeError as verify_error:
            try:
                cleanup_remote_artifact(config, request_id)
            except RuntimeError as cleanup_error:
                raise RuntimeError(f"{verify_error}; failed to clean rejected Mac artifact: {cleanup_error}") from verify_error
            if attempt:
                raise
            if artifact_path.stat().st_size != expected_size or sha256_file(artifact_path) != expected_sha256:
                raise RuntimeError("relay artifact changed after Mac verification failure") from verify_error
    return {
        "ok": True,
        "status": "artifact_rsynced",
        "path": remote_path,
        "artifact_size_bytes": expected_size,
        "artifact_sha256": expected_sha256,
        "max_bytes_per_second": maximum_bps,
    }


def cleanup_relay_spool_artifact(config: dict, request_id: str) -> bool:
    """Delete only a committed request's relay-side resumable artifacts."""
    if not config.get("pcap_broker", {}).get("artifact_spool_delete_after_upload", True):
        return True
    request_id = safe_transfer_id(request_id)
    try:
        spool_root = pcap_spool_dir(config).resolve(strict=False)
        artifact = (spool_root / f"{request_id}.tar").resolve(strict=False)
        if artifact.parent != spool_root:
            raise RuntimeError("relay spool cleanup escaped the configured spool")
        artifact.unlink(missing_ok=True)
        artifact.with_suffix(".stream.json").unlink(missing_ok=True)
        request_dir = (spool_root / request_id).resolve(strict=False)
        if request_dir.parent == spool_root and request_dir.is_dir():
            shutil.rmtree(request_dir)
        return True
    except Exception as exc:
        print(
            json.dumps(
                {"event": "pcap_relay_spool_cleanup_failed", "request_id": request_id, "error": str(exc)[:500]},
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return False


def broker_path(config: dict, name: str, default_path: str) -> str:
    paths = config.get("pcap_broker", {}).get("paths", {})
    path = paths.get(name, default_path) if isinstance(paths, dict) else default_path
    return "/" + str(path or default_path).lstrip("/")


def complete_pcap_request(config: dict, request_id: str, status: str, payload: dict) -> bool:
    broker = config.get("pcap_broker", {})
    attempts = max(1, min(5, int(broker.get("completion_retry_attempts", 3) or 3)))
    delay_seconds = max(0.0, min(30.0, float(broker.get("completion_retry_delay_seconds", 2) or 0)))
    completion = {"request_id": request_id, "status": status, "relay_host": socket.gethostname(), **payload}
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            broker_request(config, "POST", broker_path(config, "complete", "/pcap/complete"), completion)
            return True
        except Exception as exc:
            last_error = exc
            if attempt < attempts and delay_seconds:
                time.sleep(delay_seconds)
    # Completion callbacks are bookkeeping. Losing one should be loud in
    # journald but should not stop the relay from servicing other requests.
    print(
        json.dumps(
            {
                "event": "pcap_complete_failed",
                "request_id": request_id,
                "status": status,
                "attempts": attempts,
                "error": str(last_error)[:500] if last_error else "unknown completion failure",
            },
            sort_keys=True,
        ),
        file=sys.stderr,
    )
    return False


def pcap_retry_delay_seconds(config: dict, attempt_count: int) -> int:
    broker = config.get("pcap_broker", {})
    base = max(1, min(600, int(broker.get("transfer_retry_base_seconds", 30) or 30)))
    maximum = max(base, min(6 * 3600, int(broker.get("transfer_retry_max_seconds", 1800) or 1800)))
    exponent = max(0, min(10, int(attempt_count or 1) - 1))
    return min(maximum, base * (2 ** exponent))


def retry_pcap_request(
    config: dict,
    request_id: str,
    stage: str,
    error: object,
    attempt_count: int,
    diagnostics: dict | None = None,
) -> dict:
    """Persist a bounded retry without discarding resumable transfer state."""
    payload = {
        "request_id": request_id,
        "stage": stage,
        "error": str(error)[:1000],
        "retry_after_seconds": pcap_retry_delay_seconds(config, attempt_count),
    }
    if diagnostics:
        payload["diagnostics"] = diagnostics
    return broker_request(
        config,
        "POST",
        broker_path(config, "retry", "/pcap-retry"),
        payload,
    )


def pcap_outcome_from_error(error: object) -> str:
    detail = str(error or "").lower()
    if "no matching packet" in detail:
        return "no_packets_available"
    if "retention" in detail or "expired" in detail:
        return "expired"
    if "exceed" in detail and ("size" in detail or "artifact" in detail):
        return "oversize"
    if "timeout" in detail or "timed out" in detail:
        return "timeout"
    if "sha256" in detail or "checksum" in detail:
        return "checksum_failed"
    if "unsupported" in detail or "has been removed" in detail or "rejected" in detail:
        return "rejected"
    if any(term in detail for term in ("rsync", "artifact upload", "connection", "ssh", "spool filesystem")):
        return "transport_failed"
    return "failed"


def process_pcap_requests(config: dict) -> dict:
    broker = config.get("pcap_broker", {})
    if not broker.get("enabled"):
        return {
            "ok": True,
            "enabled": False,
            "processed": 0,
            "operational_failures": 0,
        }
    lock_path = Path(str(broker.get("lock_path") or "/tmp/onion-sentinel-pcap-broker.lock"))
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("w", encoding="utf-8") as lock_handle:
        try:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return {
                "ok": True,
                "enabled": True,
                "locked": True,
                "processed": 0,
                "operational_failures": 0,
            }
        lock_handle.write(f"{os.getpid()}\n")
        lock_handle.flush()
        try:
            return _process_pcap_requests_unlocked(config)
        finally:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)


def _process_pcap_requests_unlocked(config: dict) -> dict:
    broker = config.get("pcap_broker", {})
    streamed_chunk_mode(config)
    stale_spool_partials_removed = cleanup_stale_spool_partials(config)
    stale_spool_artifacts_removed = cleanup_stale_spool_artifacts(config)
    spool_snapshot = spool_usage(config)
    if bool(broker.get("artifact_spool_require_mount", False)) and not spool_snapshot.get("available"):
        return {
            "ok": False, "enabled": True, "processed": 0,
            "operational_failures": 1, "outcomes": {}, "spool": spool_snapshot,
        }
    try:
        security_onion_storage = security_onion_storage_status(config)
    except Exception as exc:
        security_onion_storage = {"available": False, "error": str(exc)[:300]}
    capture_protection = capture_protection_decision(config, security_onion_storage)
    if capture_protection.get("deferred"):
        return {
            "ok": True,
            "enabled": True,
            "processed": 0,
            "deferred": True,
            "defer_reason": capture_protection.get("reason"),
            "capture_protection": capture_protection,
            "operational_failures": 0,
            "outcomes": {},
            "stale_spool_partials_removed": stale_spool_partials_removed,
            "stale_spool_artifacts_removed": stale_spool_artifacts_removed,
            "spool": spool_snapshot,
            "security_onion_storage": security_onion_storage,
        }
    # One request per invocation is a capture-protection invariant. The timer's
    # post-run cooldown prevents a backlog from creating continuous SO reads.
    limit = 1
    pending_path = f"{broker_path(config, 'requests', '/pcap/requests')}?status=pending&limit={limit}"
    requests_method = str(broker.get("requests_method") or "GET").strip().upper()
    if requests_method not in {"GET", "POST"}:
        requests_method = "GET"
    pending_payload = {"status": "pending", "limit": limit} if requests_method == "POST" else None
    pending = broker_request(config, requests_method, pending_path, pending_payload)
    processed = 0
    fulfilled = 0
    failed = 0
    completion_failed = 0
    artifact_upload_failed = 0
    artifact_cleanup_failed = 0
    artifact_cleanup_succeeded = 0
    relay_spool_cleanup_failed = 0
    relay_spool_cleanup_succeeded = 0
    retry_scheduled = 0
    retry_exhausted = 0
    retry_callback_failed = 0
    outcomes: dict[str, int] = {}
    operational_failures = 0
    pending_requests = pending.get("requests") if isinstance(pending.get("requests"), list) else []
    eligible_requests = [
        item for item in pending_requests
        if isinstance(item, dict) and str(item.get("status") or "pending").lower() == "pending"
    ][:limit]
    for pcap_request in eligible_requests:
        request_id = pcap_request.get("request_id")
        claim = broker_request(
            config,
            "POST",
            broker_path(config, "claim", "/pcap/claim"),
            {"request_id": request_id, "relay_host": socket.gethostname()},
        )
        if not claim.get("claimed"):
            continue
        claimed_request = claim.get("request") if isinstance(claim.get("request"), dict) else pcap_request
        attempt_count = max(1, int(claimed_request.get("transfer_attempt_count") or 1))
        progress: PcapProgressReporter | None = None
        try:
            with PcapProgressReporter(config, str(request_id)) as progress:
                progress.update("exporting")
                export_request = dict(claimed_request)
                result = streamed_spool_artifact(config, export_request, progress)
                upload = None
                upload_error = ""
                try:
                    upload = upload_pcap_artifact(config, claim["request"], result, progress)
                except Exception as exc:
                    artifact_upload_failed += 1
                    upload_error = str(exc)[:500]
                    print(
                        json.dumps(
                            {
                                "event": "pcap_artifact_upload_failed",
                                "request_id": request_id,
                                "error": upload_error,
                            },
                            sort_keys=True,
                        ),
                        file=sys.stderr,
                    )
            upload_ok = bool(upload and upload.get("ok"))
            if not upload_error and not upload_ok:
                upload_error = "Mac artifact ingest did not confirm success"
            completion_status = "failed" if upload_error else "fulfilled"
            completion_payload = {
                "artifact_path": completed_artifact_path(result, upload),
                "artifact_sha256": result.get("artifact_sha256"),
                "artifact_size_bytes": result.get("artifact_size_bytes"),
                "artifact_ingested": upload_ok,
                "artifact_ingest_error": upload_error,
            }
            if upload_error:
                upload_outcome = pcap_outcome_from_error(upload_error)
                if upload_outcome in {"timeout", "transport_failed", "checksum_failed", "failed"}:
                    try:
                        retry_result = retry_pcap_request(
                            config,
                            str(request_id),
                            progress.stage,
                            f"artifact upload failed: {upload_error}",
                            attempt_count,
                        )
                        if retry_result.get("retry_scheduled"):
                            retry_scheduled += 1
                        elif retry_result.get("exhausted"):
                            retry_exhausted += 1
                            failed += 1
                            outcomes[upload_outcome] = outcomes.get(upload_outcome, 0) + 1
                            operational_failures += 1
                            if cleanup_relay_spool_artifact(config, str(request_id)):
                                relay_spool_cleanup_succeeded += 1
                            else:
                                relay_spool_cleanup_failed += 1
                        else:
                            retry_callback_failed += 1
                            operational_failures += 1
                    except Exception as retry_error:
                        retry_callback_failed += 1
                        operational_failures += 1
                        print(
                            json.dumps(
                                {"event": "pcap_retry_schedule_failed", "request_id": request_id, "error": str(retry_error)[:500]},
                                sort_keys=True,
                            ),
                            file=sys.stderr,
                        )
                else:
                    completion_payload["error"] = f"artifact upload failed: {upload_error}"
                    completion_payload["outcome"] = upload_outcome
                    if complete_pcap_request(config, str(request_id), "failed", completion_payload):
                        failed += 1
                        outcomes[upload_outcome] = outcomes.get(upload_outcome, 0) + 1
                    else:
                        completion_failed += 1
                processed += 1
                continue
            else:
                completion_payload["outcome"] = "captured"
            if complete_pcap_request(
                config,
                request_id,
                completion_status,
                completion_payload,
            ):
                if completion_status == "fulfilled":
                    fulfilled += 1
                    if cleanup_relay_spool_artifact(config, str(request_id)):
                        relay_spool_cleanup_succeeded += 1
                    else:
                        relay_spool_cleanup_failed += 1
                    # Read-only stream mode creates no Security Onion artifact,
                    # so there is intentionally no source-side cleanup action.
                else:
                    failed += 1
                    outcomes["transport_failed"] = outcomes.get("transport_failed", 0) + 1
                    operational_failures += 1
            else:
                completion_failed += 1
        except Exception as exc:
            outcome = pcap_outcome_from_error(exc)
            completion_payload = {"error": str(exc)[:500], "outcome": outcome}
            diagnostics = getattr(exc, "diagnostics", None)
            if diagnostics:
                completion_payload["diagnostics"] = diagnostics
            if outcome in {"timeout", "transport_failed", "checksum_failed", "failed"}:
                try:
                    retry_result = retry_pcap_request(
                        config,
                        str(request_id),
                        progress.stage if progress else "claimed",
                        exc,
                        attempt_count,
                        diagnostics,
                    )
                    if retry_result.get("retry_scheduled"):
                        retry_scheduled += 1
                    elif retry_result.get("exhausted"):
                        retry_exhausted += 1
                        failed += 1
                        outcomes[outcome] = outcomes.get(outcome, 0) + 1
                        operational_failures += 1
                        if cleanup_relay_spool_artifact(config, str(request_id)):
                            relay_spool_cleanup_succeeded += 1
                        else:
                            relay_spool_cleanup_failed += 1
                    else:
                        retry_callback_failed += 1
                        operational_failures += 1
                except Exception as retry_error:
                    retry_callback_failed += 1
                    operational_failures += 1
                    print(
                        json.dumps(
                            {"event": "pcap_retry_schedule_failed", "request_id": request_id, "error": str(retry_error)[:500]},
                            sort_keys=True,
                        ),
                        file=sys.stderr,
                    )
            else:
                completion_recorded = complete_pcap_request(config, request_id, "failed", completion_payload)
                if not completion_recorded:
                    completion_failed += 1
                failed += 1
                outcomes[outcome] = outcomes.get(outcome, 0) + 1
        processed += 1
    return {
        "ok": True,
        "enabled": True,
        # This is an end-to-end recovery proof for the health wrapper. Local
        # capture holds, disabled mode, and lock skips return before this point.
        "broker_contacted": True,
        "processed": processed,
        "fulfilled": fulfilled,
        "failed": failed,
        "completion_failed": completion_failed,
        "artifact_upload_failed": artifact_upload_failed,
        "artifact_cleanup_failed": artifact_cleanup_failed,
        "artifact_cleanup_succeeded": artifact_cleanup_succeeded,
        "relay_spool_cleanup_failed": relay_spool_cleanup_failed,
        "relay_spool_cleanup_succeeded": relay_spool_cleanup_succeeded,
        "retry_scheduled": retry_scheduled,
        "retry_exhausted": retry_exhausted,
        "retry_callback_failed": retry_callback_failed,
        "outcomes": outcomes,
        "operational_failures": operational_failures + completion_failed + artifact_cleanup_failed + relay_spool_cleanup_failed,
        "stale_spool_partials_removed": stale_spool_partials_removed,
        "stale_spool_artifacts_removed": stale_spool_artifacts_removed,
        "spool": spool_usage(config),
        "security_onion_storage": security_onion_storage,
    }


def post_alerts_to_webhook(
    config: dict,
    alerts: list[dict],
    conn: sqlite3.Connection | None = None,
) -> int:
    # One POST per alert keeps delivery failures obvious and lets alert-store
    # return an acknowledgement for each alert. When conn is provided, each
    # alert is marked seen immediately after a successful POST, so a later
    # delivery failure resumes with only the unposted remainder next timer run.
    if not alert_delivery.delivery_enabled(config):
        return 0

    if alert_delivery.delivery_mode(config) == "ssh_batch":
        messages = [
            {"delivery_id": str(alert.get("alert_id") or ""), "payload": alert}
            for alert in alerts
        ]
        results = alert_delivery.deliver_ssh_messages(config, messages)
        failures = [item for item in results if not item.get("ok")]
        if failures:
            raise RuntimeError(f"SSH alert intake rejected {len(failures)} alert(s)")
        if conn is not None:
            mark_seen(conn, alerts)
        return len(results)

    posted_count = 0
    for alert in alerts:
        post_json_to_webhook(config, alert)
        posted_count += 1
        if conn is not None:
            mark_seen(conn, [alert])

    return posted_count


def drain_alert_outbox(config: dict, conn: sqlite3.Connection) -> int:
    """Deliver queued alerts, preserving per-alert acknowledgement state."""
    webhook = config.get("webhook", {})
    if not alert_delivery.delivery_enabled(config):
        return 0
    posted_count = 0
    limit = max(1, min(int(webhook.get("outbox_drain_limit", 1000) or 1000), 10000))
    pending = alert_outbox.pending(conn, limit)
    if alert_delivery.delivery_mode(config) == "ssh_batch":
        retryable_failures = 0
        permanent_failures = 0
        messages = [
            {"delivery_id": item["alert_id"], "payload": item["payload"]}
            for item in pending
        ]
        for batch in alert_delivery.split_batches(config, messages):
            batch_by_id = {item["delivery_id"]: item for item in batch}
            claimed = {
                delivery_id: item
                for delivery_id, item in batch_by_id.items()
                if alert_outbox.claim(conn, delivery_id)
            }
            if not claimed:
                continue
            try:
                response = alert_delivery.deliver_ssh_batch(config, list(claimed.values()))
            except Exception as exc:
                for delivery_id in claimed:
                    alert_outbox.mark_failure(conn, delivery_id, str(exc))
                raise RuntimeError(str(exc)) from exc
            results = {
                str(item.get("delivery_id") or ""): item
                for item in response.get("results", [])
                if isinstance(item, dict)
            }
            for delivery_id, message in claimed.items():
                result = results.get(delivery_id, {
                    "ok": False,
                    "retryable": True,
                    "reason": "missing per-alert acknowledgement",
                })
                if result.get("ok"):
                    mark_seen(conn, [message["payload"]])
                    alert_outbox.mark_delivered(conn, delivery_id)
                    posted_count += 1
                elif result.get("retryable", True):
                    alert_outbox.mark_failure(
                        conn,
                        delivery_id,
                        str(result.get("reason") or "retryable rejection"),
                    )
                    retryable_failures += 1
                else:
                    # A poison message is retained for inspection but cannot
                    # hold every newer LAN alert behind it forever.
                    alert_outbox.move_to_dead_letter(
                        conn,
                        delivery_id,
                        str(result.get("reason") or "permanent rejection"),
                    )
                    mark_seen(conn, [message["payload"]])
                    permanent_failures += 1
        if retryable_failures or permanent_failures:
            raise RuntimeError(
                "SSH alert intake completed with "
                f"{retryable_failures} retryable and {permanent_failures} permanent rejection(s)"
            )
        return posted_count

    for item in pending:
        alert_id = item["alert_id"]
        if not alert_outbox.claim(conn, alert_id):
            continue
        try:
            post_json_to_webhook(config, item["payload"])
        except Exception as exc:
            alert_outbox.mark_failure(conn, alert_id, str(exc))
            raise
        mark_seen(conn, [item["payload"]])
        alert_outbox.mark_delivered(conn, alert_id)
        posted_count += 1
    return posted_count


def build_relay_heartbeat(
    batch: dict,
    alert_count: int,
    dropped_count: int,
    filtered_count: int,
    new_count: int,
    duplicate_count: int,
    posted_count: int,
    first_rule: str,
) -> dict:
    return {
        "message_type": "relay_heartbeat",
        "source": batch.get("source") or "security-onion",
        "relay_host": socket.gethostname(),
        "generated_at": now_utc_iso(),
        "exported_at": batch.get("exported_at"),
        "alert_count": alert_count,
        "dropped_alert_count": dropped_count,
        "filtered_alert_count": filtered_count,
        "new_alert_count": new_count,
        "duplicate_alert_count": duplicate_count,
        "posted_webhook_alerts": posted_count,
        "first_rule": first_rule,
    }


def post_relay_heartbeat(config: dict, heartbeat: dict) -> bool:
    if not alert_delivery.delivery_enabled(config):
        return False
    if alert_delivery.delivery_mode(config) == "ssh_batch":
        delivery_id = f"relay-heartbeat:{heartbeat.get('generated_at') or now_utc_iso()}"
        results = alert_delivery.deliver_ssh_messages(
            config,
            [{"delivery_id": delivery_id, "payload": heartbeat}],
        )
        if len(results) != 1 or not results[0].get("ok"):
            reason = results[0].get("reason") if results else "missing acknowledgement"
            raise RuntimeError(f"SSH heartbeat intake failed: {reason}")
        return True
    post_json_to_webhook(config, heartbeat)
    return True


def main() -> int:
    # The relay intentionally has one mode: pull once and exit. systemd timer
    # handles scheduling, which makes crashes and retries easier to reason about.
    parser = argparse.ArgumentParser(description="Security Onion alert relay prototype")
    parser.add_argument(
        "--config",
        default=str(APP_DIR / "config.json"),
        help="Path to relay config JSON",
    )
    parser.add_argument(
        "--pull-once",
        action="store_true",
        help="Pull one alert batch and save it locally",
    )
    parser.add_argument(
        "--process-pcap-requests",
        action="store_true",
        help="Poll the configured PCAP broker and fulfill pending requests",
    )
    parser.add_argument(
        "--webhook-url",
        help="Enable webhook forwarding for this run and POST new alerts to this URL",
    )
    parser.add_argument(
        "--webhook-token",
        default=None,
        help="Optional X-Relay-Token header value for webhook forwarding",
    )
    args = parser.parse_args()

    config = load_config(Path(args.config).resolve())
    pruned_runtime_files = prune_runtime_evidence(config)
    relay_root_storage = require_relay_root_capacity(config)
    if args.process_pcap_requests:
        result = process_pcap_requests(config)
        result["pruned_runtime_files"] = pruned_runtime_files
        result["relay_root_storage"] = relay_root_storage
        print(json.dumps(result, sort_keys=True))
        return 0

    if not args.pull_once:
        parser.error("Choose --pull-once or --process-pcap-requests")

    if args.webhook_url:
        # systemd injects live secrets through relay.env; pull-only debugging can
        # still run with webhook disabled in config.json.
        config.setdefault("webhook", {})
        config["webhook"]["enabled"] = True
        config["webhook"]["url"] = args.webhook_url
        # Prefer env over argv for the systemd path so tokens do not leak
        # through process listings. The argv option remains for isolated tests.
        config["webhook"]["token"] = args.webhook_token if args.webhook_token is not None else os.environ.get("RELAY_WEBHOOK_TOKEN", "")

    batch = run_ssh_pull(config)
    output_path = save_batch(config, batch)
    all_alerts = batch.get("alerts", [])
    filtered_alerts, dropped_count = filter_dropped_alerts(config, all_alerts)
    with closing(connect_db(config)) as conn:
        # Important order: filter -> dedupe -> durable queue -> post -> mark seen.
        new_alerts, duplicate_count = filter_unseen_alerts(conn, filtered_alerts)
        saved_alert_paths = save_new_alerts(config, new_alerts)
        delivery_enabled = alert_delivery.delivery_enabled(config)
        queued_count = alert_outbox.enqueue(conn, new_alerts) if delivery_enabled else 0
        posted_count = drain_alert_outbox(config, conn) if delivery_enabled else 0
        outbox_counts = alert_outbox.counts(conn)
        alert_outbox.prune_delivered(
            conn,
            int(config.get("webhook", {}).get("outbox_delivered_retention_days", 30) or 30),
        )
        first_rule = all_alerts[0].get("rule_name") if all_alerts else "none"
        heartbeat_posted = False
        if not new_alerts:
            heartbeat = build_relay_heartbeat(
                batch,
                alert_count=len(all_alerts),
                dropped_count=dropped_count,
                filtered_count=len(filtered_alerts),
                new_count=len(new_alerts),
                duplicate_count=duplicate_count,
                posted_count=posted_count,
                first_rule=first_rule,
            )
            heartbeat_posted = post_relay_heartbeat(config, heartbeat)
        if not delivery_enabled:
            mark_seen(conn, new_alerts)

    print(
        json.dumps(
            {
                "saved": str(output_path),
                "source": batch.get("source"),
                "exported_at": batch.get("exported_at"),
                "alert_count": len(all_alerts),
                "dropped_alert_count": dropped_count,
                "filtered_alert_count": len(filtered_alerts),
                "new_alert_count": len(new_alerts),
                "duplicate_alert_count": duplicate_count,
                "saved_new_alert_files": len(saved_alert_paths),
                "posted_webhook_alerts": posted_count,
                "queued_webhook_alerts": queued_count,
                "outbox_pending_alerts": outbox_counts.get("pending", 0),
                "outbox_dead_letter_alerts": outbox_counts.get("dead_letter", 0),
                "alert_delivery_mode": alert_delivery.delivery_mode(config),
                "posted_webhook_heartbeat": heartbeat_posted,
                "first_rule": first_rule,
                "pruned_runtime_files": pruned_runtime_files,
                "relay_root_storage": relay_root_storage,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
