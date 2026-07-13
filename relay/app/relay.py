#!/usr/bin/env python3
"""Pull Security Onion alerts over restricted SSH and forward new ones to n8n.

The relay is deliberately small: it pulls a sanitized JSON batch from Security
Onion, deduplicates alert IDs locally for retry safety, saves evidence files,
and POSTs new alerts to the Mac Studio webhook. Rule filtering, suppression,
routing, reporting, and notification policy live in Mac Studio n8n/alert-store.
Troubleshooting usually starts with the final JSON summary printed by this
script.
"""
import argparse
import fcntl
import hashlib
import json
import os
import shutil
import socket
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from re import sub
from urllib import request
from urllib.error import HTTPError, URLError


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
    result = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=relay.get("ssh_timeout_seconds", 20) + 10,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"SSH pull failed with exit code {result.returncode}: {result.stderr.strip()}"
        )

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        # A short preview makes banner/shell/JSON issues diagnosable in logs.
        preview = result.stdout[:500]
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


def run_ssh_pcap_export(config: dict, pcap_request: dict) -> dict:
    # PCAP export uses a separate forced-command key when configured. The
    # request JSON is sent over stdin; the Security Onion wrapper validates it
    # again before touching any pcap files.
    so = config["security_onion"]
    relay = config["relay"]
    key_path = resolve_path(so.get("pcap_ssh_key") or so["ssh_key"])
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
        "pcap",
    ]
    result = subprocess.run(
        command,
        input=json.dumps(pcap_request, sort_keys=True),
        check=False,
        capture_output=True,
        text=True,
        timeout=relay.get("pcap_timeout_seconds", 180),
    )
    try:
        payload = parse_last_json_object(result.stdout)
    except json.JSONDecodeError as exc:
        preview = result.stdout[:500]
        stderr_preview = result.stderr[:500]
        raise RuntimeError(
            f"PCAP export returned invalid JSON: {exc}; stdout_preview={preview!r}; stderr_preview={stderr_preview!r}"
        ) from exc
    if result.returncode != 0 or not payload.get("ok"):
        raise PcapExportError(
            payload.get("error") or result.stderr.strip() or f"PCAP export failed with exit code {result.returncode}",
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
            body = response.read().decode("utf-8", errors="replace")
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
            body = response.read().decode("utf-8")
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


def upload_pcap_artifact(config: dict, pcap_request: dict, export_result: dict) -> dict | None:
    broker = config.get("pcap_broker", {})
    upload_mode = str(broker.get("artifact_upload_mode") or "spooled_rsync").strip().lower()
    if upload_mode in {"spooled_rsync", "rsync"}:
        return upload_pcap_artifact_via_rsync(config, pcap_request, export_result)
    raise RuntimeError(
        f"unsupported PCAP artifact_upload_mode {upload_mode!r}; "
        "inline n8n artifact transfer has been removed, use spooled_rsync"
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


def require_spool_capacity(config: dict, artifact_size: int) -> None:
    broker = config.get("pcap_broker", {})
    max_bytes = int(broker.get("artifact_spool_max_bytes", 8 * 1024 * 1024 * 1024) or 0)
    min_free_bytes = int(broker.get("artifact_spool_min_free_bytes", 3 * 1024 * 1024 * 1024) or 0)
    if max_bytes > 0 and artifact_size > max_bytes:
        raise RuntimeError(f"PCAP artifact exceeds relay spool limit: {artifact_size} > {max_bytes}")
    spool_dir = pcap_spool_dir(config)
    if not spool_dir.exists() or not spool_dir.is_dir():
        raise RuntimeError(f"relay PCAP spool directory is unavailable: {spool_dir}")
    usage = shutil.disk_usage(spool_dir)
    required = artifact_size + max(0, min_free_bytes)
    if usage.free < required:
        raise RuntimeError(f"relay PCAP spool has insufficient free space: free={usage.free} required={required}")


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
    for path in spool_dir.glob("*.part"):
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


def security_onion_transfer_config(config: dict) -> dict:
    so = config.get("security_onion", {})
    transfer = so.get("pcap_artifact_transfer") if isinstance(so.get("pcap_artifact_transfer"), dict) else {}
    return transfer


def security_onion_rsync_ssh(config: dict) -> tuple[list[str], str]:
    so = config["security_onion"]
    relay = config["relay"]
    transfer = security_onion_transfer_config(config)
    host = str(transfer.get("host") or so.get("host") or "").strip()
    user = str(transfer.get("ssh_user") or "").strip()
    key = str(transfer.get("ssh_key") or "").strip()
    if not host or not user or not key:
        raise RuntimeError("security_onion.pcap_artifact_transfer requires host, ssh_user, and ssh_key")
    ssh_args = [
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
        f"ConnectTimeout={relay.get('ssh_timeout_seconds', 20)}",
    ]
    return ssh_args, f"{user}@{host}"


def validate_security_onion_artifact_path(path_value: object, request_id: str) -> str:
    path = str(path_value or "").strip()
    expected_name = f"{safe_transfer_id(request_id)}.tar"
    if not path.startswith("/nsm/pcapout/onion-sentinel/"):
        raise RuntimeError("Security Onion artifact path is outside the approved PCAP output root")
    if Path(path).name != expected_name:
        raise RuntimeError("Security Onion artifact path does not match the requested artifact name")
    if any(char in path for char in "\n\r\t*?[]{}'\""):
        raise RuntimeError("Security Onion artifact path contains unsafe characters")
    return path


def spool_pcap_artifact_from_security_onion(config: dict, pcap_request: dict, export_result: dict) -> Path:
    request_id = safe_transfer_id(export_result.get("request_id") or pcap_request.get("request_id"))
    expected_size = int(export_result.get("artifact_size_bytes") or 0)
    expected_sha256 = str(export_result.get("artifact_sha256") or "").lower()
    if not expected_size or not expected_sha256:
        raise RuntimeError("spooled PCAP transfer requires artifact size and sha256 metadata")
    remote_artifact = validate_security_onion_artifact_path(export_result.get("artifact_path"), request_id)
    spool_dir = pcap_spool_dir(config)
    spool_dir.mkdir(parents=True, exist_ok=True)
    final_path = spool_dir / f"{request_id}.tar"
    temp_path = spool_dir / f"{request_id}.tar.part"

    # A failed Mac upload leaves the verified relay artifact in place. Reuse it
    # on retry instead of requiring enough free space for a duplicate pull.
    if final_path.is_file():
        if final_path.stat().st_size == expected_size and sha256_file(final_path) == expected_sha256:
            final_path.chmod(0o600)
            return final_path
        final_path.unlink(missing_ok=True)

    require_spool_capacity(config, expected_size)
    ssh_args, target = security_onion_rsync_ssh(config)
    transfer = security_onion_transfer_config(config)
    command = [
        "rsync",
        "-av",
        "--partial",
        "--append-verify",
        "-e",
        " ".join(remote_shell_quote(part) for part in ssh_args),
        f"{target}:{remote_artifact}",
        str(temp_path),
    ]
    timeout = int(transfer.get("rsync_timeout_seconds") or config.get("relay", {}).get("pcap_timeout_seconds", 1800) or 1800)
    proc = subprocess.run(command, check=False, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        temp_path.unlink(missing_ok=True)
        raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or f"Security Onion rsync exited {proc.returncode}")
    if temp_path.stat().st_size != expected_size:
        temp_path.unlink(missing_ok=True)
        raise RuntimeError("spooled PCAP artifact size did not match Security Onion metadata")
    if sha256_file(temp_path) != expected_sha256:
        temp_path.unlink(missing_ok=True)
        raise RuntimeError("spooled PCAP artifact sha256 did not match Security Onion metadata")
    temp_path.replace(final_path)
    final_path.chmod(0o600)
    return final_path


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
    return subprocess.run(
        [*mac_ssh_base(config), command],
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def verify_remote_artifact(config: dict, remote_path: str, expected_size: int, expected_sha256: str) -> None:
    quoted = remote_shell_quote(remote_path)
    command = (
        "python3 - "
        + quoted
        + " <<'PY'\n"
        + "import hashlib, json, sys\n"
        + "from pathlib import Path\n"
        + "path = Path(sys.argv[1])\n"
        + "digest = hashlib.sha256()\n"
        + "with path.open('rb') as handle:\n"
        + "    for chunk in iter(lambda: handle.read(1024 * 1024), b''):\n"
        + "        digest.update(chunk)\n"
        + "print(json.dumps({'ok': True, 'size': path.stat().st_size, 'sha256': digest.hexdigest()}))\n"
        + "PY"
    )
    proc = run_mac_ssh(config, command, timeout=300)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or f"remote artifact verification exited {proc.returncode}")
    payload = parse_last_json_object(proc.stdout)
    if int(payload.get("size") or -1) != expected_size:
        raise RuntimeError("Mac artifact size did not match Security Onion metadata")
    if str(payload.get("sha256") or "").lower() != expected_sha256:
        raise RuntimeError("Mac artifact sha256 did not match Security Onion metadata")


def upload_pcap_artifact_via_rsync(config: dict, pcap_request: dict, export_result: dict) -> dict:
    request_id = safe_transfer_id(export_result.get("request_id") or pcap_request.get("request_id"))
    expected_size = int(export_result.get("artifact_size_bytes") or 0)
    expected_sha256 = str(export_result.get("artifact_sha256") or "").lower()
    artifact_path = spool_pcap_artifact_from_security_onion(config, pcap_request, export_result)
    transfer = mac_transfer_config(config)
    remote_dir = remote_artifact_dir(config, request_id)
    remote_name = Path(str(export_result.get("artifact_path") or artifact_path.name)).name
    remote_path = f"{remote_dir}/{remote_name}"
    mkdir_proc = run_mac_ssh(config, f"mkdir -p {remote_shell_quote(remote_dir)}", timeout=60)
    if mkdir_proc.returncode != 0:
        raise RuntimeError(mkdir_proc.stderr.strip() or f"failed to create Mac artifact dir {remote_dir}")
    rsync_ssh = " ".join(remote_shell_quote(part) for part in mac_ssh_base(config)[:-1])
    # remote_dir is already restricted to safe relative path segments. Avoid
    # shell quoting inside the rsync target because rsync passes it through to
    # the remote server and some implementations treat quotes as path bytes.
    target = f"{str(transfer.get('user')).strip()}@{str(transfer.get('host')).strip()}:{remote_dir}/"
    command = [
        "rsync",
        "-av",
        "--partial",
        "-e",
        rsync_ssh,
        str(artifact_path),
        target,
    ]
    timeout = int(transfer.get("rsync_timeout_seconds") or 1800)
    proc = subprocess.run(command, check=False, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or f"rsync exited {proc.returncode}")
    verify_remote_artifact(config, remote_path, expected_size, expected_sha256)
    if config.get("pcap_broker", {}).get("artifact_spool_delete_after_upload", True):
        artifact_path.unlink(missing_ok=True)
    return {
        "ok": True,
        "status": "artifact_rsynced",
        "path": remote_path,
        "artifact_size_bytes": expected_size,
        "artifact_sha256": expected_sha256,
    }


def cleanup_pcap_artifact(config: dict, request_id: str) -> bool:
    try:
        result = run_ssh_pcap_export(config, {"mode": "artifact_cleanup", "request_id": request_id})
    except Exception as exc:
        print(
            json.dumps(
                {
                    "event": "pcap_artifact_cleanup_failed",
                    "request_id": request_id,
                    "error": str(exc)[:500],
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return False
    if not result.get("ok"):
        print(
            json.dumps(
                {
                    "event": "pcap_artifact_cleanup_failed",
                    "request_id": request_id,
                    "error": str(result.get("error") or result.get("status") or "cleanup rejected")[:500],
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return False
    return True


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


def process_pcap_requests(config: dict) -> dict:
    broker = config.get("pcap_broker", {})
    if not broker.get("enabled"):
        return {"ok": True, "enabled": False, "processed": 0}
    lock_path = Path(str(broker.get("lock_path") or "/tmp/onion-sentinel-pcap-broker.lock"))
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("w", encoding="utf-8") as lock_handle:
        try:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return {"ok": True, "enabled": True, "locked": True, "processed": 0}
        lock_handle.write(f"{os.getpid()}\n")
        lock_handle.flush()
        try:
            return _process_pcap_requests_unlocked(config)
        finally:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)


def _process_pcap_requests_unlocked(config: dict) -> dict:
    broker = config.get("pcap_broker", {})
    stale_spool_partials_removed = cleanup_stale_spool_partials(config)
    stale_spool_artifacts_removed = cleanup_stale_spool_artifacts(config)
    limit = max(1, min(10, int(broker.get("limit", 3) or 3)))
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
    for pcap_request in pending.get("requests", []):
        if str(pcap_request.get("status") or "pending").lower() != "pending":
            continue
        request_id = pcap_request.get("request_id")
        claim = broker_request(
            config,
            "POST",
            broker_path(config, "claim", "/pcap/claim"),
            {"request_id": request_id, "relay_host": socket.gethostname()},
        )
        if not claim.get("claimed"):
            continue
        try:
            export_request = dict(claim["request"])
            result = run_ssh_pcap_export(config, export_request)
            upload = None
            upload_error = ""
            try:
                upload = upload_pcap_artifact(config, claim["request"], result)
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
                completion_payload["error"] = f"artifact upload failed: {upload_error}"
            if complete_pcap_request(
                config,
                request_id,
                completion_status,
                completion_payload,
            ):
                if completion_status == "fulfilled":
                    fulfilled += 1
                    if cleanup_pcap_artifact(config, str(request_id)):
                        artifact_cleanup_succeeded += 1
                    else:
                        artifact_cleanup_failed += 1
                else:
                    failed += 1
            else:
                completion_failed += 1
        except Exception as exc:
            completion_payload = {"error": str(exc)[:500]}
            diagnostics = getattr(exc, "diagnostics", None)
            if diagnostics:
                completion_payload["diagnostics"] = diagnostics
            if not complete_pcap_request(config, request_id, "failed", completion_payload):
                completion_failed += 1
            failed += 1
        processed += 1
    return {
        "ok": True,
        "enabled": True,
        "processed": processed,
        "fulfilled": fulfilled,
        "failed": failed,
        "completion_failed": completion_failed,
        "artifact_upload_failed": artifact_upload_failed,
        "artifact_cleanup_failed": artifact_cleanup_failed,
        "artifact_cleanup_succeeded": artifact_cleanup_succeeded,
        "stale_spool_partials_removed": stale_spool_partials_removed,
        "stale_spool_artifacts_removed": stale_spool_artifacts_removed,
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
    webhook = config.get("webhook", {})
    if not webhook.get("enabled"):
        return 0

    posted_count = 0
    for alert in alerts:
        post_json_to_webhook(config, alert)
        posted_count += 1
        if conn is not None:
            mark_seen(conn, [alert])

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
    webhook = config.get("webhook", {})
    if not webhook.get("enabled"):
        return False
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
    if args.process_pcap_requests:
        print(json.dumps(process_pcap_requests(config), sort_keys=True))
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
    with connect_db(config) as conn:
        # Important order: filter -> dedupe -> save/post -> mark seen.
        new_alerts, duplicate_count = filter_unseen_alerts(conn, filtered_alerts)
        saved_alert_paths = save_new_alerts(config, new_alerts)
        webhook_enabled = bool(config.get("webhook", {}).get("enabled"))
        posted_count = post_alerts_to_webhook(config, new_alerts, conn if webhook_enabled else None)
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
        if not webhook_enabled:
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
                "posted_webhook_heartbeat": heartbeat_posted,
                "first_rule": first_rule,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
