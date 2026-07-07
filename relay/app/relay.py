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
import json
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
        payload = json.loads(result.stdout or "{}")
    except json.JSONDecodeError as exc:
        preview = result.stdout[:500]
        raise RuntimeError(f"PCAP export returned invalid JSON: {exc}; preview={preview!r}") from exc
    if result.returncode != 0 or not payload.get("ok"):
        raise RuntimeError(payload.get("error") or result.stderr.strip() or f"PCAP export failed with exit code {result.returncode}")
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
        # Must match the token configured inside the imported n8n workflow.
        headers["X-Relay-Token"] = token

    req = request.Request(url, data=payload, headers=headers, method="POST")
    try:
        with request.urlopen(req, timeout=timeout) as response:
            if response.status < 200 or response.status >= 300:
                raise WebhookPostError(
                    f"Webhook returned HTTP {response.status}",
                    retryable=is_retryable_http_status(response.status),
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


def broker_path(config: dict, name: str, default_path: str) -> str:
    paths = config.get("pcap_broker", {}).get("paths", {})
    path = paths.get(name, default_path) if isinstance(paths, dict) else default_path
    return "/" + str(path or default_path).lstrip("/")


def process_pcap_requests(config: dict) -> dict:
    broker = config.get("pcap_broker", {})
    if not broker.get("enabled"):
        return {"ok": True, "enabled": False, "processed": 0}
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
    for pcap_request in pending.get("requests", []):
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
            result = run_ssh_pcap_export(config, claim["request"])
            broker_request(
                config,
                "POST",
                broker_path(config, "complete", "/pcap/complete"),
                {
                    "request_id": request_id,
                    "status": "fulfilled",
                    "relay_host": socket.gethostname(),
                    "artifact_path": result.get("artifact_path"),
                    "artifact_sha256": result.get("artifact_sha256"),
                    "artifact_size_bytes": result.get("artifact_size_bytes"),
                },
            )
            fulfilled += 1
        except Exception as exc:
            broker_request(
                config,
                "POST",
                broker_path(config, "complete", "/pcap/complete"),
                {
                    "request_id": request_id,
                    "status": "failed",
                    "relay_host": socket.gethostname(),
                    "error": str(exc)[:500],
                },
            )
            failed += 1
        processed += 1
    return {"ok": True, "enabled": True, "processed": processed, "fulfilled": fulfilled, "failed": failed}


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
        default="",
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
        config["webhook"]["token"] = args.webhook_token

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
