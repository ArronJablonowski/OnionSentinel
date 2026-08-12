#!/usr/bin/env python3
"""Relay alert delivery, heartbeat, and command-line application composition."""
from __future__ import annotations

import argparse
import json
import os
import socket
import sqlite3
import sys
from contextlib import closing
from pathlib import Path

from relay_core import *  # noqa: F401,F403
from relay_pcap_service import *  # noqa: F401,F403

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
