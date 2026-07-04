#!/usr/bin/env python3
"""Run the Pi relay and send Telegram health notifications.

systemd executes this wrapper, not relay.py directly. The wrapper records the
last health state so you get one Telegram message when the relay first fails and
one recovery message when it comes back, instead of a message every five minutes.
Transient failures are common enough on home lab networks that notification is
delayed until a configurable number of consecutive failures occurs.
"""
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib import request
from urllib.error import HTTPError, URLError


STATE_PATH = Path(os.environ.get("RELAY_HEALTH_STATE", "/opt/so-alert-relay/state/health_state.json"))
# RELAY_COMMAND is overrideable so you can simulate failures during testing:
# RELAY_COMMAND=/bin/false sudo -E systemctl start so-alert-relay.service
RELAY_COMMAND = os.environ.get(
    "RELAY_COMMAND",
    '/usr/bin/python3 /opt/so-alert-relay/app/relay.py --config /opt/so-alert-relay/app/config.json --pull-once --webhook-url "$RELAY_WEBHOOK_URL" --webhook-token "$RELAY_WEBHOOK_TOKEN"',
)
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
HOST_LABEL = os.environ.get("RELAY_HOST_LABEL", "Raspberry Pi SOC relay")


def env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except ValueError:
        return default


FAILURE_NOTIFY_THRESHOLD = max(1, env_int("RELAY_FAILURE_NOTIFY_THRESHOLD", 3))


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d  %H:%M:%SZ")


def load_state() -> dict:
    # A missing/corrupt state file should never block alert polling.
    try:
        return json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {
            "status": "unknown",
            "last_failure": None,
            "last_success": None,
            "consecutive_failures": 0,
            "failure_notification_sent": False,
        }


def save_state(state: dict) -> None:
    # The state file is the suppression memory for repeated failures.
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def telegram_enabled() -> bool:
    # Empty token/chat id means health notifications are disabled, but relay
    # polling should still continue.
    return bool(TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID)


def send_telegram(message: str) -> dict:
    # Return structured status instead of raising so notification failures are
    # visible in journald without masking the underlying relay result.
    if not telegram_enabled():
        return {"ok": False, "status": "disabled"}

    payload = json.dumps({
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "disable_web_page_preview": True,
    }).encode("utf-8")
    req = request.Request(
        f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with request.urlopen(req, timeout=10) as response:
            return {"ok": 200 <= response.status < 300, "status": response.status}
    except HTTPError as exc:
        return {"ok": False, "status": exc.code, "error": exc.reason}
    except URLError as exc:
        return {"ok": False, "status": "url_error", "error": str(exc.reason)}
    except Exception as exc:
        return {"ok": False, "status": "error", "error": str(exc)}


def summarize_output(stdout: str, stderr: str) -> str:
    # relay.py prints a JSON summary as its final line. Pull out the operational
    # counters so health notices are short enough to read on a phone.
    details = []
    for line in reversed(stdout.splitlines()):
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                payload = json.loads(line)
                details.append(
                    "alerts={alert_count} dropped={dropped_alert_count} new={new_alert_count} posted={posted_webhook_alerts}".format(
                        alert_count=payload.get("alert_count", "unknown"),
                        dropped_alert_count=payload.get("dropped_alert_count", 0),
                        new_alert_count=payload.get("new_alert_count", "unknown"),
                        posted_webhook_alerts=payload.get("posted_webhook_alerts", "unknown"),
                    )
                )
                break
            except Exception:
                pass
    if stderr.strip():
        details.append(stderr.strip().splitlines()[-1][:240])
    return "; ".join(details) or "no relay output summary"


def run_relay() -> subprocess.CompletedProcess:
    # shell=True is used here because the default command intentionally expands
    # environment variables from /etc/so-alert-relay/relay.env.
    return subprocess.run(
        RELAY_COMMAND,
        shell=True,
        executable="/bin/bash",
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "--test-notification":
        # Safe manual test path: does not pull Security Onion alerts.
        result = send_telegram(f"[RECOVERY TEST] {HOST_LABEL} notification path test at {now_iso()}")
        print(json.dumps({"notification": result}, sort_keys=True))
        return 0 if result.get("ok") else 1

    state = load_state()
    started_at = now_iso()
    try:
        result = run_relay()
    except Exception as exc:
        result = subprocess.CompletedProcess(RELAY_COMMAND, 1, "", str(exc))

    summary = summarize_output(result.stdout, result.stderr)
    print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)

    if result.returncode == 0:
        # If the previous run failed, this successful run is recovery-worthy.
        recovered = state.get("status") == "failed" and state.get("failure_notification_sent")
        state.update({
            "status": "ok",
            "last_success": now_iso(),
            "last_summary": summary,
            "last_returncode": result.returncode,
            "consecutive_failures": 0,
            "failure_notification_sent": False,
        })
        save_state(state)
        if recovered:
            notice = send_telegram(f"[RECOVERY] {HOST_LABEL} recovered at {state['last_success']}\n{summary}")
            print(json.dumps({"health_status": "recovered", "notification": notice}, sort_keys=True))
        else:
            print(json.dumps({"health_status": "ok", "summary": summary}, sort_keys=True))
        return 0

    failed_at = now_iso()
    # Repeated failures should stay visible in journald but should not spam
    # Telegram every timer cycle.
    previous_failures = int(state.get("consecutive_failures") or 0)
    consecutive_failures = previous_failures + 1 if state.get("status") == "failed" else 1
    already_notified = bool(state.get("failure_notification_sent"))
    state.update({
        "status": "failed",
        "last_failure": failed_at,
        "last_summary": summary,
        "last_returncode": result.returncode,
        "last_started_at": started_at,
        "consecutive_failures": consecutive_failures,
    })
    save_state(state)

    if consecutive_failures < FAILURE_NOTIFY_THRESHOLD:
        print(json.dumps({
            "health_status": "transient_failed",
            "consecutive_failures": consecutive_failures,
            "notify_after": FAILURE_NOTIFY_THRESHOLD,
            "summary": summary,
        }, sort_keys=True))
    elif already_notified:
        print(json.dumps({
            "health_status": "still_failed",
            "consecutive_failures": consecutive_failures,
            "summary": summary,
        }, sort_keys=True))
    else:
        notice = send_telegram(f"[FAILURE] {HOST_LABEL} failed at {failed_at}\n{summary}")
        state["failure_notification_sent"] = bool(notice.get("ok"))
        save_state(state)
        print(json.dumps({"health_status": "failed", "notification": notice}, sort_keys=True))
    return result.returncode or 1


if __name__ == "__main__":
    raise SystemExit(main())
