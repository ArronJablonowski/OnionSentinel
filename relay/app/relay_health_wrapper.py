#!/usr/bin/env python3
"""Run the Pi relay and send Telegram health notifications.

systemd executes this wrapper, not relay.py directly. The wrapper records the
last health state so you get one Telegram message when the relay first fails and
one recovery message when it comes back, instead of a message every five minutes.
Transient failures are common enough on home lab networks that notification is
delayed until a configurable number of consecutive failures occurs.
"""
import json
import argparse
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
    '/usr/bin/python3 /opt/so-alert-relay/app/relay.py --config /opt/so-alert-relay/app/config.json --pull-once --webhook-url "$RELAY_WEBHOOK_URL"',
)
RELAY_PCAP_COMMAND = os.environ.get(
    "RELAY_PCAP_COMMAND",
    '/usr/bin/python3 /opt/so-alert-relay/app/relay.py --config /opt/so-alert-relay/app/config.json --process-pcap-requests',
)
RELAY_STORAGE_COMMAND = os.environ.get(
    "RELAY_STORAGE_COMMAND",
    "/usr/bin/python3 /opt/so-alert-relay/app/storage_health.py",
)
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
HOST_LABEL = os.environ.get("RELAY_HOST_LABEL", "Raspberry Pi SOC relay")
RELAY_WEBHOOK_URL = os.environ.get("RELAY_WEBHOOK_URL", "").strip()
RELAY_WEBHOOK_TOKEN = os.environ.get("RELAY_WEBHOOK_TOKEN", "").strip()
RELAY_CONFIG_PATH = Path(os.environ.get("RELAY_CONFIG_PATH", "/opt/so-alert-relay/app/config.json"))


def env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except ValueError:
        return default


FAILURE_NOTIFY_THRESHOLD = max(1, env_int("RELAY_FAILURE_NOTIFY_THRESHOLD", 3))
RELAY_COMMAND_TIMEOUT_SECONDS = max(30, env_int("RELAY_COMMAND_TIMEOUT_SECONDS", 300))
# The broker can execute two independently bounded rsync legs (SO -> relay and
# relay -> Mac) plus export/checksum work. The outer watchdog must be longer
# than their combined budget or it will kill a healthy resumable transfer.
RELAY_PCAP_TIMEOUT_SECONDS = max(300, env_int("RELAY_PCAP_TIMEOUT_SECONDS", 3900))


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d  %H:%M:%SZ")


def component_state_path(component: str) -> Path:
    if component == "all":
        return STATE_PATH
    return STATE_PATH.with_name(f"{STATE_PATH.stem}-{component}{STATE_PATH.suffix}")


def load_state(path: Path = STATE_PATH) -> dict:
    # A missing/corrupt state file should never block alert polling.
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {
            "status": "unknown",
            "last_failure": None,
            "last_success": None,
            "consecutive_failures": 0,
            "failure_notification_sent": False,
        }


def save_state(state: dict, path: Path = STATE_PATH) -> None:
    # The state file is the suppression memory for repeated failures.
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def persist_component_state(state: dict, component: str, path: Path) -> None:
    # Preserve the original single-argument call contract for legacy tooling
    # and tests while split services use independent state files.
    if component == "all":
        save_state(state)
    else:
        save_state(state, path)


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


def parse_http_status(text: str) -> int | None:
    import re

    match = re.search(r"HTTP(?: Error| returned HTTP)?\s+([0-9]{3})", text or "")
    return int(match.group(1)) if match else None


def send_relay_health_event(event: dict) -> dict:
    if not RELAY_WEBHOOK_URL:
        return {"ok": False, "status": "disabled"}
    payload = json.dumps(event, sort_keys=True).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "so-alert-relay-health/0.1",
    }
    if RELAY_WEBHOOK_TOKEN:
        headers["X-Relay-Token"] = RELAY_WEBHOOK_TOKEN
    req = request.Request(RELAY_WEBHOOK_URL, data=payload, headers=headers, method="POST")
    try:
        with request.urlopen(req, timeout=10) as response:
            return {"ok": 200 <= response.status < 300, "status": response.status}
    except HTTPError as exc:
        return {"ok": False, "status": exc.code, "error": exc.reason}
    except URLError as exc:
        return {"ok": False, "status": "url_error", "error": str(exc.reason)}
    except Exception as exc:
        return {"ok": False, "status": "error", "error": str(exc)}


def config_webhook_token() -> str:
    try:
        config = json.loads(RELAY_CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception:
        return ""
    return str(config.get("webhook", {}).get("token") or "").strip()


def config_delivery_mode() -> str:
    try:
        config = json.loads(RELAY_CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception:
        return "http"
    ingest = config.get("alert_ingest", {})
    return str(ingest.get("mode") or config.get("webhook", {}).get("transport") or "http").strip().lower()


def validate_webhook_token_sources() -> str | None:
    """Catch config/env token drift before a quiet heartbeat is silently lost."""
    if config_delivery_mode() == "ssh_batch":
        # The dedicated forced-command SSH identity authenticates direct intake;
        # the legacy n8n webhook token is irrelevant on this transport.
        return None
    config_token = config_webhook_token()
    if not config_token or not RELAY_WEBHOOK_TOKEN:
        return None
    if config_token != RELAY_WEBHOOK_TOKEN:
        return "relay webhook token mismatch between config.json and relay.env"
    return None


def summarize_output(stdout: str, stderr: str) -> str:
    # relay.py prints a JSON summary as its final line. Pull out the operational
    # counters so health notices are short enough to read on a phone.
    details = []
    for line in reversed(stdout.splitlines()):
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                payload = json.loads(line)
                if "alert_count" not in payload:
                    continue
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


def run_shell_command(command: str, timeout: int = 120) -> subprocess.CompletedProcess:
    # shell=True is used here because the default command intentionally expands
    # environment variables from /etc/so-alert-relay/relay.env.
    return subprocess.run(
        command,
        shell=True,
        executable="/bin/bash",
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def run_relay() -> subprocess.CompletedProcess:
    return run_shell_command(RELAY_COMMAND, timeout=RELAY_COMMAND_TIMEOUT_SECONDS)


def run_pcap_broker() -> subprocess.CompletedProcess:
    result = run_shell_command(RELAY_PCAP_COMMAND, timeout=RELAY_PCAP_TIMEOUT_SECONDS)
    if result.returncode != 0:
        return result
    summary = None
    for line in reversed((result.stdout or "").splitlines()):
        try:
            candidate = json.loads(line)
        except Exception:
            continue
        if isinstance(candidate, dict) and "operational_failures" in candidate:
            summary = candidate
            break
    if summary and (not summary.get("ok", True) or int(summary.get("operational_failures") or 0) > 0):
        detail = json.dumps({
            "ok": summary.get("ok"),
            "operational_failures": summary.get("operational_failures"),
            "outcomes": summary.get("outcomes", {}),
            "spool": summary.get("spool", {}),
        }, sort_keys=True)
        # Keep the bounded root-cause event emitted by relay.py. Previously the
        # health wrapper replaced stderr with counters, making rsync/SSH failures
        # impossible to distinguish after the process exited.
        failure_detail = ""
        for line in reversed((result.stderr or "").splitlines()):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                failure_detail = line
                break
            if isinstance(event, dict) and event.get("error"):
                failure_detail = str(event["error"])
                break
        if failure_detail:
            detail = f"{detail}; root_cause={failure_detail[:500]}"
        return subprocess.CompletedProcess(result.args, 2, result.stdout, detail)
    return result


def run_storage_health() -> subprocess.CompletedProcess:
    return run_shell_command(RELAY_STORAGE_COMMAND, timeout=120)


def combine_results(primary: subprocess.CompletedProcess, secondary: subprocess.CompletedProcess) -> subprocess.CompletedProcess:
    returncode = primary.returncode or secondary.returncode
    return subprocess.CompletedProcess(
        primary.args,
        returncode,
        (primary.stdout or "") + (secondary.stdout or ""),
        (primary.stderr or "") + (secondary.stderr or ""),
    )


def component_summary(relay_result: subprocess.CompletedProcess, pcap_result: subprocess.CompletedProcess) -> str:
    """Summarize both relay paths so one failure does not obscure the other."""
    relay_status = "ok" if relay_result.returncode == 0 else f"failed({relay_result.returncode})"
    pcap_status = "ok" if pcap_result.returncode == 0 else f"failed({pcap_result.returncode})"
    return f"alert_relay={relay_status} pcap_broker={pcap_status}"


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "--test-notification":
        # Safe manual test path: does not pull Security Onion alerts.
        result = send_telegram(f"[RECOVERY TEST] {HOST_LABEL} notification path test at {now_iso()}")
        print(json.dumps({"notification": result}, sort_keys=True))
        return 0 if result.get("ok") else 1

    parser = argparse.ArgumentParser(description="Run and monitor an Onion Sentinel relay component")
    parser.add_argument("--component", choices=("all", "alert", "pcap", "storage"), default="all")
    args, _unknown = parser.parse_known_args()
    component = args.component
    state_path = component_state_path(component)
    state = load_state(state_path)
    started_at = now_iso()
    relay_result = subprocess.CompletedProcess(RELAY_COMMAND, 0, "", "")
    pcap_result = subprocess.CompletedProcess(RELAY_PCAP_COMMAND, 0, "", "")
    storage_result = subprocess.CompletedProcess(RELAY_STORAGE_COMMAND, 0, "", "")
    if component in {"all", "alert"}:
        token_error = validate_webhook_token_sources()
        if token_error:
            relay_result = subprocess.CompletedProcess(RELAY_COMMAND, 1, "", token_error)
        else:
            try:
                relay_result = run_relay()
            except Exception as exc:
                relay_result = subprocess.CompletedProcess(RELAY_COMMAND, 1, "", str(exc))
        print(relay_result.stdout, end="")
        if relay_result.stderr:
            print(relay_result.stderr, end="", file=sys.stderr)

    if component in {"all", "pcap"}:
        try:
            pcap_result = run_pcap_broker()
        except Exception as exc:
            pcap_result = subprocess.CompletedProcess(RELAY_PCAP_COMMAND, 1, "", str(exc))
        print(pcap_result.stdout, end="")
        if pcap_result.stderr:
            print(pcap_result.stderr, end="", file=sys.stderr)

    if component == "storage":
        try:
            storage_result = run_storage_health()
        except Exception as exc:
            storage_result = subprocess.CompletedProcess(RELAY_STORAGE_COMMAND, 1, "", str(exc))
        print(storage_result.stdout, end="")
        if storage_result.stderr:
            print(storage_result.stderr, end="", file=sys.stderr)

    result = storage_result if component == "storage" else combine_results(relay_result, pcap_result)
    component_label = component_summary(relay_result, pcap_result) if component == "all" else (
        f"alert_relay={'ok' if relay_result.returncode == 0 else f'failed({relay_result.returncode})'}"
        if component == "alert"
        else f"pcap_broker={'ok' if pcap_result.returncode == 0 else f'failed({pcap_result.returncode})'}"
        if component == "pcap"
        else f"storage_health={'ok' if storage_result.returncode == 0 else f'failed({storage_result.returncode})'}"
    )
    summary = f"{component_label}; {summarize_output(result.stdout, result.stderr)}"

    if result.returncode == 0:
        # If the previous run failed, this successful run is recovery-worthy.
        previous_failure = {
            "failed_at": state.get("last_failure"),
            "summary": state.get("last_summary"),
            "returncode": state.get("last_returncode"),
            "consecutive_failures": int(state.get("consecutive_failures") or 0),
            "http_status": state.get("last_http_status") or parse_http_status(str(state.get("last_summary") or "")),
        } if state.get("status") == "failed" else None
        recovered = bool(previous_failure and state.get("failure_notification_sent"))
        state.update({
            "status": "ok",
            "last_success": now_iso(),
            "last_summary": summary,
            "last_returncode": result.returncode,
            "consecutive_failures": 0,
            "failure_notification_sent": False,
        })
        persist_component_state(state, component, state_path)
        if previous_failure:
            recovery_event = {
                "message_type": "relay_health_recovery",
                "source": "security-onion",
                "relay_host": HOST_LABEL,
                "generated_at": state["last_success"],
                "status": "recovered",
                "relay_previous_failure": previous_failure,
            }
            notice = send_relay_health_event(recovery_event)
            print(json.dumps({"health_event_status": notice}, sort_keys=True))
        if recovered:
            notice = send_telegram(f"[RECOVERY] {HOST_LABEL} {component} recovered at {state['last_success']}\n{summary}")
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
        "last_http_status": parse_http_status(summary + "\n" + result.stderr),
    })
    persist_component_state(state, component, state_path)

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
        notice = send_telegram(f"[FAILURE] {HOST_LABEL} {component} failed at {failed_at}\n{summary}")
        state["failure_notification_sent"] = bool(notice.get("ok"))
        persist_component_state(state, component, state_path)
        print(json.dumps({"health_status": "failed", "notification": notice}, sort_keys=True))
    return result.returncode or 1


if __name__ == "__main__":
    raise SystemExit(main())
