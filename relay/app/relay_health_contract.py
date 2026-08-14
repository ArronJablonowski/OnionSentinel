#!/usr/bin/env python3
"""Run the Pi relay and send Telegram health notifications.

systemd executes this wrapper, not relay.py directly. The wrapper records the
last health state so you get one Telegram message when the relay first fails and
one recovery message when it comes back, instead of a message every five minutes.
Transient failures are common enough on home lab networks that notification is
delayed until a configurable number of consecutive failures occurs.
"""
from __future__ import annotations

import json
import argparse
import math
import os
import re
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

MAX_COUNTER = 1_000_000_000
MAX_STORAGE_BYTES = 1 << 60
MAX_SUMMARY_LINE_CHARS = 64 * 1024
MAX_DIAGNOSTIC_SCAN_CHARS = 32 * 1024
PCAP_OUTCOME_CATEGORIES = frozenset({
    "captured",
    "checksum_failed",
    "expired",
    "failed",
    "no_packets_available",
    "oversize",
    "rejected",
    "timeout",
    "transport_failed",
})
CAPTURE_METRICS = frozenset({
    "suricata_packet_loss",
    "zeek_capture_loss",
    "zeek_packet_loss",
})
CAPTURE_REASON_CATEGORIES = frozenset({
    "capture_protection_hold",
    "capture_telemetry_healthy",
    "telemetry_stale",
    "telemetry_unavailable",
    "threshold_exceeded",
})
DIAGNOSTIC_CATEGORIES = frozenset({
    "checksum_failure",
    "child_failure",
    "configuration_error",
    "connection_refused",
    "connection_reset",
    "http_error",
    "invalid_output",
    "name_resolution_failure",
    "operational_failure",
    "service_unavailable",
    "storage_unavailable",
    "timeout",
    "transport_error",
})
PRIMARY_DIAGNOSTIC_PATTERNS = (
    ("connection_reset", r"\b(?:connection[_ ]reset|econnreset)\b"),
    ("connection_refused", r"\b(?:connection[_ ]refused|econnrefused)\b"),
    ("configuration_error", r"relay webhook token mismatch"),
    ("timeout", r"\b(?:timed[_ ]out|timeout|time-out)\b"),
)
SECONDARY_DIAGNOSTIC_PATTERNS = (
    (
        "name_resolution_failure",
        r"\b(?:name or service not known|temporary failure in name resolution|"
        r"nodename nor servname provided|dns failure)\b",
    ),
    ("checksum_failure", r"\b(?:checksum|sha256)\b"),
    (
        "storage_unavailable",
        r"\b(?:spool|filesystem|disk|mount)\b.*"
        r"\b(?:unavailable|not mounted|insufficient|full|exceeded)\b",
    ),
    (
        "transport_error",
        r"\b(?:rsync|ssh|socket|transport|artifact upload|connection)\b",
    ),
    ("service_unavailable", r"\b(?:unavailable|unreachable)\b"),
    (
        "invalid_output",
        r"\b(?:invalid[_ ]output|no valid final json summary|"
        r"emitted no valid final json summary)\b",
    ),
)
PCAP_BOOLEAN_FIELDS = (
    "ok",
    "enabled",
    "locked",
    "deferred",
    "broker_contacted",
)
PCAP_COUNTER_FIELDS = (
    "processed",
    "fulfilled",
    "failed",
    "completion_failed",
    "artifact_upload_failed",
    "artifact_cleanup_failed",
    "artifact_cleanup_succeeded",
    "relay_spool_cleanup_failed",
    "relay_spool_cleanup_succeeded",
    "retry_scheduled",
    "retry_exhausted",
    "retry_callback_failed",
    "operational_failures",
    "stale_spool_partials_removed",
    "stale_spool_artifacts_removed",
)
ALERT_COUNTER_FIELDS = (
    "alert_count",
    "dropped_alert_count",
    "filtered_alert_count",
    "new_alert_count",
    "duplicate_alert_count",
    "saved_new_alert_files",
    "posted_webhook_alerts",
    "queued_webhook_alerts",
    "outbox_pending_alerts",
    "outbox_dead_letter_alerts",
    "pruned_runtime_files",
)


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
    if not isinstance(text, str):
        return None
    patterns = (
        r"\bHTTP(?:\s+Error|\s+returned\s+HTTP)?\s*[:=]?\s*([1-5][0-9]{2})\b",
        r"""(?:["'])?\bhttp_status\b(?:["'])?\s*[:=]\s*([1-5][0-9]{2})\b""",
    )
    for pattern in patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if match:
            return int(match.group(1))
    return None


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


def validated_int(
    value: object,
    *,
    minimum: int = 0,
    maximum: int = MAX_COUNTER,
) -> int | None:
    """Return only exact, bounded integers (booleans and strings are rejected)."""
    if (
        isinstance(value, int)
        and not isinstance(value, bool)
        and minimum <= value <= maximum
    ):
        return value
    return None


def validated_number(
    value: object,
    *,
    minimum: float,
    maximum: float,
) -> int | float | None:
    """Return a finite bounded JSON number without accepting strings or booleans."""
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if minimum <= value <= maximum else None
    if not math.isfinite(value) or value < minimum or value > maximum:
        return None
    return value


def bounded_nonnegative_int(value: object) -> int:
    """Use zero for a malformed counter without propagating its representation."""
    validated = validated_int(value)
    return validated if validated is not None else 0


def strict_nonnegative_counter(value: object) -> bool:
    """Validate recovery-bearing counters without lossy type coercion."""
    return validated_int(value) is not None


def strict_absent_or_false(summary: dict, field: str) -> bool:
    """Reject truthy-looking or malformed optional state flags."""
    return field not in summary or summary.get(field) is False


def safe_returncode(value: object, *, default: int = 1) -> int:
    validated = validated_int(value, minimum=-255, maximum=255)
    return validated if validated is not None else default


def final_json_object(text: object) -> dict | None:
    """Parse only a child's final nonempty, reasonably bounded output line."""
    if not isinstance(text, str):
        return None
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines or len(lines[-1]) > MAX_SUMMARY_LINE_CHARS:
        return None
    try:
        candidate = json.loads(lines[-1])
    except (json.JSONDecodeError, TypeError, ValueError, RecursionError):
        return None
    return candidate if isinstance(candidate, dict) else None


def diagnostic_scan_text(*values: object) -> str:
    """Bound diagnostic classification work without returning any source text."""
    chunks = []
    remaining = MAX_DIAGNOSTIC_SCAN_CHARS
    for value in values:
        if remaining <= 0:
            break
        if not isinstance(value, str) or not value:
            continue
        if len(value) > remaining:
            head = min(2048, remaining // 4)
            chunk = value[:head] + value[-(remaining - head):]
        else:
            chunk = value
        chunks.append(chunk)
        remaining -= len(chunk)
    return "\n".join(chunks)


def _validated_child_diagnostic(value: object) -> dict | None:
    candidate = final_json_object(value)
    nested = (
        candidate.get("child_diagnostic")
        if isinstance(candidate, dict)
        else None
    )
    if not isinstance(nested, dict):
        return None
    category = nested.get("category")
    if not isinstance(category, str) or category not in DIAGNOSTIC_CATEGORIES:
        return None
    diagnostic = {"category": category}
    http_status = validated_int(
        nested.get("http_status"),
        minimum=100,
        maximum=599,
    )
    if http_status is not None:
        diagnostic["http_status"] = http_status
    return diagnostic


def _first_diagnostic_pattern_category(
    lowered: str,
    patterns: tuple[tuple[str, str], ...],
) -> str | None:
    for category, pattern in patterns:
        if re.search(pattern, lowered):
            return category
    return None


def _classified_diagnostic_category(
    lowered: str,
    http_status: int | None,
) -> str | None:
    category = _first_diagnostic_pattern_category(
        lowered,
        PRIMARY_DIAGNOSTIC_PATTERNS,
    )
    if category is not None:
        return category
    if http_status is not None:
        return "http_error"
    return _first_diagnostic_pattern_category(
        lowered,
        SECONDARY_DIAGNOSTIC_PATTERNS,
    )


def _diagnostic_projection(
    category: str | None,
    http_status: int | None,
) -> dict:
    diagnostic = {"category": category} if category else {}
    if http_status is not None:
        diagnostic["http_status"] = http_status
    return diagnostic


def classify_child_diagnostic(
    *values: object,
    fallback: str | None = None,
) -> dict:
    """Map untrusted diagnostics to a fixed category plus a validated HTTP code."""
    for value in values:
        diagnostic = _validated_child_diagnostic(value)
        if diagnostic is not None:
            return diagnostic

    text = diagnostic_scan_text(*values)
    lowered = text.lower()
    http_status = parse_http_status(text)
    category = _classified_diagnostic_category(lowered, http_status)
    if category is None and fallback in DIAGNOSTIC_CATEGORIES:
        category = fallback
    return _diagnostic_projection(category, http_status)


def sanitize_counter_fields(payload: dict, fields: tuple[str, ...]) -> dict:
    sanitized = {}
    for field in fields:
        value = validated_int(payload.get(field))
        if value is not None:
            sanitized[field] = value
    return sanitized


def sanitize_outcomes(value: object) -> dict:
    if not isinstance(value, dict):
        return {}
    outcomes = {}
    for category in sorted(PCAP_OUTCOME_CATEGORIES):
        count = validated_int(value.get(category))
        if count is not None:
            outcomes[category] = count
    return outcomes


def sanitize_spool(value: object) -> dict:
    if not isinstance(value, dict):
        return {}
    spool = {}
    if isinstance(value.get("available"), bool):
        spool["available"] = value["available"]
    for field in ("total_bytes", "used_bytes", "free_bytes"):
        number = validated_int(value.get(field), maximum=MAX_STORAGE_BYTES)
        if number is not None:
            spool[field] = number
    used_percent = validated_number(
        value.get("used_percent"),
        minimum=0.0,
        maximum=100.0,
    )
    if used_percent is not None:
        spool["used_percent"] = used_percent
    return spool


def capture_reason_category(summary: dict) -> str:
    if summary.get("deferred") is not True:
        return "capture_telemetry_healthy"
    protection = summary.get("capture_protection")
    protection = protection if isinstance(protection, dict) else {}
    existing = protection.get("reason_category")
    if (
        isinstance(existing, str)
        and existing in CAPTURE_REASON_CATEGORIES
    ):
        return existing
    reason = diagnostic_scan_text(
        summary.get("defer_reason"),
        protection.get("reason"),
    ).lower()
    if "unavailable" in reason:
        return "telemetry_unavailable"
    if "stale" in reason:
        return "telemetry_stale"
    observed = validated_number(
        protection.get("observed_percent"),
        minimum=0.0,
        maximum=100.0,
    )
    threshold = validated_number(
        protection.get("threshold_percent"),
        minimum=0.0,
        maximum=100.0,
    )
    if observed is not None and threshold is not None and observed > threshold:
        return "threshold_exceeded"
    return "capture_protection_hold"


def sanitize_capture_protection(summary: dict) -> dict:
    value = summary.get("capture_protection")
    value = value if isinstance(value, dict) else {}
    protection = {}
    if isinstance(value.get("deferred"), bool):
        protection["deferred"] = value["deferred"]
    metric = value.get("metric")
    protection["metric"] = (
        metric if isinstance(metric, str) and metric in CAPTURE_METRICS
        else "zeek_capture_loss"
    )
    protection["reason_category"] = capture_reason_category(summary)
    for source, destination in (
        ("observed_percent", "observed_percent"),
        ("threshold_percent", "threshold_percent"),
    ):
        number = validated_number(
            value.get(source),
            minimum=0.0,
            maximum=100.0,
        )
        if number is not None:
            protection[destination] = number
    age = validated_int(value.get("age_seconds"))
    if age is not None:
        protection["age_seconds"] = age
    return protection
