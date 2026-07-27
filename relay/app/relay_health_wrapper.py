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


def classify_child_diagnostic(
    *values: object,
    fallback: str | None = None,
) -> dict:
    """Map untrusted diagnostics to a fixed category plus a validated HTTP code."""
    for value in values:
        candidate = final_json_object(value)
        nested = (
            candidate.get("child_diagnostic")
            if isinstance(candidate, dict)
            else None
        )
        if not isinstance(nested, dict):
            continue
        category = nested.get("category")
        if (
            not isinstance(category, str)
            or category not in DIAGNOSTIC_CATEGORIES
        ):
            continue
        diagnostic = {"category": category}
        http_status = validated_int(
            nested.get("http_status"),
            minimum=100,
            maximum=599,
        )
        if http_status is not None:
            diagnostic["http_status"] = http_status
        return diagnostic

    text = diagnostic_scan_text(*values)
    lowered = text.lower()
    http_status = parse_http_status(text)
    category = None
    if re.search(r"\b(?:connection[_ ]reset|econnreset)\b", lowered):
        category = "connection_reset"
    elif re.search(r"\b(?:connection[_ ]refused|econnrefused)\b", lowered):
        category = "connection_refused"
    elif "relay webhook token mismatch" in lowered:
        category = "configuration_error"
    elif re.search(r"\b(?:timed[_ ]out|timeout|time-out)\b", lowered):
        category = "timeout"
    elif http_status is not None:
        category = "http_error"
    elif re.search(
        r"\b(?:name or service not known|temporary failure in name resolution|"
        r"nodename nor servname provided|dns failure)\b",
        lowered,
    ):
        category = "name_resolution_failure"
    elif re.search(r"\b(?:checksum|sha256)\b", lowered):
        category = "checksum_failure"
    elif re.search(
        r"\b(?:spool|filesystem|disk|mount)\b.*"
        r"\b(?:unavailable|not mounted|insufficient|full|exceeded)\b",
        lowered,
    ):
        category = "storage_unavailable"
    elif re.search(
        r"\b(?:rsync|ssh|socket|transport|artifact upload|connection)\b",
        lowered,
    ):
        category = "transport_error"
    elif re.search(r"\b(?:unavailable|unreachable)\b", lowered):
        category = "service_unavailable"
    elif re.search(
        r"\b(?:invalid[_ ]output|no valid final json summary|"
        r"emitted no valid final json summary)\b",
        lowered,
    ):
        category = "invalid_output"

    if category is None and fallback in DIAGNOSTIC_CATEGORIES:
        category = fallback
    diagnostic = {"category": category} if category else {}
    if http_status is not None:
        diagnostic["http_status"] = http_status
    return diagnostic


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


def sanitize_alert_summary(payload: object) -> dict | None:
    if not isinstance(payload, dict) or "alert_count" not in payload:
        return None
    summary = sanitize_counter_fields(payload, ALERT_COUNTER_FIELDS)
    return summary if "alert_count" in summary else None


def sanitize_pcap_summary(payload: object) -> dict | None:
    if not isinstance(payload, dict) or "processed" not in payload:
        return None
    if "enabled" not in payload and "operational_failures" not in payload:
        return None
    summary = {}
    invalid_fields = []
    prior_invalid_fields = payload.get("invalid_fields")
    if isinstance(prior_invalid_fields, list):
        valid_field_names = set(PCAP_BOOLEAN_FIELDS + PCAP_COUNTER_FIELDS)
        invalid_fields.extend(
            field for field in prior_invalid_fields
            if isinstance(field, str) and field in valid_field_names
        )
    for field in PCAP_BOOLEAN_FIELDS:
        value = payload.get(field)
        if isinstance(value, bool):
            summary[field] = value
        elif field in payload:
            invalid_fields.append(field)
    summary.update(sanitize_counter_fields(payload, PCAP_COUNTER_FIELDS))
    for field in PCAP_COUNTER_FIELDS:
        if field in payload and field not in summary:
            invalid_fields.append(field)
    outcomes = sanitize_outcomes(payload.get("outcomes"))
    if outcomes:
        summary["outcomes"] = outcomes
    spool = sanitize_spool(payload.get("spool"))
    if spool:
        summary["spool"] = spool
    if (
        payload.get("deferred") is True
        or isinstance(payload.get("capture_protection"), dict)
    ):
        summary["capture_protection"] = sanitize_capture_protection(payload)
    if invalid_fields:
        summary["invalid_fields"] = sorted(set(invalid_fields))
    return summary


def storage_failure_category(value: object) -> str:
    text = diagnostic_scan_text(value).lower()
    categories = (
        ("root_capacity", ("root free space", "root usage")),
        ("mount_unavailable", ("mount is unavailable", "sd card", "unknown source")),
        ("storage_capacity", ("ssd free space", "ssd usage")),
        ("smart_query", ("smart query", "invalid json")),
        ("smart_health", ("smart overall", "critical warning", "media errors")),
        ("unsafe_shutdowns", ("unsafe shutdown",)),
        ("temperature", ("temperature",)),
    )
    for category, markers in categories:
        if any(marker in text for marker in markers):
            return category
    return "health_check_failed"


def sanitize_storage_summary(payload: object) -> dict | None:
    if not isinstance(payload, dict) or not isinstance(payload.get("ok"), bool):
        return None
    summary = {"ok": payload["ok"]}
    for section_name in ("root_storage", "storage"):
        raw_section = payload.get(section_name)
        if not isinstance(raw_section, dict):
            continue
        section = {}
        for field in ("total_bytes", "used_bytes", "free_bytes"):
            number = validated_int(
                raw_section.get(field),
                maximum=MAX_STORAGE_BYTES,
            )
            if number is not None:
                section[field] = number
        for field in ("used_percent", "warning_percent", "hard_percent"):
            number = validated_number(
                raw_section.get(field),
                minimum=0.0,
                maximum=100.0,
            )
            if number is not None:
                section[field] = number
        if section:
            summary[section_name] = section
    raw_smart = payload.get("smart")
    if isinstance(raw_smart, dict):
        smart = {}
        if isinstance(raw_smart.get("passed"), bool):
            smart["passed"] = raw_smart["passed"]
        temperature = validated_number(
            raw_smart.get("temperature_c"),
            minimum=-100.0,
            maximum=200.0,
        )
        if temperature is not None:
            smart["temperature_c"] = temperature
        for field in ("critical_warning", "media_errors", "unsafe_shutdowns"):
            number = validated_int(raw_smart.get(field))
            if number is not None:
                smart[field] = number
        if smart:
            summary["smart"] = smart
    failures = payload.get("failures")
    if isinstance(failures, list):
        summary["failure_categories"] = sorted({
            storage_failure_category(item) for item in failures
        })
    return summary


def component_payload(component: str, stdout: object) -> tuple[dict | None, bool]:
    payload = final_json_object(stdout)
    if component == "alert":
        sanitized = sanitize_alert_summary(payload)
    elif component == "pcap":
        sanitized = sanitize_pcap_summary(payload)
    elif component == "storage":
        sanitized = sanitize_storage_summary(payload)
    else:
        sanitized = None
    return sanitized, payload is not None and sanitized is not None


def pcap_outcome_diagnostic(summary: dict) -> str | None:
    outcomes = summary.get("outcomes")
    outcomes = outcomes if isinstance(outcomes, dict) else {}
    if bounded_nonnegative_int(outcomes.get("timeout")):
        return "timeout"
    if bounded_nonnegative_int(outcomes.get("checksum_failed")):
        return "checksum_failure"
    if bounded_nonnegative_int(outcomes.get("transport_failed")):
        return "transport_error"
    spool = summary.get("spool")
    if isinstance(spool, dict) and spool.get("available") is False:
        return "storage_unavailable"
    return None


def sanitized_child_result(
    result: subprocess.CompletedProcess,
    component: str,
    *,
    forced_returncode: int | None = None,
    fallback_diagnostic: str | None = None,
) -> subprocess.CompletedProcess:
    """Drop raw child streams and retain only allowlisted structured fields."""
    raw_stdout = result.stdout if isinstance(result.stdout, str) else ""
    raw_stderr = result.stderr if isinstance(result.stderr, str) else ""
    summary, summary_valid = component_payload(component, raw_stdout)
    returncode = safe_returncode(
        forced_returncode
        if forced_returncode is not None
        else result.returncode,
    )
    if not summary_valid and (raw_stdout.strip() or returncode == 0):
        fallback_diagnostic = fallback_diagnostic or "invalid_output"
    if component == "pcap" and summary:
        fallback_diagnostic = (
            pcap_outcome_diagnostic(summary)
            or fallback_diagnostic
        )
    if returncode != 0:
        fallback_diagnostic = fallback_diagnostic or "child_failure"
    diagnostic_values = [raw_stderr]
    if returncode != 0 or not summary_valid:
        diagnostic_values.append(raw_stdout)
    diagnostic = classify_child_diagnostic(
        *diagnostic_values,
        fallback=fallback_diagnostic,
    )
    safe_stdout = (
        json.dumps(summary, sort_keys=True) + "\n"
        if summary
        else ""
    )
    safe_stderr = ""
    if diagnostic:
        diagnostic_payload = dict(diagnostic)
        if component == "pcap" and summary:
            for field in ("operational_failures", "outcomes", "spool"):
                if field in summary:
                    diagnostic_payload[field] = summary[field]
        safe_stderr = json.dumps(
            {"child_diagnostic": diagnostic_payload},
            sort_keys=True,
        ) + "\n"
    return subprocess.CompletedProcess(
        result.args,
        returncode,
        safe_stdout,
        safe_stderr,
    )


def sanitized_exception_result(
    command: str,
    _component: str,
    exc: BaseException,
) -> subprocess.CompletedProcess:
    values = (
        getattr(exc, "stderr", None),
        getattr(exc, "stdout", None),
        getattr(exc, "output", None),
        str(exc),
    )
    fallback = "timeout" if isinstance(exc, subprocess.TimeoutExpired) else "child_failure"
    diagnostic = classify_child_diagnostic(*values, fallback=fallback)
    return subprocess.CompletedProcess(
        command,
        1,
        "",
        json.dumps(
            {"child_diagnostic": diagnostic},
            sort_keys=True,
        ) + "\n",
    )


def sanitize_persisted_summary(value: object) -> str:
    """Normalize legacy state before it can be replayed in a recovery notice."""
    text = diagnostic_scan_text(value)
    statuses = []
    for label in ("alert_relay", "pcap_broker", "storage_health"):
        match = re.search(
            rf"(?<![A-Za-z0-9_]){label}="
            rf"(ok|failed\((-?[0-9]{{1,3}})\))"
            rf"(?![A-Za-z0-9_])",
            text,
        )
        if not match:
            continue
        if match.group(1) == "ok":
            statuses.append(f"{label}=ok")
        else:
            returncode = safe_returncode(int(match.group(2)))
            statuses.append(f"{label}=failed({returncode})")
    diagnostic = classify_child_diagnostic(text)
    parts = [" ".join(statuses) if statuses else "component_status=unknown"]
    if diagnostic.get("category"):
        parts.append(f"diagnostic={diagnostic['category']}")
    if diagnostic.get("http_status") is not None:
        parts.append(f"http_status={diagnostic['http_status']}")
    return "; ".join(parts)


def safe_timestamp(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}  [0-9]{2}:[0-9]{2}:[0-9]{2}Z", value):
        return value
    return None


def sanitize_health_state(value: object) -> dict:
    """Keep only typed suppression state and scrub summaries from older releases."""
    raw = value if isinstance(value, dict) else {}
    status = raw.get("status")
    state = {
        "status": (
            status
            if isinstance(status, str)
            and status in {"unknown", "ok", "failed"}
            else "unknown"
        ),
        "last_failure": safe_timestamp(raw.get("last_failure")),
        "last_success": safe_timestamp(raw.get("last_success")),
        "consecutive_failures": bounded_nonnegative_int(
            raw.get("consecutive_failures")
        ),
        "failure_notification_sent": raw.get("failure_notification_sent") is True,
    }
    for field in (
        "last_started_at",
        "last_pcap_unproven_at",
    ):
        timestamp = safe_timestamp(raw.get(field))
        if timestamp is not None:
            state[field] = timestamp
    for field in ("last_summary", "last_pcap_unproven_summary"):
        if field in raw:
            state[field] = sanitize_persisted_summary(raw.get(field))
    returncode = validated_int(
        raw.get("last_returncode"),
        minimum=-255,
        maximum=255,
    )
    if returncode is not None:
        state["last_returncode"] = returncode
    http_status = validated_int(
        raw.get("last_http_status"),
        minimum=100,
        maximum=599,
    )
    if http_status is None:
        http_status = parse_http_status(
            diagnostic_scan_text(raw.get("last_summary"))
        )
    if http_status is not None:
        state["last_http_status"] = http_status
    if isinstance(raw.get("pcap_failure_unresolved"), bool):
        state["pcap_failure_unresolved"] = raw["pcap_failure_unresolved"]
    unproven_reason = raw.get("last_pcap_unproven_reason")
    if (
        isinstance(unproven_reason, str)
        and unproven_reason in {
            "broker_contact_not_proven",
            "capture_protection_hold",
        }
    ):
        state["last_pcap_unproven_reason"] = unproven_reason
    return state


def summarize_output(stdout: str, stderr: str) -> str:
    # All text in this result is locally generated. Child strings are used only
    # to select an allowlisted diagnostic category.
    details = []
    payload = final_json_object(stdout)
    alert = sanitize_alert_summary(payload)
    pcap = sanitize_pcap_summary(payload)
    storage = sanitize_storage_summary(payload)
    if alert:
        details.append(
            "alerts={alert_count} dropped={dropped_alert_count} "
            "new={new_alert_count} posted={posted_webhook_alerts}".format(
                alert_count=alert.get("alert_count", 0),
                dropped_alert_count=alert.get("dropped_alert_count", 0),
                new_alert_count=alert.get("new_alert_count", 0),
                posted_webhook_alerts=alert.get("posted_webhook_alerts", 0),
            )
        )
    elif pcap:
        details.append(
            "processed={processed} fulfilled={fulfilled} failed={failed} "
            "operational_failures={operational_failures} deferred={deferred} "
            "broker_contacted={broker_contacted}".format(
                processed=pcap.get("processed", 0),
                fulfilled=pcap.get("fulfilled", 0),
                failed=pcap.get("failed", 0),
                operational_failures=pcap.get("operational_failures", 0),
                deferred=str(pcap.get("deferred") is True).lower(),
                broker_contacted=str(
                    pcap.get("broker_contacted") is True
                ).lower(),
            )
        )
    elif storage:
        categories = storage.get("failure_categories") or []
        storage_detail = f"storage_ok={str(storage['ok']).lower()}"
        if categories:
            storage_detail += " failures=" + ",".join(categories)
        details.append(storage_detail)

    diagnostic = classify_child_diagnostic(stderr, stdout)
    if diagnostic.get("category"):
        detail = f"diagnostic={diagnostic['category']}"
        if diagnostic.get("http_status") is not None:
            detail += f" http_status={diagnostic['http_status']}"
        details.append(detail)
    return "; ".join(details) or "no_validated_child_summary"


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


def parse_pcap_summary(stdout: str) -> dict | None:
    """Return the broker's final shape-valid JSON summary, if one was emitted."""
    candidate = final_json_object(stdout)
    if candidate is None:
        return None
    if "processed" not in candidate or (
        "enabled" not in candidate
        and "operational_failures" not in candidate
    ):
        return None
    return candidate


def build_pcap_status_event(result: subprocess.CompletedProcess) -> dict:
    """Build safe relay telemetry that distinguishes a hold from a failure.

    Capture-loss protection intentionally returns success because the broker is
    healthy and refusing optional evidence work to protect Security Onion. The
    Mac needs this explicit state to avoid interpreting the quiet queue as a
    crashed worker. Only bounded counters and capture telemetry are published;
    command lines, credentials, paths, and raw stderr are never included.
    """
    raw_summary = parse_pcap_summary(
        result.stdout if isinstance(result.stdout, str) else ""
    ) or {}
    summary = sanitize_pcap_summary(raw_summary) or {}
    protection = summary.get("capture_protection")
    protection = protection if isinstance(protection, dict) else {}
    deferred = raw_summary.get("deferred") is True
    counters_valid = (
        strict_nonnegative_counter(raw_summary.get("processed"))
        and strict_nonnegative_counter(
            raw_summary.get("operational_failures")
        )
    )
    operational_failures = bounded_nonnegative_int(
        raw_summary.get("operational_failures")
    )
    returncode = safe_returncode(result.returncode)
    state = (
        "operational_failure"
        if returncode or operational_failures or not counters_valid
        else "capture_protection_hold"
        if deferred
        else "healthy"
    )
    workflow = {
        "state": state,
        "deferred": deferred,
        "reason": protection.get(
            "reason_category",
            capture_reason_category(raw_summary),
        ),
        "metric": protection.get("metric", "zeek_capture_loss"),
        "observed_percent": protection.get("observed_percent"),
        "threshold_percent": protection.get("threshold_percent"),
        "telemetry_age_seconds": protection.get("age_seconds"),
        "processed": bounded_nonnegative_int(summary.get("processed")),
        "operational_failures": operational_failures or (1 if returncode else 0),
        "broker_contacted": summary.get("broker_contacted") is True,
    }
    return {
        "message_type": "relay_heartbeat",
        "component": "pcap_broker",
        "source": "security-onion",
        "relay_host": HOST_LABEL,
        "generated_at": now_iso(),
        "pcap_workflow": workflow,
    }


def run_pcap_broker() -> subprocess.CompletedProcess:
    result = run_shell_command(
        RELAY_PCAP_COMMAND,
        timeout=RELAY_PCAP_TIMEOUT_SECONDS,
    )
    returncode = safe_returncode(result.returncode)
    if returncode != 0:
        return sanitized_child_result(
            result,
            "pcap",
            forced_returncode=returncode,
            fallback_diagnostic="child_failure",
        )
    summary = parse_pcap_summary(
        result.stdout if isinstance(result.stdout, str) else ""
    )
    if summary is None:
        return sanitized_child_result(
            result,
            "pcap",
            forced_returncode=2,
            fallback_diagnostic="invalid_output",
        )
    counters_valid = (
        strict_nonnegative_counter(summary.get("processed"))
        and strict_nonnegative_counter(
            summary.get("operational_failures")
        )
    )
    if (
        summary.get("ok") is not True
        or not counters_valid
        or summary.get("operational_failures") > 0
    ):
        safe_summary = sanitize_pcap_summary(summary) or {}
        fallback = (
            pcap_outcome_diagnostic(safe_summary)
            or "operational_failure"
        )
        return sanitized_child_result(
            result,
            "pcap",
            forced_returncode=2,
            fallback_diagnostic=fallback,
        )
    return sanitized_child_result(result, "pcap", forced_returncode=0)


def pcap_result_is_capture_protection_hold(result: subprocess.CompletedProcess) -> bool:
    """Return true when PCAP work was safely deferred before broker contact.

    A capture-protection hold proves that the relay enforced its Security Onion
    read gate; it does not prove that a previously unavailable Mac broker has
    recovered.  Keeping that distinction prevents a hold from clearing the
    failure-notification latch and causing repeated recovery/failure messages.
    """
    if result.returncode != 0:
        return False
    summary = parse_pcap_summary(result.stdout)
    return bool(
        summary
        and summary.get("deferred") is True
        and isinstance(summary.get("capture_protection"), dict)
        and summary["capture_protection"].get("deferred") is True
    )


def pcap_result_proves_broker_recovery(
    result: subprocess.CompletedProcess,
) -> bool:
    """Require a successful HTTP broker exchange before clearing a failure."""
    if result.returncode != 0:
        return False
    summary = parse_pcap_summary(result.stdout)
    if not summary:
        return False
    invalid_fields = summary.get("invalid_fields")
    if isinstance(invalid_fields, list) and invalid_fields:
        return False
    return bool(
        summary.get("ok") is True
        and summary.get("enabled") is True
        and summary.get("broker_contacted") is True
        and strict_absent_or_false(summary, "deferred")
        and strict_absent_or_false(summary, "locked")
        and strict_nonnegative_counter(summary.get("processed"))
        and strict_nonnegative_counter(
            summary.get("operational_failures")
        )
        and summary.get("operational_failures") == 0
    )


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
    state = sanitize_health_state(load_state(state_path))
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
                relay_result = sanitized_exception_result(
                    RELAY_COMMAND,
                    "alert",
                    exc,
                )
        relay_result = sanitized_child_result(relay_result, "alert")
        print(relay_result.stdout, end="")
        if relay_result.stderr:
            print(relay_result.stderr, end="", file=sys.stderr)

    if component in {"all", "pcap"}:
        try:
            pcap_result = run_pcap_broker()
        except Exception as exc:
            pcap_result = sanitized_exception_result(
                RELAY_PCAP_COMMAND,
                "pcap",
                exc,
            )
        pcap_result = sanitized_child_result(pcap_result, "pcap")
        print(pcap_result.stdout, end="")
        if pcap_result.stderr:
            print(pcap_result.stderr, end="", file=sys.stderr)
        # Publish every broker cycle, including intentional capture-protection
        # holds. Delivery failure is observable in journald but must not turn a
        # healthy, locally enforced safety hold into a broker process failure.
        pcap_status = send_relay_health_event(build_pcap_status_event(pcap_result))
        print(json.dumps({"pcap_status_event": pcap_status}, sort_keys=True))

    if component == "storage":
        try:
            storage_result = run_storage_health()
        except Exception as exc:
            storage_result = sanitized_exception_result(
                RELAY_STORAGE_COMMAND,
                "storage",
                exc,
            )
        storage_result = sanitized_child_result(storage_result, "storage")
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
    prior_pcap_failure = bool(
        state.get("status") == "failed"
        and (
            component == "pcap"
            or (
                component == "all"
                and (
                    state.get("pcap_failure_unresolved") is True
                    or "pcap_broker=failed(" in str(
                        state.get("last_summary") or ""
                    )
                )
            )
        )
    )
    if component in {"all", "pcap"}:
        if pcap_result.returncode != 0:
            state["pcap_failure_unresolved"] = True
        elif pcap_result_proves_broker_recovery(pcap_result):
            state["pcap_failure_unresolved"] = False
        elif prior_pcap_failure:
            state["pcap_failure_unresolved"] = True

    if result.returncode == 0:
        if (
            prior_pcap_failure
            and not pcap_result_proves_broker_recovery(pcap_result)
        ):
            # A local read gate, disabled worker, lock skip, or malformed/no
            # summary does not exercise the Mac broker. Preserve the prior
            # failure and notification latch until a normal poll proves
            # end-to-end recovery.
            deferred_pcap_hold = pcap_result_is_capture_protection_hold(
                pcap_result
            )
            state.update({
                "last_started_at": started_at,
                "last_pcap_unproven_at": now_iso(),
                "last_pcap_unproven_summary": summary,
                "last_pcap_unproven_reason": (
                    "capture_protection_hold"
                    if deferred_pcap_hold
                    else "broker_contact_not_proven"
                ),
            })
            persist_component_state(state, component, state_path)
            print(json.dumps({
                "health_status": "pcap_recovery_unproven",
                "consecutive_failures": int(state.get("consecutive_failures") or 0),
                "reason": state["last_pcap_unproven_reason"],
                "summary": summary,
            }, sort_keys=True))
            return 0

        # If the previous run failed, this successful run is recovery-worthy.
        previous_failure = {
            "failed_at": safe_timestamp(state.get("last_failure")),
            "summary": sanitize_persisted_summary(
                state.get("last_summary")
            ),
            "returncode": validated_int(
                state.get("last_returncode"),
                minimum=-255,
                maximum=255,
            ),
            "consecutive_failures": bounded_nonnegative_int(
                state.get("consecutive_failures")
            ),
            "http_status": validated_int(
                state.get("last_http_status"),
                minimum=100,
                maximum=599,
            ),
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
    previous_failures = bounded_nonnegative_int(
        state.get("consecutive_failures")
    )
    consecutive_failures = (
        min(MAX_COUNTER, previous_failures + 1)
        if state.get("status") == "failed"
        else 1
    )
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
