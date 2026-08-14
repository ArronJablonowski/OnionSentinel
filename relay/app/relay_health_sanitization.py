#!/usr/bin/env python3
"""Bounded Relay child-output sanitization and health-state projection."""
from __future__ import annotations

from relay_health_contract import *  # noqa: F401,F403

def sanitize_alert_summary(payload: object) -> dict | None:
    if not isinstance(payload, dict) or "alert_count" not in payload:
        return None
    summary = sanitize_counter_fields(payload, ALERT_COUNTER_FIELDS)
    return summary if "alert_count" in summary else None


def _prior_pcap_invalid_fields(payload: dict) -> list[str]:
    prior_invalid_fields = payload.get("invalid_fields")
    if not isinstance(prior_invalid_fields, list):
        return []
    valid_field_names = set(PCAP_BOOLEAN_FIELDS + PCAP_COUNTER_FIELDS)
    return [
        field for field in prior_invalid_fields
        if isinstance(field, str) and field in valid_field_names
    ]


def _sanitize_pcap_scalar_fields(payload: dict) -> tuple[dict, list[str]]:
    summary = {}
    invalid_fields = _prior_pcap_invalid_fields(payload)
    for field in PCAP_BOOLEAN_FIELDS:
        value = payload.get(field)
        if isinstance(value, bool):
            summary[field] = value
        elif field in payload:
            invalid_fields.append(field)
    summary.update(sanitize_counter_fields(payload, PCAP_COUNTER_FIELDS))
    invalid_fields.extend(
        field for field in PCAP_COUNTER_FIELDS
        if field in payload and field not in summary
    )
    return summary, invalid_fields


def _pcap_detail_projection(payload: dict) -> dict:
    details = {}
    outcomes = sanitize_outcomes(payload.get("outcomes"))
    if outcomes:
        details["outcomes"] = outcomes
    spool = sanitize_spool(payload.get("spool"))
    if spool:
        details["spool"] = spool
    if (
        payload.get("deferred") is True
        or isinstance(payload.get("capture_protection"), dict)
    ):
        details["capture_protection"] = sanitize_capture_protection(payload)
    return details


def sanitize_pcap_summary(payload: object) -> dict | None:
    if not isinstance(payload, dict) or "processed" not in payload:
        return None
    if "enabled" not in payload and "operational_failures" not in payload:
        return None
    summary, invalid_fields = _sanitize_pcap_scalar_fields(payload)
    summary.update(_pcap_detail_projection(payload))
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


def _sanitize_storage_section(raw_section: object) -> dict:
    if not isinstance(raw_section, dict):
        return {}
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
    return section


def _sanitize_smart_summary(raw_smart: object) -> dict:
    if not isinstance(raw_smart, dict):
        return {}
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
    return smart


def _storage_failure_categories(failures: object) -> list[str] | None:
    if not isinstance(failures, list):
        return None
    return sorted({storage_failure_category(item) for item in failures})


def sanitize_storage_summary(payload: object) -> dict | None:
    if not isinstance(payload, dict) or not isinstance(payload.get("ok"), bool):
        return None
    summary = {"ok": payload["ok"]}
    for section_name in ("root_storage", "storage"):
        section = _sanitize_storage_section(payload.get(section_name))
        if section:
            summary[section_name] = section
    smart = _sanitize_smart_summary(payload.get("smart"))
    if smart:
        summary["smart"] = smart
    failure_categories = _storage_failure_categories(payload.get("failures"))
    if failure_categories is not None:
        summary["failure_categories"] = failure_categories
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


def _child_fallback_diagnostic(
    component: str,
    summary: dict | None,
    summary_valid: bool,
    raw_stdout: str,
    returncode: int,
    fallback: str | None,
) -> str | None:
    if not summary_valid and (raw_stdout.strip() or returncode == 0):
        fallback = fallback or "invalid_output"
    if component == "pcap" and summary:
        fallback = pcap_outcome_diagnostic(summary) or fallback
    if returncode != 0:
        fallback = fallback or "child_failure"
    return fallback


def _child_diagnostic_values(
    raw_stderr: str,
    raw_stdout: str,
    returncode: int,
    summary_valid: bool,
) -> list[str]:
    values = [raw_stderr]
    if returncode != 0 or not summary_valid:
        values.append(raw_stdout)
    return values


def _safe_child_stderr(
    component: str,
    summary: dict | None,
    diagnostic: dict,
) -> str:
    if not diagnostic:
        return ""
    diagnostic_payload = dict(diagnostic)
    if component == "pcap" and summary:
        for field in ("operational_failures", "outcomes", "spool"):
            if field in summary:
                diagnostic_payload[field] = summary[field]
    return json.dumps(
        {"child_diagnostic": diagnostic_payload},
        sort_keys=True,
    ) + "\n"


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
    fallback_diagnostic = _child_fallback_diagnostic(
        component,
        summary,
        summary_valid,
        raw_stdout,
        returncode,
        fallback_diagnostic,
    )
    diagnostic_values = _child_diagnostic_values(
        raw_stderr,
        raw_stdout,
        returncode,
        summary_valid,
    )
    diagnostic = classify_child_diagnostic(
        *diagnostic_values,
        fallback=fallback_diagnostic,
    )
    safe_stdout = (
        json.dumps(summary, sort_keys=True) + "\n"
        if summary
        else ""
    )
    safe_stderr = _safe_child_stderr(component, summary, diagnostic)
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


def _base_health_state(raw: dict) -> dict:
    status = raw.get("status")
    return {
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


def _optional_health_timestamps(raw: dict, state: dict) -> None:
    for field in (
        "last_started_at",
        "last_pcap_unproven_at",
    ):
        timestamp = safe_timestamp(raw.get(field))
        if timestamp is not None:
            state[field] = timestamp


def _optional_health_summaries(raw: dict, state: dict) -> None:
    for field in ("last_summary", "last_pcap_unproven_summary"):
        if field in raw:
            state[field] = sanitize_persisted_summary(raw.get(field))


def _optional_health_returncode(raw: dict, state: dict) -> None:
    returncode = validated_int(
        raw.get("last_returncode"),
        minimum=-255,
        maximum=255,
    )
    if returncode is not None:
        state["last_returncode"] = returncode


def _health_http_status(raw: dict) -> int | None:
    http_status = validated_int(
        raw.get("last_http_status"),
        minimum=100,
        maximum=599,
    )
    if http_status is None:
        http_status = parse_http_status(
            diagnostic_scan_text(raw.get("last_summary"))
        )
    return http_status


def _optional_pcap_failure_state(raw: dict, state: dict) -> None:
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


def sanitize_health_state(value: object) -> dict:
    """Keep only typed suppression state and scrub legacy summaries."""
    raw = value if isinstance(value, dict) else {}
    state = _base_health_state(raw)
    _optional_health_timestamps(raw, state)
    _optional_health_summaries(raw, state)
    _optional_health_returncode(raw, state)
    http_status = _health_http_status(raw)
    if http_status is not None:
        state["last_http_status"] = http_status
    _optional_pcap_failure_state(raw, state)
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
