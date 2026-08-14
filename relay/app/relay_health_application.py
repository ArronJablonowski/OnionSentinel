#!/usr/bin/env python3
"""Relay component probes, recovery evaluation, and CLI composition."""
from __future__ import annotations

from relay_health_sanitization import *  # noqa: F401,F403

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


def _test_notification_exit() -> int | None:
    if len(sys.argv) > 1 and sys.argv[1] == "--test-notification":
        # Safe manual test path: does not pull Security Onion alerts.
        result = send_telegram(f"[RECOVERY TEST] {HOST_LABEL} notification path test at {now_iso()}")
        print(json.dumps({"notification": result}, sort_keys=True))
        return 0 if result.get("ok") else 1
    return None


def _parse_component() -> str:
    parser = argparse.ArgumentParser(description="Run and monitor an Onion Sentinel relay component")
    parser.add_argument("--component", choices=("all", "alert", "pcap", "storage"), default="all")
    args, _unknown = parser.parse_known_args()
    return args.component


def _run_alert_component() -> subprocess.CompletedProcess:
    token_error = validate_webhook_token_sources()
    if token_error:
        result = subprocess.CompletedProcess(RELAY_COMMAND, 1, "", token_error)
    else:
        try:
            result = run_relay()
        except Exception as exc:
            result = sanitized_exception_result(RELAY_COMMAND, "alert", exc)
    result = sanitized_child_result(result, "alert")
    print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)
    return result


def _run_pcap_component() -> subprocess.CompletedProcess:
    try:
        result = run_pcap_broker()
    except Exception as exc:
        result = sanitized_exception_result(RELAY_PCAP_COMMAND, "pcap", exc)
    result = sanitized_child_result(result, "pcap")
    print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)
    # Publish every broker cycle, including intentional capture-protection
    # holds. Delivery failure is observable in journald but must not turn a
    # healthy, locally enforced safety hold into a broker process failure.
    pcap_status = send_relay_health_event(build_pcap_status_event(result))
    print(json.dumps({"pcap_status_event": pcap_status}, sort_keys=True))
    return result


def _run_storage_component() -> subprocess.CompletedProcess:
    try:
        result = run_storage_health()
    except Exception as exc:
        result = sanitized_exception_result(RELAY_STORAGE_COMMAND, "storage", exc)
    result = sanitized_child_result(result, "storage")
    print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)
    return result


def _run_components(
    component: str,
) -> tuple[
    subprocess.CompletedProcess,
    subprocess.CompletedProcess,
    subprocess.CompletedProcess,
]:
    relay_result = subprocess.CompletedProcess(RELAY_COMMAND, 0, "", "")
    pcap_result = subprocess.CompletedProcess(RELAY_PCAP_COMMAND, 0, "", "")
    storage_result = subprocess.CompletedProcess(RELAY_STORAGE_COMMAND, 0, "", "")
    if component in {"all", "alert"}:
        relay_result = _run_alert_component()
    if component in {"all", "pcap"}:
        pcap_result = _run_pcap_component()
    if component == "storage":
        storage_result = _run_storage_component()
    return relay_result, pcap_result, storage_result


def _component_outcome(
    component: str,
    relay_result: subprocess.CompletedProcess,
    pcap_result: subprocess.CompletedProcess,
    storage_result: subprocess.CompletedProcess,
) -> tuple[subprocess.CompletedProcess, str]:
    result = storage_result if component == "storage" else combine_results(relay_result, pcap_result)
    component_label = component_summary(relay_result, pcap_result) if component == "all" else (
        f"alert_relay={'ok' if relay_result.returncode == 0 else f'failed({relay_result.returncode})'}"
        if component == "alert"
        else f"pcap_broker={'ok' if pcap_result.returncode == 0 else f'failed({pcap_result.returncode})'}"
        if component == "pcap"
        else f"storage_health={'ok' if storage_result.returncode == 0 else f'failed({storage_result.returncode})'}"
    )
    return result, f"{component_label}; {summarize_output(result.stdout, result.stderr)}"


def _prior_pcap_failure(state: dict, component: str) -> bool:
    return bool(
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


def _update_pcap_failure_latch(
    state: dict,
    component: str,
    pcap_result: subprocess.CompletedProcess,
    prior_pcap_failure: bool,
) -> None:
    if component in {"all", "pcap"}:
        if pcap_result.returncode != 0:
            state["pcap_failure_unresolved"] = True
        elif pcap_result_proves_broker_recovery(pcap_result):
            state["pcap_failure_unresolved"] = False
        elif prior_pcap_failure:
            state["pcap_failure_unresolved"] = True


def _persist_unproven_pcap_recovery(
    state: dict,
    component: str,
    state_path: Path,
    started_at: str,
    summary: str,
    pcap_result: subprocess.CompletedProcess,
    prior_pcap_failure: bool,
) -> bool:
    if not prior_pcap_failure or pcap_result_proves_broker_recovery(pcap_result):
        return False
    # A local read gate, disabled worker, lock skip, or malformed/no summary
    # does not exercise the Mac broker. Preserve the prior failure and latch.
    deferred_pcap_hold = pcap_result_is_capture_protection_hold(pcap_result)
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
    return True


def _previous_failure(state: dict) -> dict | None:
    return (
        {
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
        }
        if state.get("status") == "failed"
        else None
    )


def _complete_success(
    state: dict,
    component: str,
    state_path: Path,
    started_at: str,
    summary: str,
    result: subprocess.CompletedProcess,
    pcap_result: subprocess.CompletedProcess,
    prior_pcap_failure: bool,
) -> int:
    if _persist_unproven_pcap_recovery(
        state, component, state_path, started_at, summary,
        pcap_result, prior_pcap_failure,
    ):
        return 0
    previous_failure = _previous_failure(state)
    recovered = bool(previous_failure and state.get("failure_notification_sent"))
    state.update({
        "status": "ok", "last_success": now_iso(), "last_summary": summary,
        "last_returncode": result.returncode, "consecutive_failures": 0,
        "failure_notification_sent": False,
    })
    persist_component_state(state, component, state_path)
    if previous_failure:
        recovery_event = {
            "message_type": "relay_health_recovery", "source": "security-onion",
            "relay_host": HOST_LABEL, "generated_at": state["last_success"],
            "status": "recovered", "relay_previous_failure": previous_failure,
        }
        notice = send_relay_health_event(recovery_event)
        print(json.dumps({"health_event_status": notice}, sort_keys=True))
    if recovered:
        notice = send_telegram(f"[RECOVERY] {HOST_LABEL} {component} recovered at {state['last_success']}\n{summary}")
        print(json.dumps({"health_status": "recovered", "notification": notice}, sort_keys=True))
    else:
        print(json.dumps({"health_status": "ok", "summary": summary}, sort_keys=True))
    return 0


def _complete_failure(
    state: dict,
    component: str,
    state_path: Path,
    started_at: str,
    summary: str,
    result: subprocess.CompletedProcess,
) -> int:
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


def main() -> int:
    notification_exit = _test_notification_exit()
    if notification_exit is not None:
        return notification_exit
    component = _parse_component()
    state_path = component_state_path(component)
    state = sanitize_health_state(load_state(state_path))
    started_at = now_iso()
    relay_result, pcap_result, storage_result = _run_components(component)
    result, summary = _component_outcome(
        component, relay_result, pcap_result, storage_result
    )
    prior_pcap_failure = _prior_pcap_failure(state, component)
    _update_pcap_failure_latch(
        state, component, pcap_result, prior_pcap_failure
    )
    if result.returncode == 0:
        return _complete_success(
            state, component, state_path, started_at, summary, result,
            pcap_result, prior_pcap_failure,
        )
    return _complete_failure(
        state, component, state_path, started_at, summary, result
    )
