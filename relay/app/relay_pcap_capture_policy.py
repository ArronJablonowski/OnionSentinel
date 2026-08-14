#!/usr/bin/env python3
"""Relay-side admission policy protecting Security Onion live capture."""
from __future__ import annotations

from relay_core import PcapCaptureProtectionDeferred, run_ssh_pcap_export


__all__ = [
    "capture_protection_decision",
    "require_capture_safe",
    "security_onion_storage_status",
]


def security_onion_storage_status(config: dict) -> dict:
    """Read non-blocking `/nsm` telemetry through the restricted wrapper."""
    payload = run_ssh_pcap_export(config, {"mode": "storage_status"})
    if payload.get("status") != "storage_status":
        raise RuntimeError("Security Onion PCAP wrapper returned invalid storage status")
    return payload


def _capture_policy_settings(
    broker: dict,
    threshold_override: object | None,
) -> tuple[bool, float, float, int]:
    require_telemetry = bool(
        broker.get("capture_protection_require_telemetry", True)
    )
    configured_threshold = (
        broker.get("capture_loss_threshold_percent", 5.0)
        if threshold_override is None
        else threshold_override
    )
    try:
        threshold = float(configured_threshold)
    except (TypeError, ValueError):
        threshold = 5.0
    threshold = max(0.1, min(100.0, threshold))
    packet_loss_threshold = max(
        0.0,
        min(
            100.0,
            float(
                broker.get("sensor_packet_loss_threshold_percent", 0.1) or 0.1
            ),
        ),
    )
    freshness = max(
        60,
        min(
            3600,
            int(broker.get("capture_loss_freshness_seconds", 900) or 900),
        ),
    )
    return require_telemetry, threshold, packet_loss_threshold, freshness


def _unavailable_decision(require_telemetry: bool, threshold: float) -> dict:
    return {
        "deferred": require_telemetry,
        "reason": "Zeek capture-loss telemetry is unavailable",
        "threshold_percent": threshold,
    }


def _stale_decision(
    require_telemetry: bool,
    age: int,
    maximum: float,
    threshold: float,
) -> dict:
    return {
        "deferred": require_telemetry,
        "reason": f"Zeek capture-loss telemetry is stale ({age}s)",
        "observed_percent": maximum,
        "threshold_percent": threshold,
        "age_seconds": age,
    }


def _packet_loss_decision(
    status: dict,
    packet_loss_threshold: float,
    freshness: int,
) -> dict | None:
    for prefix, label in (("zeek", "Zeek"), ("suricata", "Suricata")):
        available = bool(status.get(f"{prefix}_packet_loss_available"))
        packet_age = max(
            0,
            int(status.get(f"{prefix}_packet_loss_age_seconds") or 0),
        )
        packet_loss = max(
            0.0,
            float(status.get(f"{prefix}_packet_loss_percent") or 0.0),
        )
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
    return None


def _capture_loss_decision(age: int, maximum: float, threshold: float) -> dict:
    if maximum > threshold:
        return {
            "deferred": True,
            "reason": (
                f"Zeek capture loss {maximum:.4f}% exceeds {threshold:.4f}%"
            ),
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


def capture_protection_decision(
    config: dict,
    status: dict | None,
    *,
    capture_loss_threshold_percent: object | None = None,
) -> dict:
    """Decide whether the relay may start another Security Onion PCAP read."""
    broker = config.get("pcap_broker", {})
    if not bool(broker.get("capture_protection_enabled", True)):
        return {"deferred": False, "reason": "disabled"}
    require_telemetry, threshold, packet_threshold, freshness = (
        _capture_policy_settings(broker, capture_loss_threshold_percent)
    )
    if not isinstance(status, dict) or not status.get(
        "zeek_capture_loss_available"
    ):
        return _unavailable_decision(require_telemetry, threshold)
    age = max(0, int(status.get("zeek_capture_loss_age_seconds") or 0))
    maximum = max(
        0.0,
        float(status.get("zeek_capture_loss_max_percent") or 0.0),
    )
    if age > freshness:
        return _stale_decision(require_telemetry, age, maximum, threshold)
    packet_decision = _packet_loss_decision(status, packet_threshold, freshness)
    if packet_decision is not None:
        return packet_decision
    return _capture_loss_decision(age, maximum, threshold)


def require_capture_safe(config: dict, status: dict | None = None) -> dict:
    """Raise a retryable deferral when live-capture telemetry is unhealthy."""
    current = (
        status
        if isinstance(status, dict)
        else security_onion_storage_status(config)
    )
    decision = capture_protection_decision(config, current)
    if decision.get("deferred"):
        raise PcapCaptureProtectionDeferred(
            str(decision.get("reason")),
            decision,
        )
    return current
