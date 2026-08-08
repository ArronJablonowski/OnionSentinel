"""Bounded Asset Inventory review and mutation application service."""
from __future__ import annotations

import datetime as dt
import ipaddress
import re
from typing import Callable


TimestampParser = Callable[[object], dt.datetime]
Normalizer = Callable[[object], dict]
MutationWriter = Callable[[str, dict], dict]

REVIEW_COMMON_FIELDS = {
    "discovery_id", "expected_ip", "expected_mac", "expected_hostname",
    "asset_id", "operator_ref", "reason", "confirm",
}
REVIEW_PROMOTION_FIELDS = {
    "hostname", "role", "platform", "criticality", "owner_ref",
    "accept_locally_administered_mac",
}
REVIEW_LIMITS = {
    "discovery_id": 20, "expected_ip": 64, "expected_mac": 17,
    "expected_hostname": 253, "asset_id": 160, "operator_ref": 160,
    "reason": 1000, "confirm": 256, "hostname": 253, "role": 160,
    "platform": 160, "criticality": 16, "owner_ref": 300,
}
MUTATION_COMMON_FIELDS = {
    "asset_id", "expected_valid_from", "operator_ref", "reason", "confirm",
}
MUTATION_EDIT_FIELDS = {
    "ip_addresses", "mac_addresses", "hostnames", "role", "platform",
    "criticality", "confidence",
}
MUTATION_LIMITS = {
    "asset_id": 160, "expected_valid_from": 64, "operator_ref": 160,
    "reason": 1000, "confirm": 256, "role": 160, "platform": 160,
    "criticality": 16, "confidence": 16,
}
CRITICALITIES = {"low", "medium", "high", "critical", "unknown"}
CONFIDENCES = {"low", "medium", "high", "unknown"}
MAC_PATTERN = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}")


def _bounded_strings(
    payload: dict,
    allowed: set[str],
    limits: dict[str, int],
) -> dict:
    result = {
        key: str(payload.get(key) or "").strip()[: maximum + 1]
        for key, maximum in limits.items()
        if key in allowed
    }
    for key, maximum in limits.items():
        if key in result and len(result[key]) > maximum:
            raise ValueError(f"{key} exceeds its maximum length.")
    return result


def _require_fields(result: dict, fields: set[str], noun: str) -> None:
    missing = sorted(key for key in fields if not result.get(key))
    if missing:
        raise ValueError(f"Required {noun} field is missing: {missing[0]}.")


def _normalized_ip(value: str, field: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise ValueError(f"{field} is invalid.") from exc


def _normalized_mac(value: str, field: str) -> str:
    normalized = value.lower().replace("-", ":")
    if normalized and not MAC_PATTERN.fullmatch(normalized):
        raise ValueError(f"{field} is invalid.")
    return normalized


def normalize_asset_review_payload(payload: object, *, action: str) -> dict:
    """Bound one DHCP promotion or IP-change review payload."""
    if not isinstance(payload, dict):
        raise ValueError("Request body must be a JSON object.")
    allowed = set(REVIEW_COMMON_FIELDS)
    if action == "promote":
        allowed.update(REVIEW_PROMOTION_FIELDS)
    if set(payload) - allowed:
        raise ValueError("Request contains unsupported asset review fields.")
    result = _bounded_strings(payload, allowed, REVIEW_LIMITS)
    required = {
        "discovery_id", "expected_ip", "asset_id", "operator_ref", "reason",
        "confirm",
    }
    if action == "promote":
        required.update({"expected_mac", "role"})
    _require_fields(result, required, "asset review")
    if not re.fullmatch(r"[0-9a-f]{20}", result["discovery_id"]):
        raise ValueError("discovery_id is invalid.")
    result["expected_ip"] = _normalized_ip(result["expected_ip"], "expected_ip")
    result["expected_mac"] = _normalized_mac(
        result.get("expected_mac", ""), "expected_mac",
    )
    result["expected_hostname"] = (
        result.get("expected_hostname", "").rstrip(".").lower()
    )
    if action == "promote":
        _apply_promotion_fields(result, payload)
    return result


def _apply_promotion_fields(result: dict, payload: dict) -> None:
    criticality = result.get("criticality") or "unknown"
    if criticality not in CRITICALITIES:
        raise ValueError("criticality is invalid.")
    result["criticality"] = criticality
    result["accept_locally_administered_mac"] = (
        payload.get("accept_locally_administered_mac") is True
    )


def _normalized_timestamp(value: str, parse_timestamp: TimestampParser) -> str:
    try:
        parsed = parse_timestamp(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("expected_valid_from is invalid.") from exc
    if parsed.tzinfo is None:
        raise ValueError("expected_valid_from is invalid.")
    return parsed.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _bounded_list(
    payload: dict,
    key: str,
    maximum: int,
    normalizer: Callable[[str], str],
) -> list[str]:
    raw = payload.get(key)
    if not isinstance(raw, list) or len(raw) > 64:
        raise ValueError(f"{key} must be a bounded list.")
    values: list[str] = []
    for item in raw:
        value = str(item or "").strip()
        if not value or len(value) > maximum:
            raise ValueError(f"{key} contains an invalid value.")
        normalized = normalizer(value)
        if normalized not in values:
            values.append(normalized)
    return values


def _edit_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise ValueError("ip_addresses contains an invalid address.") from exc


def _edit_mac(value: str) -> str:
    normalized = value.lower().replace("-", ":")
    if not MAC_PATTERN.fullmatch(normalized):
        raise ValueError("mac_addresses contains an invalid address.")
    if int(normalized.split(":", 1)[0], 16) & 1:
        raise ValueError("multicast MAC addresses cannot identify assets.")
    return normalized


def _edit_hostname(value: str) -> str:
    normalized = value.rstrip(".").lower()
    if not normalized:
        raise ValueError("hostnames contains an invalid value.")
    return normalized


def _apply_edit_fields(result: dict, payload: dict) -> None:
    result["ip_addresses"] = _bounded_list(payload, "ip_addresses", 64, _edit_ip)
    result["mac_addresses"] = _bounded_list(payload, "mac_addresses", 17, _edit_mac)
    result["hostnames"] = _bounded_list(payload, "hostnames", 253, _edit_hostname)
    if not any(result[key] for key in ("ip_addresses", "mac_addresses", "hostnames")):
        raise ValueError("An asset must retain at least one identifier.")
    if not result.get("role"):
        raise ValueError("role is required.")
    if result.get("criticality") not in CRITICALITIES:
        raise ValueError("criticality is invalid.")
    if result.get("confidence") not in CONFIDENCES:
        raise ValueError("confidence is invalid.")


def normalize_asset_mutation_payload(
    payload: object,
    *,
    action: str,
    parse_timestamp: TimestampParser,
) -> dict:
    """Bound an authoritative edit or demotion transaction payload."""
    if not isinstance(payload, dict):
        raise ValueError("Request body must be a JSON object.")
    allowed = set(MUTATION_COMMON_FIELDS)
    if action == "edit":
        allowed.update(MUTATION_EDIT_FIELDS)
    if set(payload) - allowed:
        raise ValueError("Request contains unsupported asset mutation fields.")
    result = _bounded_strings(payload, allowed, MUTATION_LIMITS)
    _require_fields(result, MUTATION_COMMON_FIELDS, "asset mutation")
    result["expected_valid_from"] = _normalized_timestamp(
        result["expected_valid_from"], parse_timestamp,
    )
    expected = f"{'EDIT' if action == 'edit' else 'DEMOTE'}:{result['asset_id']}"
    if result["confirm"] != expected:
        raise ValueError(f"Confirmation must exactly match {expected}.")
    if action == "edit":
        _apply_edit_fields(result, payload)
    return result


def execute_asset_mutation(
    payload: object,
    *,
    normalizer: Normalizer,
    path: str,
    success_status: int,
    write: MutationWriter,
    clear_cache: Callable[[], None],
) -> tuple[int, dict]:
    """Validate, persist, and invalidate cached inventory only on success."""
    try:
        normalized = normalizer(payload)
        result = write(path, normalized)
    except ValueError as exc:
        return 400, {"ok": False, "error": str(exc)}
    except RuntimeError as exc:
        return int(getattr(exc, "status_code", 503)), {
            "ok": False, "error": str(exc),
        }
    clear_cache()
    return int(success_status), result
