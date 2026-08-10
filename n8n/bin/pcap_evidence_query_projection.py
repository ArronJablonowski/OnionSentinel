"""Allowlisted, payload-free response projection for derived PCAP facts."""

from __future__ import annotations

from typing import Any, Callable


def forbidden_output_key(key: Any, forbidden_keys: set[str]) -> bool:
    lowered = str(key).strip().lower()
    if lowered in forbidden_keys:
        return True
    return "payload" in lowered and not lowered.endswith(
        ("_length", "_bytes", "_count")
    )


def scrub_nested(
    value: Any,
    container: str,
    *,
    nested_output_fields: dict[str, set[str]],
    forbidden: Callable[[Any], bool],
    sanitize_text: Callable[[Any, int], str],
    sanitize_value: Callable[..., Any],
) -> Any:
    if isinstance(value, dict):
        allowed = nested_output_fields.get(container)
        return {
            sanitize_text(key, 128): scrub_nested(
                item,
                str(key),
                nested_output_fields=nested_output_fields,
                forbidden=forbidden,
                sanitize_text=sanitize_text,
                sanitize_value=sanitize_value,
            )
            for key, item in value.items()
            if not forbidden(key) and (allowed is None or str(key) in allowed)
        }
    if isinstance(value, list):
        return [
            scrub_nested(
                item,
                container,
                nested_output_fields=nested_output_fields,
                forbidden=forbidden,
                sanitize_text=sanitize_text,
                sanitize_value=sanitize_value,
            )
            for item in value[:64]
        ]
    return sanitize_value(value, max_chars=512, max_items=64)


def project_coverage(
    value: Any,
    *,
    scalar_fields: set[str],
    sanitize_text: Callable[[Any, int], str],
    sanitize_value: Callable[..., Any],
) -> Any:
    if not isinstance(value, dict):
        return {}
    output: dict[str, Any] = {}
    for key, item in value.items():
        key_text = str(key)
        if key_text in scalar_fields:
            output[key_text] = sanitize_value(
                item, max_chars=128, max_items=16
            )
        elif key_text == "per_log" and isinstance(item, dict):
            output[key_text] = {
                sanitize_text(log_name, 40): project_coverage(
                    log_coverage,
                    scalar_fields=scalar_fields,
                    sanitize_text=sanitize_text,
                    sanitize_value=sanitize_value,
                )
                for log_name, log_coverage in list(item.items())[:16]
            }
        elif key_text == "per_file" and isinstance(item, list):
            output[key_text] = [
                project_coverage(
                    record,
                    scalar_fields=scalar_fields,
                    sanitize_text=sanitize_text,
                    sanitize_value=sanitize_value,
                )
                for record in item[:256]
            ]
    return output


def project_record(
    operation: str,
    candidate: Any,
    *,
    output_fields: dict[str, set[str]],
    project_coverage_record: Callable[[Any], Any],
    scrub: Callable[[Any, str], Any],
    forbidden: Callable[[Any], bool],
    sanitize_text: Callable[[Any, int], str],
) -> Any:
    if operation == "coverage":
        return project_coverage_record(candidate)
    output_operation = (
        "packet_facts"
        if operation == "packet_samples"
        else "icmp_facts"
        if operation == "icmp_anomalies"
        else operation
    )
    if not isinstance(candidate, dict):
        return {}
    allowed = output_fields[output_operation]
    return {
        sanitize_text(key, 128): scrub(value, str(key))
        for key, value in candidate.items()
        if str(key) in allowed and not forbidden(key)
    }
