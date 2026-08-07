"""Public enrichment status projection for SOC alert groups."""
from __future__ import annotations

import json


JsonObject = dict[str, object]


def _mapping(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def _list(value: object) -> list:
    return value if isinstance(value, list) else []


def _parse(value: object) -> dict:
    if isinstance(value, dict):
        return value
    try:
        parsed = json.loads(value or "{}") if isinstance(value, str) else {}
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _indicator_count(indicators: dict) -> int:
    return sum(
        len(_list(indicators.get(key)))
        for key in ("public_ips", "domains", "urls", "hashes", "cves")
    )


def _classification(records: list, skipped: list, errors: list,
                    indicator_count: int) -> tuple[str, str, str]:
    if records:
        return (
            "enriched", "Enriched",
            f"{len(records)} enrichment record(s), {len(skipped)} skipped source(s), {len(errors)} error(s)",
        )
    if errors:
        return "error", "Error", f"{len(errors)} enrichment error(s), {len(skipped)} skipped source(s)"
    if skipped:
        return "checked", "Checked", f"Indicators found, but {len(skipped)} source(s) skipped or unavailable"
    if indicator_count:
        return "pending", "Pending", f"{indicator_count} public indicator(s) found with no completed enrichment records yet"
    return "none", "None", "No public indicators were recorded for enrichment"


def compose_enrichment_status(enrichment_json: object) -> JsonObject:
    """Project bounded counts and precedence from an enrichment envelope."""
    external = _parse(enrichment_json).get("external_intel")
    if not isinstance(external, dict):
        return {
            "enrichment_status_key": "none",
            "enrichment_status_label": "None",
            "enrichment_status_detail": "No public enrichment data recorded for this alert group",
            "enrichment_record_count": 0,
            "enrichment_skip_count": 0,
            "enrichment_error_count": 0,
        }
    records = _list(external.get("records"))
    skipped = _list(external.get("skipped"))
    errors = _list(external.get("errors"))
    key, label, detail = _classification(
        records, skipped, errors, _indicator_count(_mapping(external.get("indicators"))),
    )
    return {
        "enrichment_status_key": key,
        "enrichment_status_label": label,
        "enrichment_status_detail": detail,
        "enrichment_record_count": len(records),
        "enrichment_skip_count": len(skipped),
        "enrichment_error_count": len(errors),
    }
