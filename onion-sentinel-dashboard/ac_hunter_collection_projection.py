"""AC Hunter module status, metadata, and response composition."""
from __future__ import annotations

from ac_hunter_collection_findings import OPERATION_TO_MODULE
from ac_hunter_config import *  # noqa: F401,F403
from ac_hunter_config import _safe_error
from ac_hunter_normalization import _integer_value
from ac_hunter_scoring import _count_value, _extract_time_range


def module_projections(
    findings_by_module: Mapping[str, List[Dict[str, Any]]],
    source_statuses: Mapping[str, Mapping[str, object]],
) -> Dict[str, Dict[str, Any]]:
    modules: Dict[str, Dict[str, Any]] = {}
    reverse_operations = {
        module: operation
        for operation, module in OPERATION_TO_MODULE.items()
    }
    for module in MODULE_KEYS:
        operation = reverse_operations[module]
        status = dict(source_statuses.get(operation, {}))
        modules[module] = {
            "count": len(findings_by_module[module]),
            "status": status.get("status", "unknown"),
            "error": (
                _safe_error(status.get("error"), "")
                if status.get("error")
                else ""
            ),
            "findings": findings_by_module[module],
        }
    return modules


def source_status_projection(
    source_statuses: Mapping[str, Mapping[str, object]],
) -> Dict[str, Dict[str, Any]]:
    return {
        key: {
            "status": value.get("status", "unknown"),
            "http_status": _integer_value(value.get("http_status")),
            "error": (
                _safe_error(value.get("error"), "")
                if value.get("error")
                else ""
            ),
        }
        for key, value in source_statuses.items()
    }


def collection_complete(
    source_statuses: Mapping[str, Mapping[str, object]],
) -> bool:
    return all(
        status.get("status") == "ok"
        for operation, status in source_statuses.items()
        if operation != "unexpected_ports"
    )


def count_projection(raw: Mapping[str, object]) -> Dict[str, int]:
    return {
        "dashboard": _count_value(raw.get("dashboard_count")),
        "c2_flags": _count_value(raw.get("dashboard_c2flag")),
        "beacons": _count_value(raw.get("beacons_count")),
        "certificates": _count_value(raw.get("certificate_count")),
        "user_agents_without_ja3": _count_value(
            raw.get("useragent_count_false")
        ),
        "user_agents_with_ja3": _count_value(
            raw.get("useragent_count_true")
        ),
    }


def fresh_cache(pulled_at: str) -> Dict[str, Any]:
    return {
        "status": "fresh",
        "stale": False,
        "refreshed_at": pulled_at,
        "age_seconds": 0,
    }


def compose_collection(
    raw: Mapping[str, object],
    *,
    pulled_at: str,
    source_statuses: Mapping[str, Mapping[str, object]],
    findings_by_module: Mapping[str, List[Dict[str, Any]]],
    verdict_counts: Mapping[str, int],
    top_hosts: List[Dict[str, Any]],
    correlated_hosts: List[Dict[str, Any]],
    analyst_notes: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Compose the stable Deep Review response from pure projections."""
    time_range = _extract_time_range(
        raw.get("database"), raw.get("dashboard")
    )
    return {
        "schema": REVIEW_SCHEMA,
        "version": REVIEW_VERSION,
        "ok": True,
        "last_pulled_at": pulled_at,
        "metadata": {
            "dataset": FIXED_DATASET,
            "last_pulled_at": pulled_at,
            "source": "AC Hunter behavioral triage via the Onion Sentinel Relay",
            "transport_path": "Onion Sentinel → Relay → AC Hunter",
            "complete": collection_complete(source_statuses),
            "stale": False,
            "source_statuses": source_status_projection(source_statuses),
        },
        "dataset": {"name": FIXED_DATASET, "time_range": time_range},
        "time_range": time_range,
        "cache": fresh_cache(pulled_at),
        "verdict_counts": dict(verdict_counts),
        "top_hosts": top_hosts,
        "top_risky_internal_hosts": top_hosts,
        "correlated_hosts": correlated_hosts,
        "modules": module_projections(
            findings_by_module, source_statuses
        ),
        "analyst_notes": analyst_notes,
        "counts": count_projection(raw),
        "disclaimer": (
            "AC Hunter is a behavioral triage source. Scores and correlations "
            "prioritize analyst review; they do not by themselves establish "
            "malware, compromise, or malicious intent."
        ),
    }
