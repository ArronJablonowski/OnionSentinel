"""Collection normalization, view-model projection, and operation policy."""
from __future__ import annotations

from ac_hunter_config import *  # noqa: F401,F403
from ac_hunter_config import _safe_error  # noqa: F401
from ac_hunter_normalization import *  # noqa: F401,F403
from ac_hunter_normalization import (  # noqa: F401
    _integer_value,
    _normalize_finding,
    _number,
    _rows,
)
from ac_hunter_scoring import *  # noqa: F401,F403
from ac_hunter_scoring import (  # noqa: F401
    _count_value,
    _dashboard_hosts,
    _dashboard_rare_signature_sources,
    _extract_time_range,
    _rare_signature_sources,
    _score_finding,
)
def normalize_collection(
    raw: Mapping[str, object],
    *,
    pulled_at: str,
    source_statuses: Mapping[str, Mapping[str, object]],
) -> Dict[str, Any]:
    operation_to_module = {
        "beacons": "beacons",
        "beacons_sni": "beacons_sni",
        "beacons_proxy": "beacons_proxy",
        "long_connections": "long_connections",
        "dns": "dns_anomalies",
        "unexpected_ports": "unexpected_ports",
        "blacklist_ip": "blacklist",
        "strobe": "strobe",
    }
    findings_by_module: Dict[str, List[Dict[str, Any]]] = {
        key: [] for key in MODULE_KEYS
    }
    for operation, module in operation_to_module.items():
        names = (
            operation,
            module,
            "data",
            "results",
            "items",
        )
        findings_by_module[module] = [
            _normalize_finding(module, row)
            for row in _rows(raw.get(operation), names)
        ][:MAX_FINDINGS_PER_MODULE]

    source_modules: Dict[str, set] = {}
    for module, findings in findings_by_module.items():
        for finding in findings:
            source = finding["source_ip"]
            if source:
                source_modules.setdefault(source, set()).add(module)
    rare_sources = _rare_signature_sources(raw.get("useragent_count_false"))
    for source, count in _rare_signature_sources(
        raw.get("useragent_count_true")
    ).items():
        rare_sources[source] = rare_sources.get(source, 0) + count
    for source, count in _dashboard_rare_signature_sources(
        raw.get("dashboard")
    ).items():
        rare_sources[source] = max(rare_sources.get(source, 0), count)

    for findings in findings_by_module.values():
        for finding in findings:
            source = finding["source_ip"]
            _score_finding(
                finding,
                len(source_modules.get(source, set())),
                rare_sources.get(source, 0),
            )

    correlated_hosts: List[Dict[str, Any]] = []
    all_sources = set(source_modules)
    for source in all_sources:
        modules = sorted(source_modules[source])
        source_findings = [
            finding
            for findings in findings_by_module.values()
            for finding in findings
            if finding["source_ip"] == source
        ]
        highest = max(
            (finding["verdict"] for finding in source_findings),
            key=lambda value: VERDICT_ORDER.get(value, -1),
        )
        correlated_hosts.append(
            {
                "source_ip": source,
                "host": source,
                "modules": modules,
                "module_count": len(modules),
                "finding_count": len(source_findings),
                "priority_score": max(
                    (finding["priority_score"] for finding in source_findings),
                    default=0,
                ),
                "verdict": highest,
                "reason": (
                    f"Source appears across {len(modules)} AC Hunter modules: "
                    + ", ".join(modules)
                ),
            }
        )
    correlated_hosts.sort(
        key=lambda item: (
            VERDICT_ORDER.get(str(item["verdict"]), -1),
            int(item["module_count"]),
            int(item["priority_score"]),
        ),
        reverse=True,
    )

    dashboard_hosts = _dashboard_hosts(raw.get("dashboard"))
    indexed_correlated = {
        item["source_ip"]: item for item in correlated_hosts
    }
    top_hosts: List[Dict[str, Any]] = []
    seen_hosts: set = set()
    for host in dashboard_hosts:
        source = host["source_ip"]
        correlation = indexed_correlated.get(source, {})
        host.update(
            {
                "modules": correlation.get("modules", []),
                "module_count": correlation.get("module_count", 0),
                "finding_count": correlation.get("finding_count", 0),
                "verdict": correlation.get(
                    "verdict",
                    "Needs review" if host["score"] >= 0.95 else "Informational",
                ),
                "reason": correlation.get(
                    "reason", "AC Hunter dashboard behavioral score"
                ),
            }
        )
        top_hosts.append(host)
        seen_hosts.add(source)
    for correlation in correlated_hosts:
        if correlation["source_ip"] not in seen_hosts:
            top_hosts.append(
                {
                    **correlation,
                    "score": 0.0,
                    "count": correlation["finding_count"],
                }
            )
    top_hosts.sort(
        key=lambda item: (
            _number(item.get("score"), 0.0),
            VERDICT_ORDER.get(str(item.get("verdict")), -1),
            _integer_value(item.get("module_count")),
        ),
        reverse=True,
    )
    top_hosts = top_hosts[:25]

    all_findings = [
        finding
        for module in MODULE_KEYS
        for finding in findings_by_module[module]
    ]
    verdict_counts = {name: 0 for name in VERDICT_ORDER}
    for finding in all_findings:
        verdict_counts[finding["verdict"]] += 1

    analyst_notes: List[Dict[str, Any]] = []
    notable = sorted(
        (
            finding
            for finding in all_findings
            if finding["verdict"] in {"High concern", "Needs review"}
        ),
        key=lambda finding: (
            bool(finding.get("watch_match")),
            VERDICT_ORDER.get(str(finding["verdict"]), -1),
            int(finding["priority_score"]),
        ),
        reverse=True,
    )
    for finding in notable[:20]:
        source = finding["source_ip"] or "unknown source"
        destination = finding["destination_ip"] or finding["fqdn"] or "unknown destination"
        analyst_notes.append(
            {
                "id": finding["id"],
                "title": f"{source} → {destination}",
                "summary": finding["reason"],
                "reason": finding["reason"],
                "verdict": finding["verdict"],
                "source_ip": finding["source_ip"],
                "destination_ip": finding["destination_ip"],
                "module": finding["module"],
                "watch_match": finding["watch_match"],
            }
        )
    if not analyst_notes:
        analyst_notes.append(
            {
                "id": "no-priority-findings",
                "title": "No priority findings in the cached pull",
                "summary": (
                    "AC Hunter behavioral data did not produce a High concern or "
                    "Needs review result under the deterministic triage rules."
                ),
                "reason": "Continue routine analyst validation; absence of a score is not proof of safety.",
                "verdict": "Informational",
                "source_ip": "",
                "destination_ip": "",
                "module": "summary",
                "watch_match": False,
            }
        )

    modules: Dict[str, Dict[str, Any]] = {}
    reverse_operations = {module: operation for operation, module in operation_to_module.items()}
    for module in MODULE_KEYS:
        operation = reverse_operations[module]
        status = dict(source_statuses.get(operation, {}))
        modules[module] = {
            "count": len(findings_by_module[module]),
            "status": status.get("status", "unknown"),
            "error": _safe_error(status.get("error"), "")
            if status.get("error")
            else "",
            "findings": findings_by_module[module],
        }

    complete = all(
        status.get("status") == "ok"
        for operation, status in source_statuses.items()
        if operation != "unexpected_ports"
    )
    time_range = _extract_time_range(
        raw.get("database"), raw.get("dashboard")
    )
    cache = {
        "status": "fresh",
        "stale": False,
        "refreshed_at": pulled_at,
        "age_seconds": 0,
    }
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
            "complete": complete,
            "stale": False,
            "source_statuses": {
                key: {
                    "status": value.get("status", "unknown"),
                    "http_status": _integer_value(value.get("http_status")),
                    "error": _safe_error(value.get("error"), "")
                    if value.get("error")
                    else "",
                }
                for key, value in source_statuses.items()
            },
        },
        "dataset": {
            "name": FIXED_DATASET,
            "time_range": time_range,
        },
        "time_range": time_range,
        "cache": cache,
        "verdict_counts": verdict_counts,
        "top_hosts": top_hosts,
        "top_risky_internal_hosts": top_hosts,
        "correlated_hosts": correlated_hosts,
        "modules": modules,
        "analyst_notes": analyst_notes,
        "counts": {
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
        },
        "disclaimer": (
            "AC Hunter is a behavioral triage source. Scores and correlations "
            "prioritize analyst review; they do not by themselves establish "
            "malware, compromise, or malicious intent."
        ),
    }


COLLECTION_OPERATIONS: Tuple[Tuple[str, Dict[str, Any], bool], ...] = (
    ("database", {}, False),
    ("dashboard", {}, False),
    ("dashboard_count", {}, False),
    ("dashboard_c2flag", {}, False),
    ("beacons_count", {"thresh": 0.5}, False),
    (
        "beacons",
        {"page": 1, "size": 100, "thresh": 0.5, "sort": "score"},
        False,
    ),
    (
        "beacons_sni",
        {"page": 1, "size": 100, "thresh": 0.5, "sort": "score"},
        False,
    ),
    (
        "beacons_proxy",
        {"page": 1, "size": 100, "thresh": 0.5, "sort": "score"},
        False,
    ),
    (
        "long_connections",
        {"page": 1, "size": 100, "min_length": 18_000, "sort": "duration"},
        False,
    ),
    (
        "dns",
        {"page": 1, "size": 100, "threshold": 100},
        False,
    ),
    (
        "strobe",
        {"page": 1, "size": 100, "sort": "connection_count"},
        False,
    ),
    ("blacklist_ip", {"page": 1, "size": 100}, False),
    ("certificate_count", {}, False),
    ("useragent_count_false", {"ja3flag": False}, False),
    ("useragent_count_true", {"ja3flag": True}, False),
    ("unexpected_ports", {}, True),
)
