"""AC Hunter host correlation and analyst-facing priority projections."""
from __future__ import annotations

from ac_hunter_config import *  # noqa: F401,F403
from ac_hunter_normalization import _integer_value, _number
from ac_hunter_scoring import _dashboard_hosts


def correlated_hosts(
    findings_by_module: Mapping[str, List[Dict[str, Any]]],
    source_modules: Mapping[str, set],
) -> List[Dict[str, Any]]:
    result: List[Dict[str, Any]] = []
    for source in set(source_modules):
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
        result.append(
            {
                "source_ip": source,
                "host": source,
                "modules": modules,
                "module_count": len(modules),
                "finding_count": len(source_findings),
                "priority_score": max(
                    (
                        finding["priority_score"]
                        for finding in source_findings
                    ),
                    default=0,
                ),
                "verdict": highest,
                "reason": (
                    f"Source appears across {len(modules)} AC Hunter modules: "
                    + ", ".join(modules)
                ),
            }
        )
    result.sort(
        key=lambda item: (
            VERDICT_ORDER.get(str(item["verdict"]), -1),
            int(item["module_count"]),
            int(item["priority_score"]),
        ),
        reverse=True,
    )
    return result


def top_hosts(
    dashboard: object,
    correlations: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    indexed_correlated = {
        item["source_ip"]: item for item in correlations
    }
    result: List[Dict[str, Any]] = []
    seen_hosts: set = set()
    for host in _dashboard_hosts(dashboard):
        source = host["source_ip"]
        correlation = indexed_correlated.get(source, {})
        host.update(
            {
                "modules": correlation.get("modules", []),
                "module_count": correlation.get("module_count", 0),
                "finding_count": correlation.get("finding_count", 0),
                "verdict": correlation.get(
                    "verdict",
                    (
                        "Needs review"
                        if host["score"] >= 0.95
                        else "Informational"
                    ),
                ),
                "reason": correlation.get(
                    "reason", "AC Hunter dashboard behavioral score"
                ),
            }
        )
        result.append(host)
        seen_hosts.add(source)
    for correlation in correlations:
        if correlation["source_ip"] not in seen_hosts:
            result.append(
                {
                    **correlation,
                    "score": 0.0,
                    "count": correlation["finding_count"],
                }
            )
    result.sort(
        key=lambda item: (
            _number(item.get("score"), 0.0),
            VERDICT_ORDER.get(str(item.get("verdict")), -1),
            _integer_value(item.get("module_count")),
        ),
        reverse=True,
    )
    return result[:25]


def flattened_findings(
    findings_by_module: Mapping[str, List[Dict[str, Any]]],
) -> List[Dict[str, Any]]:
    return [
        finding
        for module in MODULE_KEYS
        for finding in findings_by_module[module]
    ]


def verdict_counts(
    all_findings: List[Dict[str, Any]],
) -> Dict[str, int]:
    counts = {name: 0 for name in VERDICT_ORDER}
    for finding in all_findings:
        counts[finding["verdict"]] += 1
    return counts


def _finding_note(finding: Mapping[str, Any]) -> Dict[str, Any]:
    source = finding["source_ip"] or "unknown source"
    destination = (
        finding["destination_ip"]
        or finding["fqdn"]
        or "unknown destination"
    )
    return {
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


def _empty_note() -> Dict[str, Any]:
    return {
        "id": "no-priority-findings",
        "title": "No priority findings in the cached pull",
        "summary": (
            "AC Hunter behavioral data did not produce a High concern or "
            "Needs review result under the deterministic triage rules."
        ),
        "reason": (
            "Continue routine analyst validation; absence of a score is not "
            "proof of safety."
        ),
        "verdict": "Informational",
        "source_ip": "",
        "destination_ip": "",
        "module": "summary",
        "watch_match": False,
    }


def analyst_notes(
    all_findings: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
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
    notes = [_finding_note(finding) for finding in notable[:20]]
    return notes or [_empty_note()]
