"""AC Hunter finding admission, cross-module context, and scoring."""
from __future__ import annotations

from ac_hunter_config import *  # noqa: F401,F403
from ac_hunter_normalization import _normalize_finding, _rows
from ac_hunter_scoring import (
    _dashboard_rare_signature_sources,
    _rare_signature_sources,
    _score_finding,
)


OPERATION_TO_MODULE = {
    "beacons": "beacons",
    "beacons_sni": "beacons_sni",
    "beacons_proxy": "beacons_proxy",
    "long_connections": "long_connections",
    "dns": "dns_anomalies",
    "unexpected_ports": "unexpected_ports",
    "blacklist_ip": "blacklist",
    "strobe": "strobe",
}


def _normalized_findings(
    raw: Mapping[str, object],
) -> Dict[str, List[Dict[str, Any]]]:
    findings_by_module: Dict[str, List[Dict[str, Any]]] = {
        key: [] for key in MODULE_KEYS
    }
    for operation, module in OPERATION_TO_MODULE.items():
        names = (operation, module, "data", "results", "items")
        findings_by_module[module] = [
            _normalize_finding(module, row)
            for row in _rows(raw.get(operation), names)
        ][:MAX_FINDINGS_PER_MODULE]
    return findings_by_module


def _source_modules(
    findings_by_module: Mapping[str, List[Dict[str, Any]]],
) -> Dict[str, set]:
    source_modules: Dict[str, set] = {}
    for module, findings in findings_by_module.items():
        for finding in findings:
            source = finding["source_ip"]
            if source:
                source_modules.setdefault(source, set()).add(module)
    return source_modules


def _rare_sources(raw: Mapping[str, object]) -> Dict[str, int]:
    rare_sources = _rare_signature_sources(raw.get("useragent_count_false"))
    for source, count in _rare_signature_sources(
        raw.get("useragent_count_true")
    ).items():
        rare_sources[source] = rare_sources.get(source, 0) + count
    for source, count in _dashboard_rare_signature_sources(
        raw.get("dashboard")
    ).items():
        rare_sources[source] = max(rare_sources.get(source, 0), count)
    return rare_sources


def _score_findings(
    findings_by_module: Mapping[str, List[Dict[str, Any]]],
    source_modules: Mapping[str, set],
    rare_sources: Mapping[str, int],
) -> None:
    for findings in findings_by_module.values():
        for finding in findings:
            source = finding["source_ip"]
            _score_finding(
                finding,
                len(source_modules.get(source, set())),
                rare_sources.get(source, 0),
            )


def collect_scored_findings(
    raw: Mapping[str, object],
) -> tuple[Dict[str, List[Dict[str, Any]]], Dict[str, set]]:
    """Normalize and score every bounded operation result."""
    findings_by_module = _normalized_findings(raw)
    source_modules = _source_modules(findings_by_module)
    _score_findings(
        findings_by_module,
        source_modules,
        _rare_sources(raw),
    )
    return findings_by_module, source_modules
