"""Collection normalization, view-model projection, and operation policy."""
from __future__ import annotations

from ac_hunter_collection_findings import *  # noqa: F401,F403
from ac_hunter_collection_findings import collect_scored_findings
from ac_hunter_collection_hosts import *  # noqa: F401,F403
from ac_hunter_collection_hosts import (
    analyst_notes,
    correlated_hosts,
    flattened_findings,
    top_hosts,
    verdict_counts,
)
from ac_hunter_collection_projection import *  # noqa: F401,F403
from ac_hunter_collection_projection import compose_collection
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
    findings_by_module, source_modules = collect_scored_findings(raw)
    correlations = correlated_hosts(findings_by_module, source_modules)
    findings = flattened_findings(findings_by_module)
    return compose_collection(
        raw,
        pulled_at=pulled_at,
        source_statuses=source_statuses,
        findings_by_module=findings_by_module,
        verdict_counts=verdict_counts(findings),
        top_hosts=top_hosts(raw.get("dashboard"), correlations),
        correlated_hosts=correlations,
        analyst_notes=analyst_notes(findings),
    )


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
        {
            "page": 1,
            "size": 100,
            "min_length": 18_000,
            "sort": "duration",
        },
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
