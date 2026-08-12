"""Deterministic behavioral scoring, benign context, and host correlation."""
from __future__ import annotations

from ac_hunter_config import *  # noqa: F401,F403
from ac_hunter_config import _parse_timestamp, _safe_text, _utc_iso  # noqa: F401
from ac_hunter_normalization import *  # noqa: F401,F403
from ac_hunter_normalization import (  # noqa: F401
    _first,
    _integer_value,
    _ip,
    _is_internal,
    _number,
    _rows,
    _string_list,
)
from ac_hunter_scoring_policy import apply_scoring_policy


def _known_domain_explanation(hostnames: Iterable[str]) -> str:
    for raw_hostname in hostnames:
        hostname = raw_hostname.strip().lower().rstrip(".")
        if not re.fullmatch(
            r"(?=.{1,253}\Z)[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?",
            hostname,
        ):
            continue
        for domain, explanation in KNOWN_BENIGN_DOMAINS:
            if hostname == domain or hostname.endswith("." + domain):
                return explanation
    return ""


def _known_network_explanation(destination: str) -> str:
    try:
        destination_address = ipaddress.ip_address(destination)
    except ValueError:
        return ""
    for network, explanation in KNOWN_BENIGN_NETWORKS:
        if destination_address in network:
            return explanation
    return ""


def _known_service_explanation(port: int, protocol: str) -> str:
    if port == 123 and protocol in {"", "UDP", "NTP"}:
        return "expected NTP pool traffic"
    if port == 5228:
        return "common Google/Android push port"
    if port == 4070:
        return "common Spotify service port"
    return ""


def _known_benign_explanation(finding: Mapping[str, Any]) -> str:
    evidence = finding.get("evidence")
    ptr = (
        _safe_text(evidence.get("ptr"), 512)
        if isinstance(evidence, dict)
        else ""
    )
    explanation = _known_domain_explanation(
        (_safe_text(finding.get("fqdn"), 512), ptr)
    )
    if explanation:
        return explanation
    explanation = _known_network_explanation(
        _safe_text(finding.get("destination_ip"), 128)
    )
    if explanation:
        return explanation
    return _known_service_explanation(
        _integer_value(finding.get("port")),
        _safe_text(finding.get("protocol"), 32).upper(),
    )


def _score_finding(
    finding: Dict[str, Any],
    module_count: int,
    rare_signature_count: int = 0,
) -> Dict[str, Any]:
    """Apply deterministic behavioral priority; never infer malware."""
    return apply_scoring_policy(
        finding,
        module_count,
        rare_signature_count,
        _known_benign_explanation,
    )


def _count_value(value: object) -> int:
    if isinstance(value, dict):
        for key in ("count", "total", "value", "records", "results"):
            candidate = value.get(key)
            if isinstance(candidate, (int, float)) and not isinstance(candidate, bool):
                return max(0, int(candidate))
        for candidate in value.values():
            count = _count_value(candidate)
            if count:
                return count
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return max(0, int(value))
    return 0


def _extract_time_range(database: object, dashboard: object) -> Dict[str, str]:
    candidates: List[Mapping[str, Any]] = []

    def visit(value: object, depth: int = 0) -> None:
        if depth > 4:
            return
        if isinstance(value, dict):
            candidates.append(value)
            for item in list(value.values())[:100]:
                visit(item, depth + 1)
        elif isinstance(value, list):
            for item in value[:100]:
                visit(item, depth + 1)

    visit(database)
    visit(dashboard)
    starts = (
        "start",
        "min",
        "from",
        "first_seen",
        "start_time",
        "min_timestamp",
        "ts_min",
    )
    ends = (
        "end",
        "max",
        "to",
        "last_seen",
        "end_time",
        "max_timestamp",
        "ts_max",
    )
    best: Tuple[Optional[float], Optional[float]] = (None, None)
    for candidate in candidates:
        start = _parse_timestamp(_first(candidate, starts))
        end = _parse_timestamp(_first(candidate, ends))
        if start is not None and end is not None and start <= end:
            best = (start, end)
            break
    return {
        "start": _utc_iso(best[0]) if best[0] is not None else "",
        "end": _utc_iso(best[1]) if best[1] is not None else "",
    }


def _rare_signature_sources(value: object) -> Dict[str, int]:
    result: Dict[str, int] = {}
    for row in _rows(value, ("useragents", "user_agents")):
        seen = _integer_value(_first(row, ("seen", "count", "observations")))
        for raw in _string_list(
            _first(row, ("orig_ips", "source_ips", "hosts", "sources"))
        ):
            source = _ip(raw)
            if source:
                result[source] = result.get(source, 0) + seen
    return result


def _dashboard_rare_signature_sources(value: object) -> Dict[str, int]:
    result: Dict[str, int] = {}
    for row in _rows(value, ("dashboard", "hosts", "data")):
        source = _ip(
            _first(row, ("source_ip", "src", "host", "ip", "address", "orig_h"))
        )
        if not source:
            continue
        raw = _first(row, ("rare_sig_count", "rare_signature_count"))
        if isinstance(raw, dict):
            # AC Hunter exposes both the underlying observation count (`base`)
            # and the dashboard weighting (`points`).  Investigation rationale
            # must report the evidence count, not the score contribution.
            raw = _first(raw, ("base", "count", "value"))
        count = _integer_value(raw)
        if count:
            result[source] = count
    return result


def _dashboard_hosts(value: object) -> List[Dict[str, Any]]:
    result: List[Dict[str, Any]] = []
    seen: set = set()
    for row in _rows(value, ("dashboard", "hosts", "data")):
        host = _ip(
            _first(row, ("source_ip", "src", "host", "ip", "address", "orig_h"))
        )
        if not host or not _is_internal(host) or host in seen:
            continue
        seen.add(host)
        result.append(
            {
                "source_ip": host,
                "host": host,
                "score": round(
                    max(
                        0.0,
                        _number(
                            _first(
                                row,
                                ("score", "dashboard_score", "risk_score", "c2_score"),
                            )
                        ),
                    ),
                    6,
                ),
                "count": _integer_value(
                    _first(row, ("count", "connection_count", "connections"))
                ),
            }
        )
    return result
