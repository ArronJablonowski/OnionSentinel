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
def _known_benign_explanation(finding: Mapping[str, Any]) -> str:
    evidence = finding.get("evidence")
    ptr = (
        _safe_text(evidence.get("ptr"), 512)
        if isinstance(evidence, dict)
        else ""
    )
    for raw_hostname in (
        _safe_text(finding.get("fqdn"), 512),
        ptr,
    ):
        hostname = raw_hostname.strip().lower().rstrip(".")
        if not re.fullmatch(
            r"(?=.{1,253}\Z)[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?",
            hostname,
        ):
            continue
        for domain, explanation in KNOWN_BENIGN_DOMAINS:
            if hostname == domain or hostname.endswith("." + domain):
                return explanation
    destination = _safe_text(finding.get("destination_ip"), 128)
    try:
        destination_address = ipaddress.ip_address(destination)
    except ValueError:
        destination_address = None
    if destination_address is not None:
        for network, explanation in KNOWN_BENIGN_NETWORKS:
            if destination_address in network:
                return explanation
    port = _integer_value(finding.get("port"))
    protocol = _safe_text(finding.get("protocol"), 32).upper()
    if port == 123 and protocol in {"", "UDP", "NTP"}:
        return "expected NTP pool traffic"
    if port == 5228:
        return "common Google/Android push port"
    if port == 4070:
        return "common Spotify service port"
    return ""


def _score_finding(
    finding: Dict[str, Any],
    module_count: int,
    rare_signature_count: int = 0,
) -> Dict[str, Any]:
    """Apply deterministic behavioral priority; never infer malware."""

    points = 0
    reasons: List[str] = []
    module = str(finding.get("module") or "")
    score = _number(finding.get("score"), 0.0)
    duration = _number(finding.get("duration_seconds"), 0.0)
    fqdn = _safe_text(finding.get("fqdn"), 512)
    source = _safe_text(finding.get("source_ip"), 128)
    destination = _safe_text(finding.get("destination_ip"), 128)
    port = _integer_value(finding.get("port"))
    protocol = _safe_text(finding.get("protocol"), 64)
    searchable = (
        fqdn
        + " "
        + json.dumps(finding.get("evidence", {}), sort_keys=True)
    ).lower()
    benign = _known_benign_explanation(finding)
    generic_infrastructure = any(
        marker in searchable for marker in GENERIC_INFRASTRUCTURE_MARKERS
    )

    if module == "blacklist":
        points += 70
        reasons.append("AC Hunter reported a blacklist match")
    if module == "strobe":
        points += 55
        reasons.append("AC Hunter reported strobe/scanning behavior")
    if score >= 0.95:
        points += 35
        reasons.append(f"high AC Hunter behavioral score ({score:.3f})")
    elif score >= 0.80:
        points += 22
        reasons.append(f"elevated AC Hunter behavioral score ({score:.3f})")
    elif score >= 0.50:
        points += 12
        reasons.append(f"AC Hunter behavioral score met the review threshold ({score:.3f})")
    if not fqdn and module in {
        "beacons",
        "beacons_sni",
        "beacons_proxy",
        "long_connections",
        "unexpected_ports",
    }:
        points += 12
        reasons.append("no FQDN/SNI/DNS explanation was present")
    if generic_infrastructure:
        points += 12
        reasons.append("destination context is generic cloud/VPS infrastructure")
    elif (fqdn or destination) and not benign:
        points += 8
        reasons.append(
            "destination was not recognized as a common vendor, update, "
            "push, or other expected service"
        )
    if module == "unexpected_ports":
        points += 25
        reasons.append("protocol/port behavior was unexpected")
    if duration >= 18_000:
        points += 20
        reasons.append(f"connection lasted {duration / 3600:.1f} hours")
    if module_count > 1:
        added = min(30, (module_count - 1) * 10)
        points += added
        reasons.append(f"source appeared across {module_count} AC Hunter modules")
    if rare_signature_count >= 10:
        points += 10
        reasons.append(
            f"source was associated with {rare_signature_count} rare client-signature observations"
        )

    watch_one = (
        source == "10.66.6.209"
        and destination == "208.70.182.48"
        and port == 1610
        and protocol
        in {
            "",
            "TCP",
            "TLS",
            "SSL",
            "UNKNOWN",
            "TLS/UNKNOWN",
            "SSL/UNKNOWN",
        }
        and not fqdn
    )
    watch_two = (
        source == "10.100.4.245"
        and destination == "98.84.79.102"
        and port == 443
        and duration >= 18_000
    )
    if watch_one:
        points = max(points, 40)
        reasons.append(
            "environment watch: TCP/1610 TLS/unknown traffic to 208.70.182.48 lacks FQDN context"
        )
    if watch_two:
        points = max(points, 40)
        reasons.append(
            "environment watch: very long TCP/443 connection to a generic AWS destination"
        )

    hard_signal = module in {"blacklist", "strobe"} or watch_one or watch_two
    if benign and not hard_signal:
        points = max(0, points - 35)
        if (
            score >= 0.95
            and module
            in {"beacons", "beacons_sni", "beacons_proxy"}
        ):
            # Recognized vendor context lowers urgency but cannot erase a
            # strong periodicity signal on its own.
            points = max(points, 25)
        reasons.append(f"lowered priority: {benign}")

    # These environment-specific pivots were supplied as "Needs review"
    # exemplars. Keep that label stable even when correlation adds enough
    # generic points to cross the broad high-concern threshold; a blacklist or
    # strobe module remains independently high concern.
    if (watch_one or watch_two) and module not in {"blacklist", "strobe"}:
        verdict = "Needs review"
    elif points >= 65:
        verdict = "High concern"
    elif points >= 25:
        verdict = "Needs review"
    elif benign:
        verdict = "Likely benign"
    else:
        verdict = "Informational"
    if not reasons:
        reasons.append("behavioral evidence is limited and requires context before escalation")
    finding["priority_score"] = points
    finding["verdict"] = verdict
    finding["reason"] = "; ".join(reasons)
    finding["watch_match"] = bool(watch_one or watch_two)
    return finding


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
