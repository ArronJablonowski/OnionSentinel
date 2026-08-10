"""Bounded AC Hunter response normalization and evidence projection."""
from __future__ import annotations

from ac_hunter_config import *  # noqa: F401,F403
from ac_hunter_config import _safe_text  # noqa: F401
def _first(mapping: object, names: Sequence[str]) -> object:
    if not isinstance(mapping, dict):
        return None
    for name in names:
        current: object = mapping
        found = True
        for component in name.split("."):
            if not isinstance(current, dict) or component not in current:
                found = False
                break
            current = current[component]
        if found and current not in (None, ""):
            return current
    return None


def _rows(value: object, names: Sequence[str] = ()) -> List[Dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value[:MAX_FINDINGS_PER_MODULE] if isinstance(item, dict)]
    if not isinstance(value, dict):
        return []
    priority = tuple(names) + (
        "data",
        "results",
        "items",
        "rows",
        "records",
        "findings",
        "hosts",
    )
    for key in priority:
        candidate = value.get(key)
        if isinstance(candidate, list):
            return [
                item
                for item in candidate[:MAX_FINDINGS_PER_MODULE]
                if isinstance(item, dict)
            ]
        if isinstance(candidate, dict):
            nested = _rows(candidate, ())
            if nested:
                return nested
    # Some AC Hunter responses are objects keyed by an address/domain.
    converted: List[Dict[str, Any]] = []
    for key, item in list(value.items())[:MAX_FINDINGS_PER_MODULE]:
        if isinstance(item, dict):
            row = dict(item)
            row.setdefault("host", key)
            converted.append(row)
    return converted


def _number(value: object, default: float = 0.0) -> float:
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        result = float(value)
        return result if result == result and abs(result) != float("inf") else default
    text = str(value or "").strip().replace(",", "")
    try:
        result = float(text)
    except ValueError:
        return default
    return result if result == result and abs(result) != float("inf") else default


def _integer_value(value: object) -> int:
    if isinstance(value, (list, tuple, set)):
        return len(value)
    if isinstance(value, dict):
        candidate = _first(value, ("count", "value", "base", "points", "total"))
        if candidate is value:
            return 0
        return _integer_value(candidate)
    return max(0, int(_number(value, 0)))


def _duration_seconds(value: object) -> float:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return max(0.0, float(value))
    text = str(value or "").strip()
    if not text:
        return 0.0
    if re.fullmatch(r"\d+(?:\.\d+)?", text):
        return max(0.0, float(text))
    match = re.fullmatch(
        r"(?:(\d+)\s*d(?:ays?)?\s*)?(?:(\d+):)?(\d+):(\d+(?:\.\d+)?)",
        text,
        re.IGNORECASE,
    )
    if not match:
        return 0.0
    days, hours, minutes, seconds = match.groups()
    return (
        int(days or 0) * 86400
        + int(hours or 0) * 3600
        + int(minutes or 0) * 60
        + float(seconds)
    )


def _ip(value: object) -> str:
    text = _safe_text(value, 128)
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return ""


def _is_internal(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.is_private


def _string_list(value: object, maximum: int = 20) -> List[str]:
    if isinstance(value, str):
        candidates: Sequence[object] = re.split(r"[,;\s]+", value)
    elif isinstance(value, (list, tuple, set)):
        candidates = list(value)
    else:
        return []
    result: List[str] = []
    for candidate in candidates:
        if isinstance(candidate, dict):
            candidate = _first(
                candidate,
                ("ip", "address", "host", "fqdn", "domain", "value"),
            )
        text = _safe_text(candidate, 256)
        if text and text not in result:
            result.append(text)
        if len(result) >= maximum:
            break
    return result


def _finding_id(module: str, values: Mapping[str, object]) -> str:
    canonical = json.dumps(
        [module, values.get("source_ip"), values.get("destination_ip"),
         values.get("fqdn"), values.get("port"), values.get("protocol")],
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:20]


def _normalize_finding(module: str, row: Mapping[str, Any]) -> Dict[str, Any]:
    source = _ip(
        _first(
            row,
            (
                "source_ip",
                "src_ip",
                "src",
                "source",
                "orig_h",
                "id.orig_h",
                "source.address",
                "client_ip",
            ),
        )
    )
    destination = _ip(
        _first(
            row,
            (
                "destination_ip",
                "dst_ip",
                "dst",
                "destination",
                "resp_h",
                "id.resp_h",
                "destination.address",
                "server_ip",
                "host",
            ),
        )
    )
    fqdn = _safe_text(
        _first(
            row,
            (
                "fqdn",
                "domain",
                "dst_fqdn",
                "destination_fqdn",
                "server_name",
                "sni",
                "hostname",
                "ptr",
                "reverse_dns",
                "queried_fqdn",
            ),
        ),
        512,
    )
    if not fqdn:
        queried = _string_list(_first(row, ("queried_fqdns",)))
        fqdn = queried[0] if queried else ""
    responding_ips = [
        item for item in (_ip(value) for value in _string_list(
            _first(row, ("responding_ips", "resolved_ips", "dst_ips", "answers"))
        )) if item
    ]
    if module == "blacklist":
        host = _ip(_first(row, ("host", "ip", "address")))
        if host:
            if _is_internal(host):
                source = source or host
            else:
                destination = destination or host
    if module == "dns_anomalies" and not source:
        query_rows = _first(row, ("queries", "directs", "clients"))
        if isinstance(query_rows, list):
            for query in query_rows:
                candidate = _ip(_first(query, ("ip", "source_ip", "src")))
                if candidate:
                    source = candidate
                    break
    score = _number(
        _first(row, ("score", "beacon_score", "risk_score", "c2_score")),
        0.0,
    )
    count = _integer_value(
        _first(
            row,
            (
                "count",
                "connection_count",
                "connections",
                "conn_count",
                "seen",
                "queries",
                "query_count",
                "subdomains",
                "visited",
            ),
        )
    )
    duration = _duration_seconds(
        _first(
            row,
            (
                "duration",
                "duration_seconds",
                "length",
                "connection_duration",
            ),
        )
    )
    port_value = _first(
        row,
        (
            "port",
            "destination_port",
            "dst_port",
            "resp_p",
            "id.resp_p",
            "service_port",
        ),
    )
    port = _integer_value(port_value)
    if not 0 < port <= 65535:
        port = 0
    protocol = _safe_text(
        _first(row, ("protocol", "proto", "service", "transport")), 64
    ).upper()
    tuples = _first(row, ("tuples",))
    if isinstance(tuples, list) and tuples:
        if not count:
            count = len(tuples)
        first_tuple = tuples[0]
        if isinstance(first_tuple, dict):
            if not port:
                tuple_port = _integer_value(
                    _first(
                        first_tuple,
                        ("port", "destination_port", "dst_port", "resp_p"),
                    )
                )
                if 0 < tuple_port <= 65535:
                    port = tuple_port
            if not protocol:
                protocol = _safe_text(
                    _first(first_tuple, ("protocol", "proto", "transport")), 64
                ).upper()
    timing_mode = _safe_text(
        _first(row, ("timing_mode", "ts_mode", "time_mode", "mode")), 128
    )
    data_size_mode = _safe_text(
        _first(row, ("data_size_mode", "ds_mode", "size_mode")), 128
    )
    evidence = {
        "timing_mode": timing_mode,
        "data_size_mode": data_size_mode,
        "bytes": _integer_value(
            _first(row, ("bytes", "total_bytes", "byte_count"))
        ),
        "network": _safe_text(
            _first(row, ("network_name", "src_network_name")), 256
        ),
        "destination_network": _safe_text(
            _first(row, ("dst_network_name", "destination_network_name")), 256
        ),
        "ptr": _safe_text(
            _first(row, ("ptr", "reverse_dns", "destination_ptr")), 512
        ),
        "open": bool(_first(row, ("open", "is_open")) is True),
    }
    evidence = {key: value for key, value in evidence.items() if value not in ("", 0, False)}
    finding: Dict[str, Any] = {
        "source_ip": source,
        "destination_ip": destination,
        "fqdn": fqdn,
        "module": module,
        "score": round(max(0.0, score), 6),
        "count": count,
        "duration": round(duration, 3),
        "duration_seconds": round(duration, 3),
        "port": port,
        "protocol": protocol,
        "timing_mode": timing_mode,
        "data_size_mode": data_size_mode,
        "responding_ips": responding_ips,
        "evidence": evidence,
    }
    finding["id"] = _finding_id(module, finding)
    return finding


KNOWN_BENIGN_DOMAINS = (
    ("courier.push.apple.com", "Apple push/courier"),
    ("safebrowsing.apple", "Apple Safe Browsing"),
    ("apple.com", "Apple service"),
    ("icloud.com", "Apple service"),
    ("mzstatic.com", "Apple software distribution"),
    ("apple-dns.net", "Apple service"),
    ("push.services.mozilla.com", "Mozilla push/telemetry"),
    ("telemetry.mozilla.org", "Mozilla push/telemetry"),
    ("services.mozilla.com", "Mozilla service"),
    ("docker.com", "Docker service"),
    ("docker.io", "Docker service"),
    ("raw.githubusercontent.com", "GitHub raw content"),
    ("raw.github.com", "GitHub raw content"),
    ("obsidian.md", "Obsidian release service"),
    ("update.code.visualstudio.com", "Visual Studio Code update service"),
    ("vscode.download.prss.microsoft.com", "Visual Studio Code update service"),
    ("artifacts.elastic.co", "Elastic artifact/update service"),
    ("api.telegram.org", "Telegram API"),
    ("spotify.com", "Spotify service"),
    ("oaistatic.com", "OpenAI static/service infrastructure"),
    ("openai.com", "OpenAI service"),
    ("chatgpt.com", "OpenAI ChatGPT service"),
    ("n8n.io", "n8n service"),
    ("brave.com", "Brave browser service/update"),
)
KNOWN_BENIGN_NETWORKS = (
    (ipaddress.ip_network("17.0.0.0/8"), "Apple service network"),
)
GENERIC_INFRASTRUCTURE_MARKERS = (
    "amazonaws",
    "compute.amazonaws",
    "ec2-",
    "cloudfront",
    "digitalocean",
    "linode",
    "vultr",
    "hetzner",
    "azure",
    "cloudapp",
    "googleusercontent",
    "vps",
)
