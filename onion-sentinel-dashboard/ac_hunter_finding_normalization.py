"""Pure phases for bounded AC Hunter finding normalization."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Mapping, Sequence


@dataclass(frozen=True)
class FindingNormalizationPrimitives:
    first: Callable[[object, Sequence[str]], object]
    safe_text: Callable[[object, int], str]
    ip: Callable[[object], str]
    is_internal: Callable[[str], bool]
    string_list: Callable[..., List[str]]
    number: Callable[[object, float], float]
    integer_value: Callable[[object], int]
    duration_seconds: Callable[[object], float]
    finding_id: Callable[[str, Mapping[str, object]], str]


@dataclass
class _NetworkValues:
    source: str
    destination: str
    fqdn: str
    responding_ips: List[str]


@dataclass
class _MetricValues:
    score: float
    count: int
    duration: float
    port: int
    protocol: str


SOURCE_FIELDS = (
    "source_ip",
    "src_ip",
    "src",
    "source",
    "orig_h",
    "id.orig_h",
    "source.address",
    "client_ip",
)
DESTINATION_FIELDS = (
    "destination_ip",
    "dst_ip",
    "dst",
    "destination",
    "resp_h",
    "id.resp_h",
    "destination.address",
    "server_ip",
    "host",
)
FQDN_FIELDS = (
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
)
RESPONDING_IP_FIELDS = (
    "responding_ips",
    "resolved_ips",
    "dst_ips",
    "answers",
)
COUNT_FIELDS = (
    "count",
    "connection_count",
    "connections",
    "conn_count",
    "seen",
    "queries",
    "query_count",
    "subdomains",
    "visited",
)
DURATION_FIELDS = (
    "duration",
    "duration_seconds",
    "length",
    "connection_duration",
)
PORT_FIELDS = (
    "port",
    "destination_port",
    "dst_port",
    "resp_p",
    "id.resp_p",
    "service_port",
)


def _fqdn(
    row: Mapping[str, Any],
    primitives: FindingNormalizationPrimitives,
) -> str:
    fqdn = primitives.safe_text(primitives.first(row, FQDN_FIELDS), 512)
    if fqdn:
        return fqdn
    queried = primitives.string_list(primitives.first(row, ("queried_fqdns",)))
    return queried[0] if queried else ""


def _responding_ips(
    row: Mapping[str, Any],
    primitives: FindingNormalizationPrimitives,
) -> List[str]:
    values = primitives.string_list(primitives.first(row, RESPONDING_IP_FIELDS))
    result = []
    for value in values:
        candidate = primitives.ip(value)
        if candidate:
            result.append(candidate)
    return result


def _network_values(
    row: Mapping[str, Any],
    primitives: FindingNormalizationPrimitives,
) -> _NetworkValues:
    source = primitives.ip(primitives.first(row, SOURCE_FIELDS))
    destination = primitives.ip(primitives.first(row, DESTINATION_FIELDS))
    return _NetworkValues(
        source=source,
        destination=destination,
        fqdn=_fqdn(row, primitives),
        responding_ips=_responding_ips(row, primitives),
    )


def _apply_blacklist_fallback(
    network: _NetworkValues,
    row: Mapping[str, Any],
    primitives: FindingNormalizationPrimitives,
) -> None:
    host = primitives.ip(primitives.first(row, ("host", "ip", "address")))
    if not host:
        return
    if primitives.is_internal(host):
        network.source = network.source or host
    else:
        network.destination = network.destination or host


def _apply_dns_source_fallback(
    network: _NetworkValues,
    row: Mapping[str, Any],
    primitives: FindingNormalizationPrimitives,
) -> None:
    query_rows = primitives.first(row, ("queries", "directs", "clients"))
    if not isinstance(query_rows, list):
        return
    for query in query_rows:
        candidate = primitives.ip(
            primitives.first(query, ("ip", "source_ip", "src"))
        )
        if candidate:
            network.source = candidate
            return


def _apply_module_fallbacks(
    module: str,
    network: _NetworkValues,
    row: Mapping[str, Any],
    primitives: FindingNormalizationPrimitives,
) -> None:
    if module == "blacklist":
        _apply_blacklist_fallback(network, row, primitives)
    if module == "dns_anomalies" and not network.source:
        _apply_dns_source_fallback(network, row, primitives)


def _bounded_port(value: object, primitives: FindingNormalizationPrimitives) -> int:
    port = primitives.integer_value(value)
    return port if 0 < port <= 65535 else 0


def _apply_tuple_fallbacks(
    metrics: _MetricValues,
    row: Mapping[str, Any],
    primitives: FindingNormalizationPrimitives,
) -> None:
    tuples = primitives.first(row, ("tuples",))
    if not isinstance(tuples, list) or not tuples:
        return
    if not metrics.count:
        metrics.count = len(tuples)
    first_tuple = tuples[0]
    if not isinstance(first_tuple, dict):
        return
    if not metrics.port:
        metrics.port = _bounded_port(
            primitives.first(
                first_tuple,
                ("port", "destination_port", "dst_port", "resp_p"),
            ),
            primitives,
        )
    if not metrics.protocol:
        metrics.protocol = primitives.safe_text(
            primitives.first(first_tuple, ("protocol", "proto", "transport")),
            64,
        ).upper()


def _metric_values(
    row: Mapping[str, Any],
    primitives: FindingNormalizationPrimitives,
) -> _MetricValues:
    metrics = _MetricValues(
        score=primitives.number(
            primitives.first(row, ("score", "beacon_score", "risk_score", "c2_score")),
            0.0,
        ),
        count=primitives.integer_value(primitives.first(row, COUNT_FIELDS)),
        duration=primitives.duration_seconds(primitives.first(row, DURATION_FIELDS)),
        port=_bounded_port(primitives.first(row, PORT_FIELDS), primitives),
        protocol=primitives.safe_text(
            primitives.first(row, ("protocol", "proto", "service", "transport")),
            64,
        ).upper(),
    )
    _apply_tuple_fallbacks(metrics, row, primitives)
    return metrics


def _evidence_values(
    row: Mapping[str, Any],
    primitives: FindingNormalizationPrimitives,
) -> tuple[str, str, Dict[str, Any]]:
    timing_mode = primitives.safe_text(
        primitives.first(row, ("timing_mode", "ts_mode", "time_mode", "mode")),
        128,
    )
    data_size_mode = primitives.safe_text(
        primitives.first(row, ("data_size_mode", "ds_mode", "size_mode")),
        128,
    )
    evidence = {
        "timing_mode": timing_mode,
        "data_size_mode": data_size_mode,
        "bytes": primitives.integer_value(
            primitives.first(row, ("bytes", "total_bytes", "byte_count"))
        ),
        "network": primitives.safe_text(
            primitives.first(row, ("network_name", "src_network_name")), 256
        ),
        "destination_network": primitives.safe_text(
            primitives.first(row, ("dst_network_name", "destination_network_name")),
            256,
        ),
        "ptr": primitives.safe_text(
            primitives.first(row, ("ptr", "reverse_dns", "destination_ptr")), 512
        ),
        "open": bool(primitives.first(row, ("open", "is_open")) is True),
    }
    evidence = {
        key: value
        for key, value in evidence.items()
        if value not in ("", 0, False)
    }
    return timing_mode, data_size_mode, evidence


def normalize_finding(
    module: str,
    row: Mapping[str, Any],
    primitives: FindingNormalizationPrimitives,
) -> Dict[str, Any]:
    """Normalize one finding without transport, cache, or persistence authority."""

    network = _network_values(row, primitives)
    _apply_module_fallbacks(module, network, row, primitives)
    metrics = _metric_values(row, primitives)
    timing_mode, data_size_mode, evidence = _evidence_values(row, primitives)
    finding: Dict[str, Any] = {
        "source_ip": network.source,
        "destination_ip": network.destination,
        "fqdn": network.fqdn,
        "module": module,
        "score": round(max(0.0, metrics.score), 6),
        "count": metrics.count,
        "duration": round(metrics.duration, 3),
        "duration_seconds": round(metrics.duration, 3),
        "port": metrics.port,
        "protocol": metrics.protocol,
        "timing_mode": timing_mode,
        "data_size_mode": data_size_mode,
        "responding_ips": network.responding_ips,
        "evidence": evidence,
    }
    finding["id"] = primitives.finding_id(module, finding)
    return finding
