"""Deterministic protocol and historical-evidence query planning."""

from __future__ import annotations

import copy
import datetime as dt
from dataclasses import dataclass
import re
from typing import Any, Callable, Mapping


@dataclass(frozen=True)
class Policy:
    """Fixed planning limits and pack role semantics."""

    pack_role_modes: Mapping[str, str]
    request_size: int = 100
    event_window_minutes: int = 5
    attribution_window_hours: int = 12


@dataclass(frozen=True)
class Dependencies:
    """Trusted policy and normalization ports used by the pure planner."""

    is_incident_responder: Callable[[dict[str, Any]], bool]
    canonical_digest: Callable[[Any], str]
    parse_utc: Callable[[Any, str], dt.datetime]
    utc_text: Callable[[dt.datetime], str]
    pack_event_tuple_fields: Callable[[str], Any]
    query_error: type[Exception]
    is_historical_reader: Callable[[dict[str, Any]], bool] = (
        lambda _package: False
    )


@dataclass(frozen=True)
class PlanningContext:
    capability: dict[str, Any]
    local: dict[str, Any]
    alert: dict[str, Any]
    trusted_entries: list[dict[str, Any]]
    incident_responder: bool


@dataclass(frozen=True)
class SelectedEvent:
    entry: dict[str, Any]
    event_tuple: dict[str, Any]
    protocol: str
    rule_name: str
    anchor: dt.datetime
    observables: dict[str, list[str]]
    advertised_packs: frozenset[str]


def plan(
    prompt_package: dict[str, Any],
    *,
    policy: Policy,
    dependencies: Dependencies,
) -> list[dict[str, Any]]:
    """Compile fixed query packs from collector-authorized event context."""
    context = _planning_context(prompt_package, dependencies)
    if context is None:
        return []
    selected = _selected_event(context, policy, dependencies)
    if selected is None:
        return []
    output = (
        _protocol_requests(selected, policy, dependencies)
        if context.incident_responder
        else []
    )
    attribution = _attribution_request(context, selected, policy, dependencies)
    if attribution is not None:
        output.append(attribution)
    return output


def _planning_context(
    package: dict[str, Any], dependencies: Dependencies
) -> PlanningContext | None:
    incident_responder = dependencies.is_incident_responder(package)
    if not incident_responder and not dependencies.is_historical_reader(package):
        return None
    capability = package.get("investigation_query_capability")
    local = package.get("_local_investigation_query_context")
    if not isinstance(capability, dict) or not capability.get("enabled"):
        return None
    if not isinstance(local, dict):
        return None
    entries = _trusted_entries(local.get("permitted_event_tuples"))
    if not entries:
        return None
    alert = package.get("alert")
    return PlanningContext(
        capability=capability,
        local=local,
        alert=alert if isinstance(alert, dict) else {},
        trusted_entries=entries,
        incident_responder=incident_responder,
    )


def _trusted_entries(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [
        item for item in value
        if isinstance(item, dict) and isinstance(item.get("event_tuple"), dict)
    ]


def _selected_event(
    context: PlanningContext,
    policy: Policy,
    dependencies: Dependencies,
) -> SelectedEvent | None:
    anchor_tuple = _alert_anchor_tuple(context.alert)
    entry = min(
        context.trusted_entries,
        key=lambda candidate: _entry_rank(
            candidate, anchor_tuple, dependencies.canonical_digest
        ),
    )
    event_tuple = entry["event_tuple"]
    anchor = _anchor_time(context, dependencies)
    if anchor is None:
        return None
    protocol = _protocol(context.alert)
    ips = [
        str(value) for value in (
            event_tuple.get("source_ip"), event_tuple.get("destination_ip")
        ) if str(value or "").strip()
    ]
    return SelectedEvent(
        entry=entry,
        event_tuple=event_tuple,
        protocol=protocol,
        rule_name=str(context.alert.get("rule_name") or ""),
        anchor=anchor,
        observables={
            "ips": list(dict.fromkeys(ips)),
            "domains": [],
            "hosts": [],
            "users": [],
        },
        advertised_packs=_advertised_packs(context.capability),
    )


def _alert_anchor_tuple(alert: dict[str, Any]) -> dict[str, Any]:
    raw = _mapping(alert.get("raw_alert_subset"))
    source = _mapping(raw.get("source"))
    destination = _mapping(raw.get("destination"))
    network = _mapping(raw.get("network"))
    rule = _mapping(alert.get("rule_context"))
    candidates = {
        "source_ip": _first(alert.get("source_ip"), source.get("ip")),
        "destination_ip": _first(alert.get("destination_ip"), destination.get("ip")),
        "source_port": _first(alert.get("source_port"), source.get("port")),
        "destination_port": _first(alert.get("destination_port"), destination.get("port")),
        "transport": _first(alert.get("transport_protocol"), network.get("transport")),
        "protocol": _first(alert.get("network_protocol"), network.get("protocol")),
        "community_id": _first(alert.get("community_id"), network.get("community_id")),
        "rule_id": _first(alert.get("rule_id"), rule.get("record_rule_id"), rule.get("sid")),
    }
    return _compact_mapping(candidates)


def _first(*values: Any) -> Any:
    return next((value for value in values if value), None)


def _compact_mapping(values: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in values.items() if value not in (None, "")}


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _entry_rank(
    entry: dict[str, Any],
    anchor: dict[str, Any],
    canonical_digest: Callable[[Any], str],
) -> tuple[int, int, str]:
    candidate = entry["event_tuple"]
    mismatches = sum(
        1 for key, value in anchor.items()
        if key in candidate and _casefold(candidate[key]) != _casefold(value)
    )
    matches = sum(
        1 for key, value in anchor.items()
        if key in candidate and _casefold(candidate[key]) == _casefold(value)
    )
    return mismatches, -matches, canonical_digest(entry)


def _casefold(value: Any) -> str:
    return str(value).lower()


def _protocol(alert: dict[str, Any]) -> str:
    rule = _mapping(alert.get("rule_context"))
    deployed = _mapping(rule.get("deployed_rule"))
    return str(
        deployed.get("protocol") or _nested_value(alert, "network.protocol") or ""
    ).strip().lower()


def _nested_value(value: dict[str, Any], path: str) -> Any:
    current: Any = value
    for part in path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def _anchor_time(
    context: PlanningContext, dependencies: Dependencies
) -> dt.datetime | None:
    for candidate in (
        context.local.get("anchor_time"),
        context.capability.get("anchor_time"),
    ):
        parsed = _try_utc(candidate, "authorization anchor_time", dependencies)
        if parsed is not None:
            return parsed
    midpoint = _envelope_midpoint(context.local.get("time_envelope"), dependencies)
    if midpoint is not None:
        return midpoint
    timestamp = re.sub(r"\s+", " ", str(context.alert.get("timestamp") or "").strip())
    return _try_utc(timestamp, "selected alert timestamp", dependencies)


def _try_utc(
    value: Any, label: str, dependencies: Dependencies
) -> dt.datetime | None:
    if value in (None, ""):
        return None
    try:
        return dependencies.parse_utc(value, label)
    except dependencies.query_error:
        return None


def _envelope_midpoint(value: Any, dependencies: Dependencies) -> dt.datetime | None:
    if not isinstance(value, dict):
        return None
    start = _try_utc(value.get("start"), "authorization envelope start", dependencies)
    end = _try_utc(value.get("end"), "authorization envelope end", dependencies)
    if start is None or end is None or end <= start:
        return None
    return start + (end - start) / 2


def _advertised_packs(capability: dict[str, Any]) -> frozenset[str]:
    backends = capability.get("backends")
    elastic = backends.get("elastic") if isinstance(backends, dict) else None
    packs = elastic.get("packs") if isinstance(elastic, dict) else None
    return frozenset(str(pack) for pack in packs) if isinstance(packs, list) else frozenset()


def _protocol_packs(protocol: str, rule_name: str) -> tuple[str, str]:
    if protocol == "http":
        return "zeek_http", "zeek_files"
    if protocol in {"tls", "ssl"}:
        return "zeek_tls", "zeek_anomalies"
    if protocol == "dns":
        return "dns_activity", "zeek_tls"
    if protocol == "ssh":
        return "zeek_ssh", "system_auth"
    if protocol == "quic":
        return "zeek_quic", "network_flow"
    if protocol == "udp" and "stun" in rule_name.lower():
        return "zeek_stun", "network_flow"
    return "network_flow", "alert_context"


def _protocol_requests(
    selected: SelectedEvent,
    policy: Policy,
    dependencies: Dependencies,
) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for pack in _protocol_packs(selected.protocol, selected.rule_name):
        if pack not in selected.advertised_packs:
            continue
        event_tuple = _safe_event_tuple(selected, pack, policy, dependencies)
        output.append(_request(
            pack, selected, event_tuple, policy,
            first=not output,
        ))
    _format_protocol_windows(output, dependencies)
    return output


def _safe_event_tuple(
    selected: SelectedEvent,
    pack: str,
    policy: Policy,
    dependencies: Dependencies,
) -> dict[str, Any]:
    allowed = dependencies.pack_event_tuple_fields(pack)
    projected = {
        key: value for key, value in selected.event_tuple.items()
        if key in allowed and value not in (None, "")
    }
    role_mode = policy.pack_role_modes.get(pack)
    role_semantics = str(selected.entry.get("role_semantics") or "").strip()
    unsafe = role_mode == "cross_sensor" or (
        role_mode == "zeek_originator_responder"
        and role_semantics != "zeek_originator_responder"
    )
    return {} if unsafe and "community_id" not in projected else projected


def _request(
    pack: str,
    selected: SelectedEvent,
    event_tuple: dict[str, Any],
    policy: Policy,
    *,
    first: bool,
) -> dict[str, Any]:
    start = selected.anchor - dt.timedelta(minutes=policy.event_window_minutes)
    end = selected.anchor + dt.timedelta(minutes=policy.event_window_minutes)
    parameters = {
        "pack": pack,
        "window": {"start": "", "end": ""},
        "observables": copy.deepcopy(selected.observables),
        **({"event_tuple": event_tuple} if event_tuple else {}),
        "size": policy.request_size,
        "aggregation": "events" if first else "timeline",
    }
    # UTC formatting is installed by _protocol_requests after construction.
    parameters["window"] = {"start": start, "end": end}
    return {
        "query_id": f"deterministic-{pack}",
        "backend": "elastic",
        "purpose": "validate_detection" if first else "establish_timeline",
        "parameters": parameters,
    }


def _format_protocol_windows(
    requests: list[dict[str, Any]], dependencies: Dependencies
) -> None:
    for request in requests:
        window = request["parameters"]["window"]
        request["parameters"]["window"] = {
            "start": dependencies.utc_text(window["start"]),
            "end": dependencies.utc_text(window["end"]),
        }


def _attribution_request(
    context: PlanningContext,
    selected: SelectedEvent,
    policy: Policy,
    dependencies: Dependencies,
) -> dict[str, Any] | None:
    if not _attribution_allowed(selected):
        return None
    start, end = _attribution_window(context, selected.anchor, policy, dependencies)
    if end <= start:
        return None
    event_tuple = {
        key: selected.event_tuple[key]
        for key in ("source_ip", "destination_ip", "destination_port", "transport")
        if selected.event_tuple.get(key) not in (None, "")
    }
    return {
        "query_id": "deterministic-osquery-history-attribution",
        "backend": "elastic",
        "purpose": "test_benign_hypothesis",
        "parameters": {
            "pack": "osquery_history",
            "window": {
                "start": dependencies.utc_text(start),
                "end": dependencies.utc_text(end),
            },
            "observables": copy.deepcopy(selected.observables),
            "event_tuple": event_tuple,
            "size": policy.request_size,
            "aggregation": "anchor_nearest",
        },
    }


def _attribution_allowed(selected: SelectedEvent) -> bool:
    return (
        selected.protocol in {"http", "tls", "ssl", "dns"}
        and "osquery_history" in selected.advertised_packs
        and selected.event_tuple.get("source_ip") not in (None, "")
        and selected.event_tuple.get("destination_ip") not in (None, "")
    )


def _attribution_window(
    context: PlanningContext,
    anchor: dt.datetime,
    policy: Policy,
    dependencies: Dependencies,
) -> tuple[dt.datetime, dt.datetime]:
    delta = dt.timedelta(hours=policy.attribution_window_hours)
    default = anchor - delta, anchor + delta
    envelope = context.local.get("time_envelope")
    if not isinstance(envelope, dict):
        return default
    start = _try_utc(envelope.get("start"), "authorization envelope start", dependencies)
    end = _try_utc(envelope.get("end"), "authorization envelope end", dependencies)
    if start is None or end is None:
        return default
    return max(default[0], start), min(default[1], end)
