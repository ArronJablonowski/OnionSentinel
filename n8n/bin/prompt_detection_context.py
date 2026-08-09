#!/usr/bin/env python3
"""Prepare detection, skill, and asset context for one prompt package."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable


@dataclass(frozen=True)
class DetectionContextRequest:
    """Inputs and bounded runtime paths for deterministic preparation."""

    connection: Any
    selected: Any
    include_tests: bool
    agent_role: str
    investigation_skills_path: Path
    detection_playbooks_path: Path
    asset_inventory_path: Path
    maximum_group_rows: int


@dataclass(frozen=True)
class DetectionContextSources:
    """Trusted operations retained by the legacy prompt composition root."""

    row_value: Callable[[Any, str], Any]
    alert_group_rows: Callable[..., list[Any]]
    parse_alert_json: Callable[[str], dict]
    parse_json_object: Callable[[str], dict]
    extract_rule_context: Callable[[dict, dict, Any], dict]
    load_investigation_skills: Callable[[Path], dict]
    resolve_investigation_skills: Callable[[dict, dict, str], dict]
    load_detection_playbooks: Callable[[Path], dict]
    resolve_detection_playbook: Callable[[dict, dict], dict | None]
    marker_specs: Callable[[dict, dict | None], list]
    extract_group_packet_features: Callable[[list[Any], list], dict]
    build_detection_validation: Callable[[dict, dict, dict | None], dict]
    load_asset_inventory: Callable[[Path], dict]
    resolve_asset_context: Callable[[dict, list, Any, list], dict]


@dataclass(frozen=True)
class PreparedDetectionContext:
    """Prompt-ready context and exact rows admitted to later query planning."""

    exact_validation_rows: list[Any]
    investigation_skills: dict
    detection_validation: dict
    asset_context: dict


VALIDATION_EXTRA_COLUMNS = (
    "alert_json",
    "raw_event_json",
    "rule_id",
    "timestamp",
    "source_port",
    "network_protocol",
    "transport_protocol",
    "destination_port",
)


def _selected_rule_identity(rule_context: dict) -> tuple[str, Any, str]:
    parsed = (
        rule_context.get("parsed_rule")
        if isinstance(rule_context.get("parsed_rule"), dict)
        else {}
    )
    return (
        str(rule_context.get("sid") or ""),
        rule_context.get("revision"),
        str(parsed.get("rule_sha256") or ""),
    )


def _candidate_rule_context(sources: DetectionContextSources, item: Any) -> dict:
    alert = sources.parse_alert_json(
        str(sources.row_value(item, "alert_json") or "")
    )
    raw = sources.parse_json_object(
        str(sources.row_value(item, "raw_event_json") or "")
    )
    return sources.extract_rule_context(
        alert,
        raw,
        sources.row_value(item, "rule_id"),
    )


def _identity_conflict(context: dict) -> bool:
    conflicts = context.get("identity_conflicts")
    return bool(
        isinstance(conflicts, dict)
        and any(conflicts.get(key) for key in ("sid", "revision"))
    )


def _matches_rule_identity(
    context: dict,
    selected_sid: str,
    selected_revision: Any,
    selected_digest: str,
) -> bool:
    parsed = (
        context.get("parsed_rule")
        if isinstance(context.get("parsed_rule"), dict)
        else {}
    )
    checks = [not _identity_conflict(context)]
    if selected_sid:
        checks.append(str(context.get("sid") or "") == selected_sid)
    if selected_revision is not None:
        checks.append(context.get("revision") == selected_revision)
    if selected_digest:
        checks.append(str(parsed.get("rule_sha256") or "") == selected_digest)
    return all(checks)


def select_exact_detection_group_rows(
    sources: DetectionContextSources,
    group_rows: list[Any],
    selected_rule_context: dict,
    maximum_group_rows: int,
) -> tuple[list[Any], dict]:
    """Bind packet-validation rows to the exact selected rule identity."""
    selected_sid, selected_revision, selected_digest = _selected_rule_identity(
        selected_rule_context
    )
    exact: list[Any] = []
    excluded = 0
    for item in group_rows[:maximum_group_rows]:
        context = _candidate_rule_context(sources, item)
        if _matches_rule_identity(
            context,
            selected_sid,
            selected_revision,
            selected_digest,
        ):
            exact.append(item)
        else:
            excluded += 1
    return exact, {
        "input_rows": min(len(group_rows), maximum_group_rows),
        "exact_rule_rows": len(exact),
        "excluded_nonmatching_rows": excluded,
        "input_truncated": len(group_rows) > maximum_group_rows,
        "identity": {
            "sid": selected_sid,
            "revision": selected_revision,
            "rule_sha256": selected_digest,
        },
    }


def _skill_match_context(sources: DetectionContextSources, selected: Any) -> dict:
    return {
        "event_dataset": sources.row_value(selected, "event_dataset"),
        "transport_protocol": sources.row_value(selected, "transport_protocol"),
        "network_protocol": sources.row_value(selected, "network_protocol"),
        "destination_port": sources.row_value(selected, "destination_port"),
        "rule_name": sources.row_value(selected, "rule_name"),
    }


def _nested_alert_value(alert: dict, dotted_path: str) -> Any:
    current: Any = alert
    for part in dotted_path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def _explicit_asset_values(sources: DetectionContextSources, item: Any, alert: dict):
    value = sources.row_value
    nested = _nested_alert_value
    return [
        ("ip", value(item, "source_ip"), "source"),
        ("ip", value(item, "destination_ip"), "destination"),
        ("ip", nested(alert, "client.ip"), "client"),
        ("ip", nested(alert, "server.ip"), "server"),
        ("ip", nested(alert, "host.ip"), "host"),
        ("mac", nested(alert, "source.mac"), "source"),
        ("mac", nested(alert, "destination.mac"), "destination"),
        ("mac", nested(alert, "client.mac"), "client"),
        ("mac", nested(alert, "server.mac"), "server"),
        ("hostname", nested(alert, "source.domain"), "source"),
        ("hostname", nested(alert, "destination.domain"), "destination"),
        ("hostname", nested(alert, "client.domain"), "client"),
        ("hostname", nested(alert, "server.domain"), "server"),
        ("hostname", nested(alert, "host.hostname"), "host"),
        ("hostname", nested(alert, "host.name"), "host"),
    ]


def extract_asset_observables_and_events(
    sources: DetectionContextSources,
    group_rows: list[Any],
    maximum_group_rows: int,
) -> tuple[list[dict], list[dict]]:
    """Extract explicit endpoint identifiers without promoting sensor fields."""
    observables: list[dict] = []
    events: list[dict] = []
    for item in group_rows[:maximum_group_rows]:
        alert = sources.parse_alert_json(
            str(sources.row_value(item, "alert_json") or "")
        )
        observables.extend(
            {"type": kind, "value": value, "role": role}
            for kind, value, role in _explicit_asset_values(sources, item, alert)
            if value not in (None, "")
        )
        events.append(
            {
                "source_ip": sources.row_value(item, "source_ip"),
                "destination_ip": sources.row_value(item, "destination_ip"),
                "destination_port": sources.row_value(item, "destination_port"),
                "protocol": sources.row_value(item, "transport_protocol"),
            }
        )
    return observables, events


def _load_rule_and_skills(
    sources: DetectionContextSources,
    request: DetectionContextRequest,
) -> tuple[list[Any], dict, dict]:
    validation_rows = sources.alert_group_rows(
        request.connection,
        request.selected,
        include_tests=request.include_tests,
        extra_columns=VALIDATION_EXTRA_COLUMNS,
        row_limit=request.maximum_group_rows + 1,
    )
    selected_alert = sources.parse_alert_json(
        str(sources.row_value(request.selected, "alert_json") or "")
    )
    selected_raw_event = sources.parse_json_object(
        str(sources.row_value(request.selected, "raw_event_json") or "")
    )
    rule_context = sources.extract_rule_context(
        selected_alert,
        selected_raw_event,
        sources.row_value(request.selected, "rule_id"),
    )
    skill_registry = sources.load_investigation_skills(
        request.investigation_skills_path
    )
    skill_selection = sources.resolve_investigation_skills(
        skill_registry,
        _skill_match_context(sources, request.selected),
        request.agent_role,
    )
    return validation_rows, rule_context, skill_selection


def _validate_detection(
    sources: DetectionContextSources,
    request: DetectionContextRequest,
    validation_rows: list[Any],
    rule_context: dict,
) -> tuple[list[Any], dict]:
    exact_rows, validation_scope = select_exact_detection_group_rows(
        sources,
        validation_rows,
        rule_context,
        request.maximum_group_rows,
    )
    playbook_registry = sources.load_detection_playbooks(
        request.detection_playbooks_path
    )
    playbook = sources.resolve_detection_playbook(playbook_registry, rule_context)
    packet_features = sources.extract_group_packet_features(
        exact_rows,
        sources.marker_specs(rule_context, playbook),
    )
    packet_features["group_scope"] = validation_scope
    if validation_scope["input_truncated"]:
        packet_features["truncated"] = True
    detection_validation = sources.build_detection_validation(
        rule_context,
        packet_features,
        playbook,
    )
    return exact_rows, detection_validation


def _resolve_assets(
    sources: DetectionContextSources,
    request: DetectionContextRequest,
    exact_rows: list[Any],
) -> dict:
    asset_inventory = sources.load_asset_inventory(request.asset_inventory_path)
    asset_observables, network_events = extract_asset_observables_and_events(
        sources,
        exact_rows,
        request.maximum_group_rows,
    )
    return sources.resolve_asset_context(
        asset_inventory,
        asset_observables,
        sources.row_value(request.selected, "timestamp")
        or sources.row_value(request.selected, "last_seen"),
        network_events,
    )


def prepare_detection_context(
    sources: DetectionContextSources,
    request: DetectionContextRequest,
) -> PreparedDetectionContext:
    """Build exact-group detection and asset facts in their required order."""
    validation_rows, rule_context, skill_selection = _load_rule_and_skills(
        sources,
        request,
    )
    exact_rows, detection_validation = _validate_detection(
        sources,
        request,
        validation_rows,
        rule_context,
    )
    return PreparedDetectionContext(
        exact_validation_rows=exact_rows,
        investigation_skills=skill_selection,
        detection_validation=detection_validation,
        asset_context=_resolve_assets(sources, request, exact_rows),
    )
