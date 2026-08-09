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
    exact_detection_group_rows: Callable[[list[Any], dict], tuple[list[Any], dict]]
    load_detection_playbooks: Callable[[Path], dict]
    resolve_detection_playbook: Callable[[dict, dict], dict | None]
    marker_specs: Callable[[dict, dict | None], list]
    extract_group_packet_features: Callable[[list[Any], list], dict]
    build_detection_validation: Callable[[dict, dict, dict | None], dict]
    load_asset_inventory: Callable[[Path], dict]
    asset_observables_and_events: Callable[[list[Any]], tuple[list, list]]
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


def _skill_match_context(sources: DetectionContextSources, selected: Any) -> dict:
    return {
        "event_dataset": sources.row_value(selected, "event_dataset"),
        "transport_protocol": sources.row_value(selected, "transport_protocol"),
        "network_protocol": sources.row_value(selected, "network_protocol"),
        "destination_port": sources.row_value(selected, "destination_port"),
        "rule_name": sources.row_value(selected, "rule_name"),
    }


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
    exact_rows, validation_scope = sources.exact_detection_group_rows(
        validation_rows,
        rule_context,
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
    asset_observables, network_events = sources.asset_observables_and_events(
        exact_rows
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
