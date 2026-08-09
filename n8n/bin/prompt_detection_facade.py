#!/usr/bin/env python3
"""Configured query and exact-detection context for prompt construction."""
from __future__ import annotations

import datetime as dt

from asset_inventory import load_asset_inventory, resolve_asset_context
from detection_validation import (
    build_detection_validation,
    extract_group_packet_features,
    extract_rule_context,
    load_detection_playbooks,
    marker_specs,
    resolve_detection_playbook,
)
from investigation_skills import (
    load_investigation_skills,
    resolve_investigation_skills,
)
from prompt_builder_policy import (
    ALERT_INDEX_RE,
    EVENT_TUPLE_PATHS,
    INVESTIGATION_CONTRACT,
    INVESTIGATION_CONTRACT_PACKS,
    INVESTIGATION_DERIVED_FILTERS,
    INVESTIGATION_DERIVED_OPERATIONS,
    INVESTIGATION_EVENT_TUPLE_ATOM_RE,
    INVESTIGATION_QUERY_CONTRACT,
    INVESTIGATION_QUERY_MAX_PER_ROUND,
    INVESTIGATION_QUERY_MAX_ROUNDS,
    INVESTIGATION_QUERY_MAX_TOTAL,
    INVESTIGATION_QUERY_PACK_DESCRIPTIONS,
    INVESTIGATION_QUERY_PACKS,
    INVESTIGATION_QUERY_V2,
    INVESTIGATION_SECURITY_ONION_PURPOSES,
    MAX_DETECTION_GROUP_ROWS,
    PACK_ROLE_MODE,
    SAFE_ELASTIC_ID_RE,
    SAFE_PIVOT_ATOM_RE,
    SAFE_PIVOT_DOMAIN_RE,
)
from prompt_correlation_facts import parse_project_datetime
from prompt_detection_context import (
    DetectionContextSources,
    extract_asset_observables_and_events,
    select_exact_detection_group_rows,
)
from prompt_evidence_facade import (
    alert_group_rows,
    parse_alert_json,
    parse_json_object,
    sqlite_value,
)
from prompt_investigation_query_context import (
    QueryContextPolicy,
    QueryContextSources,
    build_investigation_query_context,
)
from prompt_role_task import build_agent_task, build_model_policy


def _nested_alert_value(alert: dict, dotted_path: str) -> object:
    current: object = alert
    for part in dotted_path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def investigation_query_context_policy() -> QueryContextPolicy:
    return QueryContextPolicy(
        query_contract=INVESTIGATION_QUERY_CONTRACT,
        query_v2=INVESTIGATION_QUERY_V2,
        query_packs=tuple(INVESTIGATION_QUERY_PACKS),
        pack_descriptions=INVESTIGATION_QUERY_PACK_DESCRIPTIONS,
        security_onion_purposes=INVESTIGATION_SECURITY_ONION_PURPOSES,
        derived_operations=INVESTIGATION_DERIVED_OPERATIONS,
        derived_filters=INVESTIGATION_DERIVED_FILTERS,
        contract_packs=INVESTIGATION_CONTRACT_PACKS,
        event_tuple_paths=EVENT_TUPLE_PATHS,
        pack_role_mode=PACK_ROLE_MODE,
        allowed_actor_roles=frozenset(INVESTIGATION_CONTRACT.ALLOWED_ACTOR_ROLES),
        event_tuple_atom_pattern=INVESTIGATION_EVENT_TUPLE_ATOM_RE,
        alert_index_pattern=ALERT_INDEX_RE,
        elastic_id_pattern=SAFE_ELASTIC_ID_RE,
        pivot_atom_pattern=SAFE_PIVOT_ATOM_RE,
        pivot_domain_pattern=SAFE_PIVOT_DOMAIN_RE,
        max_rounds=INVESTIGATION_QUERY_MAX_ROUNDS,
        max_queries_total=INVESTIGATION_QUERY_MAX_TOTAL,
        max_queries_per_round=INVESTIGATION_QUERY_MAX_PER_ROUND,
    )


def investigation_query_context_sources() -> QueryContextSources:
    return QueryContextSources(
        parse_alert=parse_alert_json,
        parse_json_object=parse_json_object,
        row_value=sqlite_value,
        nested_value=_nested_alert_value,
        parse_datetime=parse_project_datetime,
        now_utc=lambda: dt.datetime.now(dt.timezone.utc),
    )


def investigation_query_context(
    selected,
    group_rows,
    group_id: str,
    actor_role: str,
    pcap_available: bool,
) -> tuple[dict, dict]:
    return build_investigation_query_context(
        investigation_query_context_policy(),
        investigation_query_context_sources(),
        selected,
        group_rows,
        group_id,
        actor_role,
        pcap_available,
    )


def _detection_context_sources() -> DetectionContextSources:
    return DetectionContextSources(
        row_value=sqlite_value,
        alert_group_rows=alert_group_rows,
        parse_alert_json=parse_alert_json,
        parse_json_object=parse_json_object,
        extract_rule_context=extract_rule_context,
        load_investigation_skills=load_investigation_skills,
        resolve_investigation_skills=resolve_investigation_skills,
        load_detection_playbooks=load_detection_playbooks,
        resolve_detection_playbook=resolve_detection_playbook,
        marker_specs=marker_specs,
        extract_group_packet_features=extract_group_packet_features,
        build_detection_validation=build_detection_validation,
        load_asset_inventory=load_asset_inventory,
        resolve_asset_context=resolve_asset_context,
    )


def asset_observables_and_events(group_rows) -> tuple[list[dict], list[dict]]:
    return extract_asset_observables_and_events(
        _detection_context_sources(),
        group_rows,
        MAX_DETECTION_GROUP_ROWS,
    )


def exact_detection_group_rows(
    group_rows,
    selected_rule_context: dict,
) -> tuple[list, dict]:
    return select_exact_detection_group_rows(
        _detection_context_sources(),
        group_rows,
        selected_rule_context,
        MAX_DETECTION_GROUP_ROWS,
    )


def model_policy(level: str | None) -> dict:
    return build_model_policy(level)


def agent_task(agent_role: str, *, blind_reanalysis: bool = False) -> str:
    return build_agent_task(agent_role, blind_reanalysis=blind_reanalysis)
