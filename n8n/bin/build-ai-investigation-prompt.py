#!/usr/bin/env python3
"""Build a local-first AI investigation prompt package from alert-store SQLite.

The script does not call an LLM. It prepares a bounded evidence bundle and a
strict JSON response contract that can be sent to Hermes, Ollama, or a hosted
frontier model depending on the escalation policy.
"""
from __future__ import annotations

import argparse
import datetime as dt
import sqlite3
import sys
from pathlib import Path
from typing import Iterable


BIN_DIR = Path(__file__).resolve().parent
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))
from agent_memory import (
    MEMORY_ROLES,
    build_agent_memory_context,
    role_memory_file,
    role_prompt_file,
    role_second_opinion_prompt_file,
)
from incident_evidence_contract import validate_incident_evidence_artifact
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
from prompt_incident_evidence_projection import (
    project_incident_evidence_hits as project_evidence_hits,
    project_incident_evidence_osquery_rows as project_evidence_osquery_rows,
    reject_preprojected_incident_evidence_source as reject_preprojected_source,
)
from prompt_incident_grounding import (
    IncidentGroundingSources,
    immutable_query_provenance,
    mandatory_grounding_digest,
)
from prompt_builder_cli import (
    PromptBuilderCliDefaults,
    PromptBuilderCliSources,
    parse_prompt_builder_args,
)
from prompt_builder_io import (
    load_bounded_json_mapping,
    load_prompt_text,
    normalized_int,
    output_filename_timestamp,
    parse_json_mapping,
    read_bounded_bytes,
    safe_output_filename,
)
from prompt_builder_policy import (
    ALERT_INDEX_RE,
    DEFAULT_AGENT_MEMORY_DIR,
    DEFAULT_AI_ANALYSIS_DIR,
    DEFAULT_ASSET_INVENTORY_FILE,
    DEFAULT_DB,
    DEFAULT_DETECTION_PLAYBOOKS_FILE,
    DEFAULT_INVESTIGATION_SKILLS_FILE,
    DEFAULT_MAX_PACKAGE_BYTES,
    DEFAULT_OUT,
    DEFAULT_PCAP_ANALYSIS_DIR,
    DEFAULT_ROLLUPS,
    DEFAULT_SECOND_OPINION_PROMPT_FILE,
    DEFAULT_SHARED_AGENT_MEMORY_FILE,
    DEFAULT_SOC_ANALYST_MEMORY_FILE,
    DEFAULT_SYSTEM_PROMPT,
    DEFAULT_SYSTEM_PROMPT_FILE,
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
    MAX_ARTIFACT_JSON_BYTES,
    MAX_DETECTION_GROUP_ROWS,
    MAX_INCIDENT_EVIDENCE_BYTES,
    MAX_SYSTEM_PROMPT_BYTES,
    PACK_ROLE_MODE,
    SAFE_ELASTIC_ID_RE,
    SAFE_PIVOT_ATOM_RE,
    SAFE_PIVOT_DOMAIN_RE,
    TEST_PREFIXES,
)
from prompt_alert_store import (
    build_test_alert_filter,
    derive_alert_group_key,
    query_row,
    query_rows,
    sqlite_row_value,
    stable_alert_group_id,
)
from prompt_correlation_facts import (
    COMMUNITY_ID_V1_RE,
    parse_project_datetime,
)
from prompt_investigation_query_context import (
    QueryContextPolicy,
    QueryContextSources,
    build_investigation_query_context,
)
from prompt_detection_context import (
    DetectionContextSources,
    extract_asset_observables_and_events,
    select_exact_detection_group_rows,
)
from prompt_evidence_admission import (
    blind_model_authored_context,
)
from prompt_evidence_facade import (
    alert_group_rows,
    analyst_state_context,
    authorized_activity_context,
    canonical_authorized_activity_entry,
    compact_alert,
    compact_pcap_analysis,
    compact_public_enrichment_record,
    correlated_alert_context,
    execution_lineage,
    grouped_alert_context,
    pcap_evidence_context,
    pcap_request_context,
    prior_analysis_context,
    public_enrichment_context,
    related_alerts,
    select_alert,
)
from prompt_package_compactor import (
    PackageCompactionSources,
    compact_package_to_budget as compact_prompt_package,
)
from prompt_package_orchestrator import (
    PromptPackageWorkflowPolicy,
    PromptPackageWorkflowSources,
    build_prepared_prompt_package,
)
from prompt_role_task import build_agent_task, build_model_policy


def project_incident_evidence_hits(
    incident_evidence: dict,
    *,
    limit: int,
    reason: str,
) -> int:
    """Compatibility delegate for bounded Elastic evidence projection."""
    return project_evidence_hits(
        incident_evidence,
        limit=limit,
        reason=reason,
    )


def project_incident_evidence_osquery_rows(
    incident_evidence: dict,
    *,
    limit: int,
    max_retained_bytes: int,
    max_row_bytes: int,
    reason: str,
) -> int:
    """Compatibility delegate for bounded OSQuery evidence projection."""
    return project_evidence_osquery_rows(
        incident_evidence,
        limit=limit,
        max_retained_bytes=max_retained_bytes,
        max_row_bytes=max_row_bytes,
        reason=reason,
    )


def reject_preprojected_incident_evidence_source(
    incident_evidence: dict,
) -> None:
    """Compatibility delegate for rejecting preprojected source evidence."""
    reject_preprojected_source(incident_evidence)


def parse_args() -> argparse.Namespace:
    return parse_prompt_builder_args(
        PromptBuilderCliDefaults(
            db=DEFAULT_DB,
            rollup_dir=DEFAULT_ROLLUPS,
            out_dir=DEFAULT_OUT,
            system_prompt_file=DEFAULT_SYSTEM_PROMPT_FILE,
            second_opinion_prompt_file=DEFAULT_SECOND_OPINION_PROMPT_FILE,
            agent_memory_dir=DEFAULT_AGENT_MEMORY_DIR,
            agent_memory_file=DEFAULT_SOC_ANALYST_MEMORY_FILE,
            shared_memory_file=DEFAULT_SHARED_AGENT_MEMORY_FILE,
            pcap_analysis_dir=DEFAULT_PCAP_ANALYSIS_DIR,
            analysis_dir=DEFAULT_AI_ANALYSIS_DIR,
            detection_playbooks=DEFAULT_DETECTION_PLAYBOOKS_FILE,
            investigation_skills=DEFAULT_INVESTIGATION_SKILLS_FILE,
            asset_inventory_file=DEFAULT_ASSET_INVENTORY_FILE,
            max_package_bytes=DEFAULT_MAX_PACKAGE_BYTES,
        ),
        PromptBuilderCliSources(
            memory_roles=frozenset(MEMORY_ROLES),
            role_prompt_file=role_prompt_file,
            role_second_opinion_prompt_file=role_second_opinion_prompt_file,
            role_memory_file=role_memory_file,
        ),
    )


def project_now() -> str:
    return dt.datetime.now().astimezone().replace(microsecond=0).isoformat().replace("T", "  ")


def filename_timestamp(value: str) -> str:
    """Compatibility delegate for projected output timestamps."""
    return output_filename_timestamp(value)


def safe_filename(value: str) -> str:
    """Compatibility delegate for bounded output filenames."""
    return safe_output_filename(value)


def rows(conn: sqlite3.Connection, sql: str, params: Iterable[object] = ()) -> list[sqlite3.Row]:
    """Compatibility delegate for read-only multi-row queries."""
    return query_rows(conn, sql, params)


def row(conn: sqlite3.Connection, sql: str, params: Iterable[object] = ()) -> sqlite3.Row | None:
    """Compatibility delegate for read-only single-row queries."""
    return query_row(conn, sql, params)


def test_filter_sql(prefix: str = "alert_id") -> tuple[str, list[object]]:
    """Compatibility delegate for the test-alert exclusion predicate."""
    return build_test_alert_filter(TEST_PREFIXES, prefix)


def parse_alert_json(value: str | None) -> dict:
    """Compatibility delegate for fail-soft alert JSON parsing."""
    return parse_json_mapping(value)


def parse_json_object(value: str | None) -> dict:
    """Compatibility delegate for fail-soft JSON object parsing."""
    return parse_json_mapping(value)


def safe_int(value: object, default: int = 0) -> int:
    """Compatibility delegate for forgiving integer normalization."""
    return normalized_int(value, default)


def read_bytes_bounded(path: Path, max_bytes: int) -> bytes:
    """Compatibility delegate for bounded runtime artifact reads."""
    return read_bounded_bytes(path, max_bytes)


def load_json_bounded(path: Path, max_bytes: int = MAX_ARTIFACT_JSON_BYTES) -> dict:
    """Compatibility delegate for bounded object-root JSON loading."""
    return load_bounded_json_mapping(path, max_bytes)


def load_system_prompt(path: Path) -> str:
    """Load the analyst-editable system prompt used by the AI runner."""
    return load_prompt_text(
        path,
        MAX_SYSTEM_PROMPT_BYTES,
        DEFAULT_SYSTEM_PROMPT,
    )


def sqlite_value(row_value: sqlite3.Row, key: str, default: object = None) -> object:
    """Compatibility delegate for legacy-safe SQLite row access."""
    return sqlite_row_value(row_value, key, default)


def alert_group_key(row_value: sqlite3.Row) -> str:
    """Return the same duplicate-group key used by the dashboard and AI scheduler."""
    return derive_alert_group_key(row_value)


def alert_group_id(group_key: str) -> str:
    """Compatibility delegate for stable alert-group identity."""
    return stable_alert_group_id(group_key)


def _nested_alert_value(alert: dict, dotted_path: str) -> object:
    current: object = alert
    for part in dotted_path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def asset_observables_and_events(group_rows: list[sqlite3.Row]) -> tuple[list[dict], list[dict]]:
    """Compatibility delegate for explicit endpoint evidence extraction."""
    return extract_asset_observables_and_events(
        _detection_context_sources(),
        group_rows,
        MAX_DETECTION_GROUP_ROWS,
    )


def investigation_query_context(
    selected: sqlite3.Row,
    group_rows: list[sqlite3.Row],
    group_id: str,
    actor_role: str,
    pcap_available: bool,
) -> tuple[dict, dict]:
    """Compatibility delegate for broker query-context projection."""
    return build_investigation_query_context(
        investigation_query_context_policy(),
        investigation_query_context_sources(),
        selected,
        group_rows,
        group_id,
        actor_role,
        pcap_available,
    )


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
        allowed_actor_roles=frozenset(
            INVESTIGATION_CONTRACT.ALLOWED_ACTOR_ROLES
        ),
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


def exact_detection_group_rows(
    group_rows: list[sqlite3.Row],
    selected_rule_context: dict,
) -> tuple[list[sqlite3.Row], dict]:
    """Compatibility delegate for exact deployed-rule row binding."""
    return select_exact_detection_group_rows(
        _detection_context_sources(),
        group_rows,
        selected_rule_context,
        MAX_DETECTION_GROUP_ROWS,
    )


def model_policy(level: str | None) -> dict:
    """Compatibility delegate for hosted-review and prompt-privacy policy."""
    return build_model_policy(level)


def agent_task(agent_role: str, *, blind_reanalysis: bool = False) -> str:
    """Compatibility delegate for immutable role-specific objectives."""
    return build_agent_task(agent_role, blind_reanalysis=blind_reanalysis)


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


def _package_workflow_sources() -> PromptPackageWorkflowSources:
    return PromptPackageWorkflowSources(
        grouped_alert_context=grouped_alert_context,
        pcap_evidence_context=pcap_evidence_context,
        public_enrichment_context=public_enrichment_context,
        authorized_activity_context=authorized_activity_context,
        analyst_state_context=analyst_state_context,
        correlated_alert_context=correlated_alert_context,
        compact_alert=compact_alert,
        detection_context_sources=_detection_context_sources,
        investigation_query_context=investigation_query_context,
        build_agent_memory_context=build_agent_memory_context,
        blind_model_authored_context=blind_model_authored_context,
        load_json_bounded=load_json_bounded,
        validate_incident_evidence=validate_incident_evidence_artifact,
        reject_preprojected_incident_evidence=(
            reject_preprojected_incident_evidence_source
        ),
        project_incident_evidence_hits=project_incident_evidence_hits,
        load_system_prompt=load_system_prompt,
        agent_task=agent_task,
        prior_analysis_context=prior_analysis_context,
        related_alerts=related_alerts,
        query_rows=rows,
        execution_lineage=execution_lineage,
        project_now=project_now,
        model_policy=model_policy,
    )


def build_package(conn: sqlite3.Connection, selected: sqlite3.Row, args: argparse.Namespace) -> dict:
    """Compatibility delegate for ordered prompt-package construction."""
    return build_prepared_prompt_package(
        _package_workflow_sources(),
        PromptPackageWorkflowPolicy(
            default_investigation_skills_path=DEFAULT_INVESTIGATION_SKILLS_FILE,
            default_detection_playbooks_path=DEFAULT_DETECTION_PLAYBOOKS_FILE,
            default_asset_inventory_path=DEFAULT_ASSET_INVENTORY_FILE,
            maximum_detection_group_rows=MAX_DETECTION_GROUP_ROWS,
            maximum_incident_evidence_bytes=MAX_INCIDENT_EVIDENCE_BYTES,
            query_packs=tuple(INVESTIGATION_QUERY_PACKS),
            query_v2=INVESTIGATION_QUERY_V2,
        ),
        conn,
        selected,
        args,
    )


def incident_prompt_immutable_query_provenance(incident: dict) -> dict:
    """Compatibility delegate for immutable incident query provenance."""
    return immutable_query_provenance(incident)


def incident_prompt_mandatory_grounding_digest(package: dict) -> str:
    """Compatibility delegate for mandatory incident prompt grounding."""
    return mandatory_grounding_digest(
        IncidentGroundingSources(
            validate_incident_evidence=validate_incident_evidence_artifact,
        ),
        package,
    )

def compact_package_to_budget(package: dict, max_bytes: int) -> tuple[dict, str]:
    """Compatibility delegate for deterministic package compaction."""
    return compact_prompt_package(
        PackageCompactionSources(
            mandatory_grounding_digest=(
                incident_prompt_mandatory_grounding_digest
            ),
            project_hits=project_incident_evidence_hits,
            project_osquery_rows=project_incident_evidence_osquery_rows,
            validate_incident_evidence=validate_incident_evidence_artifact,
        ),
        package,
        max_bytes,
    )


def main() -> int:
    args = parse_args()
    if not args.db.exists():
        raise SystemExit(f"SQLite DB not found: {args.db}")
    conn = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        selected = select_alert(conn, args)
        package = build_package(conn, selected, args)
    finally:
        conn.close()

    package, output = compact_package_to_budget(package, args.max_package_bytes)
    if args.stdout:
        print(output)
        return 0

    args.out_dir.mkdir(parents=True, exist_ok=True)
    stamp = filename_timestamp(project_now())
    alert_id = safe_filename(str(package["alert"]["alert_id"]))
    out_path = args.out_dir / f"{stamp}-{alert_id}-ai-prompt.json"
    out_path.write_text(output + "\n", encoding="utf-8")
    print(out_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
