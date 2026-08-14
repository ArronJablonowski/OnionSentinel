#!/usr/bin/env python3
"""Build a local-first AI investigation prompt package from alert-store SQLite.

The script does not call an LLM. It prepares a bounded evidence bundle and a
strict JSON response contract that can be sent to Hermes, Ollama, or a hosted
frontier model depending on the escalation policy.
"""
from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path


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
from asset_inventory import load_asset_inventory, resolve_asset_context
from detection_validation import (
    build_detection_validation,
    extract_group_packet_features,
    extract_rule_context,
    load_detection_playbooks,
    marker_specs,
    resolve_detection_playbook,
)
from incident_evidence_contract import validate_incident_evidence_artifact
from investigation_skills import (
    load_investigation_skills,
    resolve_investigation_skills,
)
from prompt_builder_cli import (
    PromptBuilderCliDefaults,
    PromptBuilderCliSources,
    parse_prompt_builder_args,
)
from prompt_builder_io import write_private_text
from prompt_builder_compatibility import (
    alert_group_id, alert_group_key, compact_package_to_budget,
    filename_timestamp, incident_prompt_immutable_query_provenance,
    incident_prompt_mandatory_grounding_digest, load_json_bounded,
    load_system_prompt, parse_alert_json, parse_json_object,
    project_incident_evidence_hits, project_incident_evidence_osquery_rows,
    project_now, read_bytes_bounded, reject_preprojected_incident_evidence_source,
    row, rows, safe_filename, safe_int, sqlite_value, test_filter_sql,
)
from prompt_builder_policy import (
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
    DEFAULT_SYSTEM_PROMPT_FILE,
    INVESTIGATION_CONTRACT,
    INVESTIGATION_QUERY_MAX_PER_ROUND,
    INVESTIGATION_QUERY_MAX_ROUNDS,
    INVESTIGATION_QUERY_MAX_TOTAL,
    INVESTIGATION_QUERY_CONTRACT,
    INVESTIGATION_QUERY_PACKS,
    INVESTIGATION_QUERY_V2,
    MAX_DETECTION_GROUP_ROWS,
    MAX_INCIDENT_EVIDENCE_BYTES,
)
from prompt_correlation_facts import (
    COMMUNITY_ID_V1_RE,
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
from prompt_detection_facade import (
    agent_task,
    asset_observables_and_events,
    exact_detection_group_rows,
    investigation_query_context,
    investigation_query_context_policy,
    investigation_query_context_sources,
    model_policy,
)
from prompt_detection_context import DetectionContextSources
from prompt_package_orchestrator import (
    PromptPackageWorkflowPolicy,
    PromptPackageWorkflowSources,
    build_prepared_prompt_package,
)


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


def _detection_context_sources() -> DetectionContextSources:
    """Bind legacy patch points to the extracted detection workflow."""
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
    write_private_text(out_path, output + "\n")
    print(out_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
