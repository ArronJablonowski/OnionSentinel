#!/usr/bin/env python3
"""Persistent LAN report portal for Arron's local HTML reports/projects."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import html
import importlib.util
import ipaddress
import json
import os
import re
import shutil
import secrets
import shlex
import socket
import sqlite3
import stat
import subprocess
import sys
import threading
import time
import uuid
from contextlib import contextmanager
from collections.abc import Callable
from dataclasses import dataclass
from functools import partial
from http import HTTPStatus
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib import error as urllib_error
from urllib import request as urllib_request
from urllib.parse import parse_qs, unquote, urlencode, urlparse

PORTAL_SOURCE_DIR = Path(__file__).resolve().parent
if str(PORTAL_SOURCE_DIR) not in sys.path:
    sys.path.insert(0, str(PORTAL_SOURCE_DIR))

import soc_alert_api
import software_inventory
import cti_program
import portal_asset_runtime
import portal_settings_runtime
from artifact_cache import ArtifactCache
from http_runtime import BoundedResponseError, read_bounded_json
from jsonl_log import JsonlLogIndex
from portal_catalog_routes import classify_catalog_route
from portal_ai_settings_normalizer import (
    SocAiSettingsNormalizationPolicy,
    normalize_soc_ai_settings as normalize_ai_settings,
)
from portal_ai_settings_store import (
    AiSettingsStoreSources,
    read_soc_ai_settings as read_persisted_soc_ai_settings,
    save_soc_agent_model as save_persisted_soc_agent_model,
    save_soc_ai_settings as save_persisted_soc_ai_settings,
    write_soc_ai_settings as write_persisted_soc_ai_settings,
)
from portal_agent_content_store import (
    AgentMemorySources,
    read_agent_memory as read_allowlisted_agent_memory,
    read_allowlisted_prompt,
    read_prompt_file as read_agent_prompt_file,
    save_allowlisted_prompt,
    save_prompt_file as save_agent_prompt_file,
)
from portal_ai_model_policy import (
    CLI_HARNESS_MODEL_PATTERN,
    CODEX_CLI_MODEL_CATALOG,
    CODEX_CLI_MODEL_PATTERN,
    CODEX_CLI_REASONING_EFFORTS,
    CYBER_SECURITY_AGENT_ROLES,
    HERMES_AGENT_REASONING_EFFORT,
    MAXMIND_GEOIP_DATABASE_SETTINGS,
    OPENCLAW_SUPPORTED_OLLAMA_URLS,
    SOC_ANALYSIS_SEVERITY_ORDER,
    SOC_ANALYSIS_SEVERITY_THRESHOLDS,
    _boolean_setting,
    _canonical_agent_route,
    _codex_cli_route,
    _derive_model_mode,
    _enabled_agent_model_routes,
    _hermes_agent_route,
    _model_route_identity,
    _normalize_agent_adjudicator_models,
    _normalize_agent_models,
    _normalize_agent_second_opinion_models,
    _normalize_codex_cli_models,
    _normalized_model_list,
    _openclaw_route,
    _valid_cli_executable_path,
    _valid_openclaw_model,
    _valid_provider_model,
    default_soc_ai_settings,
)
from portal_cli_provider_readiness import (
    enabled_cli_harnesses_ready,
    hermes_auth_readiness_error,
    resolve_cli_harness,
)
from portal_ollama_catalog import (
    OllamaCatalogSources,
    OllamaMetadataSources,
    classify_ollama_model_compatibility as classify_ollama_compatibility,
    compose_ollama_models_response,
    list_ollama_models as discover_ollama_models,
    load_ollama_model_compatibility,
    ollama_context_length,
)
from portal_admin_dashboard import (
    AdminDashboardSources,
    compose_admin_dashboard,
    render_admin_dashboard as render_admin_dashboard_view,
)
from portal_admin_versions import (
    AdminVersionSources,
    compose_admin_action_version_info,
)
from portal_admin_availability import (
    AdminAvailabilitySources,
    AdminCommandOutcome,
    compose_admin_action_availability,
)
from portal_cron_failures import (
    CronFailureSources,
    compose_cron_failure_records,
    render_cron_failure_log,
)
from portal_admin_action_state import (
    AdminActionStateSources,
    action_log_path,
    action_status_path,
    claim_action_lock,
    latest_action_outcome,
    read_action_lock,
    read_action_status,
    release_action_lock,
    running_action,
    update_action_lock_pid,
    write_action_status,
)
from portal_admin_action_runner import (
    AdminActionRunnerSources,
    start_admin_action as run_admin_action,
)
from portal_admin_session_store import (
    admin_session_cookie_header as compose_admin_session_cookie,
    admin_session_hash as derive_admin_session_hash,
    create_admin_session as create_persisted_admin_session,
    destroy_admin_session as destroy_persisted_admin_session,
    ensure_admin_token as ensure_persisted_admin_token,
    expired_admin_session_cookie_header as compose_expired_admin_session_cookie,
    load_admin_password_record as load_persisted_admin_password_record,
    load_admin_sessions as load_persisted_admin_sessions,
    parse_cookie_header as parse_request_cookie_header,
    prune_admin_sessions as prune_persisted_admin_sessions,
    save_admin_sessions as save_persisted_admin_sessions,
    verify_admin_password as verify_persisted_admin_password,
)
from portal_admin_service_probes import (
    AdminServiceProbeSources,
    ServiceCommandOutcome,
    codex_app_status as probe_codex_app_status,
    codex_cli_status as probe_codex_cli_status,
    docker_status as probe_docker_status,
    macs_fan_control_status as probe_macs_fan_control_status,
    matching_process_lines,
)
from portal_admin_services import (
    AdminServiceStartSources,
    compose_admin_service_statuses,
    start_admin_service as start_allowed_admin_service,
)
from portal_disk_inventory import (
    DiskInventorySources,
    DiskScanOutcome,
    compose_local_disk_inventory,
    compose_local_disk_usage,
)
from portal_hermes_backup_health import (
    HermesBackupSources,
    backup_base_path,
    backup_timestamp_from_name,
    compose_backup_inventory,
    compose_latest_hermes_backup_metric,
)
from portal_update_health import (
    UpdateCommandOutcome,
    UpdateHealthSources,
    compose_brew_update_source_metric,
    compose_hermes_update_source_metric,
    compose_latest_running_update_action,
    compose_latest_update_action_failure,
    compose_macos_update_metric,
    compose_prioritized_updates_metric,
    read_macos_update_status as load_macos_update_status,
)
from portal_pcap_health import PcapHealthSources, compose_pcap_workflow_health
from portal_home_dashboard import (
    HomeDashboardSources,
    compose_home_dashboard,
    render_home_dashboard,
)
from portal_dhcp_discovery import (
    DhcpDiscoveryDependencies,
    compose_dhcp_discovery_response,
)
from portal_soc_review_metadata import (
    SocReviewDependencies,
    apply_soc_review_metadata,
    embedded_reviewer as _soc_embedded_reviewer,
    parse_review_json as _soc_review_json,
    review_epoch as _modular_soc_review_epoch,
    review_final_status as _soc_review_final_status,
    review_defaults as _soc_review_defaults,
    reviewer_automation_authorization as _soc_reviewer_automation_authorization,
)
from portal_soc_evidence_metadata import (
    SocEvidenceDependencies,
    compose_soc_evidence_metadata,
)
from portal_soc_incident_metadata import (
    SocIncidentDependencies,
    apply_soc_incident_metadata,
    incident_defaults as _soc_incident_defaults,
)
from portal_soc_alert_presenter import (
    SocAlertPresentationDependencies,
    compose_soc_alert_row,
)
from portal_soc_ai_status import (
    SocAiStatusPolicy,
    compose_soc_ai_status,
    severity_meets_threshold as _modular_severity_meets_threshold,
)
from portal_soc_pcap_status import (
    SocPcapStatusDependencies,
    compose_pcap_status,
    load_pcap_request_statuses,
)
from portal_soc_pcap_artifacts import (
    PcapArtifactSources,
    build_pcap_analysis_index,
    has_parsed_pcap as _modular_has_parsed_pcap,
    newest_pcap_analysis_record,
)
from portal_soc_pcap_renderer import render_pcap_summary
from portal_soc_enrichment_status import compose_enrichment_status
from portal_soc_ai_artifact_context import (
    AiArtifactContextDependencies,
    compose_page_ai_artifact_context,
)
from portal_soc_ai_artifacts import (
    AiArtifactSources,
    AiGroupArtifactDependencies,
    build_ai_artifact_index,
    group_has_analysis_artifact as _modular_group_has_analysis_artifact,
    latest_analysis_mtime as _modular_latest_analysis_mtime,
    latest_prompt_mtime as _modular_latest_prompt_mtime,
)
from portal_soc_group_query import (
    SocAlertQuerySnapshot,
    SocGroupQueryDependencies,
    SocGroupQueryRequest,
    SocGroupQueryRequestPolicy,
    SocGroupSnapshotDependencies,
    compose_group_query_payload,
    compose_group_query_snapshot,
    fallback_query_plan,
    parse_group_query_request,
    summary_query_plan,
)
from portal_soc_group_enrichment import (
    group_enrichment_query_plan,
    merge_page_enrichment,
    page_group_keys,
    project_group_enrichment_rows,
)
from portal_soc_metrics import (
    compose_metrics_payload,
    compose_status_payload,
    exclude_group_rows,
    metrics_query_plan,
)
from portal_live_revisions import (
    RevisionSchemaDependencies,
    bounded_file_revision as _bounded_file_revision,
    incident_response_revision,
    revision_digest as _revision_digest,
)
from portal_metric_detail_renderer import (
    metric_detail_shell as render_metric_detail_shell,
    render_hermes_backups_detail as render_hermes_backup_metrics,
    render_local_disk_detail as render_local_disk_metrics,
    render_macos_updates_detail as render_macos_update_metrics,
    render_portal_update_detail as render_portal_update_metrics,
    render_prioritized_updates_detail as render_prioritized_update_metrics,
    render_system_uptime_detail as render_system_uptime_metrics,
)
from portal_incident_actions import (
    IncidentStatusPayloadError,
    normalize_incident_status_payload,
)
from portal_incident_read_model import (
    IncidentRowCallbacks,
    empty_incident_page,
    parse_incident_list_request,
)
from portal_incident_list_service import compose_incident_list_rows
from portal_incident_read_service import (
    IncidentReadServiceSources,
    incident_detail_response,
    incident_list_response,
)
from portal_incident_reanalysis import (
    IncidentReanalysisQueryError,
    compose_reanalysis_progress_payload,
    load_reanalysis_progress,
    parse_reanalysis_run_id,
)
from portal_incident_report_renderer import (
    IncidentReportRenderCallbacks,
    render_incident_response_report,
)
from portal_investigation_audit_renderer import (
    InvestigationAuditRenderCallbacks,
    render_investigation_query_audit,
)
from portal_review_panel_renderer import (
    ReviewPanelRenderCallbacks,
    render_analyst_review_panel as render_review_panel,
)
from portal_incident_review_model import (
    compose_incident_detail_payload,
    compose_incident_review_state,
    parse_analysis_response,
)
from portal_incident_repository import (
    incident_schema_ready,
    load_current_incident_analysis,
    load_incident_detail_records,
    load_incident_list_records,
    load_incident_review_records,
)
from portal_json_body import parse_json_body
from portal_request_routes import (
    classify_get_route,
    classify_post_route,
    head_content_type,
    is_head_route,
)
from portal_report_catalog import (
    Report,
    category_for as classify_report_category,
    human_size as format_human_size,
    is_daily_threat_brief_file as classify_daily_threat_brief,
    report_id as derive_report_id,
    scan_reports as discover_reports,
    should_skip_dir as exclude_report_directory,
    soc_alerts_default_path as project_soc_alerts_default_path,
    soc_alerts_report as select_soc_alerts_report,
    title_from_html as read_report_title,
)
from portal_soc_read_dispatch import (
    SocReadCallbacks,
    dispatch_soc_read,
)
from portal_soc_write_dispatch import SocWriteCallbacks, dispatch_authorized_soc_write
from portal_software_inventory_service import (
    AssetLabelSnapshot,
    append_incomplete_asset_warning,
    database_query_parameters,
    enrich_database_payload,
    load_asset_label_snapshot,
)
from portal_asset_inventory_service import (
    apply_asset_overlays,
    asset_public_record,
    asset_record_state,
    compose_local_response as compose_local_asset_inventory_response,
    current_asset_projection,
    database_query_parameters as asset_database_query_parameters,
    database_unavailable_payload as asset_database_unavailable_payload,
    resolve_asset_ip as resolve_asset_ip_record,
)
from portal_asset_dhcp_overlay import (
    annotate_exact_ip_dhcp_macs,
    dhcp_asset_inventory_overlay,
    mac_address_scope,
)
from portal_asset_mutation_service import (
    execute_asset_mutation,
    normalize_asset_mutation_payload,
    normalize_asset_review_payload,
)
from portal_asset_repository import AssetInventoryRepository, DhcpStateRepository
from portal_asset_store_client import (
    AlertStoreRequestError,
    AssetStoreClient,
    load_asset_store_write_token,
)
from portal_cti_program_service import (
    CtiProgramCallbacks,
    read_cti_program,
)
from portal_soc_settings_write import SocSettingsWriteCallbacks
from portal_admin_service_write import AdminServiceWriteCallbacks
from portal_resource_library_write import ResourceLibraryWriteCallbacks
from portal_resource_library_store import (
    clean_resource_tags as normalize_resource_tags,
    find_resource_library_pdf as locate_resource_library_pdf,
    load_resource_library_metadata as load_resource_metadata_file,
    move_resource_to_removal as move_resource_file_to_removal,
    rename_resource_file as rename_resource_library_file,
    resource_favorites as project_resource_favorites,
    resource_library_id_for as derive_resource_library_id,
    sanitize_resource_filename as normalize_resource_filename,
    save_resource_library_metadata as save_resource_metadata_file,
    set_resource_favorite as update_resource_favorite,
    set_resource_tags as update_resource_tags,
    unique_destination as available_resource_destination,
)
from portal_admin_form_service import AdminFormCallbacks, prepare_admin_form
from portal_admin_read_service import prepare_admin_read
from portal_health_read_service import compose_portal_health
from portal_http_handler import build_portal_handler
from portal_resource_action_read import read_resource_action_status
from portal_catalog_read_service import CatalogReadCallbacks, dispatch_catalog_read
from portal_catalog_delivery import CatalogDeliveryCallbacks, deliver_catalog_route
from portal_general_read_service import GeneralReadCallbacks, dispatch_general_read
from portal_post_intake import prepare_post_intake
from portal_json_write_service import JsonWriteCallbacks, dispatch_json_write
from portal_llm_runtime_state import llm_runtime_model_state
from portal_llm_activity import (
    compose_current_llm_analysis,
    decorate_llm_analysis_record as project_llm_analysis_record,
    llm_agent_execution_state as project_llm_agent_execution_state,
    merge_live_llm_activity as project_live_llm_activity,
)
from portal_llm_active_store import (
    ActiveLlmSources,
    active_llm_record_paths,
    llm_analysis_process_active as active_llm_process_present,
    llm_queue_size,
    read_active_llm_analyses as load_active_llm_analyses,
    read_bounded_llm_record,
)
from portal_llm_history import (
    PARENT_RUN_FIELDS as LLM_PARENT_RUN_FIELDS,
    compose_llm_activity_snapshot,
    hydrate_llm_reviewer_from_parent as hydrate_projected_llm_reviewer,
    llm_analysis_run_timestamp as projected_llm_run_timestamp,
    llm_log_sort_timestamp as projected_llm_log_sort_timestamp,
    llm_primary_run_identity as projected_llm_primary_identity,
    llm_reviewer_started_at as projected_llm_reviewer_started_at,
    project_adjudication_rows,
    project_database_primary_rows,
    project_second_opinion_rows,
    reconcile_llm_primary_logs as reconcile_projected_llm_primary_logs,
)
from portal_llm_history_store import (
    LlmHistoryStoreSources,
    read_adjudication_history_rows,
    read_primary_history_rows,
    read_second_opinion_history_rows,
)
from portal_llm_history_api import (
    LlmHistoryApiSources,
    llm_analysis_log_limit as bounded_llm_analysis_log_limit,
    llm_analysis_log_page as bounded_llm_analysis_log_page,
    llm_analysis_logs_response as compose_llm_analysis_logs_response,
    read_llm_agent_activity_snapshot as load_llm_agent_activity_snapshot,
)
from portal_soc_alert_status_write import (
    SocAlertStatusWriteSources,
    update_soc_alert_status as apply_soc_alert_status_update,
)
from portal_soc_alert_status_store import (
    SocAlertStatusStoreSources,
    ensure_soc_alert_status_schema,
    load_active_soc_group_ids,
    load_manually_escalated_group_ids,
    load_soc_alert_group_counts,
    load_soc_group_statuses,
    normalize_soc_alert_status_meta as normalize_status_meta,
    soc_alert_group_summary_available as group_summary_available,
    write_soc_group_status,
    write_soc_group_statuses,
)
from portal_soc_alert_status_service import (
    SocAlertStatusPersistenceSources,
    load_soc_alert_statuses as load_persisted_soc_alert_statuses,
    load_soc_alert_statuses_from_db as load_persisted_soc_alert_statuses_from_db,
    save_soc_alert_statuses as save_persisted_soc_alert_statuses,
    save_soc_alert_statuses_to_db as save_persisted_soc_alert_statuses_to_db,
    write_soc_alert_status as persist_soc_alert_status,
    write_soc_alert_status_json_snapshot as write_persisted_soc_alert_status_snapshot,
)
from portal_soc_adjudication_policy import (
    SOC_ANALYST_ACTIVITY_DISPOSITIONS,
    SOC_ANALYST_ADJUDICATION_OUTCOMES,
    SOC_ANALYST_DETECTION_VALIDITIES,
    SOC_ANALYST_EVENT_STATUSES,
    SOC_ANALYST_HANDLING_VALUES,
    adjudication_verdict_contradictions,
    derive_legacy_detection_outcome,
    legacy_verdict_factors,
    normalize_soc_adjudication_payload as normalize_adjudication_payload,
)
from portal_soc_adjudication_history import (
    SocAdjudicationHistorySources,
    read_soc_adjudication_history,
)
from portal_soc_pcap_request_policy import (
    PcapRequestPolicySources,
    bounded_int as bounded_pcap_int,
    normalize_pcap_request as normalize_pcap_request_policy,
    pcap_request_id as projected_pcap_request_id,
)
from portal_soc_pcap_request_store import (
    PcapRequestStoreSources,
    insert_pcap_request as store_pcap_request,
    pcap_capture_file_from_json as extract_pcap_capture_file,
    read_pcap_request_candidate,
)
from portal_soc_pcap_request_service import (
    PcapRequestServiceSources,
    request_soc_alert_pcap,
)
from portal_soc_action_service import (
    SocActionServiceSources,
    escalate_soc_alert,
    forward_controlled_dispatch_contract,
    queue_soc_alert_analysis,
)
from portal_sse_stream import send_soc_alert_events
from portal_beacon_history import project_beacon_history
from portal_n8n_container_status import (
    N8nContainerStatusSources,
    compose_n8n_container_status,
)
from response_cache import ResponseCache

HOME = Path.home()
DEFAULT_PORT = 8765
DEFAULT_HOST = "0.0.0.0"
EXCLUDE_DIR_NAMES = {
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv",
    "Library", "Applications", "Music", "Movies", "Pictures", "Public", ".Trash",
    "backups", "backup", "templates",
}
SCAN_ROOTS = [
    # LaunchAgent-safe source: mirrored by ~/.hermes/scripts/sync_report_portal.py.
    # This avoids macOS privacy/TCC edge cases where launchd services can see a Documents
    # directory but not enumerate files inside it.
    HOME / "report_portal" / "library",
]
LAST_UPDATED_FILE = HOME / "report_portal" / ".last_updated"
MACOS_UPDATE_STATUS_FILE = HOME / "report_portal" / ".macos_update_status.json"
SOC_ALERT_STATUS_FILE = HOME / "report_portal" / ".soc_alert_status.json"
SOC_ALERT_STORE_DB = HOME / "n8n-local" / "alert_store_data" / "alerts.sqlite3"
SOC_ALERT_STORE_API_URL = os.environ.get("SOC_ALERT_STORE_API_URL", "http://127.0.0.1:8787").rstrip("/")
SOC_ALERT_STORE_DIRECT_WRITE_ALLOWED = (
    str(os.environ.get("SOC_ALERT_STORE_DIRECT_WRITE_ALLOWED") or "").strip()
    == "1"
)
SOC_ALERT_STORE_EVALUATION_TOKEN = str(
    os.environ.get("ONION_SENTINEL_EVALUATION_TOKEN") or ""
).strip()
SOC_ALERT_DB_WRITE_LOCK = threading.RLock()
SOC_ALERT_DB_WRITE_RETRY_ATTEMPTS = 5
SOC_ALERT_DB_WRITE_RETRY_BASE_SECONDS = 0.02
SOC_ALERT_DASHBOARD_DIR = HOME / "report_portal" / "library" / "Cybersecurity" / "SOC Alerts"
SOC_ALERT_DETAIL_DIR = SOC_ALERT_DASHBOARD_DIR / "details"
SOC_ALERT_STATIC_STATUS_FILE = SOC_ALERT_DASHBOARD_DIR / "soc-alerts-status.json"
SOC_ALERT_N8N_BEACON_FILE = SOC_ALERT_DASHBOARD_DIR / "n8n-beacon.json"
SOC_ALERT_N8N_BEACON_HISTORY_FILE = SOC_ALERT_DASHBOARD_DIR / "n8n-beacon-history.json"
SOC_ALERT_PCAP_WORKFLOW_STATE_FILE = SOC_ALERT_DASHBOARD_DIR / "pcap-workflow-state.json"
SOC_ALERT_PCAP_ANALYSIS_DIR = HOME / "n8n-local" / "soc-alerts" / "pcap-analysis"
SOC_ALERT_PCAP_ARTIFACT_DIR = HOME / "n8n-local" / "pcap-evidence" / "artifacts"
SOC_ALERT_AI_PROMPT_DIR = HOME / "n8n-local" / "soc-alerts" / "ai-prompts"
SOC_ALERT_AI_ANALYSIS_DIR = HOME / "n8n-local" / "soc-alerts" / "ai-analysis"
SOC_ALERT_AI_PROMPT_BUILDER = HOME / "n8n-local" / "bin" / "build-ai-investigation-prompt.py"
SOC_ALERT_LLM_ANALYSIS_LOG_DIR = HOME / "n8n-local" / "soc-alerts" / "llm-analysis-logs"
SOC_ALERT_LLM_ANALYSIS_LOG_FILE = SOC_ALERT_LLM_ANALYSIS_LOG_DIR / "llm-analysis-log.jsonl"
SOC_ALERT_LLM_ANALYSIS_CURRENT_FILE = SOC_ALERT_LLM_ANALYSIS_LOG_DIR / "current-analysis.json"
SOC_ALERT_LLM_ANALYSIS_ACTIVE_DIR = SOC_ALERT_LLM_ANALYSIS_LOG_DIR / "active"
SOC_ALERT_LLM_ANALYSIS_RECORD_MAX_BYTES = 256 * 1024
SOC_ALERT_LLM_ANALYSIS_ACTIVE_LIMIT = 16
SOC_ALERT_LLM_ANALYSIS_LOG_INDEX = JsonlLogIndex(SOC_ALERT_LLM_ANALYSIS_LOG_FILE)
SOC_ANALYST_PROMPT_FILE = HOME / "n8n-local" / "config" / "soc_analyst_system_prompt.md"
SIEM_ENGINEER_PROMPT_FILE = HOME / "n8n-local" / "config" / "siem_engineer_system_prompt.md"
THREAT_HUNTER_PROMPT_FILE = HOME / "n8n-local" / "config" / "threat_hunter_system_prompt.md"
CYBER_THREAT_INTEL_PROMPT_FILE = HOME / "n8n-local" / "config" / "cyber_threat_intel_system_prompt.md"
INCIDENT_RESPONDER_PROMPT_FILE = HOME / "n8n-local" / "config" / "incident_responder_system_prompt.md"
SOC_ANALYST_SECOND_OPINION_PROMPT_FILE = HOME / "n8n-local" / "config" / "soc_analyst_second_opinion_prompt.md"
SIEM_ENGINEER_SECOND_OPINION_PROMPT_FILE = HOME / "n8n-local" / "config" / "siem_engineer_second_opinion_prompt.md"
THREAT_HUNTER_SECOND_OPINION_PROMPT_FILE = HOME / "n8n-local" / "config" / "threat_hunter_second_opinion_prompt.md"
CYBER_THREAT_INTEL_SECOND_OPINION_PROMPT_FILE = HOME / "n8n-local" / "config" / "cyber_threat_intel_second_opinion_prompt.md"
INCIDENT_RESPONDER_SECOND_OPINION_PROMPT_FILE = HOME / "n8n-local" / "config" / "incident_responder_second_opinion_prompt.md"
SOC_SETTINGS_PROMPT_FILES = {
    "/api/soc-settings/analyst-prompt": ("SOC Analyst", SOC_ANALYST_PROMPT_FILE),
    "/api/soc-settings/analyst-second-opinion-prompt": ("SOC Analyst second-opinion", SOC_ANALYST_SECOND_OPINION_PROMPT_FILE),
    "/api/soc-settings/siem-engineer-prompt": ("SIEM Engineer", SIEM_ENGINEER_PROMPT_FILE),
    "/api/soc-settings/siem-engineer-second-opinion-prompt": ("SIEM Engineer second-opinion", SIEM_ENGINEER_SECOND_OPINION_PROMPT_FILE),
    "/api/soc-settings/threat-hunter-prompt": ("Threat Hunter", THREAT_HUNTER_PROMPT_FILE),
    "/api/soc-settings/threat-hunter-second-opinion-prompt": ("Threat Hunter second-opinion", THREAT_HUNTER_SECOND_OPINION_PROMPT_FILE),
    "/api/soc-settings/cyber-threat-intel-prompt": ("Cyber Threat Intel", CYBER_THREAT_INTEL_PROMPT_FILE),
    "/api/soc-settings/cyber-threat-intel-second-opinion-prompt": ("Cyber Threat Intel second-opinion", CYBER_THREAT_INTEL_SECOND_OPINION_PROMPT_FILE),
    "/api/soc-settings/incident-responder-prompt": ("Incident Responder", INCIDENT_RESPONDER_PROMPT_FILE),
    "/api/soc-settings/incident-responder-second-opinion-prompt": ("Incident Responder second-opinion", INCIDENT_RESPONDER_SECOND_OPINION_PROMPT_FILE),
}
SOC_SETTINGS_PROMPT_API_PATHS = frozenset(SOC_SETTINGS_PROMPT_FILES)
AGENT_MEMORY_DIR = HOME / "n8n-local" / "soc-alerts" / "agent-memory"
SOC_ANALYST_MEMORY_FILE = AGENT_MEMORY_DIR / "soc-analyst-memory.md"
INCIDENT_RESPONDER_MEMORY_FILE = AGENT_MEMORY_DIR / "incident-responder-memory.md"
SIEM_ENGINEER_MEMORY_FILE = AGENT_MEMORY_DIR / "siem-engineer-memory.md"
CYBER_THREAT_INTEL_MEMORY_FILE = AGENT_MEMORY_DIR / "cyber-threat-intel-memory.md"
THREAT_HUNTER_MEMORY_FILE = AGENT_MEMORY_DIR / "threat-hunter-memory.md"
SHARED_AGENT_MEMORY_FILE = AGENT_MEMORY_DIR / "shared-agent-memory.md"
SOC_AI_SETTINGS_FILE = HOME / "n8n-local" / "config" / "ai_model_settings.json"
ASSET_INVENTORY_FILE = HOME / "n8n-local" / "config" / "asset_inventory.json"
ASSET_INVENTORY_MAX_BYTES = 64 * 1024 * 1024
ASSET_DATABASE_READ_ENABLED = str(
    os.environ.get("ASSET_DATABASE_READ_ENABLED") or ""
).strip().lower() in {"1", "true", "yes"}
SOFTWARE_DATABASE_READ_ENABLED = str(
    os.environ.get(
        "SOFTWARE_DATABASE_READ_ENABLED",
        os.environ.get("ASSET_DATABASE_READ_ENABLED") or "",
    )
).strip().lower() in {"1", "true", "yes"}
ASSET_INVENTORY_ADMIN_WRITE_REQUIRED = str(
    os.environ.get("ASSET_INVENTORY_ADMIN_WRITE_REQUIRED") or ""
).strip().lower() in {"1", "true", "yes"}
ASSET_STORE_ENV_FILE = HOME / "n8n-local" / ".env"
DHCP_ASSET_DISCOVERY_STATE_FILE = (
    HOME / "n8n-local" / "asset-discovery" / "dhcp-observations.json"
)
DHCP_ASSET_DISCOVERY_MAX_BYTES = 8 * 1024 * 1024
SOFTWARE_INVENTORY_STATE_FILE = (
    HOME / "n8n-local" / "software-inventory" / "software-inventory.json"
)
SOFTWARE_INVENTORY_MAX_BYTES = software_inventory.MAX_STATE_BYTES
CTI_PROGRAM_API_PATH = "/api/cyber-threat-intel/program"
ASSET_INVENTORY_CACHE_LOCK = threading.RLock()
ASSET_INVENTORY_CACHE: dict[str, object] = {
    "signature": None,
    "inventory": None,
    "expires_at": 0.0,
}
DEFAULT_HERMES_AUTH_FILE = (
    HOME / "n8n-local" / "private" / "hermes-agent" / "auth.json"
)
HERMES_AUTH_MAX_BYTES = 2 * 1024 * 1024
SOC_ANALYST_PROMPT_MAX_BYTES = 20000
AGENT_MEMORY_VIEW_MAX_BYTES = 1024 * 1024
SOC_ALERT_API_MAX_LIMIT = 500
SOC_ALERT_DB_BUSY_TIMEOUT_SECONDS = 30
SOC_ALERT_DB_BUSY_TIMEOUT_MS = SOC_ALERT_DB_BUSY_TIMEOUT_SECONDS * 1000
SOC_ALERT_STORE_RESPONSE_MAX_BYTES = 64 * 1024 * 1024
SOC_ALERT_DETAIL_FRAGMENT_MAX_BYTES = 32 * 1024 * 1024
SOC_ALERT_LEVEL_RANK = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "informational": 1,
    "info": 1,
    "unknown": 0,
}
SOC_ALERT_AI_ELIGIBLE_FILTER_STATUSES = {"accepted", "escalated", "unknown", "suppressed"}
SOC_ALERT_TEST_PREFIXES = ("phase", "config-", "internal-test-", "sqlite-", "policy-", "codex-")
SOC_ALERT_ARTIFACT_CACHE_TTL_SECONDS = 5.0
SOC_ALERT_ARTIFACT_CACHE = ArtifactCache(SOC_ALERT_ARTIFACT_CACHE_TTL_SECONDS)
SOC_ALERT_RESPONSE_CACHE = ResponseCache(1.0)
SOC_ALERT_EVENTS_CACHE = ResponseCache(4.0, max_entries=2, lock_stripes=1)
OLLAMA_MODEL_COMPATIBILITY_CACHE = ResponseCache(300.0, max_entries=128, lock_stripes=16)
OLLAMA_MODEL_SHOW_MAX_BYTES = 2 * 1024 * 1024
OLLAMA_MODEL_MIN_CONTEXT_TOKENS = 32_768
HERMES_DR_BACKUP_DIR = HOME / "Hermes_DR_Backups"
HERMES_DR_REMOTE_DEST = "aj_lab@10.77.7.222"
HERMES_DR_REMOTE_DIR = "/Users/aj_lab/Hermes_DR_Backups"
CRON_JOBS_FILE = HOME / ".hermes" / "cron" / "jobs.json"
CRON_OUTPUT_DIR = HOME / ".hermes" / "cron" / "output"
RESOURCE_LIBRARY_SOURCES = [
    ("Books", HOME / "Documents" / "Books"),
    ("Talks", HOME / "Documents" / "Talks"),
    ("Posters", HOME / "Documents" / "CheatSheets" / "SANS_Posters"),
    ("CheatSheets", HOME / "Documents" / "CheatSheets"),
    ("LinkedIn", HOME / "Documents" / "LinkedIn"),
    ("Tools", HOME / "Documents" / "Tools"),
    ("Certificates", HOME / "Documents" / "Certs"),
]
RESOURCE_LIBRARY_REMOVAL_DIR = HOME / "Documents" / "removal"
RESOURCE_LIBRARY_BUILDER = HOME / ".hermes" / "scripts" / "build_pdf_library_dashboard.py"
RESOURCE_LIBRARY_SYNC = HOME / ".hermes" / "scripts" / "sync_report_portal.py"
RESOURCE_LIBRARY_MUTATION_WORKER = HOME / ".hermes" / "scripts" / "process_resource_library_removals.py"
RESOURCE_LIBRARY_REMOVAL_QUEUE = HOME / "report_portal" / ".resource_removal_queue" / "requests.jsonl"
RESOURCE_LIBRARY_METADATA_FILE = HOME / "report_portal" / "resource_library_metadata.json"
RESOURCE_LIBRARY_ACTION_STATUS_DIR = HOME / "report_portal" / ".resource_removal_queue" / "status"
RESOURCE_LIBRARY_MUTATION_CRON_ID = "a246853c325f"
ADMIN_STATE_DIR = HOME / "report_portal" / ".admin_actions"
ADMIN_TOKEN_FILE = HOME / "report_portal" / ".admin_token"
ADMIN_PASSWORD_FILE = HOME / "report_portal" / ".admin_password.json"
ADMIN_SESSIONS_FILE = ADMIN_STATE_DIR / ".admin_sessions.json"
ADMIN_SESSION_COOKIE = "lan_portal_admin"
ADMIN_SESSION_TTL_SECONDS = 8 * 60 * 60
ADMIN_LOCK_FILE = ADMIN_STATE_DIR / ".admin_action.lock"
N8N_CONTAINER_NAME = "n8n"
N8N_HEALTH_URL = "http://127.0.0.1:5678/healthz"
ADMIN_COMMAND_ENV = {
    **os.environ,
    "PATH": f"/opt/homebrew/bin:{HOME / '.hermes' / 'hermes-agent' / 'venv' / 'bin'}:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
    "HOMEBREW_NO_AUTO_UPDATE": "0",
}
HERMES_BIN = str(HOME / ".hermes" / "hermes-agent" / "venv" / "bin" / "hermes")
CODEX_CLI_BIN = str(HOME / ".local" / "bin" / "codex")
ADMIN_ACTIONS = {
    "hermes-update": {
        "label": "Hermes Agent update",
        "summary": "Runs hermes update from the installed Hermes CLI.",
        "command": [HERMES_BIN, "update"],
        "accent": "#23d3ee",
    },
    "brew-update": {
        "label": "Homebrew update + upgrade",
        "summary": "Runs brew update, then brew upgrade for installed formulae/casks.",
        "command": ["/bin/bash", "-lc", "/opt/homebrew/bin/brew update && /opt/homebrew/bin/brew upgrade"],
        "accent": "#f8c76a",
    },
    "macos-update": {
        "label": "macOS software updates",
        "summary": "Runs softwareupdate --install --all --agree-to-license. Some macOS updates may still require admin authorization or a restart.",
        "command": ["/usr/sbin/softwareupdate", "--install", "--all", "--agree-to-license"],
        "accent": "#a78bfa",
    },
    "reboot": {
        "label": "Reboot system",
        "summary": "Reboots the Mac with passwordless sudo after typed confirmation. Requires the LAN Portal sudoers drop-in that allows only the exact reboot command.",
        "command": [
            "/usr/bin/sudo",
            "-n",
            "/sbin/shutdown",
            "-r",
            "now",
        ],
        "accent": "#ff7a90",
        "requires_confirmation": "REBOOT",
    },
}
STANDALONE_HTML: list[Path] = []
ISO_DATE_TIME_SEPARATOR_RE = re.compile(r"(\d{4}-\d{2}-\d{2})(?:T|\s+)(?=\d{2}:\d{2}:\d{2})")

@dataclass(frozen=True)
class CronJobSummary:
    jid: str
    name: str
    schedule: str
    next_run: str
    enabled: bool
    state: str
    last_status: str
    sort_key: str


def format_iso_timestamp(value: dt.datetime, *, timespec: str = "seconds", utc_z: bool = False) -> str:
    """Render project timestamps as ISO 8601 with the T separator replaced by two spaces."""
    if value.tzinfo is None:
        value = value.astimezone()
    if utc_z:
        value = value.astimezone(dt.timezone.utc)
    rendered = value.isoformat(timespec=timespec).replace("T", "  ")
    return rendered.replace("+00:00", "Z") if utc_z else rendered


def now_iso_local() -> str:
    return format_iso_timestamp(dt.datetime.now().astimezone())


def now_iso_utc() -> str:
    return format_iso_timestamp(dt.datetime.now(dt.timezone.utc), utc_z=True)


def parse_iso_timestamp(value: object) -> dt.datetime:
    """Parse current and historical ISO timestamp separators."""
    cleaned = str(value).strip()
    cleaned = ISO_DATE_TIME_SEPARATOR_RE.sub(r"\1T", cleaned).replace("Z", "+00:00")
    return dt.datetime.fromisoformat(cleaned)


def _asset_inventory_module():
    """Load the shared strict inventory implementation in source and runtime layouts."""
    return portal_asset_runtime.asset_inventory_module(sys.modules[__name__])


def load_asset_inventory_data() -> tuple[dict, str]:
    """Return the PostgreSQL export used by investigation identity resolution."""
    return portal_asset_runtime.load_asset_inventory_data(sys.modules[__name__])


def _asset_record_state(asset: dict, observed_at: dt.datetime) -> str:
    return asset_record_state(asset, observed_at, parse_iso_timestamp)


def _asset_public_record(asset: dict, state: str) -> dict:
    return asset_public_record(asset, state)


def load_dhcp_asset_discovery_state_data() -> tuple[dict, str]:
    """Load the bounded collector state without treating absence as an error."""
    return DhcpStateRepository(
        database_enabled=ASSET_DATABASE_READ_ENABLED,
        fetch_json=alert_store_get_json,
        state_path=Path(DHCP_ASSET_DISCOVERY_STATE_FILE),
        maximum_bytes=DHCP_ASSET_DISCOVERY_MAX_BYTES,
    ).load()


def _mac_address_scope(value: object) -> str:
    return mac_address_scope(value)


def _annotate_exact_ip_dhcp_macs(records: list[dict], observed_at: dt.datetime) -> dict:
    return portal_asset_runtime.annotate_exact_ip_dhcp_macs(
        sys.modules[__name__], records, observed_at
    )


def _dhcp_asset_inventory_overlay(
    inventory: dict, observed_at: dt.datetime
) -> tuple[dict[str, dict], list[dict], dict]:
    return portal_asset_runtime.dhcp_asset_inventory_overlay(
        sys.modules[__name__], inventory, observed_at
    )


def asset_inventory_response(
    *,
    observed_at: dt.datetime | None = None,
    query: dict[str, list[str]] | None = None,
) -> tuple[int, dict]:
    """Return current authoritative asset-to-address assignments."""
    return portal_asset_runtime.asset_inventory_response(
        sys.modules[__name__], observed_at=observed_at, query=query
    )


def software_asset_label_snapshot() -> AssetLabelSnapshot:
    """Load complete public identities before resolving pseudonymous hosts."""
    return portal_asset_runtime.software_asset_label_snapshot(sys.modules[__name__])


def software_inventory_response(
    *,
    observed_at: dt.datetime | None = None,
    query: dict[str, list[str]] | None = None,
) -> tuple[int, dict]:
    """Return only the bounded, collector-produced Software Inventory view."""
    return portal_asset_runtime.software_inventory_response(
        sys.modules[__name__], observed_at=observed_at, query=query
    )


def resolve_asset_ip(
    value: object, observed_at: object, inventory: dict | None = None
) -> dict:
    return portal_asset_runtime.resolve_asset_ip(
        sys.modules[__name__], value, observed_at, inventory
    )


def dhcp_asset_discovery_response(
    *, observed_at: dt.datetime | None = None
) -> tuple[int, dict]:
    """Return DHCP candidates reconciled against authoritative inventory."""
    return portal_asset_runtime.dhcp_asset_discovery_response(
        sys.modules[__name__], observed_at=observed_at
    )


def pcap_transfer_duration_seconds(
    row: sqlite3.Row, *, has_transfer_duration: bool
) -> int | None:
    """Return persisted PCAP transfer time, deriving legacy rows when possible."""
    if has_transfer_duration and row["transfer_duration_seconds"] is not None:
        return max(0, int(row["transfer_duration_seconds"]))
    if not row["claimed_at"] or not row["completed_at"]:
        return None
    try:
        started = parse_iso_timestamp(row["claimed_at"])
        completed = parse_iso_timestamp(row["completed_at"])
        return max(0, round((completed - started).total_seconds()))
    except (TypeError, ValueError):
        return None


def format_timestamp_text(value: object, *, fallback: str = "unknown time") -> str:
    if not value:
        return fallback
    try:
        parsed = value if isinstance(value, dt.datetime) else parse_iso_timestamp(value)
        if parsed.tzinfo is None:
            parsed = parsed.astimezone()
        return format_iso_timestamp(parsed.astimezone())
    except Exception:
        text = str(value).strip()
        return ISO_DATE_TIME_SEPARATOR_RE.sub(r"\1  ", text) if text else fallback


def _safe_read_json(path: Path, fallback: object) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return fallback


def _freshest_existing_path(paths: list[Path]) -> Path | None:
    existing = [path for path in paths if path.exists()]
    if not existing:
        return None
    return max(existing, key=lambda path: path.stat().st_mtime)


def n8n_beacon_history_response(query: dict[str, list[str]]) -> dict[str, object]:
    now = dt.datetime.now(dt.timezone.utc)
    history_path = _freshest_existing_path([
        SOC_ALERT_N8N_BEACON_HISTORY_FILE,
        HOME / "SOC Alerts Web" / "n8n-beacon-history.json",
        HOME / "n8n-local" / "alert_store_data" / "n8n-beacon-history.json",
    ])
    raw_history = _safe_read_json(history_path, []) if history_path else []
    history = raw_history if isinstance(raw_history, list) else []
    latest_path = _freshest_existing_path([
        SOC_ALERT_N8N_BEACON_FILE,
        HOME / "SOC Alerts Web" / "n8n-beacon.json",
        HOME / "n8n-local" / "alert_store_data" / "n8n-beacon.json",
    ])
    if not history and latest_path:
        latest = _safe_read_json(latest_path, {})
        if isinstance(latest, dict):
            history = [latest]

    pipeline: dict[str, object] = {"available": False, "stages": [], "disk": {}}
    try:
        metrics_payload = alert_store_get_json("/metrics", timeout=2.0)
        pipeline = dict((metrics_payload.get("metrics") or {}).get("pipeline") or {})
        pipeline["available"] = True
    except RuntimeError as exc:
        pipeline["error"] = str(exc)

    return project_beacon_history(
        query, history, now=now, generated_at=now_iso_local(),
        history_source=str(history_path) if history_path else None,
        pcap=pcap_workflow_health_response(), pipeline=pipeline,
        parse_timestamp=parse_iso_timestamp, format_timestamp=format_iso_timestamp,
    )


def pcap_workflow_health_response() -> dict[str, object]:
    """Return compact PCAP broker/parser health for the System Health page."""
    sources = PcapHealthSources(
        store_db=SOC_ALERT_STORE_DB,
        artifact_dir=SOC_ALERT_PCAP_ARTIFACT_DIR,
        analysis_dir=SOC_ALERT_PCAP_ANALYSIS_DIR,
        relay_state_paths=(
            SOC_ALERT_PCAP_WORKFLOW_STATE_FILE,
            HOME / "SOC Alerts Web" / "pcap-workflow-state.json",
            HOME / "n8n-local" / "alert_store_data" / "pcap-workflow-state.json",
        ),
        db_connect=soc_alert_db_connect,
        table_exists=sqlite_table_exists,
        parse_timestamp=parse_iso_timestamp,
        format_timestamp=format_iso_timestamp,
        directory_size=directory_size_bytes,
        freshest_path=_freshest_existing_path,
        read_json=_safe_read_json,
    )
    return compose_pcap_workflow_health(sources, pcap_transfer_duration_seconds)


def ensure_admin_token() -> str:
    """Return a persistent CSRF token for admin POST actions."""
    return ensure_persisted_admin_token(ADMIN_TOKEN_FILE, random_bytes=os.urandom)


def load_admin_password_record() -> dict | None:
    """Load the local admin password hash record, if configured."""
    return load_persisted_admin_password_record(ADMIN_PASSWORD_FILE)


def admin_password_configured() -> bool:
    return load_admin_password_record() is not None


def verify_admin_password(password: str) -> bool:
    return verify_persisted_admin_password(password, load_admin_password_record())


def admin_session_hash(session_id: str) -> str:
    return derive_admin_session_hash(session_id)


def load_admin_sessions() -> dict:
    return load_persisted_admin_sessions(ADMIN_SESSIONS_FILE)


def save_admin_sessions(sessions: dict) -> None:
    save_persisted_admin_sessions(ADMIN_STATE_DIR, ADMIN_SESSIONS_FILE, sessions)


def prune_admin_sessions(sessions: dict | None = None) -> dict:
    sessions = load_admin_sessions() if sessions is None else sessions
    return prune_persisted_admin_sessions(
        sessions,
        now_timestamp=int(dt.datetime.now().timestamp()),
        save_sessions=save_admin_sessions,
    )


def create_admin_session(client_ip: str) -> str:
    return create_persisted_admin_session(
        client_ip,
        now_timestamp=int(dt.datetime.now().timestamp()),
        ttl_seconds=ADMIN_SESSION_TTL_SECONDS,
        new_session_id=lambda: secrets.token_urlsafe(32),
        load_pruned_sessions=prune_admin_sessions,
        save_sessions=save_admin_sessions,
    )


def destroy_admin_session(session_id: str) -> None:
    destroy_persisted_admin_session(
        session_id,
        load_sessions=load_admin_sessions,
        save_sessions=save_admin_sessions,
    )


def resource_library_id_for(path: Path) -> str:
    return derive_resource_library_id(path)


def find_resource_library_pdf(resource_id: str, source_path: str = "") -> tuple[Path, str, Path] | None:
    return locate_resource_library_pdf(resource_id, source_path, RESOURCE_LIBRARY_SOURCES)


def unique_destination(path: Path) -> Path:
    return available_resource_destination(path)


def refresh_resource_library() -> None:
    env = {**os.environ, "PATH": ADMIN_COMMAND_ENV.get("PATH", os.environ.get("PATH", ""))}
    subprocess.run([sys.executable, str(RESOURCE_LIBRARY_BUILDER)], check=True, timeout=180, env=env, capture_output=True, text=True)
    subprocess.run([sys.executable, str(RESOURCE_LIBRARY_SYNC)], check=True, timeout=180, env=env, capture_output=True, text=True)


def load_resource_library_metadata() -> dict:
    return load_resource_metadata_file(RESOURCE_LIBRARY_METADATA_FILE)


def save_resource_library_metadata(data: dict) -> None:
    save_resource_metadata_file(RESOURCE_LIBRARY_METADATA_FILE, data)


def clean_resource_tags(values) -> list[str]:
    return normalize_resource_tags(values)


def sanitize_resource_filename(name: str, original_suffix: str) -> str:
    """Return a safe basename while preserving the source file extension.

    Users rename the visible title in the web UI; the actual file on disk must
    keep its original extension. If they type another extension, strip it and
    restore the original suffix instead of producing names like `.txt.pdf`.
    """
    return normalize_resource_filename(name, original_suffix)


def queue_resource_action(record: dict) -> dict:
    RESOURCE_LIBRARY_REMOVAL_QUEUE.parent.mkdir(parents=True, exist_ok=True)
    action_id = str(record.get("action_id") or uuid.uuid4())
    payload = {**record, "action_id": action_id, "queued_at": now_iso_local()}
    with RESOURCE_LIBRARY_REMOVAL_QUEUE.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(payload, sort_keys=True) + "\n")
    return {"ok": True, "queued": True, "action_id": action_id, "message": "Resource Library action queued for the Hermes worker."}


def trigger_resource_library_worker() -> None:
    hermes = HOME / ".hermes" / "hermes-agent" / "venv" / "bin" / "hermes"
    cmd = [str(hermes if hermes.exists() else "hermes"), "cron", "run", RESOURCE_LIBRARY_MUTATION_CRON_ID]
    try:
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    except Exception:
        pass


def resource_favorites() -> list[str]:
    return project_resource_favorites(load_resource_library_metadata())


def set_resource_favorite(resource_id: str, favorite: bool) -> tuple[bool, dict]:
    return update_resource_favorite(
        resource_id,
        favorite,
        load_metadata=load_resource_library_metadata,
        save_metadata=save_resource_library_metadata,
        queue_action=queue_resource_action,
        trigger_worker=trigger_resource_library_worker,
    )


def set_resource_tags(resource_id: str, tags) -> tuple[bool, dict]:
    return update_resource_tags(
        resource_id,
        tags,
        load_metadata=load_resource_library_metadata,
        save_metadata=save_resource_library_metadata,
        queue_action=queue_resource_action,
        trigger_worker=trigger_resource_library_worker,
    )


def rename_resource_file(resource_id: str, source_path: str, new_name: str) -> tuple[bool, dict]:
    return rename_resource_library_file(
        resource_id,
        source_path,
        new_name,
        find_pdf=find_resource_library_pdf,
        load_metadata=load_resource_library_metadata,
        save_metadata=save_resource_library_metadata,
        queue_action=queue_resource_action,
        trigger_worker=trigger_resource_library_worker,
        refresh_library=refresh_resource_library,
    )


def queue_resource_removal(resource_id: str, source_path: str, error: str) -> dict:
    data = queue_resource_action({"action": "remove", "id": resource_id, "source": source_path, "portal_error": error})
    trigger_resource_library_worker()
    data.update({"message": "Removal queued for the Hermes Resource Library worker.", "source": source_path})
    return data


def move_resource_to_removal(resource_id: str, source_path: str = "") -> tuple[bool, dict]:
    return move_resource_file_to_removal(
        resource_id,
        source_path,
        removal_dir=RESOURCE_LIBRARY_REMOVAL_DIR,
        find_pdf=find_resource_library_pdf,
        queue_removal=queue_resource_removal,
        refresh_library=refresh_resource_library,
    )


def parse_cookie_header(cookie_header: str | None) -> dict[str, str]:
    return parse_request_cookie_header(cookie_header)


def admin_session_cookie_header(session_id: str, max_age: int | None = None) -> str:
    max_age = ADMIN_SESSION_TTL_SECONDS if max_age is None else max_age
    return compose_admin_session_cookie(ADMIN_SESSION_COOKIE, session_id, max_age)


def expired_admin_session_cookie_header() -> str:
    return compose_expired_admin_session_cookie(ADMIN_SESSION_COOKIE)


SOC_AI_SETTINGS_LOCK = threading.RLock()
_SETTINGS_RUNTIME = sys.modules[__name__]

read_prompt_file = partial(portal_settings_runtime.read_prompt_file, _SETTINGS_RUNTIME)
read_soc_analyst_prompt = partial(portal_settings_runtime.read_soc_analyst_prompt, _SETTINGS_RUNTIME)
read_siem_engineer_prompt = partial(portal_settings_runtime.read_siem_engineer_prompt, _SETTINGS_RUNTIME)
read_threat_hunter_prompt = partial(portal_settings_runtime.read_threat_hunter_prompt, _SETTINGS_RUNTIME)
read_cyber_threat_intel_prompt = partial(portal_settings_runtime.read_cyber_threat_intel_prompt, _SETTINGS_RUNTIME)
read_incident_responder_prompt = partial(portal_settings_runtime.read_incident_responder_prompt, _SETTINGS_RUNTIME)
read_settings_prompt = partial(portal_settings_runtime.read_settings_prompt, _SETTINGS_RUNTIME)
agent_memory_files = partial(portal_settings_runtime.agent_memory_files, _SETTINGS_RUNTIME)
read_agent_memory = partial(portal_settings_runtime.read_agent_memory, _SETTINGS_RUNTIME)
save_prompt_file = partial(portal_settings_runtime.save_prompt_file, _SETTINGS_RUNTIME)
save_soc_analyst_prompt = partial(portal_settings_runtime.save_soc_analyst_prompt, _SETTINGS_RUNTIME)
save_siem_engineer_prompt = partial(portal_settings_runtime.save_siem_engineer_prompt, _SETTINGS_RUNTIME)
save_threat_hunter_prompt = partial(portal_settings_runtime.save_threat_hunter_prompt, _SETTINGS_RUNTIME)
save_cyber_threat_intel_prompt = partial(portal_settings_runtime.save_cyber_threat_intel_prompt, _SETTINGS_RUNTIME)
save_incident_responder_prompt = partial(portal_settings_runtime.save_incident_responder_prompt, _SETTINGS_RUNTIME)
save_settings_prompt = partial(portal_settings_runtime.save_settings_prompt, _SETTINGS_RUNTIME)
normalize_soc_ai_settings = partial(portal_settings_runtime.normalize_soc_ai_settings, _SETTINGS_RUNTIME)
maxmind_geoip_database_status = partial(portal_settings_runtime.maxmind_geoip_database_status, _SETTINGS_RUNTIME)
maxmind_geoip_databases_status = partial(portal_settings_runtime.maxmind_geoip_databases_status, _SETTINGS_RUNTIME)
_enabled_model_routes_for_settings = partial(portal_settings_runtime.enabled_model_routes_for_settings, _SETTINGS_RUNTIME)
soc_ai_settings_store_sources = partial(portal_settings_runtime.soc_ai_settings_store_sources, _SETTINGS_RUNTIME)
read_soc_ai_settings = partial(portal_settings_runtime.read_soc_ai_settings, _SETTINGS_RUNTIME)
list_ollama_models = partial(portal_settings_runtime.list_ollama_models, _SETTINGS_RUNTIME)
_ollama_context_length = partial(portal_settings_runtime.ollama_context_length, _SETTINGS_RUNTIME)
classify_ollama_model_compatibility = partial(portal_settings_runtime.classify_ollama_model_compatibility, _SETTINGS_RUNTIME)
ollama_model_compatibility = partial(portal_settings_runtime.ollama_model_compatibility, _SETTINGS_RUNTIME)
ollama_catalog_sources = partial(portal_settings_runtime.ollama_catalog_sources, _SETTINGS_RUNTIME)
ollama_models_response = partial(portal_settings_runtime.ollama_models_response, _SETTINGS_RUNTIME)
_write_soc_ai_settings = partial(portal_settings_runtime.write_soc_ai_settings, _SETTINGS_RUNTIME)
_resolve_cli_harness_for_settings = partial(portal_settings_runtime.resolve_cli_harness_for_settings, _SETTINGS_RUNTIME)
_hermes_auth_readiness_error = partial(portal_settings_runtime.hermes_auth_readiness_error, _SETTINGS_RUNTIME)
_enabled_cli_harnesses_ready = partial(portal_settings_runtime.enabled_cli_harnesses_ready, _SETTINGS_RUNTIME)
save_soc_ai_settings = partial(portal_settings_runtime.save_soc_ai_settings, _SETTINGS_RUNTIME)
save_soc_agent_model = partial(portal_settings_runtime.save_soc_agent_model, _SETTINGS_RUNTIME)


def admin_status_path(action_id: str) -> Path:
    return action_status_path(action_id, _admin_action_state_sources())


def admin_log_path(action_id: str) -> Path:
    return action_log_path(action_id, _admin_action_state_sources())


def process_is_running(pid: int | None) -> bool:
    if not pid:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _admin_action_state_sources() -> AdminActionStateSources:
    return AdminActionStateSources(
        state_dir=ADMIN_STATE_DIR,
        lock_file=ADMIN_LOCK_FILE,
        actions=ADMIN_ACTIONS,
        process_running=process_is_running,
        now_iso=now_iso_local,
        parse_timestamp=parse_iso_timestamp,
        format_timestamp=format_iso_timestamp,
    )


def read_admin_action_status(action_id: str) -> dict:
    return read_action_status(action_id, _admin_action_state_sources())


def write_admin_action_status(action_id: str, status: dict) -> None:
    write_action_status(action_id, status, _admin_action_state_sources())


def latest_admin_action_outcome() -> dict | None:
    """Return the newest non-running admin action outcome for status banner rendering."""
    return latest_action_outcome(_admin_action_state_sources())


def read_admin_lock() -> dict | None:
    return read_action_lock(_admin_action_state_sources())


def running_admin_action() -> dict | None:
    """Return the currently running admin action, clearing stale locks when safe."""
    return running_action(_admin_action_state_sources())


def claim_admin_action_lock(action_id: str, label: str, started_at: str) -> tuple[bool, str]:
    """Atomically claim the singleton admin-action lock."""
    return claim_action_lock(
        action_id, label, started_at, _admin_action_state_sources()
    )


def update_admin_action_lock_pid(action_id: str, pid: int) -> None:
    update_action_lock_pid(action_id, pid, _admin_action_state_sources())


def release_admin_action_lock(action_id: str) -> None:
    release_action_lock(action_id, _admin_action_state_sources())


def start_admin_action(action_id: str, confirmation: str = "") -> tuple[bool, str]:
    def spawn(wrapped_command: str, log) -> int:
        proc = subprocess.Popen(
            ["/bin/bash", "-lc", wrapped_command],
            stdout=log,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            cwd=str(HOME),
            env=ADMIN_COMMAND_ENV,
            start_new_session=True,
        )
        return proc.pid

    return run_admin_action(
        action_id,
        confirmation,
        AdminActionRunnerSources(
            actions=ADMIN_ACTIONS,
            state_dir=ADMIN_STATE_DIR,
            lock_file=ADMIN_LOCK_FILE,
            macos_update_checker=HOME
            / ".hermes"
            / "scripts"
            / "check_macos_updates.py",
            now_iso=now_iso_local,
            running_action=running_admin_action,
            read_status=read_admin_action_status,
            process_running=process_is_running,
            check_available=check_admin_action_available,
            claim_lock=claim_admin_action_lock,
            release_lock=release_admin_action_lock,
            update_lock_pid=update_admin_action_lock_pid,
            write_status=write_admin_action_status,
            status_path=admin_status_path,
            log_path=admin_log_path,
            quote=shlex.quote,
            spawn=spawn,
        ),
    )


def tail_file(path: Path, max_chars: int = 7000) -> str:
    try:
        data = path.read_bytes()
    except Exception:
        return "No log output yet."
    if len(data) > max_chars:
        data = data[-max_chars:]
    return data.decode("utf-8", errors="replace")


def _cron_failure_sources() -> CronFailureSources:
    return CronFailureSources(
        jobs_file=CRON_JOBS_FILE,
        output_dir=CRON_OUTPUT_DIR,
        parse_timestamp=parse_iso_timestamp,
        format_timestamp=format_iso_timestamp,
        redact=redact_sensitive_text,
    )


def cron_failure_records(limit: int = 12) -> list[dict]:
    """Collect recent failed Hermes cron runs from jobs.json and output files."""
    return compose_cron_failure_records(_cron_failure_sources(), limit=limit)


def render_cron_failure_log_section() -> str:
    sources = _cron_failure_sources()
    return render_cron_failure_log(
        compose_cron_failure_records(sources), sources
    )



def _run_admin_version_command(command: list[str], timeout: int = 12) -> tuple[int | None, str]:
    """Run a bounded version/discovery command for Admin card metadata."""
    try:
        proc = subprocess.run(
            command,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            env=ADMIN_COMMAND_ENV,
        )
        return proc.returncode, proc.stdout.strip()
    except Exception as exc:
        return None, f"Unable to run {' '.join(command)}: {exc}"


def admin_action_version_info(action_id: str) -> dict[str, str]:
    """Return current/latest version metadata for an Administration update card."""
    return compose_admin_action_version_info(
        action_id,
        AdminVersionSources(
            run_command=lambda command, timeout: _run_admin_version_command(
                command, timeout=timeout
            ),
            read_macos_update_status=read_macos_update_status,
            hermes_bin=HERMES_BIN,
            hermes_project=HOME / ".hermes" / "hermes-agent",
        ),
    )

def check_admin_action_available(action_id: str, skip_expensive: bool = False) -> tuple[bool, str]:
    """Return whether an admin action can be started because relevant updates exist."""
    def run_command(
        command: list[str], timeout: int, combine_stderr: bool
    ) -> AdminCommandOutcome:
        try:
            proc = subprocess.run(
                command,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT if combine_stderr else subprocess.PIPE,
                timeout=timeout,
                env=ADMIN_COMMAND_ENV,
            )
            return AdminCommandOutcome(
                returncode=proc.returncode,
                stdout=proc.stdout or "",
                stderr="" if combine_stderr else (proc.stderr or ""),
            )
        except Exception as exc:
            return AdminCommandOutcome(returncode=None, error=str(exc))

    return compose_admin_action_availability(
        action_id,
        skip_expensive,
        AdminAvailabilitySources(
            read_macos_update_status=read_macos_update_status,
            run_command=run_command,
            hermes_bin=HERMES_BIN,
        ),
    )


def local_ip() -> str:
    candidates = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        candidates.append(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    try:
        hostname = socket.gethostname()
        candidates.append(socket.gethostbyname(hostname))
    except Exception:
        pass
    for ip in candidates:
        if ip and not ip.startswith("127."):
            return ip
    return "127.0.0.1"


def title_from_html(path: Path) -> str:
    return read_report_title(path)


def category_for(path: Path) -> str:
    return classify_report_category(path, HOME)


def should_skip_dir(path: Path) -> bool:
    return exclude_report_directory(path, EXCLUDE_DIR_NAMES)


def report_id(path: Path) -> str:
    return derive_report_id(path)


def scan_reports() -> list[Report]:
    return discover_reports(
        home=HOME,
        scan_roots=SCAN_ROOTS,
        standalone_html=STANDALONE_HTML,
        excluded_names=EXCLUDE_DIR_NAMES,
    )


def soc_alerts_report(reports: list[Report]) -> Report | None:
    """Return the SOC Alerts dashboard report used as the LAN Portal default page."""
    return select_soc_alerts_report(reports)


def soc_alerts_default_path(reports: list[Report]) -> str | None:
    return project_soc_alerts_default_path(reports)


def is_daily_threat_brief_file(report: Report) -> bool:
    """Return True for individual daily brief HTML files now grouped under the dashboard."""
    return classify_daily_threat_brief(report)


def human_size(n: int) -> str:
    return format_human_size(n)


def artifact_library_disk_usage() -> int:
    """Return disk usage for mirrored HTML artifacts plus supporting files.

    This intentionally measures the whole configured portal library, not just
    `.html` files, so PDFs, images, JS/CSS assets, SQLite/db files, and other
    supporting artifacts count toward the dashboard metric. Use allocated disk
    blocks when the platform exposes them; fall back to logical file size.
    """
    total = 0
    seen: set[Path] = set()
    for root in SCAN_ROOTS:
        if not root.exists():
            continue
        try:
            root = root.resolve()
        except Exception:
            continue
        if root.is_file():
            files = [root]
        else:
            files = []
            for dirpath, dirnames, filenames in os.walk(root):
                dirnames[:] = [d for d in dirnames if not should_skip_dir(Path(dirpath) / d)]
                for filename in filenames:
                    files.append(Path(dirpath) / filename)
        for path in files:
            try:
                p = path.resolve()
                if p in seen or not p.is_file():
                    continue
                seen.add(p)
                st = p.stat()
                total += int(getattr(st, "st_blocks", 0) or 0) * 512 or st.st_size
            except Exception:
                continue
    return total


def _admin_process_lines() -> list[str]:
    proc = subprocess.run(
        ["/bin/ps", "axww", "-o", "pid=,args="],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=3,
        check=True,
    )
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


def _admin_service_probe_sources() -> AdminServiceProbeSources:
    def docker_info() -> ServiceCommandOutcome:
        docker_bin = shutil.which("docker") or "/usr/local/bin/docker"
        proc = subprocess.run(
            [docker_bin, "info", "--format", "{{.ServerVersion}}"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=4,
            check=False,
            env={
                **os.environ,
                "PATH": ADMIN_COMMAND_ENV.get(
                    "PATH", os.environ.get("PATH", "")
                ),
            },
        )
        return ServiceCommandOutcome(
            returncode=proc.returncode,
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
        )

    return AdminServiceProbeSources(
        process_lines=_admin_process_lines,
        docker_info=docker_info,
    )


def process_matches(matchers: list[str], exclude: list[str] | None = None) -> list[str]:
    """Return ps output lines whose command text matches supplied substrings."""
    return matching_process_lines(_admin_process_lines(), matchers, exclude)


def macs_fan_control_status() -> tuple[bool, str]:
    """Return whether Macs Fan Control is currently running plus detail text."""
    return probe_macs_fan_control_status(_admin_service_probe_sources())


def codex_app_status() -> tuple[bool, str]:
    """Return whether the Codex desktop app is currently running plus detail text."""
    return probe_codex_app_status(_admin_service_probe_sources())


def codex_cli_status() -> tuple[bool, str]:
    """Return whether the Codex command-line interface is currently running."""
    return probe_codex_cli_status(_admin_service_probe_sources())


def docker_status() -> tuple[bool, str]:
    """Return whether Docker is currently running plus detail text."""
    return probe_docker_status(_admin_service_probe_sources())


def n8n_container_status() -> dict[str, object]:
    """Return compact n8n container/app health without exposing container config."""
    docker_bin = shutil.which("docker") or "/usr/local/bin/docker"
    env = {**os.environ, "PATH": ADMIN_COMMAND_ENV.get("PATH", os.environ.get("PATH", ""))}
    return compose_n8n_container_status(N8nContainerStatusSources(
        docker_bin=docker_bin, container_name=N8N_CONTAINER_NAME,
        health_url=N8N_HEALTH_URL, environment=env,
        pipe=subprocess.PIPE, run=subprocess.run,
        now=lambda: dt.datetime.now().astimezone(),
        format_timestamp=format_iso_timestamp,
    ))


ADMIN_SERVICE_LABELS = {
    "macs-fan-control": "Macs Fan Control",
    "codex": "Codex app",
    "codex-cli": "Codex CLI",
    "docker": "Docker",
    "n8n": "n8n container",
}


def admin_service_statuses() -> dict[str, dict[str, object]]:
    """Return current process/service status records for Administration status cards."""
    checks = {
        "macs-fan-control": macs_fan_control_status,
        "codex": codex_app_status,
        "codex-cli": codex_cli_status,
        "docker": docker_status,
    }
    return compose_admin_service_statuses(
        ADMIN_SERVICE_LABELS, checks, n8n_container_status
    )


def start_admin_service(service_id: str) -> tuple[bool, str, dict[str, object] | None]:
    """Start one allowed Administration service/app without repeating the request on refresh."""
    start_commands = {
        "macs-fan-control": ["/usr/bin/open", "-a", "Macs Fan Control"],
        "codex": ["/usr/bin/open", "-a", "Codex"],
        "codex-cli": ["/usr/bin/osascript", "-e", f'tell application "Terminal" to do script "{CODEX_CLI_BIN}"', "-e", 'tell application "Terminal" to activate'],
        "docker": ["/usr/bin/open", "-a", "Docker"],
    }
    def spawn(command: list[str]) -> None:
        subprocess.Popen(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )

    return start_allowed_admin_service(
        service_id,
        AdminServiceStartSources(
            labels=ADMIN_SERVICE_LABELS,
            start_commands=start_commands,
            statuses=admin_service_statuses,
            spawn=spawn,
        ),
    )


def defang_admin_service_json(statuses: dict[str, dict[str, object]]) -> dict[str, object]:
    return {"ok": True, "services": statuses, "time": now_iso_local()}


def system_uptime_metric() -> tuple[str, str, bool]:
    """Return compact system uptime/detail and warning state using macOS boot time plus fan-control status."""
    fan_running, fan_detail = macs_fan_control_status()
    try:
        proc = subprocess.run(
            ["/usr/sbin/sysctl", "-n", "kern.boottime"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=2,
            check=True,
        )
        match = re.search(r"sec\s*=\s*(\d+)", proc.stdout)
        if not match:
            raise ValueError(proc.stdout.strip() or "Unable to parse kern.boottime")
        boot_epoch = int(match.group(1))
        boot_dt = dt.datetime.fromtimestamp(boot_epoch).astimezone()
        now = dt.datetime.now().astimezone()
        total_seconds = max(0, int((now - boot_dt).total_seconds()))
        days, rem = divmod(total_seconds, 86400)
        hours, rem = divmod(rem, 3600)
        minutes = rem // 60
        if days:
            uptime_value = f"{days}d {hours}h"
        elif hours:
            uptime_value = f"{hours}h {minutes}m"
        else:
            uptime_value = f"{minutes}m"
        uptime_detail = f"Booted {format_iso_timestamp(boot_dt)} · uptime {days} days, {hours} hours, {minutes} minutes"
        if not fan_running:
            return "⚠ Fan Ctrl", f"{fan_detail} · {uptime_detail}", True
        return uptime_value, f"{uptime_detail} · {fan_detail}", False
    except Exception as exc:
        if not fan_running:
            return "⚠ Fan Ctrl", f"{fan_detail} · Unable to determine system uptime: {exc}", True
        return "Unknown", f"Unable to determine system uptime: {exc} · {fan_detail}", True


def local_disk_usage_metric() -> tuple[int, int, float]:
    """Return free bytes, total bytes, and percent free for the user's home volume."""
    return compose_local_disk_usage(HOME, shutil.disk_usage)


DISK_INVENTORY_CACHE: dict[str, object] = {"generated": 0.0, "dirs": [], "files": [], "warnings": []}


def _directory_disk_scan() -> DiskScanOutcome:
    try:
        proc = subprocess.run(
            ["/usr/bin/du", "-k", "-x", "-d", "4", str(HOME)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
        return DiskScanOutcome(stdout=proc.stdout, stderr=proc.stderr)
    except subprocess.TimeoutExpired:
        return DiskScanOutcome(timed_out=True)
    except Exception as exc:
        return DiskScanOutcome(error=str(exc))


def _file_disk_scan() -> DiskScanOutcome:
    find_cmd = (
        f"/usr/bin/find {shlex.quote(str(HOME))} -xdev -type f -size +1M "
        "-exec /usr/bin/stat -f '%b\t%z\t%N' {} + 2>/dev/null "
        "| /usr/bin/sort -nr | /usr/bin/head -10"
    )
    try:
        proc = subprocess.run(
            ["/bin/bash", "-lc", find_cmd],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
        return DiskScanOutcome(stdout=proc.stdout, stderr=proc.stderr)
    except subprocess.TimeoutExpired:
        return DiskScanOutcome(timed_out=True)
    except Exception as exc:
        return DiskScanOutcome(error=str(exc))


def local_disk_inventory(limit: int = 10, cache_seconds: int = 600) -> tuple[list[dict], list[dict], list[str], dt.datetime]:
    """Return cached largest directories/files under HOME for the Local Disk detail page."""

    return compose_local_disk_inventory(
        DiskInventorySources(
            home=HOME,
            cache=DISK_INVENTORY_CACHE,
            now=lambda: dt.datetime.now().astimezone(),
            directory_scan=_directory_disk_scan,
            file_scan=_file_disk_scan,
        ),
        limit=limit,
        cache_seconds=cache_seconds,
    )


def disk_inventory_rows(rows: list[dict]) -> str:
    if not rows:
        return '<tr><td colspan="3">No entries found.</td></tr>'
    return "".join(
        f"<tr><td>{idx}</td><td>{html.escape(human_size(int(row['size'])))}</td><td><code>{html.escape(str(row['path']))}</code></td></tr>"
        for idx, row in enumerate(rows, 1)
    )


def disk_file_inventory_rows(rows: list[dict]) -> str:
    if not rows:
        return '<tr><td colspan="4">No entries found.</td></tr>'
    return "".join(
        f"<tr><td>{idx}</td><td>{html.escape(human_size(int(row['size'])))}</td><td>{html.escape(human_size(int(row.get('logical_size', row['size']))))}</td><td><code>{html.escape(str(row['path']))}</code></td></tr>"
        for idx, row in enumerate(rows, 1)
    )


def hermes_backup_sources() -> HermesBackupSources:
    return HermesBackupSources(
        backup_dir=HERMES_DR_BACKUP_DIR,
        remote_dest=HERMES_DR_REMOTE_DEST,
        remote_directory=HERMES_DR_REMOTE_DIR,
        format_timestamp=format_iso_timestamp,
        human_size=human_size,
        relative_time_label=relative_time_label,
        redact_text=redact_sensitive_text,
    )


def latest_hermes_backup_metric() -> tuple[str, str, bool]:
    return compose_latest_hermes_backup_metric(hermes_backup_sources())


def macos_update_metric() -> tuple[str, str, int]:
    return compose_macos_update_metric(MACOS_UPDATE_STATUS_FILE)


def _brew_update_check() -> UpdateCommandOutcome:
    proc = subprocess.run(
        ["/opt/homebrew/bin/brew", "outdated", "--quiet"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=12,
        env=ADMIN_COMMAND_ENV,
    )
    return UpdateCommandOutcome(proc.returncode, proc.stdout, proc.stderr)


def _hermes_update_check() -> UpdateCommandOutcome:
    proc = subprocess.run(
        [HERMES_BIN, "update", "--check"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=20,
        env=ADMIN_COMMAND_ENV,
    )
    return UpdateCommandOutcome(proc.returncode, proc.stdout or "")


def update_health_sources() -> UpdateHealthSources:
    return UpdateHealthSources(
        macos_status_file=MACOS_UPDATE_STATUS_FILE,
        run_brew_check=_brew_update_check,
        run_hermes_check=_hermes_update_check,
        read_action_status=read_admin_action_status,
        process_running=process_is_running,
        action_labels={
            action_id: str(action.get("label") or action_id)
            for action_id, action in ADMIN_ACTIONS.items()
        },
        parse_timestamp=parse_iso_timestamp,
        format_timestamp=format_iso_timestamp,
    )


def brew_update_source_metric() -> tuple[int, str, list[str]]:
    return compose_brew_update_source_metric(_brew_update_check)


def hermes_update_source_metric() -> tuple[bool, str]:
    return compose_hermes_update_source_metric(_hermes_update_check)


def latest_running_update_action() -> tuple[str, str] | None:
    return compose_latest_running_update_action(update_health_sources())


def latest_update_action_failure() -> tuple[str, str] | None:
    return compose_latest_update_action_failure(update_health_sources())


def prioritized_updates_metric() -> tuple[str, str, int, str]:
    return compose_prioritized_updates_metric(update_health_sources())


def human_time(ts: float) -> str:
    return format_iso_timestamp(dt.datetime.fromtimestamp(ts).astimezone())


def update_time_label(ts: float) -> str:
    """Display an exact compact portal update timestamp."""
    return format_iso_timestamp(dt.datetime.fromtimestamp(ts).astimezone())


def relative_time_label(ts: float) -> str:
    """Display a compact relative time label such as 20m ago."""
    then = dt.datetime.fromtimestamp(ts).astimezone()
    now = dt.datetime.now().astimezone()
    seconds = max(0, int((now - then).total_seconds()))
    if seconds < 60:
        return "now"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes}m ago"
    hours = minutes // 60
    if hours < 24:
        return f"{hours}h ago"
    days = hours // 24
    return f"{days}d ago"


def admin_last_performed_label(status: dict) -> tuple[str, str]:
    """Return compact/exact labels for the last completed or attempted admin action."""
    timestamp = status.get("finished_at") or status.get("updated_at") or status.get("started_at")
    if not timestamp:
        return "Never", "No previous run recorded."
    try:
        parsed = parse_iso_timestamp(timestamp)
        if parsed.tzinfo is None:
            parsed = parsed.astimezone()
        local = parsed.astimezone()
        relative = relative_time_label(local.timestamp())
        exact = format_iso_timestamp(local)
        state = str(status.get("state") or "unknown")
        rc = status.get("returncode")
        rc_text = "running" if state == "running" else (f"rc {rc}" if rc is not None else "no return code")
        return relative, f"{exact} · {state} · {rc_text}"
    except Exception:
        return str(timestamp), str(status.get("message") or "Timestamp could not be parsed.")


def portal_last_updated(reports: list[Report]) -> float | None:
    """Return the last time the mirrored LAN portal library actually changed.

    The sync script updates LAST_UPDATED_FILE only when it copies/removes mirrored
    artifacts. If that marker does not exist yet, fall back to the newest report
    mtime so the stat still shows an actual timestamp rather than a relative label.
    """
    try:
        raw = LAST_UPDATED_FILE.read_text().strip()
        if raw:
            return parse_iso_timestamp(raw).timestamp()
    except Exception:
        pass
    return max((r.mtime for r in reports), default=None)


def schedule_label(job: dict) -> str:
    schedule = job.get("schedule") or {}
    if isinstance(schedule, dict):
        return str(schedule.get("display") or schedule.get("expr") or schedule.get("kind") or "unscheduled")
    return str(job.get("schedule_display") or schedule or "unscheduled")


def next_run_label(value: str | None, enabled: bool) -> tuple[str, str]:
    if not enabled:
        return "Disabled", "9999"
    if not value:
        return "Not scheduled", "9998"
    try:
        parsed = parse_iso_timestamp(value)
        if parsed.tzinfo is None:
            parsed = parsed.astimezone()
        local = parsed.astimezone()
        label = format_iso_timestamp(local)
        return label, format_iso_timestamp(parsed)
    except Exception:
        return value, value


def load_cron_summaries() -> tuple[list[CronJobSummary], list[CronJobSummary]]:
    """Load current Hermes cron jobs for the portal dropdown.

    Enabled jobs are sorted by next run. Disabled/paused jobs are returned separately
    so the UI can pin them to the bottom of the menu.
    """
    try:
        data = json.loads(CRON_JOBS_FILE.read_text())
    except Exception:
        return [], []
    enabled_jobs: list[CronJobSummary] = []
    disabled_jobs: list[CronJobSummary] = []
    for job in data.get("jobs", []):
        is_enabled = bool(job.get("enabled")) and str(job.get("state", "")).lower() not in {"paused", "disabled"}
        next_label, sort_key = next_run_label(job.get("next_run_at"), is_enabled)
        summary = CronJobSummary(
            jid=str(job.get("id") or job.get("job_id") or "unknown"),
            name=str(job.get("name") or "Unnamed cron"),
            schedule=schedule_label(job),
            next_run=next_label,
            enabled=is_enabled,
            state=str(job.get("state") or ("scheduled" if is_enabled else "disabled")),
            last_status=str(job.get("last_status") or "never"),
            sort_key=sort_key,
        )
        (enabled_jobs if is_enabled else disabled_jobs).append(summary)
    enabled_jobs.sort(key=lambda j: (j.sort_key, j.name.lower()))
    disabled_jobs.sort(key=lambda j: j.name.lower())
    return enabled_jobs, disabled_jobs


def render_cron_menu() -> str:
    enabled_jobs, disabled_jobs = load_cron_summaries()
    total = len(enabled_jobs) + len(disabled_jobs)
    if total == 0:
        body = '<div class="cron-empty">No Hermes cron jobs found.</div>'
    else:
        enabled_html = "".join(render_cron_item(j) for j in enabled_jobs) or '<div class="cron-empty">No enabled cron jobs.</div>'
        disabled_html = "".join(render_cron_item(j, disabled=True) for j in disabled_jobs)
        disabled_section = f'<div class="cron-disabled"><div class="cron-section-label">Disabled / paused</div>{disabled_html}</div>' if disabled_jobs else ''
        body = f'{enabled_html}{disabled_section}'
    return f'''
    <details class="cron-menu">
      <summary>
        <span class="cron-summary-main"><span class="cron-dot"></span><span><b>Cron Schedule</b><small>{len(enabled_jobs)} enabled · {len(disabled_jobs)} disabled</small></span></span>
        <span class="cron-chevron">⌄</span>
      </summary>
      <div class="cron-panel">{body}</div>
    </details>'''


def render_cron_item(job: CronJobSummary, disabled: bool = False) -> str:
    status_class = "disabled" if disabled else "enabled"
    return f'''
      <div class="cron-item {status_class}">
        <div class="cron-item-top">
          <strong>{html.escape(job.name)}</strong>
          <span class="cron-status {status_class}">{'Disabled' if disabled else 'Enabled'}</span>
        </div>
        <div class="cron-next"><span>Next run</span><b>{html.escape(job.next_run)}</b></div>
        <div class="cron-meta"><span>ID: {html.escape(job.jid)}</span><span>Schedule: {html.escape(job.schedule)}</span><span>Last: {html.escape(job.last_status)}</span></div>
      </div>'''


def icon_for(cat: str) -> str:
    if "Threat" in cat:
        return "🛡️"
    if "Product" in cat:
        return "📈"
    if "Prototype" in cat:
        return "🧩"
    if "Web App Projects" in cat:
        return "🧩"
    if "Local AI" in cat:
        return "🧠"
    if "Cybersecurity" in cat or "Resource Library" in cat:
        return "📚"
    if "Portal Operations" in cat:
        return "🧭"
    return "📄"


def redact_sensitive_text(text: str) -> str:
    """Redact secrets/sensitive credential file references before rendering logs."""
    text = re.sub(re.escape(str(HOME / ".hermes" / "backup" / "full-backup.passphrase")), "[REDACTED_PASSPHRASE_FILE]", text)
    text = re.sub(r"(Passphrase file(?: at creation time)?:\s*)\S+", r"\1[REDACTED_PASSPHRASE_FILE]", text)
    return text


def read_macos_update_status() -> dict:
    return load_macos_update_status(MACOS_UPDATE_STATUS_FILE)


def backup_inventory() -> tuple[list[dict], dict]:
    return compose_backup_inventory(hermes_backup_sources())


def metric_detail_shell(title: str, kicker: str, body_html: str, hero_extra_html: str = "") -> bytes:
    return render_metric_detail_shell(title, kicker, body_html, hero_extra_html)


def render_macos_updates_detail() -> bytes:
    return render_macos_update_metrics(
        read_macos_update_status(), MACOS_UPDATE_STATUS_FILE
    )


def render_prioritized_updates_detail() -> bytes:
    return render_prioritized_update_metrics(
        prioritized_updates_metric(),
        macos_update_metric(),
        brew_update_source_metric(),
        hermes_update_source_metric(),
    )


def render_hermes_backups_detail() -> bytes:
    rows, meta = backup_inventory()
    return render_hermes_backup_metrics(
        rows,
        meta,
        format_timestamp=format_iso_timestamp,
        human_size=human_size,
        relative_time=relative_time_label,
    )


def render_system_uptime_detail() -> bytes:
    return render_system_uptime_metrics(
        system_uptime_metric(), macs_fan_control_status(), socket.gethostname()
    )


def render_local_disk_detail() -> bytes:
    return render_local_disk_metrics(
        local_disk_usage_metric(),
        local_disk_inventory(),
        home=HOME,
        human_size=human_size,
        format_timestamp=format_iso_timestamp,
        directory_rows=disk_inventory_rows,
        file_rows=disk_file_inventory_rows,
    )


def render_portal_update_detail(reports: list[Report]) -> bytes:
    return render_portal_update_metrics(
        len(reports),
        portal_last_updated(reports),
        marker_file=LAST_UPDATED_FILE,
        from_timestamp=dt.datetime.fromtimestamp,
        now=dt.datetime.now,
        update_time_label=update_time_label,
        format_timestamp=format_iso_timestamp,
    )


def render_admin_login(message: str = "", error: bool = False) -> bytes:
    token = ensure_admin_token()
    configured = admin_password_configured()
    message_html = ""
    if message:
        message_html = f'<section class="section"><span class="badge {"warn" if error else ""}">{"Authentication blocked" if error else "Authentication"}</span><p>{html.escape(message)}</p></section>'
    setup_html = "" if configured else f'''
<section class="section"><span class="badge warn">Password not configured</span><p>Set the local admin password before using the Administration dashboard:</p><pre>{html.escape(str(HOME / "report_portal" / "set_admin_password.py"))}</pre><p>The password is stored only as a salted PBKDF2-HMAC-SHA256 hash at <code>{html.escape(str(ADMIN_PASSWORD_FILE))}</code>.</p></section>'''
    disabled_attr = "" if configured else " disabled"
    body = f'''
<style>
.login-card {{ max-width:520px; border:1px solid var(--line); border-radius:22px; background:linear-gradient(145deg, rgba(18,26,41,.94), rgba(10,16,27,.90)); padding:20px; box-shadow:0 14px 40px rgba(0,0,0,.18) }}
.login-card form {{ display:grid; gap:12px }}
.login-card label {{ display:grid; gap:8px; color:#d7e5f8; font-size:13px; font-weight:900 }}
.login-card input {{ width:100%; border:1px solid rgba(35,211,238,.28); border-radius:14px; padding:12px 13px; color:#fff; background:rgba(2,6,23,.62); font:inherit }}
.login-card button {{ border:0; border-radius:14px; padding:12px 14px; font-weight:950; color:#061018; background:linear-gradient(135deg, var(--cyan), var(--blue)); cursor:pointer }}
.login-card button:disabled {{ cursor:not-allowed; opacity:.48; filter:saturate(.45); background:linear-gradient(135deg, #64748b, #334155); color:#dbeafe }}
</style>
{message_html}
{setup_html}
<section class="login-card">
  <form method="post" action="/admin/login">
    <input type="hidden" name="token" value="{html.escape(token)}" />
    <label>Admin password<input name="password" type="password" autocomplete="current-password" autofocus /></label>
    <button type="submit"{disabled_attr}>Sign in</button>
  </form>
</section>
<section class="section"><p>Administration uses a password form, local salted password hash, server-side session cookie, CSRF validation, POST-only actions, and the existing typed reboot confirmation.</p></section>'''
    return metric_detail_shell("Administration sign in", "Protected administration", body)


def render_admin_dashboard(message: str = "", error: bool = False) -> bytes:
    """Render the Administration dashboard through its modular view model."""
    sources = AdminDashboardSources(
        ensure_token=ensure_admin_token,
        running_action=running_admin_action,
        latest_outcome=latest_admin_action_outcome,
        service_statuses=admin_service_statuses,
        actions=ADMIN_ACTIONS,
        read_action_status=read_admin_action_status,
        last_performed_label=admin_last_performed_label,
        check_action_available=check_admin_action_available,
        action_version_info=admin_action_version_info,
        state_dir=ADMIN_STATE_DIR,
        human_size=human_size,
        format_timestamp=format_iso_timestamp,
        tail_file=tail_file,
        admin_log_path=admin_log_path,
        render_cron_failure=render_cron_failure_log_section,
        render_cron_menu=render_cron_menu,
    )
    view = compose_admin_dashboard(sources)
    return render_admin_dashboard_view(
        view,
        message,
        error,
        metric_detail_shell,
    )


def render_home(reports: list[Report], host: str, port: int) -> bytes:
    """Render the home dashboard through its modular view model."""
    del host, port  # Retained in the public API for route compatibility.
    sources = HomeDashboardSources(
        system_uptime=system_uptime_metric,
        portal_last_updated=portal_last_updated,
        prioritized_updates=prioritized_updates_metric,
        latest_hermes_backup=latest_hermes_backup_metric,
        local_disk_usage=local_disk_usage_metric,
        human_size=human_size,
        relative_time=relative_time_label,
        format_timestamp=format_iso_timestamp,
        soc_alerts_report=soc_alerts_report,
        now=lambda: dt.datetime.now().astimezone(),
    )
    return render_home_dashboard(compose_home_dashboard(reports, sources))

def normalize_soc_alert_status_meta(value: object, *, now: str | None = None) -> dict | None:
    """Normalize analyst-controlled alert workflow state before persistence."""
    return normalize_status_meta(value, now_iso=now_iso_utc, now=now)


def ensure_soc_alert_status_table(conn: sqlite3.Connection) -> None:
    """Create and migrate analyst status/adjudication persistence tables."""
    ensure_soc_alert_status_schema(conn)


def soc_alert_group_key_from_values(
    triage_level: object,
    rule_name: object,
    source_ip: object,
    destination_ip: object,
    filter_status: object,
    suppression_key: object = None,
) -> str:
    """Return the stable grouped-detection key used by the dashboard/API."""
    if suppression_key:
        return str(suppression_key)
    return "|".join([
        str(triage_level or "unknown-level"),
        str(rule_name or "unknown-rule"),
        str(source_ip or "unknown-source"),
        str(destination_ip or "unknown-destination"),
        str(filter_status or "accepted"),
    ])


def soc_alert_group_id(group_key: object) -> str:
    return hashlib.sha1(str(group_key or "").encode("utf-8")).hexdigest()[:12]


def soc_alert_group_key_sql() -> str:
    return """
      COALESCE(
        NULLIF(suppression_key, ''),
        COALESCE(triage_level, 'unknown-level') || '|' ||
        COALESCE(rule_name, 'unknown-rule') || '|' ||
        COALESCE(source_ip, 'unknown-source') || '|' ||
        COALESCE(destination_ip, 'unknown-destination') || '|' ||
        COALESCE(filter_status, 'accepted')
      )
    """


def soc_alert_public_enrichment_status(enrichment_json: object) -> dict:
    return compose_enrichment_status(enrichment_json)


def soc_alert_group_enrichment_json(conn: sqlite3.Connection, group_key: object) -> str:
    key = str(group_key or "").strip()
    return soc_alert_group_enrichment_json_map(conn, [key]).get(key, "") if key else ""


def soc_alert_group_enrichment_json_map(
    conn: sqlite3.Connection,
    group_keys: list[object],
) -> dict[str, str]:
    """Load the best enrichment record for each visible group in one query.

    Group keys are derived expressions rather than indexed columns in the raw
    alert table. Looking them up one row at a time therefore scans the alert
    corpus once per displayed group. The window query below scans it once for
    the bounded page and preserves the same quality/newness ordering used by
    ``soc_alert_group_enrichment_json``.
    """
    plan = group_enrichment_query_plan(group_keys, soc_alert_group_key_sql())
    if not plan.args:
        return {}
    try:
        rows = conn.execute(plan.sql, plan.args).fetchall()
    except sqlite3.Error:
        return {}
    return project_group_enrichment_rows(rows)


def directory_size_bytes(path: Path) -> int:
    """Return total bytes for a runtime evidence directory without following symlinks."""
    if not path.exists():
        return 0
    total = 0
    for item in path.rglob("*"):
        try:
            if item.is_file() and not item.is_symlink():
                total += item.stat().st_size
        except OSError:
            continue
    return total


def soc_alert_has_parsed_pcap(record: dict) -> bool:
    """Return true only for admitted parsed capture artifacts."""
    return _modular_has_parsed_pcap(record)


def read_artifact_cache(name: str, path: Path) -> object | None:
    return SOC_ALERT_ARTIFACT_CACHE.get(name, path)


def write_artifact_cache(name: str, path: Path, value: object) -> object:
    return SOC_ALERT_ARTIFACT_CACHE.put(name, path, value)


def _soc_pcap_artifact_sources() -> PcapArtifactSources:
    return PcapArtifactSources(
        paths=lambda: SOC_ALERT_PCAP_ANALYSIS_DIR.glob("*-pcap-analysis.json"),
        read_record=lambda path: json.loads(path.read_text(encoding="utf-8")),
        modified_time=lambda path: path.stat().st_mtime,
    )


def soc_alert_pcap_analysis_index() -> dict[str, object]:
    """Index parsed Zeek/TShark artifacts once per API response."""
    return SOC_ALERT_ARTIFACT_CACHE.get_or_compute(
        "pcap-analysis-index", SOC_ALERT_PCAP_ANALYSIS_DIR,
        lambda: build_pcap_analysis_index(_soc_pcap_artifact_sources()),
    )


def soc_alert_pcap_request_statuses(conn: sqlite3.Connection, rows: list[sqlite3.Row | dict]) -> dict[str, dict]:
    """Return page-bounded PCAP request state through the modular repository."""
    dependencies = SocPcapStatusDependencies(
        table_exists=sqlite_table_exists,
        dashboard_group_id=soc_alert_group_id,
    )
    return load_pcap_request_statuses(conn, rows, dependencies)


def soc_alert_pcap_status(group_id: str, alert_id: str, analysis_index: dict[str, object], request_statuses: dict[str, dict]) -> dict:
    """Return the compact PCAP status through the modular policy."""
    return compose_pcap_status(group_id, alert_id, analysis_index, request_statuses)


def soc_alert_pcap_analysis_record(group_id: str) -> dict | None:
    """Return newest parsed PCAP evidence for a grouped alert detail fragment."""
    if not SOC_ALERT_PCAP_ANALYSIS_DIR.exists():
        return None
    return newest_pcap_analysis_record(group_id, _soc_pcap_artifact_sources())


def soc_alert_pcap_summary_html(record: dict) -> str:
    """Render bounded parsed packet evidence through the modular renderer."""
    return render_pcap_summary(record)


SOC_ALERT_DETAIL_LAYOUT_VERSION = "2026-07-15.1"
SOC_ALERT_DETAIL_LAYOUT_MARKERS = (
    ("alert identity", "<h2>["),
    ("triage reasons", "detail-section-triage-reasons"),
    ("duplicate alert timeline", "alert-timeline-section"),
    ("ai analysis output", "detail-section-ai-analysis-output"),
    ("ai model used", "detail-section-ai-model-used"),
    ("enriched alert details", "detail-section-enriched-alert-details"),
    ("alert summary", "detail-section-alert-summary"),
    ("analyst notes", "detail-section-analyst-notes"),
    ("parsed pcap evidence", "detail-section-parsed-pcap-evidence"),
    ("network and flow details", "detail-section-network-and-flow-details"),
    ("protocol details", "detail-section-protocol-details"),
    ("host and sensor details", "detail-section-host-and-sensor-details"),
    ("threat context", "detail-section-threat-context"),
    ("security onion detail fields", "detail-section-security-onion-detail-fields"),
    ("raw logs", "detail-section-raw-logs"),
)


def soc_alert_validate_detail_layout_html(detail_html: str) -> list[str]:
    """Validate the immutable analyst-facing layout before the API serves it."""
    issues: list[str] = []
    version_match = re.search(r'data-layout-version="([^"]+)"', detail_html or "")
    version = version_match.group(1) if version_match else "missing"
    if version != SOC_ALERT_DETAIL_LAYOUT_VERSION:
        issues.append(
            f"Report layout version is {version}; expected {SOC_ALERT_DETAIL_LAYOUT_VERSION}. "
            "The dashboard must be rebuilt from the current report template."
        )
    positions: list[int] = []
    for label, marker in SOC_ALERT_DETAIL_LAYOUT_MARKERS:
        count = (detail_html or "").count(marker)
        if count != 1:
            issues.append(f'Required section "{label}" appeared {count} time(s); exactly one is required.')
        positions.append((detail_html or "").find(marker))
    present_positions = [position for position in positions if position >= 0]
    if present_positions != sorted(present_positions):
        issues.append("Required report sections are not in the canonical order.")
    return list(dict.fromkeys(issues))


def soc_alert_layout_error_html(issues: list[str]) -> str:
    """Return an escaped error payload that the dashboard promotes to a modal."""
    items = "".join(f"<li>{html.escape(issue)}</li>" for issue in issues)
    return (
        f'<section class="detail-layout-error" role="alert" data-layout-version="{SOC_ALERT_DETAIL_LAYOUT_VERSION}">'
        "<strong>Detailed Alert Report layout error</strong>"
        "<p>Historical or malformed report data could not be mapped to the required layout. "
        "The report is shown for recovery context, but it does not satisfy the current standard.</p>"
        f"<ul>{items}</ul></section>"
    )


def soc_alert_append_live_pcap_detail(group_id: str, detail_html: str) -> str:
    """Preserve the canonical fragment; late evidence must never append a new section.

    PCAP status is queried live for the alert row, while the scheduled dashboard
    rebuild refreshes the canonical Parsed PCAP Evidence body. Appending here
    used to place PCAP evidence after Raw Logs and silently broke the contract.
    """
    _ = group_id
    return detail_html


SOC_ALERT_COLLAPSIBLE_DETAIL_SECTIONS = {
    "ai model used": "AI Model Used",
    "alert summary": "Alert Summary",
    "network and flow details": "Network And Flow Details",
    "tshark findings": "TShark Findings",
    "tshark corroboration": "TShark Findings",
    "protocol details": "Protocol Details",
    "host and sensor details": "Host And Sensor Details",
    "threat context": "Threat Context",
    "analyst notes": "Analyst Notes",
}


def soc_alert_normalize_heading_text(value: str) -> str:
    text = re.sub(r"<[^>]+>", "", value or "")
    text = html.unescape(text)
    text = re.sub(r"[^a-z0-9]+", " ", text.lower()).strip()
    return text


def soc_alert_collapse_detail_sections(detail_html: str) -> str:
    """Collapse expensive reference sections in lazy-loaded alert detail HTML."""
    if not detail_html or "detail-collapsible-section" in detail_html:
        return detail_html
    heading_re = re.compile(r"<h([2-6])([^>]*)>(.*?)</h\1>", re.IGNORECASE | re.DOTALL)
    matches = list(heading_re.finditer(detail_html))
    if not matches:
        return detail_html
    chunks: list[str] = []
    cursor = 0
    index = 0
    while index < len(matches):
        match = matches[index]
        level = int(match.group(1))
        normalized = soc_alert_normalize_heading_text(match.group(3))
        summary = SOC_ALERT_COLLAPSIBLE_DETAIL_SECTIONS.get(normalized)
        if not summary:
            index += 1
            continue
        end = len(detail_html)
        next_index = index + 1
        while next_index < len(matches):
            next_level = int(matches[next_index].group(1))
            if next_level <= level:
                end = matches[next_index].start()
                break
            next_index += 1
        slug = re.sub(r"[^a-z0-9]+", "-", normalized).strip("-") or "detail"
        chunks.append(detail_html[cursor:match.start()])
        chunks.append(
            f'<details class="detail-report-section detail-collapsible-section detail-section-{slug}">'
            f"<summary>{html.escape(summary)}</summary>"
            f'<div class="detail-collapsible-body">{detail_html[match.end():end]}</div>'
            "</details>"
        )
        cursor = end
        index = next_index
    chunks.append(detail_html[cursor:])
    return "".join(chunks)


def sqlite_table_exists(conn: sqlite3.Connection, table_name: str) -> bool:
    try:
        row = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
            (table_name,),
        ).fetchone()
    except sqlite3.Error:
        return False
    return bool(row)


def sqlite_table_columns(conn: sqlite3.Connection, table_name: str) -> set[str]:
    try:
        rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    except sqlite3.Error:
        return set()
    return {str(row[1]) for row in rows}


def bounded_int(value: object, default: int, low: int, high: int) -> int:
    return bounded_pcap_int(value, default, low, high)


def pcap_request_id(seed: dict) -> str:
    return projected_pcap_request_id(seed)


def normalize_pcap_timestamp(value: object) -> str:
    if not value:
        return ""
    try:
        return format_iso_timestamp(parse_iso_timestamp(value), utc_z=True)
    except Exception:
        return ""


def pcap_capture_file_from_json(*values: object) -> str | None:
    return extract_pcap_capture_file(*values)


def pcap_request_store_sources() -> PcapRequestStoreSources:
    return PcapRequestStoreSources(
        table_exists=sqlite_table_exists,
        table_columns=sqlite_table_columns,
        now_iso=now_iso_utc,
    )


def pcap_request_candidate_from_group(conn: sqlite3.Connection, group_id: str) -> dict:
    return read_pcap_request_candidate(
        pcap_request_store_sources(), conn, group_id
    )


def pcap_request_policy_sources() -> PcapRequestPolicySources:
    return PcapRequestPolicySources(normalize_timestamp=normalize_pcap_timestamp)


def normalize_pcap_request(payload: dict, candidate: dict) -> tuple[dict | None, str]:
    return normalize_pcap_request_policy(
        pcap_request_policy_sources(), payload, candidate
    )


def insert_pcap_request(conn: sqlite3.Connection, request: dict) -> sqlite3.Row:
    return store_pcap_request(pcap_request_store_sources(), conn, request)


def asset_store_write_token() -> str:
    """Read the owner-controlled local asset-write credential without exporting it."""
    return load_asset_store_write_token(
        os.environ.get("ASSET_STORE_WRITE_TOKEN"),
        Path(ASSET_STORE_ENV_FILE),
    )


def asset_store_post_json(path: str, payload: dict, timeout: float = 10.0) -> dict:
    """Send one authenticated asset mutation to the loopback alert-store."""
    return AssetStoreClient(
        base_url=SOC_ALERT_STORE_API_URL,
        maximum_response_bytes=SOC_ALERT_STORE_RESPONSE_MAX_BYTES,
        token=asset_store_write_token,
        read_json=read_bounded_json,
    ).post(path, payload, timeout)


def alert_store_post_json(path: str, payload: dict, timeout: float = 5.0) -> dict:
    """POST to the host alert-store and preserve its bounded error detail."""
    encoded = json.dumps(payload).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Content-Length": str(len(encoded)),
    }
    if SOC_ALERT_STORE_EVALUATION_TOKEN:
        headers["X-Onion-Sentinel-Evaluation-Token"] = (
            SOC_ALERT_STORE_EVALUATION_TOKEN
        )
    req = urllib_request.Request(
        f"{SOC_ALERT_STORE_API_URL}{path}",
        data=encoded,
        method="POST",
        headers=headers,
    )
    try:
        with urllib_request.urlopen(req, timeout=timeout) as response:
            result = read_bounded_json(response, max_bytes=SOC_ALERT_STORE_RESPONSE_MAX_BYTES)
    except urllib_error.HTTPError as exc:
        try:
            error_payload = read_bounded_json(exc, max_bytes=SOC_ALERT_STORE_RESPONSE_MAX_BYTES)
            detail = str(error_payload.get("reason") or error_payload.get("error") or exc.reason)
        except (OSError, BoundedResponseError):
            detail = str(exc.reason)
        raise AlertStoreRequestError(detail, int(exc.code or 503)) from exc
    except (OSError, urllib_error.URLError, json.JSONDecodeError) as exc:
        raise AlertStoreRequestError(str(exc), 503) from exc
    if not isinstance(result, dict) or not result.get("ok"):
        raise AlertStoreRequestError(
            str(result.get("reason") or result.get("error") or "alert-store rejected request"),
            400,
        )
    return result


def _normalized_asset_review_payload(
    payload: object,
    *,
    action: str,
) -> dict:
    return normalize_asset_review_payload(payload, action=action)


def _clear_asset_inventory_cache() -> None:
    with ASSET_INVENTORY_CACHE_LOCK:
        ASSET_INVENTORY_CACHE.clear()
        ASSET_INVENTORY_CACHE.update(
            {"signature": None, "inventory": None, "expires_at": 0.0}
        )


def asset_dhcp_promotion_response(payload: object) -> tuple[int, dict]:
    return execute_asset_mutation(
        payload,
        normalizer=lambda value: _normalized_asset_review_payload(
            value, action="promote",
        ),
        path="/assets/promote-dhcp",
        success_status=HTTPStatus.CREATED,
        write=asset_store_post_json,
        clear_cache=_clear_asset_inventory_cache,
    )


def asset_dhcp_ip_change_response(payload: object) -> tuple[int, dict]:
    return execute_asset_mutation(
        payload,
        normalizer=lambda value: _normalized_asset_review_payload(
            value, action="ip_change",
        ),
        path="/assets/approve-dhcp-ip-change",
        success_status=HTTPStatus.CREATED,
        write=asset_store_post_json,
        clear_cache=_clear_asset_inventory_cache,
    )


def _normalized_asset_mutation_payload(
    payload: object,
    *,
    action: str,
) -> dict:
    return normalize_asset_mutation_payload(
        payload, action=action, parse_timestamp=parse_iso_timestamp,
    )


def asset_update_response(payload: object) -> tuple[int, dict]:
    return execute_asset_mutation(
        payload,
        normalizer=lambda value: _normalized_asset_mutation_payload(
            value, action="edit",
        ),
        path="/assets/update",
        success_status=HTTPStatus.OK,
        write=asset_store_post_json,
        clear_cache=_clear_asset_inventory_cache,
    )


def asset_demote_response(payload: object) -> tuple[int, dict]:
    return execute_asset_mutation(
        payload,
        normalizer=lambda value: _normalized_asset_mutation_payload(
            value, action="demote",
        ),
        path="/assets/demote",
        success_status=HTTPStatus.OK,
        write=asset_store_post_json,
        clear_cache=_clear_asset_inventory_cache,
    )


def dispatch_asset_write(path: str, payload: object) -> tuple[int, dict]:
    callbacks = {
        "/api/assets/promote-dhcp": asset_dhcp_promotion_response,
        "/api/assets/approve-dhcp-ip-change": asset_dhcp_ip_change_response,
        "/api/assets/update": asset_update_response,
        "/api/assets/demote": asset_demote_response,
    }
    callback = callbacks.get(path)
    if callback is None:
        return HTTPStatus.NOT_FOUND, {"ok": False, "error": "Not found"}
    return callback(payload)


def portal_cti_program_callbacks(
    audit,
) -> CtiProgramCallbacks:
    """Bind current CTI storage functions without defeating test patching."""
    return CtiProgramCallbacks(
        load=cti_program.load_program,
        save=cti_program.save_program,
        public_response=cti_program.public_response,
        audit=audit,
        conflict_error=cti_program.CTIProgramConflict,
        program_error=cti_program.CTIProgramError,
    )


def alert_store_get_json(path: str, timeout: float = 5.0) -> dict:
    """Read a bounded, non-secret alert-store operational endpoint."""
    if not SOC_ALERT_STORE_API_URL:
        raise RuntimeError("alert-store API URL is not configured")
    try:
        req = urllib_request.Request(f"{SOC_ALERT_STORE_API_URL}{path}", method="GET")
    except ValueError as exc:
        raise RuntimeError(f"invalid alert-store API URL: {exc}") from exc
    try:
        with urllib_request.urlopen(req, timeout=timeout) as response:
            result = read_bounded_json(response, max_bytes=SOC_ALERT_STORE_RESPONSE_MAX_BYTES)
    except urllib_error.HTTPError as exc:
        raise RuntimeError(f"HTTP {exc.code}: {exc.reason}") from exc
    except (OSError, urllib_error.URLError, json.JSONDecodeError) as exc:
        raise RuntimeError(str(exc)) from exc
    if not isinstance(result, dict) or not result.get("ok"):
        raise RuntimeError(str(result.get("reason") or result.get("error") or "alert-store returned invalid metrics"))
    return result


def pcap_request_service_sources() -> PcapRequestServiceSources:
    return PcapRequestServiceSources(
        connect_write=soc_alert_db_write_connect,
        table_exists=sqlite_table_exists,
        read_candidate=pcap_request_candidate_from_group,
        normalize_request=normalize_pcap_request,
        insert_request=insert_pcap_request,
        post_alert_store=alert_store_post_json,
        alert_store_configured=bool(SOC_ALERT_STORE_API_URL),
    )


def soc_alert_pcap_request_response(group_id: str, payload: dict) -> tuple[int, dict]:
    return request_soc_alert_pcap(
        pcap_request_service_sources(), group_id, payload
    )


def soc_alert_group_summary_available(conn: sqlite3.Connection) -> bool:
    """Return true when alert-store has populated the fast grouped summary."""
    return group_summary_available(soc_alert_status_store_sources(), conn)


def soc_alert_group_counts(conn: sqlite3.Connection) -> dict[str, int]:
    """Return current grouped repeat counts, keyed by group_id."""
    return load_soc_alert_group_counts(soc_alert_status_store_sources(), conn)


def soc_alert_manually_escalated_group_ids(conn: sqlite3.Connection) -> set[str]:
    """Return every dashboard alias moved manually to Incident Responder."""
    return load_manually_escalated_group_ids(
        soc_alert_status_store_sources(), conn
    )


def soc_alert_active_group_ids(
    conn: sqlite3.Connection,
    statuses: dict,
    manually_escalated_group_ids: set[str] | None = None,
) -> set[str]:
    """Return grouped detections currently visible in the default active view."""
    return load_active_soc_group_ids(
        soc_alert_status_store_sources(),
        conn,
        statuses,
        manually_escalated_group_ids,
    )


def soc_alert_status_store_sources() -> SocAlertStatusStoreSources:
    return SocAlertStatusStoreSources(
        table_exists=sqlite_table_exists,
        group_key_sql=soc_alert_group_key_sql,
        group_id=soc_alert_group_id,
        now_iso=now_iso_utc,
    )


def normalize_soc_group_statuses(conn: sqlite3.Connection) -> dict:
    """Load current group state and hide stale acknowledgements.

    Acknowledged detections should reappear when the matching grouped detection
    count increases. Suppressed detections remain hidden until explicitly
    exposed. Production deletion is owned by alert-store; portal reads must not
    become a second SQLite writer.
    """
    return load_soc_group_statuses(soc_alert_status_store_sources(), conn)


def soc_alert_status_persistence_sources() -> SocAlertStatusPersistenceSources:
    store = soc_alert_status_store_sources()
    return SocAlertStatusPersistenceSources(
        db_path=SOC_ALERT_STORE_DB,
        mirror_path=SOC_ALERT_STATUS_FILE,
        connect_read=soc_alert_db_connect,
        connect_write=soc_alert_db_write_connect,
        ensure_schema=ensure_soc_alert_status_table,
        load_db=normalize_soc_group_statuses,
        write_one=lambda conn, alert_id, meta: write_soc_group_status(
            store, conn, alert_id, meta
        ),
        write_many=lambda conn, statuses: write_soc_group_statuses(
            store, conn, statuses
        ),
        normalize=normalize_soc_alert_status_meta,
        now_iso=now_iso_utc,
        uuid_hex=lambda: uuid.uuid4().hex,
        lock=SOC_ALERT_DB_WRITE_LOCK,
        sleep=time.sleep,
        retry_attempts=SOC_ALERT_DB_WRITE_RETRY_ATTEMPTS,
        retry_base_seconds=SOC_ALERT_DB_WRITE_RETRY_BASE_SECONDS,
    )


def load_soc_alert_statuses_from_db() -> dict:
    return load_persisted_soc_alert_statuses_from_db(
        soc_alert_status_persistence_sources()
    )


def write_soc_alert_status_json_snapshot(statuses: dict) -> None:
    write_persisted_soc_alert_status_snapshot(
        soc_alert_status_persistence_sources(), statuses
    )


def save_soc_alert_statuses_to_db(statuses: dict) -> None:
    """Persist offline DR-test state; production writes through alert-store."""
    save_persisted_soc_alert_statuses_to_db(
        soc_alert_status_persistence_sources(), statuses
    )


def load_soc_alert_statuses() -> dict:
    """Load shared SOC alert status state, using JSON only if SQLite is absent."""
    return load_persisted_soc_alert_statuses(
        soc_alert_status_persistence_sources()
    )


def save_soc_alert_statuses(statuses: dict) -> None:
    save_persisted_soc_alert_statuses(
        soc_alert_status_persistence_sources(), statuses
    )


def current_soc_alert_group_repeat_count(alert_id: str) -> int:
    if not SOC_ALERT_STORE_DB.exists():
        return 0
    try:
        with soc_alert_db_connect() as conn:
            return int(soc_alert_group_counts(conn).get(alert_id, 0) or 0)
    except Exception:
        return 0


def write_soc_alert_status(alert_id: str, meta: dict) -> None:
    """Atomically persist one analyst state change, then refresh the JSON mirror."""
    persist_soc_alert_status(
        soc_alert_status_persistence_sources(), alert_id, meta
    )


def soc_alert_status_response() -> dict:
    statuses = load_soc_alert_statuses()
    try:
        with soc_alert_db_connect() as conn:
            group_counts = soc_alert_group_counts(conn)
            escalated_group_ids = soc_alert_manually_escalated_group_ids(conn)
            active_group_ids = soc_alert_active_group_ids(conn, statuses, escalated_group_ids)
    except Exception:
        return compose_status_payload(statuses)
    return compose_status_payload(
        statuses,
        group_counts=group_counts,
        escalated_group_ids=escalated_group_ids,
        active_group_ids=active_group_ids,
    )


def llm_analysis_log_limit(raw: object) -> int:
    return bounded_llm_analysis_log_limit(raw)


def llm_analysis_log_page(raw: object) -> int:
    return bounded_llm_analysis_log_page(raw)


def read_llm_analysis_logs(max_rows: int = 1000) -> list[dict]:
    """Read a bounded newest-first tail without retaining full history."""
    return SOC_ALERT_LLM_ANALYSIS_LOG_INDEX.tail(max_rows)


def current_llm_queue_size() -> int:
    static_status = read_soc_alert_json_file(SOC_ALERT_STATIC_STATUS_FILE)
    return llm_queue_size(static_status)


def read_bounded_llm_analysis_record(path: Path) -> dict:
    return read_bounded_llm_record(path, SOC_ALERT_LLM_ANALYSIS_RECORD_MAX_BYTES)


def active_llm_analysis_record_paths() -> list[Path]:
    return active_llm_record_paths(
        SOC_ALERT_LLM_ANALYSIS_ACTIVE_DIR,
        SOC_ALERT_LLM_ANALYSIS_ACTIVE_LIMIT,
    )


def active_llm_sources() -> ActiveLlmSources:
    return ActiveLlmSources(
        active_directory=SOC_ALERT_LLM_ANALYSIS_ACTIVE_DIR,
        record_max_bytes=SOC_ALERT_LLM_ANALYSIS_RECORD_MAX_BYTES,
        active_limit=SOC_ALERT_LLM_ANALYSIS_ACTIVE_LIMIT,
        process_commands=llm_analysis_process_commands,
    )


def read_active_llm_analyses() -> list[dict]:
    return load_active_llm_analyses(active_llm_sources())


def llm_agent_execution_state(record: object) -> dict:
    return project_llm_agent_execution_state(record)


def decorate_llm_analysis_record(record: object, *, live: bool) -> dict:
    return project_llm_analysis_record(record, live=live)


def read_llm_current_analysis() -> dict:
    queue_size = current_llm_queue_size()
    active_runs = read_active_llm_analyses()
    data = (
        {}
        if active_runs
        else read_bounded_llm_analysis_record(SOC_ALERT_LLM_ANALYSIS_CURRENT_FILE)
    )
    return compose_current_llm_analysis(
        queue_size,
        active_runs,
        data,
        llm_analysis_process_active,
    )


def merge_live_llm_activity(static_ai: object, current: object) -> dict:
    return project_live_llm_activity(static_ai, current)


def llm_analysis_process_commands() -> list[str]:
    try:
        proc = subprocess.run(
            ["ps", "axo", "pid=,command="],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=3,
        )
    except Exception:
        return []
    return proc.stdout.splitlines()


def llm_analysis_process_active(
    prompt_package: str,
    commands: list[str] | None = None,
    runner_pid: object = None,
) -> bool:
    commands = commands if commands is not None else llm_analysis_process_commands()
    return active_llm_process_present(prompt_package, commands, runner_pid)


LLM_ANALYSIS_COMBINED_HISTORY_LIMIT = 5000
LLM_AGENT_ACTIVITY_CACHE = ResponseCache(
    3.0,
    max_entries=1,
    lock_stripes=1,
)


def llm_history_store_sources() -> LlmHistoryStoreSources:
    return LlmHistoryStoreSources(
        connect=soc_alert_db_connect,
        history_limit=LLM_ANALYSIS_COMBINED_HISTORY_LIMIT,
    )


def _llm_analysis_run_timestamp(value: object) -> float:
    return projected_llm_run_timestamp(value)


def _llm_primary_run_identity(record: object) -> tuple[str, str, float]:
    return projected_llm_primary_identity(record)


def read_llm_database_primary_logs(
    *,
    limit: int = LLM_ANALYSIS_COMBINED_HISTORY_LIMIT,
) -> list[dict]:
    """Read committed primary executions for every configured agent role.

    JSONL contains the richer runtime and mactop telemetry, but SQLite is the
    authoritative record that an analysis was committed. Returning a bounded
    database projection lets Reports surface SIEM Engineer, Threat Hunter,
    Cyber Threat Intel, Incident Responder, and SOC Analyst runs even if their
    local telemetry was rotated or missed during a rolling deployment.
    """
    rows = read_primary_history_rows(llm_history_store_sources(), limit=limit)
    return project_database_primary_rows(rows)


def reconcile_llm_primary_logs(
    telemetry_logs: list[dict],
    database_logs: list[dict],
) -> tuple[list[dict], int]:
    return reconcile_projected_llm_primary_logs(telemetry_logs, database_logs)


def _llm_reviewer_started_at(generated_at: object, runtime: object) -> str:
    return projected_llm_reviewer_started_at(generated_at, runtime)


def hydrate_llm_reviewer_from_parent(
    reviewer: dict,
    parent: dict | None,
) -> None:
    hydrate_projected_llm_reviewer(reviewer, parent)


def read_llm_second_opinion_logs(
    primary_logs: list[dict],
    *,
    limit: int = LLM_ANALYSIS_COMBINED_HISTORY_LIMIT,
) -> list[dict]:
    """Return bounded reviewer executions shaped like the primary audit log.

    Second opinions are durable SQLite telemetry, while primary resource
    telemetry is append-only JSONL. Bind them by the shared analysis/log ID and
    copy only alert context and observed host metrics from the parent run.
    Reviewer model, runtime, status, outcome, and error always come from the
    independent reviewer row.
    """
    rows = read_second_opinion_history_rows(
        llm_history_store_sources(), limit=limit
    )
    return project_second_opinion_rows(rows, primary_logs)


def read_llm_disagreement_adjudication_logs(
    primary_logs: list[dict],
    *,
    limit: int = LLM_ANALYSIS_COMBINED_HISTORY_LIMIT,
) -> list[dict]:
    """Return durable shadow adjudicator executions as distinct audit runs."""
    rows = read_adjudication_history_rows(
        llm_history_store_sources(), limit=limit
    )
    return project_adjudication_rows(rows, primary_logs)


def _llm_log_sort_timestamp(record: dict) -> float:
    return projected_llm_log_sort_timestamp(record)


def llm_history_api_sources() -> LlmHistoryApiSources:
    return LlmHistoryApiSources(
        telemetry_page=lambda page, limit: (
            SOC_ALERT_LLM_ANALYSIS_LOG_INDEX.page(page=page, limit=limit)
        ),
        read_database_primary=read_llm_database_primary_logs,
        reconcile_primary=reconcile_llm_primary_logs,
        read_reviewer=read_llm_second_opinion_logs,
        read_adjudication=read_llm_disagreement_adjudication_logs,
        compose_snapshot=compose_llm_activity_snapshot,
        read_active=read_active_llm_analyses,
        decorate=lambda record, live: decorate_llm_analysis_record(
            record, live=live
        ),
        cache=LLM_AGENT_ACTIVITY_CACHE,
        history_limit=LLM_ANALYSIS_COMBINED_HISTORY_LIMIT,
    )


def read_llm_agent_activity_snapshot() -> dict:
    """Return one cached, bounded, role-complete history snapshot."""
    return load_llm_agent_activity_snapshot(llm_history_api_sources())


def llm_analysis_logs_response(query: dict[str, list[str]]) -> dict:
    return compose_llm_analysis_logs_response(llm_history_api_sources(), query)


def soc_alert_suppression_review_state(alert_id: str) -> dict:
    try:
        with soc_alert_db_connect() as conn:
            return soc_alert_review_state_for_group(conn, alert_id)
    except (FileNotFoundError, sqlite3.Error):
        return _soc_review_defaults()


def soc_alert_status_write_sources() -> SocAlertStatusWriteSources:
    return SocAlertStatusWriteSources(
        now_iso=now_iso_utc,
        validate_store_id=valid_soc_alert_store_id,
        status_response=soc_alert_status_response,
        current_repeat_count=current_soc_alert_group_repeat_count,
        suppression_review_state=soc_alert_suppression_review_state,
        write_offline_status=write_soc_alert_status,
        post_alert_store=alert_store_post_json,
        alert_store_error=AlertStoreRequestError,
        alert_store_configured=bool(SOC_ALERT_STORE_API_URL),
        direct_write_allowed=SOC_ALERT_STORE_DIRECT_WRITE_ALLOWED,
    )


def update_soc_alert_status(payload: dict) -> tuple[bool, dict]:
    return apply_soc_alert_status_update(soc_alert_status_write_sources(), payload)


def valid_soc_alert_store_id(value: object) -> str:
    alert_id = str(value or "").strip()
    # Security Onion/Elastic alert ids include index:id forms. Keep this URL-safe
    # and forbid path separators/control characters because ids are accepted from
    # dynamic API routes.
    if 1 <= len(alert_id) <= 256 and re.fullmatch(r"[A-Za-z0-9._:@=-]+", alert_id):
        return alert_id
    return ""


def soc_alert_api_error(message: str, status: int = 400) -> tuple[int, dict]:
    return status, {"ok": False, "error": message}


@contextmanager
def soc_alert_db_connect():
    if not SOC_ALERT_STORE_DB.exists():
        raise FileNotFoundError(f"SOC alert store DB not found: {SOC_ALERT_STORE_DB}")
    conn = sqlite3.connect(
        f"file:{SOC_ALERT_STORE_DB}?mode=ro",
        uri=True,
        timeout=SOC_ALERT_DB_BUSY_TIMEOUT_SECONDS,
    )
    conn.row_factory = sqlite3.Row
    conn.execute(f"PRAGMA busy_timeout = {SOC_ALERT_DB_BUSY_TIMEOUT_MS}")
    try:
        yield conn
    finally:
        conn.close()


@contextmanager
def soc_alert_db_write_connect():
    if not SOC_ALERT_STORE_DB.exists():
        raise FileNotFoundError(f"SOC alert store DB not found: {SOC_ALERT_STORE_DB}")
    # Portal-side writes are infrequent administrative fallbacks. Serialize
    # their complete connection lifetime so concurrent requests cannot race
    # journal-mode setup, idempotent DDL, or transaction start. SQLite's busy
    # timeout remains the cross-process contention boundary.
    with SOC_ALERT_DB_WRITE_LOCK:
        conn = sqlite3.connect(
            SOC_ALERT_STORE_DB,
            timeout=SOC_ALERT_DB_BUSY_TIMEOUT_SECONDS,
        )
        conn.row_factory = sqlite3.Row
        conn.execute(f"PRAGMA busy_timeout = {SOC_ALERT_DB_BUSY_TIMEOUT_MS}")
        # Preserve the journal mode selected by the database owner. Changing
        # it per request requires an exclusive lock and can fail when alert
        # store readers are already attached.
        conn.execute("PRAGMA synchronous = FULL")
        conn.execute("PRAGMA wal_autocheckpoint = 1000")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


def parse_soc_alert_since(value: str) -> str:
    raw = str(value or "").strip().lower()
    if not raw:
        return ""
    match = re.fullmatch(r"(\d{1,4})([mhdw])", raw)
    if match:
        amount = int(match.group(1))
        unit = match.group(2)
        delta = {
            "m": dt.timedelta(minutes=amount),
            "h": dt.timedelta(hours=amount),
            "d": dt.timedelta(days=amount),
            "w": dt.timedelta(weeks=amount),
        }[unit]
        return format_iso_timestamp(dt.datetime.now(dt.timezone.utc) - delta, utc_z=True)
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}t\d{2}:\d{2}(:\d{2})?z?", raw):
        return ISO_DATE_TIME_SEPARATOR_RE.sub(r"\1  ", raw.upper() if raw.endswith("z") else raw.upper() + "Z")
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", raw):
        return raw + "  00:00:00Z"
    return ""


def soc_alert_level_names(raw: str) -> list[str]:
    levels: list[str] = []
    for part in str(raw or "").split(","):
        level = part.strip().lower()
        if level in SOC_ALERT_LEVEL_RANK:
            levels.append("informational" if level == "info" else level)
    return sorted(set(levels), key=lambda x: SOC_ALERT_LEVEL_RANK.get(x, 0), reverse=True)


def soc_alert_row_level(row: sqlite3.Row) -> str:
    """Normalize an alert row severity for API-wide visible severity metrics."""
    level = str(row["triage_level"] or row["severity_label"] or "informational").strip().lower()
    if level == "info":
        level = "informational"
    if level in SOC_ALERT_LEVEL_RANK:
        return level
    severity = row["severity"] if "severity" in row.keys() else None
    if severity == 1:
        return "high"
    if severity == 2:
        return "medium"
    if severity == 3:
        return "low"
    return "informational"


def soc_alert_visible_severity_summary(rows: list[sqlite3.Row]) -> dict:
    """Summarize severity across all filtered/visible grouped alerts, before paging."""
    counts = {level: 0 for level in ("critical", "high", "medium", "low", "informational")}
    highest = "none"
    highest_rank = 0
    for row in rows:
        level = soc_alert_row_level(row)
        counts[level] = counts.get(level, 0) + 1
        rank = SOC_ALERT_LEVEL_RANK.get(level, 0)
        if rank > highest_rank:
            highest = level
            highest_rank = rank
    return {"counts": counts, "highest": highest}


def soc_alert_limit(raw: object, default: int = 100) -> int:
    try:
        value = int(str(raw or default))
    except ValueError:
        value = default
    return max(1, min(SOC_ALERT_API_MAX_LIMIT, value))


def soc_alert_page(raw: object) -> int:
    try:
        value = int(str(raw or 1))
    except ValueError:
        value = 1
    return max(1, value)


SOC_ALERT_SORT_SQL = {
    "count": "COALESCE(total_seen_count, raw_alert_count, seen_count, 0)",
    "severity": "CASE lower(coalesce(triage_level, severity_label, 'informational')) WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 WHEN 'informational' THEN 1 WHEN 'info' THEN 1 ELSE 0 END",
    "last_seen": "replace(replace(COALESCE(last_seen, timestamp, first_seen), 'T', ' '), 'Z', '')",
    "alert": "lower(coalesce(rule_name, ''))",
    "source_ip": "lower(coalesce(source_ip, ''))",
    "destination_ip": "lower(coalesce(destination_ip, ''))",
    "destination_port": "CAST(COALESCE(destination_port, '') AS INTEGER)",
    "ai": "'not-queued'",
    "enrichment": "'none'",
    "pcap": "'none'",
    "log_source": "lower(coalesce(event_dataset, ''))",
    "size": "COALESCE(payload_size_bytes, 0)",
    "risk": "COALESCE(triage_score, 0)",
}


def soc_alert_sort_clause(query: dict[str, list[str]], *, fallback: bool = False) -> tuple[str, str, str]:
    """Return an allowlisted ORDER BY clause for grouped alert table sorting."""
    raw_sort = str((query.get("sort") or ["last_seen"])[0]).strip().lower().replace("-", "_")
    direction = str((query.get("direction") or query.get("dir") or ["desc"])[0]).strip().lower()
    if direction not in {"asc", "desc"}:
        direction = "desc"
    if raw_sort not in SOC_ALERT_SORT_SQL:
        raw_sort = "last_seen"
    expression = SOC_ALERT_SORT_SQL[raw_sort]
    if fallback:
        expression = "COALESCE(payload_size_bytes, LENGTH(COALESCE(alert_json, '')), 0)" if raw_sort == "size" else expression
    tie = "ASC" if direction == "asc" else "DESC"
    id_column = "group_key" if fallback else "group_id"
    return raw_sort, direction, f"{expression} {direction.upper()}, replace(replace(COALESCE(last_seen, timestamp, first_seen), 'T', ' '), 'Z', '') DESC, {id_column} {tie}"


def soc_alert_cursor_parts(raw: str) -> tuple[str, str]:
    cursor = str(raw or "")
    if "|" not in cursor:
        return "", ""
    last_seen, alert_id = cursor.split("|", 1)
    return (last_seen.strip(), valid_soc_alert_store_id(alert_id))


def soc_alert_row_to_api(row: sqlite3.Row, include_payload: bool = False) -> dict:
    alert_id = row["alert_id"]
    statuses = load_soc_alert_statuses()
    local_status = statuses.get(alert_id, {}) if isinstance(statuses, dict) else {}
    data = {
        "alert_id": alert_id,
        "first_seen": row["first_seen"],
        "last_seen": row["last_seen"],
        "seen_count": row["seen_count"],
        "timestamp": row["timestamp"],
        "rule_name": row["rule_name"],
        "event_dataset": row["event_dataset"],
        "severity": row["severity"],
        "severity_label": row["severity_label"],
        "triage_score": row["triage_score"],
        "triage_level": row["triage_level"],
        "routing": row["routing"],
        "traffic_direction": row["traffic_direction"],
        "source_ip": row["source_ip"],
        "destination_ip": row["destination_ip"],
        "filter_status": row["filter_status"] or "accepted",
        "filter_reason": row["filter_reason"],
        "suppression_key": row["suppression_key"],
        "analyst_status": local_status.get("status", "open") if isinstance(local_status, dict) else "open",
        "analyst_status_reason": local_status.get("reason") if isinstance(local_status, dict) else "",
        "analyst_status_updated_at": local_status.get("updated_at") if isinstance(local_status, dict) else None,
    }
    if include_payload:
        try:
            data["alert"] = json.loads(row["alert_json"] or "{}")
        except Exception:
            data["alert"] = None
    return data


def soc_alert_static_ai_reports() -> dict:
    data = read_soc_alert_json_file(SOC_ALERT_STATIC_STATUS_FILE)
    reports = data.get("reports") if isinstance(data, dict) else {}
    return reports if isinstance(reports, dict) else {}


def _soc_ai_artifact_sources() -> AiArtifactSources:
    return AiArtifactSources(
        prompt_paths=lambda: SOC_ALERT_AI_PROMPT_DIR.glob("*-ai-prompt.json"),
        analysis_paths=lambda: SOC_ALERT_AI_ANALYSIS_DIR.glob("*-local-ai-analysis.json"),
        read_record=lambda path: json.loads(path.read_text(encoding="utf-8")),
        modified_time=lambda path: path.stat().st_mtime,
    )


def soc_alert_latest_prompt_mtime(alert_id: str) -> float:
    if not alert_id or not SOC_ALERT_AI_PROMPT_DIR.exists():
        return 0
    return _modular_latest_prompt_mtime(alert_id, _soc_ai_artifact_sources())


def soc_alert_latest_analysis_mtime(alert_id: str) -> float:
    if not alert_id or not SOC_ALERT_AI_ANALYSIS_DIR.exists():
        return 0
    return _modular_latest_analysis_mtime(alert_id, _soc_ai_artifact_sources())


def soc_alert_ai_artifact_index() -> dict[str, object]:
    """Index AI prompt/analysis artifact mtimes once for one API response."""
    cache_path = SOC_ALERT_AI_ANALYSIS_DIR.parent
    sources = _soc_ai_artifact_sources()
    include_prompts = (
        SOC_ALERT_AI_PROMPT_DIR.exists()
        and SOC_ALERT_AI_ANALYSIS_DIR.exists()
        and SOC_ALERT_AI_PROMPT_DIR.parent == SOC_ALERT_AI_ANALYSIS_DIR.parent
    )
    return SOC_ALERT_ARTIFACT_CACHE.get_or_compute(
        "ai-artifact-index", cache_path,
        lambda: build_ai_artifact_index(sources, include_prompts=include_prompts),
    )


def _soc_ai_group_members(group_keys: list[str]) -> list[tuple[str, str]]:
    if not group_keys:
        return []
    placeholders = ",".join("?" for _ in group_keys)
    try:
        with soc_alert_db_connect() as conn:
            rows = conn.execute(
                f"SELECT {soc_alert_group_key_sql()} AS group_key, alert_id FROM alerts "
                f"WHERE {soc_alert_group_key_sql()} IN ({placeholders})",
                group_keys,
            ).fetchall()
    except Exception:
        return []
    return [
        (str(row["group_key"] or "").strip(), str(row["alert_id"] or "").strip())
        for row in rows
        if row["group_key"] and row["alert_id"]
    ]


def soc_alert_page_ai_artifact_context(rows: list[sqlite3.Row | dict]) -> dict[str, object]:
    """Return page-scoped AI artifact state through the modular correlator."""
    dependencies = AiArtifactContextDependencies(
        dashboard_group_id=soc_alert_group_id,
        group_members=_soc_ai_group_members,
    )
    return compose_page_ai_artifact_context(
        rows, soc_alert_ai_artifact_index(), dependencies,
    )


def soc_alert_group_has_analysis_artifact(row: sqlite3.Row) -> bool:
    """Return true when any current member of this dashboard group has AI output."""
    if not SOC_ALERT_AI_ANALYSIS_DIR.exists():
        return False
    dependencies = AiGroupArtifactDependencies(
        group_members=lambda group_key: [
            alert_id for _, alert_id in _soc_ai_group_members([group_key])
        ],
        latest_analysis_mtime=soc_alert_latest_analysis_mtime,
    )
    return _modular_group_has_analysis_artifact(row, dependencies)


def soc_alert_severity_meets_analysis_threshold(
    severity: object,
    threshold: object,
) -> bool:
    return _modular_severity_meets_threshold(
        severity, threshold, tuple(SOC_ANALYSIS_SEVERITY_ORDER),
    )


def soc_alert_group_ai_status(
    row: sqlite3.Row,
    group_id: str,
    ai_reports: dict | None = None,
    ai_artifacts: dict[str, object] | None = None,
    analysis_min_severity: str = "informational",
) -> dict:
    policy = SocAiStatusPolicy(
        severity_order=tuple(SOC_ANALYSIS_SEVERITY_ORDER),
        eligible_filter_statuses=frozenset(SOC_ALERT_AI_ELIGIBLE_FILTER_STATUSES),
        test_prefixes=SOC_ALERT_TEST_PREFIXES,
        latest_prompt_mtime=soc_alert_latest_prompt_mtime,
        latest_analysis_mtime=soc_alert_latest_analysis_mtime,
        static_reports=soc_alert_static_ai_reports,
        group_has_artifact=soc_alert_group_has_analysis_artifact,
    )
    return compose_soc_ai_status(
        row, group_id, ai_reports, ai_artifacts, analysis_min_severity, policy,
    )


SOC_ALERT_DETECTION_OUTCOME_LABELS = {
    "true_positive_malicious": "TP - Malicious",
    "true_positive_suspicious": "TP - Suspicious",
    "true_positive_authorized_benign": "TP - Benign",
    "true_positive_benign": "TP - Benign",
    "false_positive_logic_rule": "FP - Rule",
    "false_positive_data_parser": "FP - Parser",
    "false_positive_bad_intel_ioc": "FP - Bad Intel",
    "false_negative": "False Negative",
    "duplicate": "Duplicate",
    "informational_no_action": "Informational",
    "inconclusive": "Inconclusive",
}


def soc_alert_detection_outcome_label(value: object) -> str:
    """Return a compact analyst-facing label without discarding the model key."""
    key = re.sub(r"[^a-z0-9]+", "_", str(value or "").strip().lower()).strip("_")
    if not key:
        return "n/a"
    return SOC_ALERT_DETECTION_OUTCOME_LABELS.get(key, key.replace("_", " ").title())


def _soc_review_epoch(value: object) -> float:
    return _modular_soc_review_epoch(value, parse_iso_timestamp)


def soc_alert_apply_review_metadata(
    conn: sqlite3.Connection,
    rows: list[sqlite3.Row | dict],
    metadata: dict[str, dict[str, object]],
    group_by_alert: dict[str, str],
) -> None:
    """Attach page-bounded SOC review metadata through the modular read model."""
    dependencies = SocReviewDependencies(
        table_exists=sqlite_table_exists,
        table_columns=sqlite_table_columns,
        dashboard_group_id=soc_alert_group_id,
        outcome_label=soc_alert_detection_outcome_label,
        parse_timestamp=parse_iso_timestamp,
    )
    apply_soc_review_metadata(conn, rows, metadata, group_by_alert, dependencies)

def soc_alert_review_state_for_group(
    conn: sqlite3.Connection,
    group_id: str,
) -> dict[str, object]:
    """Return the same bounded review state used by the list API."""
    defaults = _soc_review_defaults()
    if not re.fullmatch(r"[a-f0-9]{12}", str(group_id or "")):
        return defaults
    if not sqlite_table_exists(conn, "alert_group_summary"):
        return defaults
    row = conn.execute(
        "SELECT * FROM alert_group_summary WHERE group_id = ?",
        (group_id,),
    ).fetchone()
    if not row:
        return defaults
    alert_id = str(row["representative_alert_id"] or "")
    metadata = {
        group_id: {
            "pcap_size_bytes": 0,
            "detection_outcome": "",
            "detection_outcome_label": "n/a",
            **_soc_incident_defaults(),
            **defaults,
        }
    }
    soc_alert_apply_review_metadata(
        conn,
        [row],
        metadata,
        {alert_id: group_id} if alert_id else {},
    )
    soc_alert_apply_incident_metadata(
        conn,
        [row],
        metadata,
        {alert_id: group_id} if alert_id else {},
    )
    return metadata[group_id]


def soc_alert_apply_incident_metadata(
    conn: sqlite3.Connection,
    rows: list[sqlite3.Row | dict],
    metadata: dict[str, dict[str, object]],
    group_by_alert: dict[str, str],
) -> None:
    """Attach page-bounded Incident Response routing state through the module."""
    dependencies = SocIncidentDependencies(
        table_exists=sqlite_table_exists,
        table_columns=sqlite_table_columns,
    )
    apply_soc_incident_metadata(conn, metadata, group_by_alert, dependencies)


def soc_alert_group_evidence_metadata(
    conn: sqlite3.Connection | None,
    rows: list[sqlite3.Row | dict],
    ai_artifacts: dict[str, object] | None = None,
    pcap_analysis: dict[str, object] | None = None,
) -> dict[str, dict[str, object]]:
    """Compose bounded SOC evidence metadata through the modular read model."""
    dependencies = SocEvidenceDependencies(
        table_exists=sqlite_table_exists,
        table_columns=sqlite_table_columns,
        dashboard_group_id=soc_alert_group_id,
        outcome_label=soc_alert_detection_outcome_label,
        incident_defaults=_soc_incident_defaults,
        review_defaults=_soc_review_defaults,
        apply_review=soc_alert_apply_review_metadata,
        apply_incident=soc_alert_apply_incident_metadata,
    )
    return compose_soc_evidence_metadata(
        conn, rows, ai_artifacts, pcap_analysis, dependencies,
    )


def soc_alert_group_row_to_api(
    row: sqlite3.Row | dict,
    statuses: dict,
    ai_reports: dict | None = None,
    pcap_analysis: dict[str, object] | None = None,
    pcap_requests: dict[str, dict] | None = None,
    ai_artifacts: dict[str, object] | None = None,
    evidence_metadata: dict[str, dict[str, object]] | None = None,
    analysis_min_severity: str = "informational",
) -> dict:
    dependencies = SocAlertPresentationDependencies(
        dashboard_group_id=soc_alert_group_id,
        ai_status=soc_alert_group_ai_status,
        enrichment_status=soc_alert_public_enrichment_status,
        pcap_status=soc_alert_pcap_status,
        incident_defaults=_soc_incident_defaults,
        review_defaults=_soc_review_defaults,
    )
    return compose_soc_alert_row(
        row, statuses, ai_reports, pcap_analysis, pcap_requests, ai_artifacts,
        evidence_metadata, analysis_min_severity, dependencies,
    )


def soc_alert_group_representative_alert_id(group_id: str) -> str:
    """Resolve a dashboard group id to the newest raw alert id in SQLite."""
    group_id = str(group_id or "").strip().lower()
    if not re.fullmatch(r"[a-f0-9]{12}", group_id):
        return ""
    group_expr = soc_alert_group_key_sql()
    newest_alert_time = "COALESCE(NULLIF(last_seen, ''), NULLIF(timestamp, ''), NULLIF(first_seen, ''))"
    sql = f"""
        SELECT alert_id, {group_expr} AS group_key
        FROM alerts
        ORDER BY replace(replace({newest_alert_time}, 'T', ' '), 'Z', '') DESC,
                 alert_id DESC
    """
    with soc_alert_db_connect() as conn:
        for row in conn.execute(sql):
            if soc_alert_group_id(row["group_key"]) == group_id:
                return str(row["alert_id"] or "").strip()
    return ""


def _forward_controlled_dispatch_contract(
    payload: dict,
    request_payload: dict,
) -> None:
    """Forward frozen route fields only for a controlled cohort dispatch."""
    forward_controlled_dispatch_contract(payload, request_payload)


def soc_action_service_sources() -> SocActionServiceSources:
    """Bind portal transport, error, and clock dependencies for SOC actions."""
    return SocActionServiceSources(
        post_json=alert_store_post_json,
        api_error=soc_alert_api_error,
        now_local=now_iso_local,
        request_error_status=lambda exc: (
            exc.status_code if isinstance(exc, AlertStoreRequestError) else None
        ),
    )


def soc_alert_queue_analysis_response(group_id: str, payload: dict | None = None) -> tuple[int, dict]:
    """Record durable reanalysis intent; the worker builds fresh evidence later."""
    return queue_soc_alert_analysis(soc_action_service_sources(), group_id, payload)


def soc_alert_escalate_response(group_id: str, payload: dict | None = None) -> tuple[int, dict]:
    """Create or refresh one durable Incident Response case for an alert group."""
    return escalate_soc_alert(soc_action_service_sources(), group_id, payload)


def _soc_legacy_verdict_factors(outcome: str) -> dict[str, str | None]:
    return legacy_verdict_factors(outcome)


def _soc_derive_legacy_detection_outcome(
    factors: dict[str, str | None],
) -> str:
    return derive_legacy_detection_outcome(factors)


def _soc_adjudication_verdict_contradictions(
    outcome: str,
    explicit_factors: dict[str, str | None],
) -> list[str]:
    return adjudication_verdict_contradictions(outcome, explicit_factors)


def normalize_soc_adjudication_payload(
    payload: dict | None,
    *,
    group_id: str,
    case_id: str = "",
) -> tuple[bool, dict]:
    return normalize_adjudication_payload(
        payload,
        group_id=group_id,
        case_id=case_id,
    )


def _soc_alert_store_mutation(
    path: str,
    payload: dict,
    *,
    success_status: int = 200,
) -> tuple[int, dict]:
    if not SOC_ALERT_STORE_API_URL:
        return soc_alert_api_error(
            "Alert-store API is required for append-only analyst review writes.",
            503,
        )
    try:
        result = alert_store_post_json(path, payload, timeout=10.0)
    except AlertStoreRequestError as exc:
        return soc_alert_api_error(str(exc), exc.status_code)
    return success_status, result


def soc_alert_adjudication_response(
    group_id: str,
    payload: dict | None = None,
) -> tuple[int, dict]:
    ok, normalized = normalize_soc_adjudication_payload(
        payload,
        group_id=str(group_id or "").strip().lower(),
    )
    if not ok:
        return HTTPStatus.BAD_REQUEST, normalized
    return _soc_alert_store_mutation(
        "/adjudications",
        normalized,
        success_status=HTTPStatus.CREATED,
    )


def _soc_incident_case_group_id(case_id: str) -> tuple[int, str]:
    case_id = str(case_id or "").strip().lower()
    if not re.fullmatch(r"ir-[a-z0-9_-]{1,64}", case_id):
        return HTTPStatus.BAD_REQUEST, ""
    try:
        with soc_alert_db_connect() as conn:
            row = conn.execute(
                "SELECT dashboard_group_id FROM incident_response_cases WHERE case_id = ?",
                (case_id,),
            ).fetchone()
    except (FileNotFoundError, sqlite3.Error):
        row = None
    return (HTTPStatus.OK, str(row["dashboard_group_id"] or "")) if row else (HTTPStatus.NOT_FOUND, "")


def soc_incident_adjudication_response(
    case_id: str,
    payload: dict | None = None,
) -> tuple[int, dict]:
    status, group_id = _soc_incident_case_group_id(case_id)
    if status != HTTPStatus.OK:
        return soc_alert_api_error(
            "Incident case not found" if status == HTTPStatus.NOT_FOUND else "Invalid incident case id",
            status,
        )
    ok, normalized = normalize_soc_adjudication_payload(
        payload,
        group_id=group_id,
        case_id=case_id,
    )
    if not ok:
        return HTTPStatus.BAD_REQUEST, normalized
    return _soc_alert_store_mutation(
        "/adjudications",
        normalized,
        success_status=HTTPStatus.CREATED,
    )


def soc_incident_status_response(
    case_id: str,
    payload: dict | None = None,
) -> tuple[int, dict]:
    status, _group_id = _soc_incident_case_group_id(case_id)
    if status != HTTPStatus.OK:
        return soc_alert_api_error(
            "Incident case not found" if status == HTTPStatus.NOT_FOUND else "Invalid incident case id",
            status,
        )
    try:
        request_payload = normalize_incident_status_payload(case_id, payload)
    except IncidentStatusPayloadError as exc:
        return soc_alert_api_error(str(exc))
    return _soc_alert_store_mutation(
        "/incidents/status",
        request_payload,
    )


def soc_incident_reanalysis_response(
    case_id: str,
    payload: dict | None = None,
) -> tuple[int, dict]:
    status, _group_id = _soc_incident_case_group_id(case_id)
    if status != HTTPStatus.OK:
        return soc_alert_api_error(
            "Incident case not found" if status == HTTPStatus.NOT_FOUND else "Invalid incident case id",
            status,
        )
    payload = payload if isinstance(payload, dict) else {}
    request_payload = {
        "case_id": case_id,
        "reason": str(
            payload.get("reason")
            or "Analyst requested fresh Incident Responder analysis"
        )[:1000],
        "requested_by": str(payload.get("requested_by") or "dashboard")[:100],
    }
    for identity_field in (
        "representative_alert_id",
        "stable_group_id",
        "stable_group_key",
        "cohort_id",
        "dispatch_id",
    ):
        if identity_field in payload:
            request_payload[identity_field] = payload[identity_field]
    _forward_controlled_dispatch_contract(payload, request_payload)
    return _soc_alert_store_mutation(
        "/incidents/reanalyze",
        request_payload,
        success_status=HTTPStatus.ACCEPTED,
    )


def soc_incident_bulk_reanalysis_response(
    payload: dict | None = None,
) -> tuple[int, dict]:
    payload = payload if isinstance(payload, dict) else {}
    return _soc_alert_store_mutation(
        "/incidents/reanalyze-all",
        {
            "reason": str(
                payload.get("reason")
                or "Analyst requested fresh analysis of all incident cases"
            )[:1000],
            "requested_by": str(payload.get("requested_by") or "dashboard")[:100],
        },
        success_status=HTTPStatus.ACCEPTED,
    )


def soc_incident_reanalysis_runs_response(
    query: dict[str, list[str]],
) -> tuple[int, dict]:
    try:
        run_id = parse_reanalysis_run_id(query)
    except IncidentReanalysisQueryError as exc:
        return soc_alert_api_error(str(exc))
    try:
        with soc_alert_db_connect() as conn:
            progress = load_reanalysis_progress(conn, run_id)
    except (FileNotFoundError, sqlite3.Error) as exc:
        return soc_alert_api_error(
            f"Incident reanalysis progress unavailable: {exc}",
            HTTPStatus.SERVICE_UNAVAILABLE,
        )
    return 200, compose_reanalysis_progress_payload(progress)


def soc_incident_current_analysis(
    conn: sqlite3.Connection,
    case: dict[str, object],
) -> dict[str, object]:
    """Resolve a case's current IR run without trusting a stale foreign pointer."""
    return load_current_incident_analysis(conn, case)


def soc_adjudication_history_sources() -> SocAdjudicationHistorySources:
    return SocAdjudicationHistorySources(
        connect=soc_alert_db_connect,
        table_exists=sqlite_table_exists,
        table_columns=sqlite_table_columns,
        review_defaults=_soc_review_defaults,
        alert_review_state=soc_alert_review_state_for_group,
        current_incident_analysis=soc_incident_current_analysis,
        parse_review_json=_soc_review_json,
        incident_review_state=soc_incident_review_state,
    )


def soc_adjudication_history_response(
    group_id: str,
    *,
    case_id: str = "",
    limit: int = 25,
) -> tuple[int, dict]:
    return read_soc_adjudication_history(
        soc_adjudication_history_sources(),
        group_id,
        case_id=case_id,
        limit=limit,
    )


def soc_incident_agent_display_state(
    agent_status: object,
    analysis_id: object,
    reviewer_status: object,
) -> tuple[str, str]:
    """Distinguish a failed refresh or review from a missing primary analysis."""
    status = str(agent_status or "queued").strip().lower()
    has_analysis = bool(str(analysis_id or "").strip())
    review = str(reviewer_status or "not_requested").strip().lower()
    if status != "failed":
        return status, status.replace("_", " ")
    if not has_analysis:
        return "analysis_failed", "Analysis failed"
    if review in {"failed", "invalid"}:
        return "review_failed", "Primary ready · review failed"
    return "refresh_failed", "Analysis ready · refresh failed"


INCIDENT_ROW_CALLBACKS = IncidentRowCallbacks(
    epoch=_soc_review_epoch,
    embedded_reviewer=_soc_embedded_reviewer,
    final_review_status=_soc_review_final_status,
    outcome_label=soc_alert_detection_outcome_label,
    agent_display_state=soc_incident_agent_display_state,
    reviewer_authorization=_soc_reviewer_automation_authorization,
    resolve_asset_ip=resolve_asset_ip,
)


def soc_incidents_query_response(query: dict[str, list[str]]) -> tuple[int, dict]:
    """Return one bounded page of durable Incident Response cases.

    Case lists intentionally omit raw model JSON and packet evidence. The UI
    loads the existing group-detail endpoint only after an analyst expands a
    row, keeping routine polling inexpensive even with a large case history.
    """
    return incident_list_response(
        incident_read_service_sources(),
        query,
        max_per_page=SOC_ALERT_API_MAX_LIMIT,
    )


def soc_incident_review_state(
    conn: sqlite3.Connection,
    case: dict[str, object],
    analysis: dict[str, object],
    response: dict[str, object],
) -> dict[str, object]:
    """Derive durable current-review state for one Incident Response detail."""
    records = load_incident_review_records(conn, case, analysis)
    return compose_incident_review_state(
        case,
        analysis,
        response,
        records.evidence_updated_at,
        records.reviewer,
        records.adjudication,
        _soc_review_defaults(),
        INCIDENT_ROW_CALLBACKS,
    )


def _incident_html_text(value: object, fallback: str = "n/a") -> str:
    text = str(value or "").strip() or fallback
    return html.escape(text)


def _incident_nonnegative_int(value: object) -> int:
    """Render malformed evidence counters as zero instead of failing the case API."""
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError, OverflowError):
        return 0


def _incident_query_linked_finding(report: dict[str, object], query_digest: object) -> str:
    """Return the first responder statement explicitly linked to a trusted query."""
    digest = str(query_digest or "").strip()
    if not digest:
        return ""
    timeline = report.get("factual_timeline")
    if isinstance(timeline, list):
        for event in timeline:
            if not isinstance(event, dict) or str(event.get("query_digest") or "").strip() != digest:
                continue
            finding = str(event.get("event") or "").strip()
            if finding:
                return finding if len(finding) <= 360 else f"{finding[:357].rstrip()}…"
    for key in (
        "security_onion_findings",
        "osquery_findings",
        "pcap_findings",
        "host_findings",
        "correlation_findings",
        "evidence_gaps",
    ):
        values = report.get(key)
        items = values if isinstance(values, list) else [values]
        for item in items:
            finding = str(item or "").strip()
            if digest in finding:
                return finding if len(finding) <= 360 else f"{finding[:357].rstrip()}…"
    return ""


def _incident_html_list(values: object, fallback: str = "No findings were recorded.") -> str:
    items = values if isinstance(values, list) else ([values] if values not in (None, "") else [])
    rendered = []
    for item in items[:100]:
        if isinstance(item, (dict, list)):
            text = json.dumps(item, sort_keys=True, default=str)
        else:
            text = str(item)
        if text.strip():
            rendered.append(f"<li>{html.escape(text.strip())}</li>")
    return f'<ul class="ir-report-list">{"".join(rendered)}</ul>' if rendered else f"<p>{html.escape(fallback)}</p>"


def _incident_report_section(title: str, body: str) -> str:
    return (
        '<section class="ir-report-subsection">'
        f"<h4>{html.escape(title)}</h4>"
        f'<div class="ir-report-subsection-body">{body}</div>'
        "</section>"
    )


def render_analyst_review_panel(
    review: dict[str, object] | None,
    *,
    group_id: str,
    case_id: str = "",
) -> str:
    """Render bounded review state and one explicit human-adjudication entry."""
    callbacks = ReviewPanelRenderCallbacks(
        html_text=_incident_html_text,
        outcome_label=soc_alert_detection_outcome_label,
        review_defaults=_soc_review_defaults,
    )
    return render_review_panel(
        review,
        group_id=group_id,
        case_id=case_id,
        callbacks=callbacks,
    )


def render_investigation_query_audit_html(
    response: dict[str, object],
    report: dict[str, object],
) -> tuple[str, int]:
    """Render broker-owned iterative pivot records, never model-authored queries."""
    callbacks = InvestigationAuditRenderCallbacks(
        html_text=_incident_html_text,
        nonnegative_int=_incident_nonnegative_int,
        linked_finding=_incident_query_linked_finding,
    )
    return render_investigation_query_audit(response, report, callbacks)


def render_incident_response_report_html(
    case: dict[str, object],
    response: dict[str, object],
    analysis: dict[str, object],
    review: dict[str, object] | None = None,
) -> tuple[str, int]:
    """Render a fact-grounded responder report and immutable query audit."""
    callbacks = IncidentReportRenderCallbacks(
        html_text=_incident_html_text,
        nonnegative_int=_incident_nonnegative_int,
        linked_finding=_incident_query_linked_finding,
        html_list=_incident_html_list,
        report_section=_incident_report_section,
        investigation_audit=render_investigation_query_audit_html,
        review_panel=render_analyst_review_panel,
    )
    return render_incident_response_report(
        case,
        response,
        analysis,
        review,
        callbacks,
    )


def render_prior_soc_analysis_html(response: dict[str, object], analysis: dict[str, object]) -> str:
    sections = [
        _incident_report_section("BLUF", f"<p>{_incident_html_text(response.get('bluf') or analysis.get('bluf'))}</p>"),
        _incident_report_section("Assessment", f"<p>{_incident_html_text(response.get('summary') or analysis.get('summary'))}</p>"),
        _incident_report_section("Likely Meaning", f"<p>{_incident_html_text(response.get('likely_meaning'))}</p>"),
        _incident_report_section("Severity Reasoning", f"<p>{_incident_html_text(response.get('severity_reasoning'))}</p>"),
        _incident_report_section("Alert Frequency Assessment", f"<p>{_incident_html_text(response.get('alert_frequency_assessment'))}</p>"),
        _incident_report_section("Public Enrichment Findings", _incident_html_list(response.get("public_enrichment_findings"))),
        _incident_report_section("PCAP Analysis Findings", _incident_html_list(response.get("pcap_analysis_findings"))),
        _incident_report_section("False Positive Possibilities", _incident_html_list(response.get("false_positive_possibilities"))),
        _incident_report_section("Recommended Next Steps", _incident_html_list(response.get("recommended_next_steps"))),
        _incident_report_section("Evidence Used", _incident_html_list(response.get("evidence_used"))),
        _incident_report_section("Evidence Gaps", _incident_html_list(response.get("evidence_gaps"))),
        _incident_report_section("Recommended Tuning Actions", _incident_html_list(response.get("recommended_tuning_actions"))),
    ]
    return '<div class="ir-prior-analysis">' + "".join(sections) + "</div>"


def incident_read_service_sources() -> IncidentReadServiceSources:
    """Bind portal runtime resources to Incident Response read orchestration."""
    return IncidentReadServiceSources(
        connect=soc_alert_db_connect,
        api_error=soc_alert_api_error,
        parse_list_request=parse_incident_list_request,
        schema_ready=incident_schema_ready,
        empty_page=empty_incident_page,
        load_list_records=load_incident_list_records,
        load_inventory=load_asset_inventory_data,
        compose_list_rows=compose_incident_list_rows,
        load_detail_records=load_incident_detail_records,
        parse_analysis_response=parse_analysis_response,
        compose_review_state=compose_incident_review_state,
        review_defaults=_soc_review_defaults,
        row_callbacks=INCIDENT_ROW_CALLBACKS,
        render_incident_report=render_incident_response_report_html,
        render_prior_analysis=render_prior_soc_analysis_html,
        compose_detail_payload=compose_incident_detail_payload,
    )


def soc_incident_detail_response(case_id: str) -> tuple[int, dict]:
    """Return one bounded IR report, its exact query audit, and prior SOC analysis."""
    return incident_detail_response(incident_read_service_sources(), case_id)


def soc_alert_status_bucket_counts(rows: list[sqlite3.Row], statuses: dict) -> dict[str, int]:
    return soc_alert_api.status_bucket_counts(
        rows, statuses, soc_alert_group_id_for_query_row,
    )


def soc_alert_top_endpoint_metrics(rows: list[sqlite3.Row]) -> dict[str, str]:
    return soc_alert_api.top_endpoint_metrics(rows)


def soc_alert_group_id_for_query_row(row: sqlite3.Row | dict) -> str:
    keys = row.keys()
    if "group_id" in keys and row["group_id"]:
        return str(row["group_id"])
    return soc_alert_group_id(row["group_key"])


def soc_alert_enriched_page_rows(page_rows: list[sqlite3.Row]) -> list[sqlite3.Row | dict]:
    if not page_rows:
        return []
    try:
        with soc_alert_db_connect() as conn:
            enrichment_by_group = soc_alert_group_enrichment_json_map(
                conn, page_group_keys(page_rows),
            )
    except Exception:
        return [dict(row) for row in page_rows]
    return merge_page_enrichment(page_rows, enrichment_by_group)


def soc_alert_group_query_snapshot(
    rows: list[sqlite3.Row],
    *,
    analyst_status: str,
    cursor_seen: str,
    cursor_id: str,
    limit: int,
    requested_page: int,
    excluded_group_ids: set[str] | None = None,
) -> SocAlertQuerySnapshot:
    dependencies = SocGroupSnapshotDependencies(
        load_statuses=load_soc_alert_statuses,
        status_counts=soc_alert_status_bucket_counts,
        severity_summary=soc_alert_visible_severity_summary,
        top_endpoints=soc_alert_top_endpoint_metrics,
        enrich_page_rows=soc_alert_enriched_page_rows,
        group_id=soc_alert_group_id_for_query_row,
    )
    return compose_group_query_snapshot(
        rows,
        analyst_status=analyst_status,
        cursor_seen=cursor_seen,
        cursor_id=cursor_id,
        limit=limit,
        requested_page=requested_page,
        excluded_group_ids=excluded_group_ids,
        dependencies=dependencies,
    )


def soc_alert_group_query_payload(
    *,
    source: str,
    snapshot: SocAlertQuerySnapshot,
    limit: int,
    sort_key: str,
    sort_direction: str,
) -> dict:
    dependencies = SocGroupQueryDependencies(
        db_path=str(SOC_ALERT_STORE_DB),
        load_ai_reports=soc_alert_static_ai_reports,
        load_ai_artifacts=soc_alert_page_ai_artifact_context,
        load_analysis_min_severity=_soc_analysis_min_severity,
        load_pcap_analysis=soc_alert_pcap_analysis_index,
        load_page_evidence=_soc_group_page_evidence,
        present_alert=soc_alert_group_row_to_api,
    )
    return compose_group_query_payload(
        source=source,
        snapshot=snapshot,
        limit=limit,
        sort_key=sort_key,
        sort_direction=sort_direction,
        dependencies=dependencies,
    )


def _soc_analysis_min_severity() -> str:
    ai_settings_response = read_soc_ai_settings()
    ai_settings = (
        ai_settings_response.get("settings", {})
        if isinstance(ai_settings_response, dict)
        else {}
    )
    return str(
        ai_settings.get("soc_analyst_analysis_min_severity")
        or "informational"
    )


def _soc_group_page_evidence(
    page_rows: list[sqlite3.Row | dict],
    ai_artifacts: dict,
    pcap_analysis: dict,
) -> tuple[dict, dict]:
    try:
        with soc_alert_db_connect() as conn:
            pcap_requests = soc_alert_pcap_request_statuses(conn, page_rows)
            evidence_metadata = soc_alert_group_evidence_metadata(
                conn,
                page_rows,
                ai_artifacts,
                pcap_analysis,
            )
    except Exception:
        pcap_requests = {}
        evidence_metadata = soc_alert_group_evidence_metadata(
            None,
            page_rows,
            ai_artifacts,
            pcap_analysis,
        )
    return pcap_requests, evidence_metadata


def soc_alert_group_query_request(
    query: dict[str, list[str]],
) -> SocGroupQueryRequest:
    policy = SocGroupQueryRequestPolicy(
        parse_since=parse_soc_alert_since,
        parse_levels=soc_alert_level_names,
        parse_cursor=soc_alert_cursor_parts,
        parse_limit=soc_alert_limit,
        parse_page=soc_alert_page,
        parse_sort=lambda values, fallback: soc_alert_sort_clause(
            values, fallback=fallback,
        ),
    )
    return parse_group_query_request(query, policy)


def soc_alerts_summary_query_response(
    request: SocGroupQueryRequest,
) -> tuple[int, dict] | None:
    """Serve the grouped summary-table plan when its durable table is available."""
    plan = summary_query_plan(request)
    try:
        with soc_alert_db_connect() as conn:
            if not soc_alert_group_summary_available(conn):
                return None
            rows = conn.execute(plan.sql, plan.args).fetchall()
            manually_escalated_group_ids = soc_alert_manually_escalated_group_ids(conn)
    except Exception as exc:
        return soc_alert_api_error(str(exc), 503)
    snapshot = soc_alert_group_query_snapshot(
        rows,
        analyst_status=request.analyst_status,
        cursor_seen=request.cursor_seen,
        cursor_id=request.cursor_id,
        limit=request.limit,
        requested_page=request.requested_page,
        excluded_group_ids=manually_escalated_group_ids,
    )
    return 200, soc_alert_group_query_payload(
        source="sqlite-summary",
        snapshot=snapshot,
        limit=request.limit,
        sort_key=request.sort_key,
        sort_direction=request.sort_direction,
    )


def soc_alerts_query_response(query: dict[str, list[str]]) -> tuple[int, dict]:
    request = soc_alert_group_query_request(query)
    summary_response = soc_alerts_summary_query_response(request)
    if summary_response is not None:
        return summary_response
    plan = fallback_query_plan(request, soc_alert_group_key_sql())
    try:
        with soc_alert_db_connect() as conn:
            rows = conn.execute(plan.sql, plan.args).fetchall()
            manually_escalated_group_ids = soc_alert_manually_escalated_group_ids(conn)
    except Exception as exc:
        return soc_alert_api_error(str(exc), 503)
    snapshot = soc_alert_group_query_snapshot(
        rows,
        analyst_status=request.analyst_status,
        cursor_seen=request.cursor_seen,
        cursor_id=request.cursor_id,
        limit=request.limit,
        requested_page=request.requested_page,
        excluded_group_ids=manually_escalated_group_ids,
    )
    return 200, soc_alert_group_query_payload(
        source="sqlite",
        snapshot=snapshot,
        limit=request.limit,
        sort_key=request.sort_key,
        sort_direction=request.sort_direction,
    )


def cached_soc_alerts_query_response(query: dict[str, list[str]]) -> tuple[int, bytes]:
    """Coalesce query and JSON encoding work during multi-analyst bursts."""
    key = json.dumps(query, sort_keys=True, separators=(",", ":"))

    def build_response() -> tuple[int, bytes]:
        status, data = soc_alerts_query_response(query)
        return status, json.dumps(data, separators=(",", ":")).encode()

    return SOC_ALERT_RESPONSE_CACHE.get_or_compute(("soc-alerts", key), build_response)


def soc_alert_detail_fragment_response(group_id: str) -> tuple[int, dict]:
    group_id = str(group_id or "").strip().lower()
    if not re.fullmatch(r"[a-f0-9]{12}", group_id):
        return soc_alert_api_error("Invalid SOC alert group id")
    detail_path = SOC_ALERT_DETAIL_DIR / f"{group_id}.html"
    try:
        base = SOC_ALERT_DETAIL_DIR.resolve()
        target = detail_path.resolve()
    except Exception:
        return soc_alert_api_error("SOC alert detail path unavailable", 503)
    if base not in target.parents or target.suffix != ".html":
        return soc_alert_api_error("Invalid SOC alert detail path")
    if not target.exists():
        return soc_alert_api_error("SOC alert detail fragment not found", 404)
    try:
        if target.stat().st_size > SOC_ALERT_DETAIL_FRAGMENT_MAX_BYTES:
            return soc_alert_api_error("SOC alert detail fragment exceeded the safe render limit", 413)
        detail_html = target.read_text(encoding="utf-8")
    except OSError as exc:
        return soc_alert_api_error(str(exc), 503)
    review = _soc_review_defaults()
    try:
        with soc_alert_db_connect() as conn:
            review = soc_alert_review_state_for_group(conn, group_id)
    except (FileNotFoundError, sqlite3.Error):
        pass
    detail_html = soc_alert_append_live_pcap_detail(group_id, detail_html)
    detail_html = soc_alert_collapse_detail_sections(detail_html)
    detail_html = render_analyst_review_panel(review, group_id=group_id) + detail_html
    layout_issues = soc_alert_validate_detail_layout_html(detail_html)
    if layout_issues and "detail-layout-error" not in detail_html:
        detail_html = soc_alert_layout_error_html(layout_issues) + detail_html
    return 200, {
        "ok": True,
        "source": "detail-fragment",
        "group_id": group_id,
        "layout_version": SOC_ALERT_DETAIL_LAYOUT_VERSION,
        "layout_valid": not layout_issues,
        "layout_issues": layout_issues,
        "review": review,
        "detail_html": detail_html,
    }


def soc_alert_detail_response(alert_id: str) -> tuple[int, dict]:
    alert_id = valid_soc_alert_store_id(alert_id)
    if not alert_id:
        return soc_alert_api_error("Invalid SOC alert id")
    try:
        with soc_alert_db_connect() as conn:
            row = conn.execute("""
                select alert_id, first_seen, last_seen, seen_count, timestamp, rule_name,
                       event_dataset, severity, severity_label, source_ip, destination_ip,
                       traffic_direction, triage_score, triage_level, routing, filter_status,
                       filter_reason, suppression_key, alert_json
                from alerts where alert_id = ?
            """, (alert_id,)).fetchone()
    except Exception as e:
        return soc_alert_api_error(str(e), 503)
    if not row:
        return soc_alert_api_error("SOC alert not found", 404)
    return 200, {"ok": True, "source": "sqlite", "alert": soc_alert_row_to_api(row, include_payload=True)}


def soc_alert_metrics_response(query: dict[str, list[str]]) -> tuple[int, dict]:
    since = parse_soc_alert_since((query.get("since") or ["24h"])[0])
    try:
        with soc_alert_db_connect() as conn:
            plan = metrics_query_plan(
                since, soc_alert_group_key_sql(), soc_alert_group_summary_available(conn),
            )
            total = conn.execute(plan.total_sql, plan.args).fetchone()[0]
            latest = conn.execute(plan.latest_sql, plan.args).fetchone()[0]
            grouped_rows = conn.execute(plan.grouped_sql, plan.args).fetchall()
            grouped_rows = exclude_group_rows(
                grouped_rows,
                soc_alert_manually_escalated_group_ids(conn),
                soc_alert_group_id_for_query_row,
            )
            by_filter = {r[0] or "accepted": r[1] for r in conn.execute(plan.filter_status_sql, plan.args)}
            by_level = {r[0] or "unknown": r[1] for r in conn.execute(plan.level_sql, plan.args)}
            top_rules = [dict(rule_name=r[0] or "unknown", count=r[1]) for r in conn.execute(plan.top_rules_sql, plan.args)]
            suppression_windows = conn.execute(plan.suppression_sql).fetchone()
    except Exception as e:
        return soc_alert_api_error(str(e), 503)
    statuses = load_soc_alert_statuses()
    by_analyst_status = soc_alert_status_bucket_counts(grouped_rows, statuses)
    return 200, compose_metrics_payload(
        source=plan.source,
        since=since,
        total=total,
        latest_seen=latest,
        grouped_rows=grouped_rows,
        pcap_ingest_size_bytes=directory_size_bytes(SOC_ALERT_PCAP_ARTIFACT_DIR),
        by_filter_status=by_filter,
        by_analyst_status=by_analyst_status,
        by_level=by_level,
        top_rules=top_rules,
        suppression_totals=suppression_windows,
    )


def soc_alert_suppressions_response(query: dict[str, list[str]]) -> tuple[int, dict]:
    limit = soc_alert_limit((query.get("limit") or [100])[0])
    try:
        with soc_alert_db_connect() as conn:
            rows = conn.execute("""
                select suppression_key, rule_name, reason, window_start, last_seen,
                       seen_count, suppressed_count, escalated_count, ttl_seconds,
                       escalation_threshold
                from suppression_log
                order by last_seen desc, suppression_key asc
                limit ?
            """, (limit,)).fetchall()
    except Exception as e:
        return soc_alert_api_error(str(e), 503)
    return 200, {"ok": True, "source": "sqlite", "count": len(rows), "suppressions": [dict(row) for row in rows]}


def read_soc_alert_json_file(path: Path) -> dict:
    try:
        if path.exists() and path.is_file():
            data = json.loads(path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}
    return {}


def soc_alert_events_snapshot() -> dict:
    analyst_status = soc_alert_status_response()
    static_status = read_soc_alert_json_file(SOC_ALERT_STATIC_STATUS_FILE)
    current_analysis = read_llm_current_analysis()
    beacon = read_soc_alert_json_file(SOC_ALERT_N8N_BEACON_FILE)
    # Event snapshots drive live nav badges and metric cards. Keep them aligned
    # with the default SOC Alerts table/counts instead of a time-windowed view,
    # otherwise older still-active groups disappear from the live metrics.
    metrics_status, metrics = soc_alert_metrics_response({"since": [""]})
    if metrics_status != 200:
        metrics = {"ok": False, "error": metrics.get("error", "SOC alert metrics unavailable")}
    return {
        "ok": True,
        "event": "soc-alerts",
        "time": now_iso_utc(),
        "revisions": dashboard_live_revisions(),
        "counts": analyst_status.get("counts", {}),
        "statuses": analyst_status.get("statuses", {}),
        "ai": merge_live_llm_activity(static_status.get("ai", {}), current_analysis),
        "reports": static_status.get("reports", {}),
        "status_updated_at": static_status.get("updated_at"),
        "metrics": metrics,
        "beacon": beacon,
    }


def asset_inventory_live_revision() -> str:
    """Track the public inventory view, including time-scoped assignments."""
    _status, payload = asset_inventory_response()
    stable = dict(payload)
    stable.pop("observed_at", None)
    return _revision_digest(stable)


def dhcp_asset_discovery_live_revision(asset_revision: str) -> str:
    """Track collector output and inventory-driven reconciliation changes."""
    state_revision = _bounded_file_revision(
        Path(DHCP_ASSET_DISCOVERY_STATE_FILE),
        DHCP_ASSET_DISCOVERY_MAX_BYTES,
    )
    return _revision_digest((state_revision, asset_revision))


def software_inventory_live_revision() -> str:
    """Track the local last-known-good software evidence snapshot."""
    return _bounded_file_revision(
        Path(SOFTWARE_INVENTORY_STATE_FILE),
        SOFTWARE_INVENTORY_MAX_BYTES,
    )


def incident_response_live_revision() -> str:
    """Fingerprint only records capable of changing the Incident Responder UI."""
    try:
        with soc_alert_db_connect() as conn:
            return incident_response_revision(
                conn,
                RevisionSchemaDependencies(
                    table_exists=sqlite_table_exists,
                    table_columns=sqlite_table_columns,
                ),
            )
    except (FileNotFoundError, sqlite3.Error):
        return _revision_digest(("unavailable",))


def dashboard_live_revisions() -> dict[str, str]:
    """Return revision-only signals; never include incident or asset records."""
    asset_revision = asset_inventory_live_revision()
    return {
        "incidents": incident_response_live_revision(),
        "asset_inventory": asset_revision,
        "dhcp_asset_discovery": dhcp_asset_discovery_live_revision(asset_revision),
        "software_inventory": software_inventory_live_revision(),
        "ac_hunter": ac_hunter_live_revision(),
    }


def ac_hunter_live_revision() -> str:
    """Return only the PostgreSQL AC Hunter dataset digest for SSE updates."""

    try:
        payload = alert_store_get_json("/ac-hunter/snapshot", timeout=2.0)
        cache = payload.get("cache")
        if isinstance(cache, dict):
            digest = str(cache.get("dataset_digest") or "").strip().lower()
            if re.fullmatch(r"[0-9a-f]{64}", digest):
                return digest
    except RuntimeError:
        pass
    return _revision_digest(("unavailable",))


def cached_soc_alert_events_snapshot() -> dict:
    """Share one bounded-cost live snapshot across concurrent SSE clients."""
    return SOC_ALERT_EVENTS_CACHE.get_or_compute("soc-alert-events", soc_alert_events_snapshot)


def ack_soc_alert_store_id(alert_id: str, payload: dict) -> tuple[int, dict]:
    alert_id = valid_soc_alert_store_id(alert_id)
    if not alert_id:
        return soc_alert_api_error("Invalid SOC alert id")
    payload = {**payload, "id": alert_id}
    ok, data = update_soc_alert_status(payload)
    status = HTTPStatus.OK if ok else int(data.get("status") or HTTPStatus.BAD_REQUEST)
    if ok:
        alert_status = load_soc_alert_statuses().get(alert_id, {})
        data = {
            **data,
            "alert_id": alert_id,
            "analyst_status": alert_status.get("status", "open") if isinstance(alert_status, dict) else "open",
            "analyst_status_reason": alert_status.get("reason", "") if isinstance(alert_status, dict) else "",
        }
    return int(status), data


PORTAL_SOC_WRITE_CALLBACKS = SocWriteCallbacks(
    alert_ack=ack_soc_alert_store_id,
    alert_pcap=soc_alert_pcap_request_response,
    alert_analyze=soc_alert_queue_analysis_response,
    alert_escalate=soc_alert_escalate_response,
    alert_adjudicate=soc_alert_adjudication_response,
    incident_adjudicate=soc_incident_adjudication_response,
    incident_status=soc_incident_status_response,
    incident_reanalyze=soc_incident_reanalysis_response,
    incident_reanalyze_all=soc_incident_bulk_reanalysis_response,
)

def portal_soc_read_callbacks() -> SocReadCallbacks:
    """Bind portal adapters late so tests and runtime overrides remain visible."""
    return SocReadCallbacks(
        llm_current=read_llm_current_analysis,
        llm_logs=llm_analysis_logs_response,
        alert_status=soc_alert_status_response,
        settings_prompt=read_settings_prompt,
        agent_memory=read_agent_memory,
        ai_settings=read_soc_ai_settings,
        ollama_models=ollama_models_response,
        alerts=cached_soc_alerts_query_response,
        alert_metrics=soc_alert_metrics_response,
        alert_suppressions=soc_alert_suppressions_response,
        incidents=soc_incidents_query_response,
        reanalysis_runs=soc_incident_reanalysis_runs_response,
        incident_case_group=_soc_incident_case_group_id,
        api_error=soc_alert_api_error,
        adjudication_history=soc_adjudication_history_response,
        incident_detail=soc_incident_detail_response,
        alert_detail_fragment=soc_alert_detail_fragment_response,
        alert_detail=soc_alert_detail_response,
    )


def portal_general_read_callbacks(home: Callable[[], bytes]) -> GeneralReadCallbacks:
    def cti_program_read() -> tuple[int, dict]:
        result = read_cti_program(portal_cti_program_callbacks(lambda _program: None))
        return result.status, result.payload
    return GeneralReadCallbacks(
        home=home,
        health=lambda: compose_portal_health(
            scan_reports(), SCAN_ROOTS, local_address=local_ip(), generated_at=now_iso_local(),
        ),
        resource_favorites=resource_favorites,
        system_health_beacons=n8n_beacon_history_response,
        asset_inventory=lambda query: asset_inventory_response(query=query),
        dhcp_asset_discovery=dhcp_asset_discovery_response,
        software_inventory=lambda query: software_inventory_response(query=query),
        cti_program=cti_program_read,
    )


def portal_json_write_callbacks(handler) -> JsonWriteCallbacks:
    return JsonWriteCallbacks(
        same_origin_authorized=lambda: handler._soc_review_write_authorized(),
        cti_admin_authenticated=lambda: handler._cti_program_write_authorized(),
        cti_program=portal_cti_program_callbacks(
            lambda program: handler._cti_program_mutation_audit(program),
        ),
        asset_admin_authenticated=lambda: handler._admin_authenticated(),
        asset_dispatcher=dispatch_asset_write,
        soc_dispatcher=dispatch_authorized_soc_write,
        soc=PORTAL_SOC_WRITE_CALLBACKS,
        clear_soc_cache=SOC_ALERT_RESPONSE_CACHE.clear,
        status_update=update_soc_alert_status,
        settings_admin_authenticated=lambda: handler._soc_settings_write_authorized(),
        settings=SocSettingsWriteCallbacks(
            save_prompt=save_settings_prompt,
            save_ai_settings=save_soc_ai_settings,
            save_agent_model=save_soc_agent_model,
        ),
        admin_authenticated=lambda: handler._admin_authenticated(),
        admin_service=AdminServiceWriteCallbacks(ensure_admin_token, start_admin_service),
        resource_library=ResourceLibraryWriteCallbacks(
            move_resource_to_removal, set_resource_tags,
            rename_resource_file, set_resource_favorite,
        ),
    )


PortalHandler = build_portal_handler(
    BaseHTTPRequestHandler, lambda: sys.modules[__name__]
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Arron's persistent LAN report portal")
    parser.add_argument("--host", default=os.environ.get("REPORT_PORTAL_HOST", DEFAULT_HOST))
    parser.add_argument("--port", type=int, default=int(os.environ.get("REPORT_PORTAL_PORT", DEFAULT_PORT)))
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), PortalHandler)
    print(f"Work LAN Portal listening on http://{local_ip()}:{args.port}/ (bind {args.host}:{args.port})", flush=True)
    server.serve_forever()

if __name__ == "__main__":
    main()
