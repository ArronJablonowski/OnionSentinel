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
import portal_admin_runtime
import portal_operational_runtime
import portal_settings_runtime
import portal_soc_status_runtime
import portal_soc_pcap_runtime
import portal_llm_runtime
import portal_soc_query_runtime
import portal_incident_action_runtime
import portal_incident_read_runtime
import portal_soc_record_runtime
import portal_write_runtime
import portal_soc_core_runtime
import portal_soc_detail_runtime
import portal_delivery_runtime
import portal_dashboard_runtime
import portal_foundation_runtime
import portal_access_runtime
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


_FOUNDATION_RUNTIME = sys.modules[__name__]
format_iso_timestamp = partial(portal_foundation_runtime.format_iso_timestamp, _FOUNDATION_RUNTIME)
now_iso_local = partial(portal_foundation_runtime.now_iso_local, _FOUNDATION_RUNTIME)
now_iso_utc = partial(portal_foundation_runtime.now_iso_utc, _FOUNDATION_RUNTIME)
parse_iso_timestamp = partial(portal_foundation_runtime.parse_iso_timestamp, _FOUNDATION_RUNTIME)
_asset_inventory_module = partial(portal_foundation_runtime.asset_inventory_module, _FOUNDATION_RUNTIME)
load_asset_inventory_data = partial(portal_foundation_runtime.load_asset_inventory_data, _FOUNDATION_RUNTIME)
_asset_record_state = partial(portal_foundation_runtime.asset_record_state, _FOUNDATION_RUNTIME)
_asset_public_record = partial(portal_foundation_runtime.asset_public_record, _FOUNDATION_RUNTIME)
load_dhcp_asset_discovery_state_data = partial(portal_foundation_runtime.load_dhcp_asset_discovery_state_data, _FOUNDATION_RUNTIME)
_mac_address_scope = partial(portal_foundation_runtime.mac_address_scope, _FOUNDATION_RUNTIME)
_annotate_exact_ip_dhcp_macs = partial(portal_foundation_runtime.annotate_exact_ip_dhcp_macs, _FOUNDATION_RUNTIME)
_dhcp_asset_inventory_overlay = partial(portal_foundation_runtime.dhcp_asset_inventory_overlay, _FOUNDATION_RUNTIME)
asset_inventory_response = partial(portal_foundation_runtime.asset_inventory_response, _FOUNDATION_RUNTIME)
software_asset_label_snapshot = partial(portal_foundation_runtime.software_asset_label_snapshot, _FOUNDATION_RUNTIME)
software_inventory_response = partial(portal_foundation_runtime.software_inventory_response, _FOUNDATION_RUNTIME)
resolve_asset_ip = partial(portal_foundation_runtime.resolve_asset_ip, _FOUNDATION_RUNTIME)
dhcp_asset_discovery_response = partial(portal_foundation_runtime.dhcp_asset_discovery_response, _FOUNDATION_RUNTIME)
pcap_transfer_duration_seconds = partial(portal_foundation_runtime.pcap_transfer_duration_seconds, _FOUNDATION_RUNTIME)
format_timestamp_text = partial(portal_foundation_runtime.format_timestamp_text, _FOUNDATION_RUNTIME)
_safe_read_json = partial(portal_foundation_runtime.safe_read_json, _FOUNDATION_RUNTIME)
_freshest_existing_path = partial(portal_foundation_runtime.freshest_existing_path, _FOUNDATION_RUNTIME)
n8n_beacon_history_response = partial(portal_foundation_runtime.n8n_beacon_history_response, _FOUNDATION_RUNTIME)
pcap_workflow_health_response = partial(portal_foundation_runtime.pcap_workflow_health_response, _FOUNDATION_RUNTIME)


_ACCESS_RUNTIME = sys.modules[__name__]
ensure_admin_token = partial(portal_access_runtime.ensure_admin_token, _ACCESS_RUNTIME)
load_admin_password_record = partial(portal_access_runtime.load_admin_password_record, _ACCESS_RUNTIME)
admin_password_configured = partial(portal_access_runtime.admin_password_configured, _ACCESS_RUNTIME)
verify_admin_password = partial(portal_access_runtime.verify_admin_password, _ACCESS_RUNTIME)
admin_session_hash = partial(portal_access_runtime.admin_session_hash, _ACCESS_RUNTIME)
load_admin_sessions = partial(portal_access_runtime.load_admin_sessions, _ACCESS_RUNTIME)
save_admin_sessions = partial(portal_access_runtime.save_admin_sessions, _ACCESS_RUNTIME)
prune_admin_sessions = partial(portal_access_runtime.prune_admin_sessions, _ACCESS_RUNTIME)
create_admin_session = partial(portal_access_runtime.create_admin_session, _ACCESS_RUNTIME)
destroy_admin_session = partial(portal_access_runtime.destroy_admin_session, _ACCESS_RUNTIME)
resource_library_id_for = partial(portal_access_runtime.resource_library_id_for, _ACCESS_RUNTIME)
find_resource_library_pdf = partial(portal_access_runtime.find_resource_library_pdf, _ACCESS_RUNTIME)
unique_destination = partial(portal_access_runtime.unique_destination, _ACCESS_RUNTIME)
refresh_resource_library = partial(portal_access_runtime.refresh_resource_library, _ACCESS_RUNTIME)
load_resource_library_metadata = partial(portal_access_runtime.load_resource_library_metadata, _ACCESS_RUNTIME)
save_resource_library_metadata = partial(portal_access_runtime.save_resource_library_metadata, _ACCESS_RUNTIME)
clean_resource_tags = partial(portal_access_runtime.clean_resource_tags, _ACCESS_RUNTIME)
sanitize_resource_filename = partial(portal_access_runtime.sanitize_resource_filename, _ACCESS_RUNTIME)
queue_resource_action = partial(portal_access_runtime.queue_resource_action, _ACCESS_RUNTIME)
trigger_resource_library_worker = partial(portal_access_runtime.trigger_resource_library_worker, _ACCESS_RUNTIME)
resource_favorites = partial(portal_access_runtime.resource_favorites, _ACCESS_RUNTIME)
set_resource_favorite = partial(portal_access_runtime.set_resource_favorite, _ACCESS_RUNTIME)
set_resource_tags = partial(portal_access_runtime.set_resource_tags, _ACCESS_RUNTIME)
rename_resource_file = partial(portal_access_runtime.rename_resource_file, _ACCESS_RUNTIME)
queue_resource_removal = partial(portal_access_runtime.queue_resource_removal, _ACCESS_RUNTIME)
move_resource_to_removal = partial(portal_access_runtime.move_resource_to_removal, _ACCESS_RUNTIME)
parse_cookie_header = partial(portal_access_runtime.parse_cookie_header, _ACCESS_RUNTIME)
admin_session_cookie_header = partial(portal_access_runtime.admin_session_cookie_header, _ACCESS_RUNTIME)
expired_admin_session_cookie_header = partial(portal_access_runtime.expired_admin_session_cookie_header, _ACCESS_RUNTIME)


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


_ADMIN_RUNTIME = sys.modules[__name__]
admin_status_path = partial(portal_admin_runtime.admin_status_path, _ADMIN_RUNTIME)
admin_log_path = partial(portal_admin_runtime.admin_log_path, _ADMIN_RUNTIME)
process_is_running = partial(portal_admin_runtime.process_is_running, _ADMIN_RUNTIME)
_admin_action_state_sources = partial(portal_admin_runtime.admin_action_state_sources, _ADMIN_RUNTIME)
read_admin_action_status = partial(portal_admin_runtime.read_admin_action_status, _ADMIN_RUNTIME)
write_admin_action_status = partial(portal_admin_runtime.write_admin_action_status, _ADMIN_RUNTIME)
latest_admin_action_outcome = partial(portal_admin_runtime.latest_admin_action_outcome, _ADMIN_RUNTIME)
read_admin_lock = partial(portal_admin_runtime.read_admin_lock, _ADMIN_RUNTIME)
running_admin_action = partial(portal_admin_runtime.running_admin_action, _ADMIN_RUNTIME)
claim_admin_action_lock = partial(portal_admin_runtime.claim_admin_action_lock, _ADMIN_RUNTIME)
update_admin_action_lock_pid = partial(portal_admin_runtime.update_admin_action_lock_pid, _ADMIN_RUNTIME)
release_admin_action_lock = partial(portal_admin_runtime.release_admin_action_lock, _ADMIN_RUNTIME)
start_admin_action = partial(portal_admin_runtime.start_admin_action, _ADMIN_RUNTIME)
tail_file = partial(portal_admin_runtime.tail_file, _ADMIN_RUNTIME)
_cron_failure_sources = partial(portal_admin_runtime.cron_failure_sources, _ADMIN_RUNTIME)
cron_failure_records = partial(portal_admin_runtime.cron_failure_records, _ADMIN_RUNTIME)
render_cron_failure_log_section = partial(portal_admin_runtime.render_cron_failure_log_section, _ADMIN_RUNTIME)
_run_admin_version_command = partial(portal_admin_runtime.run_admin_version_command, _ADMIN_RUNTIME)
admin_action_version_info = partial(portal_admin_runtime.admin_action_version_info, _ADMIN_RUNTIME)
check_admin_action_available = partial(portal_admin_runtime.check_admin_action_available, _ADMIN_RUNTIME)


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


ADMIN_SERVICE_LABELS = {
    "macs-fan-control": "Macs Fan Control",
    "codex": "Codex app",
    "codex-cli": "Codex CLI",
    "docker": "Docker",
    "n8n": "n8n container",
}
_admin_process_lines = partial(portal_admin_runtime.admin_process_lines, _ADMIN_RUNTIME)
_admin_service_probe_sources = partial(portal_admin_runtime.admin_service_probe_sources, _ADMIN_RUNTIME)
process_matches = partial(portal_admin_runtime.process_matches, _ADMIN_RUNTIME)
macs_fan_control_status = partial(portal_admin_runtime.macs_fan_control_status, _ADMIN_RUNTIME)
codex_app_status = partial(portal_admin_runtime.codex_app_status, _ADMIN_RUNTIME)
codex_cli_status = partial(portal_admin_runtime.codex_cli_status, _ADMIN_RUNTIME)
docker_status = partial(portal_admin_runtime.docker_status, _ADMIN_RUNTIME)
n8n_container_status = partial(portal_admin_runtime.n8n_container_status, _ADMIN_RUNTIME)
admin_service_statuses = partial(portal_admin_runtime.admin_service_statuses, _ADMIN_RUNTIME)
start_admin_service = partial(portal_admin_runtime.start_admin_service, _ADMIN_RUNTIME)
defang_admin_service_json = partial(portal_admin_runtime.defang_admin_service_json, _ADMIN_RUNTIME)


DISK_INVENTORY_CACHE: dict[str, object] = {
    "generated": 0.0, "dirs": [], "files": [], "warnings": []
}
_OPERATIONAL_RUNTIME = sys.modules[__name__]
system_uptime_metric = partial(portal_operational_runtime.system_uptime_metric, _OPERATIONAL_RUNTIME)
local_disk_usage_metric = partial(portal_operational_runtime.local_disk_usage_metric, _OPERATIONAL_RUNTIME)
_directory_disk_scan = partial(portal_operational_runtime.directory_disk_scan, _OPERATIONAL_RUNTIME)
_file_disk_scan = partial(portal_operational_runtime.file_disk_scan, _OPERATIONAL_RUNTIME)
local_disk_inventory = partial(portal_operational_runtime.local_disk_inventory, _OPERATIONAL_RUNTIME)
disk_inventory_rows = partial(portal_operational_runtime.disk_inventory_rows, _OPERATIONAL_RUNTIME)
disk_file_inventory_rows = partial(portal_operational_runtime.disk_file_inventory_rows, _OPERATIONAL_RUNTIME)
hermes_backup_sources = partial(portal_operational_runtime.hermes_backup_sources, _OPERATIONAL_RUNTIME)
latest_hermes_backup_metric = partial(portal_operational_runtime.latest_hermes_backup_metric, _OPERATIONAL_RUNTIME)
macos_update_metric = partial(portal_operational_runtime.macos_update_metric, _OPERATIONAL_RUNTIME)
_brew_update_check = partial(portal_operational_runtime.brew_update_check, _OPERATIONAL_RUNTIME)
_hermes_update_check = partial(portal_operational_runtime.hermes_update_check, _OPERATIONAL_RUNTIME)
update_health_sources = partial(portal_operational_runtime.update_health_sources, _OPERATIONAL_RUNTIME)
brew_update_source_metric = partial(portal_operational_runtime.brew_update_source_metric, _OPERATIONAL_RUNTIME)
hermes_update_source_metric = partial(portal_operational_runtime.hermes_update_source_metric, _OPERATIONAL_RUNTIME)
latest_running_update_action = partial(portal_operational_runtime.latest_running_update_action, _OPERATIONAL_RUNTIME)
latest_update_action_failure = partial(portal_operational_runtime.latest_update_action_failure, _OPERATIONAL_RUNTIME)
prioritized_updates_metric = partial(portal_operational_runtime.prioritized_updates_metric, _OPERATIONAL_RUNTIME)
human_time = partial(portal_operational_runtime.human_time, _OPERATIONAL_RUNTIME)
update_time_label = partial(portal_operational_runtime.update_time_label, _OPERATIONAL_RUNTIME)
relative_time_label = partial(portal_operational_runtime.relative_time_label, _OPERATIONAL_RUNTIME)
admin_last_performed_label = partial(portal_operational_runtime.admin_last_performed_label, _OPERATIONAL_RUNTIME)
portal_last_updated = partial(portal_operational_runtime.portal_last_updated, _OPERATIONAL_RUNTIME)
schedule_label = partial(portal_operational_runtime.schedule_label, _OPERATIONAL_RUNTIME)
next_run_label = partial(portal_operational_runtime.next_run_label, _OPERATIONAL_RUNTIME)
load_cron_summaries = partial(portal_operational_runtime.load_cron_summaries, _OPERATIONAL_RUNTIME)
render_cron_menu = partial(portal_operational_runtime.render_cron_menu, _OPERATIONAL_RUNTIME)
render_cron_item = partial(portal_operational_runtime.render_cron_item, _OPERATIONAL_RUNTIME)
icon_for = partial(portal_operational_runtime.icon_for, _OPERATIONAL_RUNTIME)
redact_sensitive_text = partial(portal_operational_runtime.redact_sensitive_text, _OPERATIONAL_RUNTIME)
read_macos_update_status = partial(portal_operational_runtime.read_macos_update_status, _OPERATIONAL_RUNTIME)


_DASHBOARD_RUNTIME = sys.modules[__name__]
backup_inventory = partial(portal_dashboard_runtime.backup_inventory, _DASHBOARD_RUNTIME)
metric_detail_shell = partial(portal_dashboard_runtime.metric_detail_shell, _DASHBOARD_RUNTIME)
render_macos_updates_detail = partial(portal_dashboard_runtime.render_macos_updates_detail, _DASHBOARD_RUNTIME)
render_prioritized_updates_detail = partial(portal_dashboard_runtime.render_prioritized_updates_detail, _DASHBOARD_RUNTIME)
render_hermes_backups_detail = partial(portal_dashboard_runtime.render_hermes_backups_detail, _DASHBOARD_RUNTIME)
render_system_uptime_detail = partial(portal_dashboard_runtime.render_system_uptime_detail, _DASHBOARD_RUNTIME)
render_local_disk_detail = partial(portal_dashboard_runtime.render_local_disk_detail, _DASHBOARD_RUNTIME)
render_portal_update_detail = partial(portal_dashboard_runtime.render_portal_update_detail, _DASHBOARD_RUNTIME)
render_admin_login = partial(portal_dashboard_runtime.render_admin_login, _DASHBOARD_RUNTIME)
render_admin_dashboard = partial(portal_dashboard_runtime.render_admin_dashboard, _DASHBOARD_RUNTIME)
render_home = partial(portal_dashboard_runtime.render_home, _DASHBOARD_RUNTIME)


_SOC_DETAIL_RUNTIME = sys.modules[__name__]
normalize_soc_alert_status_meta = partial(portal_soc_detail_runtime.normalize_soc_alert_status_meta, _SOC_DETAIL_RUNTIME)
ensure_soc_alert_status_table = partial(portal_soc_detail_runtime.ensure_soc_alert_status_table, _SOC_DETAIL_RUNTIME)
soc_alert_group_key_from_values = partial(portal_soc_detail_runtime.soc_alert_group_key_from_values, _SOC_DETAIL_RUNTIME)
soc_alert_group_id = partial(portal_soc_detail_runtime.soc_alert_group_id, _SOC_DETAIL_RUNTIME)
soc_alert_group_key_sql = partial(portal_soc_detail_runtime.soc_alert_group_key_sql, _SOC_DETAIL_RUNTIME)
soc_alert_public_enrichment_status = partial(portal_soc_detail_runtime.soc_alert_public_enrichment_status, _SOC_DETAIL_RUNTIME)
soc_alert_group_enrichment_json = partial(portal_soc_detail_runtime.soc_alert_group_enrichment_json, _SOC_DETAIL_RUNTIME)
soc_alert_group_enrichment_json_map = partial(portal_soc_detail_runtime.soc_alert_group_enrichment_json_map, _SOC_DETAIL_RUNTIME)
directory_size_bytes = partial(portal_soc_detail_runtime.directory_size_bytes, _SOC_DETAIL_RUNTIME)
soc_alert_validate_detail_layout_html = partial(portal_soc_detail_runtime.soc_alert_validate_detail_layout_html, _SOC_DETAIL_RUNTIME)
soc_alert_layout_error_html = partial(portal_soc_detail_runtime.soc_alert_layout_error_html, _SOC_DETAIL_RUNTIME)
soc_alert_append_live_pcap_detail = partial(portal_soc_detail_runtime.soc_alert_append_live_pcap_detail, _SOC_DETAIL_RUNTIME)
soc_alert_normalize_heading_text = partial(portal_soc_detail_runtime.soc_alert_normalize_heading_text, _SOC_DETAIL_RUNTIME)
soc_alert_collapse_detail_sections = partial(portal_soc_detail_runtime.soc_alert_collapse_detail_sections, _SOC_DETAIL_RUNTIME)


_SOC_PCAP_RUNTIME = sys.modules[__name__]
soc_alert_has_parsed_pcap = partial(portal_soc_pcap_runtime.soc_alert_has_parsed_pcap, _SOC_PCAP_RUNTIME)
read_artifact_cache = partial(portal_soc_pcap_runtime.read_artifact_cache, _SOC_PCAP_RUNTIME)
write_artifact_cache = partial(portal_soc_pcap_runtime.write_artifact_cache, _SOC_PCAP_RUNTIME)
_soc_pcap_artifact_sources = partial(portal_soc_pcap_runtime.soc_pcap_artifact_sources, _SOC_PCAP_RUNTIME)
soc_alert_pcap_analysis_index = partial(portal_soc_pcap_runtime.soc_alert_pcap_analysis_index, _SOC_PCAP_RUNTIME)
soc_alert_pcap_request_statuses = partial(portal_soc_pcap_runtime.soc_alert_pcap_request_statuses, _SOC_PCAP_RUNTIME)
soc_alert_pcap_status = partial(portal_soc_pcap_runtime.soc_alert_pcap_status, _SOC_PCAP_RUNTIME)
soc_alert_pcap_analysis_record = partial(portal_soc_pcap_runtime.soc_alert_pcap_analysis_record, _SOC_PCAP_RUNTIME)
soc_alert_pcap_summary_html = partial(portal_soc_pcap_runtime.soc_alert_pcap_summary_html, _SOC_PCAP_RUNTIME)
sqlite_table_exists = partial(portal_soc_pcap_runtime.sqlite_table_exists, _SOC_PCAP_RUNTIME)
sqlite_table_columns = partial(portal_soc_pcap_runtime.sqlite_table_columns, _SOC_PCAP_RUNTIME)
bounded_int = partial(portal_soc_pcap_runtime.bounded_int, _SOC_PCAP_RUNTIME)
pcap_request_id = partial(portal_soc_pcap_runtime.pcap_request_id, _SOC_PCAP_RUNTIME)
normalize_pcap_timestamp = partial(portal_soc_pcap_runtime.normalize_pcap_timestamp, _SOC_PCAP_RUNTIME)
pcap_capture_file_from_json = partial(portal_soc_pcap_runtime.pcap_capture_file_from_json, _SOC_PCAP_RUNTIME)
pcap_request_store_sources = partial(portal_soc_pcap_runtime.pcap_request_store_sources, _SOC_PCAP_RUNTIME)
pcap_request_candidate_from_group = partial(portal_soc_pcap_runtime.pcap_request_candidate_from_group, _SOC_PCAP_RUNTIME)
pcap_request_policy_sources = partial(portal_soc_pcap_runtime.pcap_request_policy_sources, _SOC_PCAP_RUNTIME)
normalize_pcap_request = partial(portal_soc_pcap_runtime.normalize_pcap_request, _SOC_PCAP_RUNTIME)
insert_pcap_request = partial(portal_soc_pcap_runtime.insert_pcap_request, _SOC_PCAP_RUNTIME)
pcap_request_service_sources = partial(portal_soc_pcap_runtime.pcap_request_service_sources, _SOC_PCAP_RUNTIME)
soc_alert_pcap_request_response = partial(portal_soc_pcap_runtime.soc_alert_pcap_request_response, _SOC_PCAP_RUNTIME)


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



_WRITE_RUNTIME = sys.modules[__name__]
asset_store_write_token = partial(portal_write_runtime.asset_store_write_token, _WRITE_RUNTIME)
asset_store_post_json = partial(portal_write_runtime.asset_store_post_json, _WRITE_RUNTIME)
alert_store_post_json = partial(portal_write_runtime.alert_store_post_json, _WRITE_RUNTIME)
_normalized_asset_review_payload = partial(portal_write_runtime.normalized_asset_review_payload, _WRITE_RUNTIME)
_clear_asset_inventory_cache = partial(portal_write_runtime.clear_asset_inventory_cache, _WRITE_RUNTIME)
asset_dhcp_promotion_response = partial(portal_write_runtime.asset_dhcp_promotion_response, _WRITE_RUNTIME)
asset_dhcp_ip_change_response = partial(portal_write_runtime.asset_dhcp_ip_change_response, _WRITE_RUNTIME)
_normalized_asset_mutation_payload = partial(portal_write_runtime.normalized_asset_mutation_payload, _WRITE_RUNTIME)
asset_update_response = partial(portal_write_runtime.asset_update_response, _WRITE_RUNTIME)
asset_demote_response = partial(portal_write_runtime.asset_demote_response, _WRITE_RUNTIME)
dispatch_asset_write = partial(portal_write_runtime.dispatch_asset_write, _WRITE_RUNTIME)
portal_cti_program_callbacks = partial(portal_write_runtime.portal_cti_program_callbacks, _WRITE_RUNTIME)
alert_store_get_json = partial(portal_write_runtime.alert_store_get_json, _WRITE_RUNTIME)


_SOC_STATUS_RUNTIME = sys.modules[__name__]
soc_alert_group_summary_available = partial(portal_soc_status_runtime.soc_alert_group_summary_available, _SOC_STATUS_RUNTIME)
soc_alert_group_counts = partial(portal_soc_status_runtime.soc_alert_group_counts, _SOC_STATUS_RUNTIME)
soc_alert_manually_escalated_group_ids = partial(portal_soc_status_runtime.soc_alert_manually_escalated_group_ids, _SOC_STATUS_RUNTIME)
soc_alert_active_group_ids = partial(portal_soc_status_runtime.soc_alert_active_group_ids, _SOC_STATUS_RUNTIME)
soc_alert_status_store_sources = partial(portal_soc_status_runtime.soc_alert_status_store_sources, _SOC_STATUS_RUNTIME)
normalize_soc_group_statuses = partial(portal_soc_status_runtime.normalize_soc_group_statuses, _SOC_STATUS_RUNTIME)
soc_alert_status_persistence_sources = partial(portal_soc_status_runtime.soc_alert_status_persistence_sources, _SOC_STATUS_RUNTIME)
load_soc_alert_statuses_from_db = partial(portal_soc_status_runtime.load_soc_alert_statuses_from_db, _SOC_STATUS_RUNTIME)
write_soc_alert_status_json_snapshot = partial(portal_soc_status_runtime.write_soc_alert_status_json_snapshot, _SOC_STATUS_RUNTIME)
save_soc_alert_statuses_to_db = partial(portal_soc_status_runtime.save_soc_alert_statuses_to_db, _SOC_STATUS_RUNTIME)
load_soc_alert_statuses = partial(portal_soc_status_runtime.load_soc_alert_statuses, _SOC_STATUS_RUNTIME)
save_soc_alert_statuses = partial(portal_soc_status_runtime.save_soc_alert_statuses, _SOC_STATUS_RUNTIME)
current_soc_alert_group_repeat_count = partial(portal_soc_status_runtime.current_soc_alert_group_repeat_count, _SOC_STATUS_RUNTIME)
write_soc_alert_status = partial(portal_soc_status_runtime.write_soc_alert_status, _SOC_STATUS_RUNTIME)
soc_alert_status_response = partial(portal_soc_status_runtime.soc_alert_status_response, _SOC_STATUS_RUNTIME)


_LLM_RUNTIME = sys.modules[__name__]
llm_analysis_log_limit = partial(portal_llm_runtime.llm_analysis_log_limit, _LLM_RUNTIME)
llm_analysis_log_page = partial(portal_llm_runtime.llm_analysis_log_page, _LLM_RUNTIME)
read_llm_analysis_logs = partial(portal_llm_runtime.read_llm_analysis_logs, _LLM_RUNTIME)
current_llm_queue_size = partial(portal_llm_runtime.current_llm_queue_size, _LLM_RUNTIME)
read_bounded_llm_analysis_record = partial(portal_llm_runtime.read_bounded_llm_analysis_record, _LLM_RUNTIME)
active_llm_analysis_record_paths = partial(portal_llm_runtime.active_llm_analysis_record_paths, _LLM_RUNTIME)
active_llm_sources = partial(portal_llm_runtime.active_llm_sources, _LLM_RUNTIME)
read_active_llm_analyses = partial(portal_llm_runtime.read_active_llm_analyses, _LLM_RUNTIME)
llm_agent_execution_state = partial(portal_llm_runtime.llm_agent_execution_state, _LLM_RUNTIME)
decorate_llm_analysis_record = partial(portal_llm_runtime.decorate_llm_analysis_record, _LLM_RUNTIME)
read_llm_current_analysis = partial(portal_llm_runtime.read_llm_current_analysis, _LLM_RUNTIME)
merge_live_llm_activity = partial(portal_llm_runtime.merge_live_llm_activity, _LLM_RUNTIME)
llm_analysis_process_commands = partial(portal_llm_runtime.llm_analysis_process_commands, _LLM_RUNTIME)
llm_analysis_process_active = partial(portal_llm_runtime.llm_analysis_process_active, _LLM_RUNTIME)
llm_history_store_sources = partial(portal_llm_runtime.llm_history_store_sources, _LLM_RUNTIME)
_llm_analysis_run_timestamp = partial(portal_llm_runtime.llm_analysis_run_timestamp, _LLM_RUNTIME)
_llm_primary_run_identity = partial(portal_llm_runtime.llm_primary_run_identity, _LLM_RUNTIME)
read_llm_database_primary_logs = partial(portal_llm_runtime.read_llm_database_primary_logs, _LLM_RUNTIME)
reconcile_llm_primary_logs = partial(portal_llm_runtime.reconcile_llm_primary_logs, _LLM_RUNTIME)
_llm_reviewer_started_at = partial(portal_llm_runtime.llm_reviewer_started_at, _LLM_RUNTIME)
hydrate_llm_reviewer_from_parent = partial(portal_llm_runtime.hydrate_llm_reviewer_from_parent, _LLM_RUNTIME)
read_llm_second_opinion_logs = partial(portal_llm_runtime.read_llm_second_opinion_logs, _LLM_RUNTIME)
read_llm_disagreement_adjudication_logs = partial(portal_llm_runtime.read_llm_disagreement_adjudication_logs, _LLM_RUNTIME)
_llm_log_sort_timestamp = partial(portal_llm_runtime.llm_log_sort_timestamp, _LLM_RUNTIME)
llm_history_api_sources = partial(portal_llm_runtime.llm_history_api_sources, _LLM_RUNTIME)
read_llm_agent_activity_snapshot = partial(portal_llm_runtime.read_llm_agent_activity_snapshot, _LLM_RUNTIME)
llm_analysis_logs_response = partial(portal_llm_runtime.llm_analysis_logs_response, _LLM_RUNTIME)


LLM_ANALYSIS_COMBINED_HISTORY_LIMIT = 5000
LLM_AGENT_ACTIVITY_CACHE = ResponseCache(
    3.0,
    max_entries=1,
    lock_stripes=1,
)



_SOC_CORE_RUNTIME = sys.modules[__name__]
soc_alert_suppression_review_state = partial(portal_soc_core_runtime.soc_alert_suppression_review_state, _SOC_CORE_RUNTIME)
soc_alert_status_write_sources = partial(portal_soc_core_runtime.soc_alert_status_write_sources, _SOC_CORE_RUNTIME)
update_soc_alert_status = partial(portal_soc_core_runtime.update_soc_alert_status, _SOC_CORE_RUNTIME)
valid_soc_alert_store_id = partial(portal_soc_core_runtime.valid_soc_alert_store_id, _SOC_CORE_RUNTIME)
soc_alert_api_error = partial(portal_soc_core_runtime.soc_alert_api_error, _SOC_CORE_RUNTIME)
soc_alert_db_connect = partial(portal_soc_core_runtime.soc_alert_db_connect, _SOC_CORE_RUNTIME)
soc_alert_db_write_connect = partial(portal_soc_core_runtime.soc_alert_db_write_connect, _SOC_CORE_RUNTIME)
parse_soc_alert_since = partial(portal_soc_core_runtime.parse_soc_alert_since, _SOC_CORE_RUNTIME)
soc_alert_level_names = partial(portal_soc_core_runtime.soc_alert_level_names, _SOC_CORE_RUNTIME)
soc_alert_row_level = partial(portal_soc_core_runtime.soc_alert_row_level, _SOC_CORE_RUNTIME)
soc_alert_visible_severity_summary = partial(portal_soc_core_runtime.soc_alert_visible_severity_summary, _SOC_CORE_RUNTIME)
soc_alert_limit = partial(portal_soc_core_runtime.soc_alert_limit, _SOC_CORE_RUNTIME)
soc_alert_page = partial(portal_soc_core_runtime.soc_alert_page, _SOC_CORE_RUNTIME)
soc_alert_sort_clause = partial(portal_soc_core_runtime.soc_alert_sort_clause, _SOC_CORE_RUNTIME)
soc_alert_cursor_parts = partial(portal_soc_core_runtime.soc_alert_cursor_parts, _SOC_CORE_RUNTIME)


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

_SOC_RECORD_RUNTIME = sys.modules[__name__]
soc_alert_row_to_api = partial(portal_soc_record_runtime.soc_alert_row_to_api, _SOC_RECORD_RUNTIME)
soc_alert_static_ai_reports = partial(portal_soc_record_runtime.soc_alert_static_ai_reports, _SOC_RECORD_RUNTIME)
_soc_ai_artifact_sources = partial(portal_soc_record_runtime.soc_ai_artifact_sources, _SOC_RECORD_RUNTIME)
soc_alert_latest_prompt_mtime = partial(portal_soc_record_runtime.soc_alert_latest_prompt_mtime, _SOC_RECORD_RUNTIME)
soc_alert_latest_analysis_mtime = partial(portal_soc_record_runtime.soc_alert_latest_analysis_mtime, _SOC_RECORD_RUNTIME)
soc_alert_ai_artifact_index = partial(portal_soc_record_runtime.soc_alert_ai_artifact_index, _SOC_RECORD_RUNTIME)
_soc_ai_group_members = partial(portal_soc_record_runtime.soc_ai_group_members, _SOC_RECORD_RUNTIME)
soc_alert_page_ai_artifact_context = partial(portal_soc_record_runtime.soc_alert_page_ai_artifact_context, _SOC_RECORD_RUNTIME)
soc_alert_group_has_analysis_artifact = partial(portal_soc_record_runtime.soc_alert_group_has_analysis_artifact, _SOC_RECORD_RUNTIME)
soc_alert_severity_meets_analysis_threshold = partial(portal_soc_record_runtime.soc_alert_severity_meets_analysis_threshold, _SOC_RECORD_RUNTIME)
soc_alert_group_ai_status = partial(portal_soc_record_runtime.soc_alert_group_ai_status, _SOC_RECORD_RUNTIME)
soc_alert_detection_outcome_label = partial(portal_soc_record_runtime.soc_alert_detection_outcome_label, _SOC_RECORD_RUNTIME)
_soc_review_epoch = partial(portal_soc_record_runtime.soc_review_epoch, _SOC_RECORD_RUNTIME)
soc_alert_apply_review_metadata = partial(portal_soc_record_runtime.soc_alert_apply_review_metadata, _SOC_RECORD_RUNTIME)
soc_alert_review_state_for_group = partial(portal_soc_record_runtime.soc_alert_review_state_for_group, _SOC_RECORD_RUNTIME)
soc_alert_apply_incident_metadata = partial(portal_soc_record_runtime.soc_alert_apply_incident_metadata, _SOC_RECORD_RUNTIME)
soc_alert_group_evidence_metadata = partial(portal_soc_record_runtime.soc_alert_group_evidence_metadata, _SOC_RECORD_RUNTIME)
soc_alert_group_row_to_api = partial(portal_soc_record_runtime.soc_alert_group_row_to_api, _SOC_RECORD_RUNTIME)
soc_alert_group_representative_alert_id = partial(portal_soc_record_runtime.soc_alert_group_representative_alert_id, _SOC_RECORD_RUNTIME)


_INCIDENT_ACTION_RUNTIME = sys.modules[__name__]
_forward_controlled_dispatch_contract = partial(portal_incident_action_runtime.forward_controlled_dispatch_contract, _INCIDENT_ACTION_RUNTIME)
soc_action_service_sources = partial(portal_incident_action_runtime.soc_action_service_sources, _INCIDENT_ACTION_RUNTIME)
soc_alert_queue_analysis_response = partial(portal_incident_action_runtime.soc_alert_queue_analysis_response, _INCIDENT_ACTION_RUNTIME)
soc_alert_escalate_response = partial(portal_incident_action_runtime.soc_alert_escalate_response, _INCIDENT_ACTION_RUNTIME)
_soc_legacy_verdict_factors = partial(portal_incident_action_runtime.soc_legacy_verdict_factors, _INCIDENT_ACTION_RUNTIME)
_soc_derive_legacy_detection_outcome = partial(portal_incident_action_runtime.soc_derive_legacy_detection_outcome, _INCIDENT_ACTION_RUNTIME)
_soc_adjudication_verdict_contradictions = partial(portal_incident_action_runtime.soc_adjudication_verdict_contradictions, _INCIDENT_ACTION_RUNTIME)
normalize_soc_adjudication_payload = partial(portal_incident_action_runtime.normalize_soc_adjudication_payload, _INCIDENT_ACTION_RUNTIME)
_soc_alert_store_mutation = partial(portal_incident_action_runtime.soc_alert_store_mutation, _INCIDENT_ACTION_RUNTIME)
soc_alert_adjudication_response = partial(portal_incident_action_runtime.soc_alert_adjudication_response, _INCIDENT_ACTION_RUNTIME)
_soc_incident_case_group_id = partial(portal_incident_action_runtime.soc_incident_case_group_id, _INCIDENT_ACTION_RUNTIME)
soc_incident_adjudication_response = partial(portal_incident_action_runtime.soc_incident_adjudication_response, _INCIDENT_ACTION_RUNTIME)
soc_incident_status_response = partial(portal_incident_action_runtime.soc_incident_status_response, _INCIDENT_ACTION_RUNTIME)
soc_incident_reanalysis_response = partial(portal_incident_action_runtime.soc_incident_reanalysis_response, _INCIDENT_ACTION_RUNTIME)
soc_incident_bulk_reanalysis_response = partial(portal_incident_action_runtime.soc_incident_bulk_reanalysis_response, _INCIDENT_ACTION_RUNTIME)
soc_incident_reanalysis_runs_response = partial(portal_incident_action_runtime.soc_incident_reanalysis_runs_response, _INCIDENT_ACTION_RUNTIME)
soc_incident_current_analysis = partial(portal_incident_action_runtime.soc_incident_current_analysis, _INCIDENT_ACTION_RUNTIME)
soc_adjudication_history_sources = partial(portal_incident_action_runtime.soc_adjudication_history_sources, _INCIDENT_ACTION_RUNTIME)
soc_adjudication_history_response = partial(portal_incident_action_runtime.soc_adjudication_history_response, _INCIDENT_ACTION_RUNTIME)
soc_incident_agent_display_state = partial(portal_incident_action_runtime.soc_incident_agent_display_state, _INCIDENT_ACTION_RUNTIME)


INCIDENT_ROW_CALLBACKS = IncidentRowCallbacks(
    epoch=_soc_review_epoch,
    embedded_reviewer=_soc_embedded_reviewer,
    final_review_status=_soc_review_final_status,
    outcome_label=soc_alert_detection_outcome_label,
    agent_display_state=soc_incident_agent_display_state,
    reviewer_authorization=_soc_reviewer_automation_authorization,
    resolve_asset_ip=resolve_asset_ip,
)


_INCIDENT_READ_RUNTIME = sys.modules[__name__]
soc_incidents_query_response = partial(portal_incident_read_runtime.soc_incidents_query_response, _INCIDENT_READ_RUNTIME)
soc_incident_review_state = partial(portal_incident_read_runtime.soc_incident_review_state, _INCIDENT_READ_RUNTIME)
_incident_html_text = partial(portal_incident_read_runtime.incident_html_text, _INCIDENT_READ_RUNTIME)
_incident_nonnegative_int = partial(portal_incident_read_runtime.incident_nonnegative_int, _INCIDENT_READ_RUNTIME)
_incident_query_linked_finding = partial(portal_incident_read_runtime.incident_query_linked_finding, _INCIDENT_READ_RUNTIME)
_incident_html_list = partial(portal_incident_read_runtime.incident_html_list, _INCIDENT_READ_RUNTIME)
_incident_report_section = partial(portal_incident_read_runtime.incident_report_section, _INCIDENT_READ_RUNTIME)
render_analyst_review_panel = partial(portal_incident_read_runtime.render_analyst_review_panel, _INCIDENT_READ_RUNTIME)
render_investigation_query_audit_html = partial(portal_incident_read_runtime.render_investigation_query_audit_html, _INCIDENT_READ_RUNTIME)
render_incident_response_report_html = partial(portal_incident_read_runtime.render_incident_response_report_html, _INCIDENT_READ_RUNTIME)
render_prior_soc_analysis_html = partial(portal_incident_read_runtime.render_prior_soc_analysis_html, _INCIDENT_READ_RUNTIME)
incident_read_service_sources = partial(portal_incident_read_runtime.incident_read_service_sources, _INCIDENT_READ_RUNTIME)
soc_incident_detail_response = partial(portal_incident_read_runtime.soc_incident_detail_response, _INCIDENT_READ_RUNTIME)


_SOC_QUERY_RUNTIME = sys.modules[__name__]
soc_alert_status_bucket_counts = partial(portal_soc_query_runtime.soc_alert_status_bucket_counts, _SOC_QUERY_RUNTIME)
soc_alert_top_endpoint_metrics = partial(portal_soc_query_runtime.soc_alert_top_endpoint_metrics, _SOC_QUERY_RUNTIME)
soc_alert_group_id_for_query_row = partial(portal_soc_query_runtime.soc_alert_group_id_for_query_row, _SOC_QUERY_RUNTIME)
soc_alert_enriched_page_rows = partial(portal_soc_query_runtime.soc_alert_enriched_page_rows, _SOC_QUERY_RUNTIME)
soc_alert_group_query_snapshot = partial(portal_soc_query_runtime.soc_alert_group_query_snapshot, _SOC_QUERY_RUNTIME)
soc_alert_group_query_payload = partial(portal_soc_query_runtime.soc_alert_group_query_payload, _SOC_QUERY_RUNTIME)
_soc_analysis_min_severity = partial(portal_soc_query_runtime.soc_analysis_min_severity, _SOC_QUERY_RUNTIME)
_soc_group_page_evidence = partial(portal_soc_query_runtime.soc_group_page_evidence, _SOC_QUERY_RUNTIME)
soc_alert_group_query_request = partial(portal_soc_query_runtime.soc_alert_group_query_request, _SOC_QUERY_RUNTIME)
soc_alerts_summary_query_response = partial(portal_soc_query_runtime.soc_alerts_summary_query_response, _SOC_QUERY_RUNTIME)
soc_alerts_query_response = partial(portal_soc_query_runtime.soc_alerts_query_response, _SOC_QUERY_RUNTIME)
cached_soc_alerts_query_response = partial(portal_soc_query_runtime.cached_soc_alerts_query_response, _SOC_QUERY_RUNTIME)
soc_alert_detail_fragment_response = partial(portal_soc_query_runtime.soc_alert_detail_fragment_response, _SOC_QUERY_RUNTIME)
soc_alert_detail_response = partial(portal_soc_query_runtime.soc_alert_detail_response, _SOC_QUERY_RUNTIME)
soc_alert_metrics_response = partial(portal_soc_query_runtime.soc_alert_metrics_response, _SOC_QUERY_RUNTIME)
soc_alert_suppressions_response = partial(portal_soc_query_runtime.soc_alert_suppressions_response, _SOC_QUERY_RUNTIME)


_DELIVERY_RUNTIME = sys.modules[__name__]
read_soc_alert_json_file = partial(portal_delivery_runtime.read_soc_alert_json_file, _DELIVERY_RUNTIME)
soc_alert_events_snapshot = partial(portal_delivery_runtime.soc_alert_events_snapshot, _DELIVERY_RUNTIME)
asset_inventory_live_revision = partial(portal_delivery_runtime.asset_inventory_live_revision, _DELIVERY_RUNTIME)
dhcp_asset_discovery_live_revision = partial(portal_delivery_runtime.dhcp_asset_discovery_live_revision, _DELIVERY_RUNTIME)
software_inventory_live_revision = partial(portal_delivery_runtime.software_inventory_live_revision, _DELIVERY_RUNTIME)
incident_response_live_revision = partial(portal_delivery_runtime.incident_response_live_revision, _DELIVERY_RUNTIME)
dashboard_live_revisions = partial(portal_delivery_runtime.dashboard_live_revisions, _DELIVERY_RUNTIME)
ac_hunter_live_revision = partial(portal_delivery_runtime.ac_hunter_live_revision, _DELIVERY_RUNTIME)
cached_soc_alert_events_snapshot = partial(portal_delivery_runtime.cached_soc_alert_events_snapshot, _DELIVERY_RUNTIME)
ack_soc_alert_store_id = partial(portal_delivery_runtime.ack_soc_alert_store_id, _DELIVERY_RUNTIME)
portal_soc_read_callbacks = partial(portal_delivery_runtime.portal_soc_read_callbacks, _DELIVERY_RUNTIME)
portal_general_read_callbacks = partial(portal_delivery_runtime.portal_general_read_callbacks, _DELIVERY_RUNTIME)
portal_json_write_callbacks = partial(portal_delivery_runtime.portal_json_write_callbacks, _DELIVERY_RUNTIME)


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
