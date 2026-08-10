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
import portal_catalog_runtime
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
